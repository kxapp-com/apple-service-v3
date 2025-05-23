package gsa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"gitee.com/kxapp/kxapp-common/errorz"
	"github.com/appuploader/apple-service-v3/appuploader"
	"github.com/appuploader/apple-service-v3/srp"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"howett.net/plist"
	"reflect"
	"strconv"
	"time"
)

const APP_BUNDLE_ID_XCODE = "com.apple.gs.xcode.auth"

// var XMmeClientInfo string = "<MacBookPro17,1> <macOS;12.2.1;21D62> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>" //work good
var XMmeClientInfo string // "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>" //work good
// GsaClient apple gsa login
type GsaClient struct {
	ExchangeHashFun hash.Hash
	//Proto     []string
	sRPClient *srp.SRPClient
	UserName  string
	Password  string
	CPD       *GSARequestCPD
	DCH       bool //DisregardChannelBindings
	SC        []byte
}

/*
udid X-Mme-Device-Id  MobileMe Device Identifier
imd X-Apple-I-MD Machine Data, One Time Password (OTP)
imdm X-Apple-I-MD-M Machine Data, Machine Information
*/
func NewSrpGsaClient(username, password string, data *appuploader.AnisseteData) *GsaClient {
	context := new(GsaClient)
	context.sRPClient = srp.NewSRPClient(srp.GetSRPParam(srp.SRP_N_LEN_2048), nil)
	context.UserName = username
	context.Password = password
	context.ExchangeHashFun = sha256.New()
	XMmeClientInfo = data.XMmeClientInfo

	rinfo, _ := strconv.Atoi(data.XAppleIMDRINFO)
	var cpd = GSARequestCPD{CID: data.XMmeDeviceId, ClientTime: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		IMD: data.XAppleIMD, IMDM: data.XAppleIMDM, RInfo: rinfo, BootStrap: true, CKGen: true, UDID: data.XMmeDeviceId}
	cpd.SerialNumber = data.XAppleISRLNO
	cpd.Loc = data.XAppleLocale
	cpd.ClientTimeZone = data.XAppleITimeZone
	cpd.Icscrec = true
	cpd.PRKGEN = true
	cpd.SVCT = "iCloud"
	/*cpd = {
		# Many of these values are not strictly necessary, but may be tracked by Apple
		# I've chosen to match the AltServer implementation
		# Not sure what these are for, needs some investigation
		"bootstrap": True,  # All implementations set this to true
		"icscrec": True,  # Only AltServer sets this to true
		"pbe": False,  # All implementations explicitly set this to false
		"prkgen": True,  # I've also seen ckgen
		"svct": "iCloud",  # In certian circumstances, this can be 'iTunes' or 'iCloud'
		# Not included, but I've also seen:
		# 'capp': 'AppStore',
		# 'dc': '#d4c5b3',
		# 'dec': '#e1e4e3',
		# 'prtn': 'ME349',
	}*/
	//var cpd = GSARequestCPD{CID: "649B8728-B398-4A6A-835A-5517488C3F9A", ClientTime: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	//	IMD: data.XAppleIMD, IMDM: data.XAppleIMDM, RInfo: 17106176, BootStrap: true, CKGen: true, UDID: data.XMmeDeviceId}
	context.CPD = &cpd
	return context
}

/*
*
开始登录，返回失败的状态码，如果成功返回m2解密的spd数据，也就是token数据,tokens数据是nsdic格式,可用被plist.unmarshal 为ServerProvidedData
得到spd表示密码校验成功，后面可用使用spd里面的token开始二次校验登录或者获取其他的token
如果hsc=434表示 anissete 已经过期，如果是433则表示需要reprovision设备了,409表示需要2次校验，200表示成功
*/
func (gsaSession *GsaClient) Login() (*ServerProvidedData, *errorz.StatusError) {
	resp, e := gsaSession.RequestInitForB()
	if e != nil {
		return nil, e
	}
	m1 := gsaSession.CalculateM1(resp)
	if len(m1) == 0 {
		return nil, errorz.NewInternalError("calculate m1 fail ,internal error")
	}
	m2Response, e2 := gsaSession.RequestCompleteForM2(m1, resp.Cookie, resp.SeverProto)
	if e2 != nil {
		return nil, e2
	}
	if !reflect.DeepEqual(m2Response.M2, gsaSession.sRPClient.M2) {
		return nil, errorz.NewInternalError("m2 check failed,internal error")
	}
	var spd ServerProvidedData
	_, e3 := plist.Unmarshal(m2Response.SPD, &spd)
	if e3 != nil {
		return nil, errorz.NewParseDataError(e3)
	}
	return &spd, nil
}

/*
*
登录的第一个请求，发送init请求SRP的B值
*/
func (gsaSession *GsaClient) RequestInitForB() (*GSAInitResponse, *errorz.StatusError) {
	req := GSAInitRequest{A2K: gsaSession.sRPClient.GetA(), CPD: gsaSession.CPD, ProtoStyle: []string{"s2k", "s2k_fo"}, UserName: gsaSession.UserName, Operation: "init"}
	//对请求参数进行hash
	for i, name := range req.ProtoStyle {
		gsaSession.updateNegString(name)
		if i != len(req.ProtoStyle)-1 {
			gsaSession.updateNegString(",")
		}
	}
	gsaSession.updateNegString("|")
	if gsaSession.DCH {
		gsaSession.updateNegString("DisregardChannelBindings")
	}
	return PostLoginStep1Request(req)
}

// CalculateM1 登录的第二步 , 根据第一步返回的B值计算M1值
func (gsaSession *GsaClient) CalculateM1(resp *GSAInitResponse) []byte {
	salt := resp.Salt
	iter := resp.IterationCount
	nots2k := true
	if resp.SeverProto == "s2k" {
		nots2k = false
	}
	key := srpPassword(sha256.New, nots2k, gsaSession.Password, salt, iter)
	gsaSession.sRPClient.ProcessClientChanllenge([]byte(gsaSession.UserName), key, salt, resp.SRPB)
	return gsaSession.sRPClient.GetM1()
}

/*
*
登录的第2个请求，客户端根据服务器第一个请求的返回的B计算得到M1，再把M1和cookie，selectedProtocol一起发给服务器，获取M2，m2如果校验成功，
可用解密除spd数据，此请求返回结果中的spd是已经解密的可用被plist解码为ServerProvicedData的二进制了。得到spd表示srp密码校验完成。并获得了临时token。
临时token可用给后面二次校验使用，或者用于获取后面的业务逻辑token
*/
func (gsaSession *GsaClient) RequestCompleteForM2(m1 []byte, cookie string, selectedProtocol string) (*GSACompleteResponse, *errorz.StatusError) {
	req := GSACompleteRequest{CPD: *gsaSession.CPD, M1: m1, Cookie: cookie, UserName: gsaSession.UserName, Operation: "complete"}
	//对请求的参数进行hash
	gsaSession.updateNegString("|")
	gsaSession.updateNegString(selectedProtocol)
	//发送请求
	resp, e := PostLoginStep2Request(req)
	if e != nil {
		return resp, e
	}
	//对返回记过进行hash
	m2equal := reflect.DeepEqual(resp.M2, gsaSession.sRPClient.M2)
	if resp != nil && (resp.Status.StatusCode == 0 || resp.Status.StatusCode == Status_GSA_Response_SecondaryActionRequired || resp.Status.StatusCode == Status_GSA_Response_OK) && m2equal {
		gsaSession.updateNegString("|")
		gsaSession.updateNegData(resp.SPD)
		gsaSession.updateNegString("|")
		if len(gsaSession.SC) > 0 {
			gsaSession.updateNegData(gsaSession.SC)
		}
		gsaSession.updateNegString("|")
	}
	if len(resp.SPD) > 0 {
		resp.SPD = gsaSession.DecryptSPD(resp.SPD)
		//fmt.Sprintf("desed  %s", resp.SPD)
	}
	return resp, nil
}

/**
DecryptSPD 解密Server Provided Data	User token information, AES-CBC encrypted using session key
 * 登陆成功后， 服务器返回了M2, np, spd.  其中np用于校验spd解密。  spd 字段是用aes加密的.SPD 字段中你会得到几个ID 和token ，这些token 是用于后续登陆authenticate服务器用
 * SPD 解密
 * spd 使用aes_cbc_mode 加密，pkcsv7对齐数据块。 需要key,iv方可解密。 SRP 过程中，客户端和服务器共同分享K。 AES 的key,iv 通过HMAC算法得到， 其中SRP K 作为HMAC key， mac信息
 * "extra data key:"
 * "extra data iv:"
 * 解密出plaintext 后，pkcsv7 去掉尾部填充数据，得到各种密码token。 至此，普通账号登陆完成。通过iDevice 设备通知或者短信作二次认证本文不讨论。 二次认证通过后，得到新的SPD字典。
 * descripted spd sample <dict><key>authmode</key><integer>1</integer><key>acname</key><string>877028320@qq.com</string><key>c</key><data>YjljNTMwNDQtYmU1My00YjhmLTg0ZGEtODNkOGMwODQzMDEwNFEyYWlCOFpDSkw0clBhVmpnUDlZeGowVHJXMnNsRzNsY0ZoYjViejNxbCt6U2E5dWVzSVJENnNhbVJ0amVJaVpLcUt1Rnk0K3gydjE4R1d6eDNnSy8xaXkxdnJWbWZucTh6OFZaK1dMWjlWdEMrRnZOTWNVQUMwZXdTYWQ0V0pXRnBI</data><key>primaryEmailVetted</key><integer>1</integer><key>adsid</key><string>000139-10-7621bc09-3475-43e5-a1b4-f9c035e0b1b2</string><key>duration</key><integer>3600</integer><key>GsIdmsToken</key><string>AAAABLwIAAAAAGBN6cARDGdzLmlkbXMuYXV0aL0AQwHkn62Ax0X+twKP4gzWt/ROd7rjPsFYGSfKMbx4C7Bdv6s4p20Ct6TM2dd2emOcqIwjKx6RnY/lUMpC3xeGgf1SIQy6zyk312t7Wdg53uSDBCYb2mOVKdBL/hk0/yBgt03uDLvewlfDICbXKWIgo3gELeQlk4F/60AGqytnhHDGrjS6aor1oOLs17ext+qa4YbWdICjSEzsOr9hg6DB4qq4+CQ=</string><key>status-code</key><integer>200</integer><key>t</key><dict><key>com.apple.gs.idms.pet</key><dict><key>duration</key><integer>300</integer><key>expiry</key><integer>1615719148291</integer><key>token</key><string>GaUHSTg9TTls64YOriOsXd7hYxfVECmnI++6JulBivJyWBkNirpmqTFtzTeJiOhImOGQiGC4cH1H0ccygEmzs9pL/4b8PjW+15qnIBvrSIq38Dv/YHoOgvDZr24Lc66WLfiHaFGL3X18jTlrSRH0JGocl8rviGWdqp9GNZtVvBeZSyEIXnvvS9j8X6ypjYVh/QhevcD+NEVTDNeE9fEBXUwvhcuqNXuv9tk4E4oGSSIDpU+Qk0xdNldaVE6TKyDaDqTvt9bxluQfdAuza9hKAZg2E4upecojaKvvYwgvSc+IDErGWeT1X8vwUcG3hV2Jk/LBowboVunHaCk0VnpZfUInYykwHHI6/iFmpVVwjPaNeuTLrpCjgrNCQi0De/pUWw6tGio=PET</string></dict><key>com.apple.gs.icloud.auth</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>GaUHSTg9TTls64YOriOsXd4pHC4OQ7W9PNfsEKGj8IP+CY+6zfy+2HLGDJnCqgPI05Nzoy2Nb3GS6Q73zQIbE1OLy99CpCl0gzbsUCjfnopudTRcfXA4xsHSbi6qF4h0RHOZLxBOSJy1TiBUNMuRxPLSBW5uQYaCGPUzsUF/0Vw6vW6HYRLjVLDkIvFWScmZZ5pqsJABgu11UMJCKtReG+GJ8Ls114FD+d8Q69Xf74qwxG0ImjA6Q2SOcjUFVIMYpTO7QKjMkAfkYe10G7X2R/7YX7mjhoeuxh3dMpYDFoWLoJbH3SvzxF2aRxnPGl8znL/iO4pX/vJ8I1Jp+QNBpBlqQrphxaUcV7xP2ozfEG9M+0p6kRQHUL3p7kbdPQ015mrBMvM=</string></dict><key>com.apple.gs.appleid.auth</key><dict><key>duration</key><integer>3600</integer><key>expiry</key><integer>1615722448291</integer><key>token</key><string>GaUHSTg9TTls64YOriOsXd7hPmYynNw9WEqGiYDftkfY/S6bYlZo6xNyPwjAzSGXcXOCai3U17eSu9UnSbanpPLAINW2BurtnXWQ3mPHKGnP/+65E+SJhJbDIBh4sR6BQwqCeZV/vIVTOPmgI3KsM97OU5uYjEM9Od6jsKC8/KQtrJCMNOlCM/RsMkiPHsADies4QZ2cHHrCLdwVpEkt3k5b+ksGcEH87I29Fs4LJeWTnO+W/+LEx9BhaBuDjJwq057TZ19kDMm2r1r/sjKOocMK+X3J8YjIz9hGm7y1AcUhZxFdcSkLPx85eTA7wOcGBjfFhMESDdkJjo9RLmak4HY6YtbNvr9vvJn8pN+jhSWeNU1CJ5av9nT3kdt+YX0T/dzZprY=</string></dict><key>com.apple.gs.idms.hb</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cARCmdzLmlkbXMuaGK9AEMB5J+tgMdF/rcCj+IM1rf0Tne64z7BWBknyjG8eAuwXb+rOKdtArekzNnXdnpjnKiMIysekZ2P5VDKQt8XhoH9UiEMus8pN9dre1nYOd7kgwQmG9pjlSnQS/4ZNP8gYLdN7gy73sJXwyAm1yliIKN4BC3kJZOBf+tABqsrZ4RwCbZ6CPt9/sg3cPRsrfpnxgMV0MRp10xuR2R7cdg7+pCFiBVj</string></dict><key>com.apple.gs.pb.auth</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cARCmdzLnBiLmF1dGi9AEMB5J+tgMdF/rcCj+IM1rf0Tne64z7BWBknyjG8eAuwXb+rOKdtArekzNnXdnpjnKiMIysekZ2P5VDKQt8XhoH9UiEMus8pN9dre1nYOd7kgwQmG9pjlSnQS/4ZNP8gYLdN7gy73sJXwyAm1yliIKN4BC3kJZOBf+tABqsrZ4RwyilTNJYhoPMLbIQtzsk8alYgUnaCKzbqh6Jno+qoZk0j4ZWs</string></dict><key>com.apple.gs.idms.ln</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cARCmdzLmlkbXMubG69AEMB5J+tgMdF/rcCj+IM1rf0Tne64z7BWBknyjG8eAuwXb+rOKdtArekzNnXdnpjnKiMIysekZ2P5VDKQt8XhoH9UiEMus8pN9dre1nYOd7kgwQmG9pjlSnQS/4ZNP8gYLdN7gy73sJXwyAm1yliIKN4BC3kJZOBf+tABqsrZ4Rwq3l878eYOqDr51Sh3c0vPFwLqB7sZdle1SopIQ+NtnMUGoIl</string></dict><key>com.apple.gs.supportapp.auth</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cAREmdzLnN1cHBvcnRhcHAuYXV0aL0AQwHkn62Ax0X+twKP4gzWt/ROd7rjPsFYGSfKMbx4C7Bdv6s4p20Ct6TM2dd2emOcqIwjKx6RnY/lUMpC3xeGgf1SIQy6zyk312t7Wdg53uSDBCYb2mOVKdBL/hk0/yBgt03uDLvewlfDICbXKWIgo3gELeQlk4F/60AGqytnhHAA7RGAAGMcdnmw8y3Vgcb1VFu2dTYW7EYGaOO6Pk0DfzQFUFE=</string></dict><key>com.apple.gs.global.auth</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cARDmdzLmdsb2JhbC5hdXRovQBDAeSfrYDHRf63Ao/iDNa39E53uuM+wVgZJ8oxvHgLsF2/qzinbQK3pMzZ13Z6Y5yojCMrHpGdj+VQykLfF4aB/VIhDLrPKTfXa3tZ2Dne5IMEJhvaY5Up0Ev+GTT/IGC3Te4Mu97CV8MgJtcpYiCjeAQt5CWTgX/rQAarK2eEcGTkQZRS86BsGBuciGcFHqWN8T8IkYY3ZuRj1OL6+ejpz5QeXQ==</string></dict><key>com.apple.gs.beta.auth</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cARDGdzLmJldGEuYXV0aL0AQwHkn62Ax0X+twKP4gzWt/ROd7rjPsFYGSfKMbx4C7Bdv6s4p20Ct6TM2dd2emOcqIwjKx6RnY/lUMpC3xeGgf1SIQy6zyk312t7Wdg53uSDBCYb2mOVKdBL/hk0/yBgt03uDLvewlfDICbXKWIgo3gELeQlk4F/60AGqytnhHAlrV+vXjKJLvL/RHzqkdn0Z4H+9Q+AaRWmA+0V7c76V5eiM50=</string></dict><key>com.apple.gs.itunes.mu.invite</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cARE2dzLml0dW5lcy5tdS5pbnZpdGW9AEMB5J+tgMdF/rcCj+IM1rf0Tne64z7BWBknyjG8eAuwXb+rOKdtArekzNnXdnpjnKiMIysekZ2P5VDKQt8XhoH9UiEMus8pN9dre1nYOd7kgwQmG9pjlSnQS/4ZNP8gYLdN7gy73sJXwyAm1yliIKN4BC3kJZOBf+tABqsrZ4RwtUS4zNaCwPip4uNcdM9h0BsF9DOCWERSOQuIiog3IqUQCJKy</string></dict><key>com.apple.gs.icloud.storage.buy</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cARFWdzLmljbG91ZC5zdG9yYWdlLmJ1eb0AQwHkn62Ax0X+twKP4gzWt/ROd7rjPsFYGSfKMbx4C7Bdv6s4p20Ct6TM2dd2emOcqIwjKx6RnY/lUMpC3xeGgf1SIQy6zyk312t7Wdg53uSDBCYb2mOVKdBL/hk0/yBgt03uDLvewlfDICbXKWIgo3gELeQlk4F/60AGqytnhHDt9WmLxLFcoC5U0ASH5dwqSS9lDZQvPzR6eju0PokGzzEcst0=</string></dict><key>com.apple.gs.news.auth</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cARDGdzLm5ld3MuYXV0aL0AQwHkn62Ax0X+twKP4gzWt/ROd7rjPsFYGSfKMbx4C7Bdv6s4p20Ct6TM2dd2emOcqIwjKx6RnY/lUMpC3xeGgf1SIQy6zyk312t7Wdg53uSDBCYb2mOVKdBL/hk0/yBgt03uDLvewlfDICbXKWIgo3gELeQlk4F/60AGqytnhHCVGIo/qI0XBnPnZyUg693mYb6CHfR0v6d1Tb4AL6hQPdlZg8k=</string></dict><key>com.apple.gs.authagent.auth</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cAREWdzLmF1dGhhZ2VudC5hdXRovQBDAeSfrYDHRf63Ao/iDNa39E53uuM+wVgZJ8oxvHgLsF2/qzinbQK3pMzZ13Z6Y5yojCMrHpGdj+VQykLfF4aB/VIhDLrPKTfXa3tZ2Dne5IMEJhvaY5Up0Ev+GTT/IGC3Te4Mu97CV8MgJtcpYiCjeAQt5CWTgX/rQAarK2eEcDe0nEpNmzXWQLeaBQk7KesnIjWRy2NTyw6hLZQsORKPyF8Dbw==</string></dict><key>com.apple.gs.dip.auth</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cARC2dzLmRpcC5hdXRovQBDAeSfrYDHRf63Ao/iDNa39E53uuM+wVgZJ8oxvHgLsF2/qzinbQK3pMzZ13Z6Y5yojCMrHpGdj+VQykLfF4aB/VIhDLrPKTfXa3tZ2Dne5IMEJhvaY5Up0Ev+GTT/IGC3Te4Mu97CV8MgJtcpYiCjeAQt5CWTgX/rQAarK2eEcOEF2ac3jWN46JTiUwhO+ktNi35gP5LYjMASzfevZPwZxLIJnA==</string></dict><key>com.apple.gs.icloud.family.auth</key><dict><key>duration</key><integer>31536000</integer><key>expiry</key><integer>1647254848291</integer><key>token</key><string>AAAABLwIAAAAAGBN6cARFWdzLmljbG91ZC5mYW1pbHkuYXV0aL0AQwHkn62Ax0X+twKP4gzWt/ROd7rjPsFYGSfKMbx4C7Bdv6s4p20Ct6TM2dd2emOcqIwjKx6RnY/lUMpC3xeGgf1SIQy6zyk312t7Wdg53uSDBCYb2mOVKdBL/hk0/yBgt03uDLvewlfDICbXKWIgo3gELeQlk4F/60AGqytnhHCwhs+Bu1FDVgCRMFmx4UjHt2fj0+qNl3pDKRbPviUwMES38RQ=</string></dict></dict><key>sk</key><data>6DqecvOW2wkssiK3sdCFdFRRaM9LLnSoIF12nWxV8ak=</data><key>underAge</key><integer>0</integer><key>additionalInfo</key><dict></dict><key>DsPrsId</key><integer>1248358234</integer><key>primaryEmail</key><string>877028320@qq.com</string><key>ut</key><integer>2</integer></dict>
 **/
//
func (gsaSession *GsaClient) DecryptSPD(spd []byte) []byte {
	key := gsaSession.createSessionKey("extra data key:")
	iv := gsaSession.createSessionKey("extra data iv:")
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(iv) >= block.BlockSize() {

		iv = iv[:block.BlockSize()]
	} else {
		iv = make([]byte, block.BlockSize())
	}
	ciphertext := spd
	plaintext := make([]byte, len(ciphertext))
	bm := cipher.NewCBCDecrypter(block, iv)
	bm.CryptBlocks(plaintext, ciphertext)
	plaintext, _ = pkcs7Unpad(plaintext, block.BlockSize())
	return plaintext
}

/*
func (gsaSession *GsaClient) HandleStep2(resp *GSACompleteResponse) []byte {
	gsaSession.updateNegString("|")
	gsaSession.updateNegData(resp.SPD)
	gsaSession.updateNegString("|")
	if len(gsaSession.SC) > 0 {
		gsaSession.updateNegData(gsaSession.SC)
	}
	gsaSession.updateNegString("|")
	if len(resp.SPD) > 0 {
		return gsaSession.DecryptSPD(resp.SPD)
	}
	return nil
}*/

// srpPassword 计算srp P 字段， 密码用明文经多次sha256 迭代所得  s2kfo sp field not equal to s2k set true
func srpPassword(h func() hash.Hash, s2kfo bool, password string, salt []byte, iterationcount int) []byte {
	hashPass := sha256.New()
	hashPass.Write([]byte(password))
	var digest []byte
	if s2kfo {
		digest = []byte(hex.EncodeToString(hashPass.Sum(nil)))
	} else {
		digest = hashPass.Sum(nil)
	}
	return pbkdf2.Key(digest, salt, iterationcount, h().Size(), h)
}

func (gsaSession *GsaClient) updateNegData(data []byte) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(len(data)))
	gsaSession.ExchangeHashFun.Write(buf.Bytes())
	gsaSession.ExchangeHashFun.Write(data)
}
func (gsaSession *GsaClient) updateNegString(s string) {
	gsaSession.ExchangeHashFun.Write([]byte(s))
}

/*
	func (kls *GsaClient) ClientStep1() {
		for i, proto := range kls.Proto {
			kls.updateNegString(proto)
			if i != len(kls.Proto)-1 {
				kls.updateNegString(",")
			}
		}
	}
*/
func (gsaSession *GsaClient) createSessionKey(keyname string) []byte {
	skey := gsaSession.sRPClient.GetSessionKey()
	mac := hmac.New(sha256.New, skey)
	mac.Write([]byte(keyname))
	expectedMAC := mac.Sum(nil)
	return expectedMAC
}

/*
*
此spd必须是短信验证后重新登录后获得的spd，初次获得，返回状态码是409的spd是无法用于调用此接口的
*/
func FetchXCodeToken(spd *ServerProvidedData, data *appuploader.AnisseteData) (*GSAToken, *errorz.StatusError) {
	if spd == nil || data == nil {
		return nil, errorz.NewUnauthorizedError("no token found")
	}
	tokens, e := FetchGSAToken(spd, data, []string{APP_BUNDLE_ID_XCODE})
	if e != nil {
		return nil, e
	}
	return tokens[APP_BUNDLE_ID_XCODE], e
}

/*
*
此spd必须是短信验证后重新登录后获得的spd，初次获得，返回状态码是409的spd是无法用于调用此接口的
*/
func FetchGSAToken(spd *ServerProvidedData, data *appuploader.AnisseteData, bundleIDs []string) (map[string]*GSAToken, *errorz.StatusError) {
	rinfo, _ := strconv.Atoi(data.XAppleIMDRINFO)
	var cpd = GSARequestCPD{CID: data.XMmeDeviceId, ClientTime: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		IMD: data.XAppleIMD, IMDM: data.XAppleIMDM, RInfo: rinfo, BootStrap: true, CKGen: true, UDID: data.XMmeDeviceId}

	checkSum := createAppTokensChecksum(spd.Sk, spd.Adsid, bundleIDs)
	request := GSAAppTokensRequest{U: spd.Adsid, App: bundleIDs, C: spd.C, T: spd.GsIdmsToken, Operation: "apptokens", Checksum: checkSum, CPD: &cpd}
	response, status := PostFetchTokenRequest(request)
	if status != nil {
		return nil, status
	}
	if response.Status.ErrorCode != 0 {
		return nil, &errorz.StatusError{Status: response.Status.StatusCode, Body: response.Status.ErrorMessage}
	}
	tt, e2 := DecryptDataGCM(spd.Sk, response.ET)
	if e2 != nil {
		return nil, errorz.NewParseDataError(e2)
	}
	var tok DecryptedAppToken
	_, em := plist.Unmarshal(tt, &tok)
	if em != nil {
		return nil, errorz.NewParseDataError(em)
	}
	return tok.TokenBundles, nil
}
func createAppTokensChecksum(skNode []byte, adsid string, appNode []string) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("apptokens")
	buf.WriteString(adsid)
	for _, app := range appNode {
		buf.WriteString(app)
	}
	mac := hmac.New(sha256.New, skNode)
	mac.Write(buf.Bytes())
	expectedMAC := mac.Sum(nil)
	return expectedMAC
}
