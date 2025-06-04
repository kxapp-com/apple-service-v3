package gsa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"gitee.com/kxapp/kxapp-common/errorz"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/appuploader"
	"github.com/appuploader/apple-service-v3/srp"
	log "github.com/sirupsen/logrus"
	"howett.net/plist"
	"net/http"
	"reflect"
	"strconv"
	"time"
)

const APP_BUNDLE_ID_XCODE = "com.apple.gs.xcode.auth"

/*
开始登录，返回失败的状态码，如果成功返回m2解密的spd数据，也就是token数据,tokens数据是nsdic格式,可用被plist.unmarshal 为ServerProvidedData
得到spd表示密码校验成功，后面可用使用spd里面的token开始二次校验登录或者获取其他的token
如果hsc=434表示 anissete 已经过期，如果是433则表示需要reprovision设备了,409表示需要2次校验，200表示成功
*/
var XMmeClientInfo string

func Login(username, password string, data *appuploader.AnisseteData) (*GSACompleteResponse, *errorz.StatusError) {
	sRPClient := srp.NewSRPClient(srp.GetSRPParam(srp.SRP_N_LEN_2048), nil)
	rinfo, _ := strconv.Atoi(data.XAppleIMDRINFO)
	var cpd = &GSARequestCPD{CID: data.XMmeDeviceId, ClientTime: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		IMD: data.XAppleIMD, IMDM: data.XAppleIMDM, RInfo: rinfo, BootStrap: true, CKGen: true, UDID: data.XMmeDeviceId,
		SerialNumber: data.XAppleISRLNO, Loc: data.XAppleLocale, ClientTimeZone: data.XAppleITimeZone, Icscrec: true, PRKGEN: true, SVCT: "iCloud"}

	XMmeClientInfo = data.XMmeClientInfo

	req := GSAInitRequest{A2K: sRPClient.GetA(), CPD: cpd, ProtoStyle: []string{"s2k", "s2k_fo"}, UserName: username, Operation: "init"}
	resp, e := parseGsaPlistResponse[GSAInitResponse](postGsaPlistRequest(req))
	//resp, e := PostLoginStep1Request(req)
	if e != nil {
		return nil, e
	}
	hashedPassword := srp.PbkPassword(password, resp.Salt, resp.IterationCount, resp.SeverProto != "s2k")
	sRPClient.ProcessClientChanllenge([]byte(username), hashedPassword, resp.Salt, resp.SRPB)
	if len(sRPClient.M1) == 0 {
		return nil, errorz.NewInternalError("calculate m1 fail ,internal error")
	}

	reqComplete := GSACompleteRequest{CPD: *cpd, M1: sRPClient.M1, Cookie: resp.Cookie, UserName: username, Operation: "complete"}
	//m2Response, e2 := PostLoginStep2Request(reqComplete)
	m2Response, e2 := parseGsaPlistResponse[GSACompleteResponse](postGsaPlistRequest(reqComplete))
	if e2 != nil {
		return nil, e
	}
	if !reflect.DeepEqual(m2Response.M2, sRPClient.M2) {
		return nil, errorz.NewInternalError("m2 check failed,internal error")
	}
	if len(m2Response.SPD) > 0 {
		m2Response.SPD = DecryptSPD(m2Response.SPD, sRPClient.GetSessionKey())
	}
	return m2Response, nil
	//var spd ServerProvidedData
	//_, e3 := plist.Unmarshal(m2Response.SPD, &spd)
	//if e3 != nil {
	//	return nil, errorz.NewParseDataError(e3)
	//}
	//return &spd, nil
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
func DecryptSPD(spd []byte, srpSessionKey []byte) []byte {
	key := createSessionKey("extra data key:", srpSessionKey)
	iv := createSessionKey("extra data iv:", srpSessionKey)
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

func createSessionKey(keyname string, srpSessionKey []byte) []byte {
	mac := hmac.New(sha256.New, srpSessionKey)
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
	//response, status := PostFetchTokenRequest(request)
	response, status := parseGsaPlistResponse[GSAAppTokensResponse](postGsaPlistRequest(request))
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

func parseGsaPlistResponse[T any](res *httpz.HttpResponse) (*T, *errorz.StatusError) {
	if res.HasError() {
		return nil, errorz.NewNetworkError(res.Error)
	}
	var mp map[string]map[string]any
	_, e1 := plist.Unmarshal(res.Body, &mp)
	responseDic := mp["Response"]
	status := responseDic["Status"]
	statusBytes, e2 := plist.Marshal(status, plist.XMLFormat)
	var statusBean GSAStatus
	_, e4 := plist.Unmarshal(statusBytes, &statusBean)
	if e1 != nil || e2 != nil || e4 != nil {
		return nil, errorz.NewParseDataError(e1, e2, e4)
	}
	if statusBean.ErrorCode != 0 {
		//return nil, &errorz.StatusError{Status: statusBean.StatusCode, Body: statusBean.ErrorMessage}
		return nil, &errorz.StatusError{Status: statusBean.ErrorCode, Body: statusBean.ErrorMessage}
		//return nil, &errorz.StatusError{Status: statusBean.StatusCode, Message: statusBean.ErrorMessage, Body: responseBytes}
	}
	responseBytes, e3 := plist.Marshal(responseDic, plist.XMLFormat)
	if e3 != nil {
		return nil, errorz.NewParseDataError(e3)
	}
	target := new(T)
	_, e5 := plist.Unmarshal(responseBytes, target)
	if e5 != nil {
		return nil, errorz.NewParseDataError(e5)
	}
	return target, nil
}

/*
req必须是值类型，如果是指针类型，在plist编码的时候会失败
*/
func postGsaPlistRequest(req any) *httpz.HttpResponse {
	authHttpHeaders := map[string]string{
		"Content-Type": httpz.ContentType_Plist,
		//"X-Requested-With": "XMLHttpRequest",
		"Accept":          "*/*",
		"Accept-Language": "en-us",
		//"Accept":             "application/json, */*",
		"User-Agent": httpz.UserAgent_AKD,
		//"X-MMe-Client-Info": "<iMac20,2> <Mac OS X;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",//产生的token获取用户信息报401错误
		//"X-MMe-Client-Info": "<iPhone13,2> <iPhone OS;15.2;14C92> <com.apple.akd/1.0 (com.apple.akd/1.0)>",
		"X-MMe-Client-Info": XMmeClientInfo,
		//"X-MMe-Client-Info": "<MacBookPro17,1> <macOS;12.2.1;21D62> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",//work good
	}
	httpClient := httpz.NewHttpClient(nil)
	request := map[string]any{}
	request["Header"] = map[string]string{"Version": "1.0.1"}
	request["Request"] = req
	body, e := plist.MarshalIndent(&request, plist.XMLFormat, "\t")
	if e != nil {
		log.Error("request param error", e)
	}
	return httpz.NewHttpRequestBuilder(http.MethodPost, "https://gsa.apple.com/grandslam/GsService2").AddHeaders(authHttpHeaders).AddBody(body).Request(httpClient)
}
