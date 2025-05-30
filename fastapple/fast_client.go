package fastapple

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/srp"
	"github.com/appuploader/apple-service-v3/storage"
	"github.com/appuploader/apple-service-v3/util"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"net/http"
	"strconv"
	"strings"
)

type IdmsaClient struct {
	httpClient  *http.Client
	baseHeaders map[string]string
	scnt        string

	xAppleAuthAttributes   string
	xAppleHCBits           string
	xAppleHCChallenge      string
	xAppleIDAccountCountry string
	xAppleIDSessionId      string

	username string
}

func NewAppleAuthClient() *IdmsaClient {
	// 设置通用请求头
	headers := map[string]string{
		"User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"X-Csrf-Itc":         "itc",
		"Content-Type":       "application/json",
		"X-Requested-With":   "XMLHttpRequest",
		"X-Apple-Widget-Key": "e0b80c3bf78523bfe80974d320935bfa30add02e1bff88ec2166c6bd5a706c42",
		"Accept":             "application/json, text/javascript",
		"Accept-Encoding":    "gzip;q=1.0,deflate;q=0.6,identity;q=0.3",
	}

	hClient := httpz.NewHttpClient(http.DefaultClient.Jar)

	return &IdmsaClient{
		httpClient:  hClient,
		baseHeaders: headers,
	}
}

/*
登录，返回409，或者token
*/
func (c *IdmsaClient) Login(username string, password string) *httpz.HttpResponse {
	username = strings.ToLower(username) //srp挑战的时候发现其js代码里面有tolowcase
	c.username = username
	var srpPassword = func(h func() hash.Hash, protocol string, password string, salt []byte, iterationcount int) []byte {
		hashPass := sha256.New()
		hashPass.Write([]byte(password))
		var digest = hashPass.Sum(nil)
		if protocol == "s2k_fo" {
			digest = []byte(hex.EncodeToString(digest))
		}
		return pbkdf2.Key(digest, salt, iterationcount, h().Size(), h)
	}
	srpClient := srp.NewSRPClient(srp.GetSRPParam(srp.SRP_N_LEN_2048), nil)
	basedA := base64.StdEncoding.EncodeToString(srpClient.GetA())
	initRequestBody := map[string]interface{}{
		"a":           basedA,
		"accountName": username,
		"protocols":   []string{"s2k", "s2k_fo"},
	}
	initResponse := c.postInit(initRequestBody)
	if initResponse.HasError() {
		return initResponse
	}
	if initResponse.Status != http.StatusOK {
		return initResponse
	}
	type InitResponse struct {
		Iteration int    `json:"iteration"`
		Salt      string `json:"salt"`
		Protocol  string `json:"protocol"`
		B         string `json:"b"`
		C         string `json:"c"`
	}
	var initResponseBody InitResponse
	json.Unmarshal(initResponse.Body, &initResponseBody)
	saltData, _ := base64.StdEncoding.DecodeString(initResponseBody.Salt)
	bData, _ := base64.StdEncoding.DecodeString(initResponseBody.B)
	hashedPassword := srpPassword(sha256.New, initResponseBody.Protocol, password, saltData, initResponseBody.Iteration)
	srpClient.ProcessClientChanllenge([]byte(username), hashedPassword, saltData, bData)
	srpResult := map[string]any{
		"accountName": username,
		"rememberMe":  true,
		"m1":          base64.StdEncoding.EncodeToString(srpClient.GetM1()),
		"c":           initResponseBody.C,
		"m2":          base64.StdEncoding.EncodeToString(srpClient.M2),
	}
	c.getAuthAndDhHeaders() //获取auth和dh的头部信息
	return c.postComplete(srpResult)
}

/*
发送srp的初始化请求，获取init的返回值
*/
func (c *IdmsaClient) postInit(srpInitData map[string]any) *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/signin/init"
	requestHeaders := map[string]string{}
	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(srpInitData).Request(c.httpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get("scnt")
	return response
}

/*
*
发送srp的完成请求，获取complete的返回值
包含头X-Apple-ID-Account-Country和X-Apple-ID-Session-Id,scnt
*/
func (c *IdmsaClient) postComplete(srpInitResult map[string]any) *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/signin/complete?isRememberMeEnabled=true"
	bits, _ := strconv.Atoi(c.xAppleHCBits)
	xAppleHC := util.MakeAppleHashCash(bits, c.xAppleHCChallenge)
	requestHeaders := map[string]string{
		"scnt":                    c.scnt,
		"X-Apple-Auth-Attributes": c.xAppleAuthAttributes,
		"X-Apple-HC":              xAppleHC,
	}

	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(srpInitResult).Request(c.httpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get("scnt")
	c.xAppleIDSessionId = response.Header.Get(_HEADER_SESSION_ID_KEY)
	c.xAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	c.xAppleIDAccountCountry = response.Header.Get("X-Apple-ID-Account-Country")
	//trusTw: = response.Header.Get("X-Apple-TwoSV-Trust-Eligible")
	if response.Status == http.StatusUnauthorized && strings.Contains(string(response.Body), "-20101") {
		return response
	} else if response.Status == http.StatusOK || response.Status == http.StatusFound {
		//c.xAppleIDSessionId = response.Header.Get(_HEADER_SESSION_ID_KEY)
		//c.Myacinfo = response.CookieValue("myacinfo")
		//c.dslang = response.CookieValue("dslang")
		c.onLoginSuccess(response)
		return response
	} else if response.Status == http.StatusConflict { //二次校验，返回设备列表
		return response
		//var authType map[string]string
		//e2 := json.Unmarshal(response.Body, &authType)
		//if e2 != nil {
		//	return response
		//}
		//if authType["authType"] == "hsa" {
		//	return response
		//}
		//return response, nil
	} else {
		return response
	}
}
func (c *IdmsaClient) getAuthAndDhHeaders() {
	requestHeaders := map[string]string{"X-Csrf-Itc": "itc", "Accept": "*/*"}
	response := httpz.NewHttpRequestBuilder(http.MethodGet, "https://idmsa.apple.com/appleauth/auth/signin?widgetKey=e0b80c3bf78523bfe80974d320935bfa30add02e1bff88ec2166c6bd5a706c42").AddHeaders(requestHeaders).Request(c.httpClient)
	c.scnt = response.Header.Get("scnt")
	c.xAppleAuthAttributes = response.Header.Get("X-Apple-Auth-Attributes")
	c.xAppleHCBits = response.Header.Get("X-Apple-HC-Bits")
	c.xAppleHCChallenge = response.Header.Get("X-Apple-HC-Challenge")
}

/*
*
获取设备列表
*/
func (c *IdmsaClient) LoadTwoStepDevices() *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/appleauth/auth"
	requestHeaders := map[string]string{
		"scnt":                  c.scnt,
		"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	}
	response := httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).Request(c.httpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.xAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	return response
}

/*
*
发送短信码
*/
func (c *IdmsaClient) RequestSMSVoiceCode(phoneId string, mode string) *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/verify/phone"
	requestHeaders := map[string]string{
		"scnt":                  c.scnt,
		"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	}
	param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param = fmt.Sprintf(param, phoneId, mode)
	response := httpz.NewHttpRequestBuilder(http.MethodPut, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.httpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.xAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	if response.HasError() {
		return response
	} else if response.Status == http.StatusOK || response.Status == http.StatusAccepted {
		return response
	} else {
		return response
	}
}

/*
验证短信码
*/
func (c *IdmsaClient) VerifySMSVoiceCode(phoneId string, code string, mode string) *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/verify/phone/securitycode"
	requestHeaders := map[string]string{
		"scnt":                  c.scnt,
		"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	}
	nonFTEU := false
	//for _, device := range c.TwoStepDevicesResponse.TrustedPhoneNumbers {
	//	if strconv.Itoa(device.Id) == phoneId {
	//		nonFTEU = device.NonFTEU
	//		break
	//	}
	//}
	param := ""
	if nonFTEU {
		param = fmt.Sprintf(`{"phoneNumber":{"id":%v,"nonFTEU":%v},"securityCode":{"code":"%v"},"mode":"%v"}`, phoneId, nonFTEU, code, mode)
	} else {
		param = fmt.Sprintf(`{"phoneNumber":{"id":%v},"securityCode":{"code":"%v"},"mode":"%v"}`, phoneId, code, mode)
	}

	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.httpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.xAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	if response.Status == http.StatusOK || response.Status == http.StatusAccepted {
		c.onLoginSuccess(response)
		return response
	} else {
		return response
	}
}

/*
*
发送设备码，202表示发送成功
*/
func (c *IdmsaClient) RequestDeviceCode() *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode"
	requestHeaders := map[string]string{
		"scnt":                  c.scnt,
		"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	}
	param := "{}"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.httpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.xAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	return response
	//if response.Status == http.StatusOK || response.Status == http.StatusAccepted {
	//	return response, nil
	//} else {
	//	return response, errors.New(util.ReadErrorMessage(response.Body))
	//}
}

/*
验证设备码,成功会获取trust cookie，如果失败会返回错误的具体信息
*/
func (c *IdmsaClient) VerifyDeviceCode(code string) *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode"
	requestHeaders := map[string]string{
		"scnt":                  c.scnt,
		"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	}

	//param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param := `{"securityCode":{"code":"%s"}}`
	param = fmt.Sprintf(param, code)
	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.httpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.xAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	if response.Status == http.StatusOK || response.Status == http.StatusNoContent {
		c.onLoginSuccess(response)
		return response
	} else {
		return response
	}
}

// 登录成功后trust设备，登录itc，存储cookie
func (c *IdmsaClient) onLoginSuccess(response *httpz.HttpResponse) error {
	c.Trust()
	c.FetchItcCookies()
	return c.saveCookiesToFile()
}

/*
登录用于信任设备
*/
func (c *IdmsaClient) Trust() *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/2sv/trust"
	requestHeaders := map[string]string{
		"scnt":                  c.scnt,
		"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	}
	response := httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).Request(c.httpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.xAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	return response
}
func (c *IdmsaClient) FetchItcCookies() *httpz.HttpResponse {
	var requestURL = "https://appstoreconnect.apple.com/olympus/v1/session"
	requestHeaders := map[string]string{
		"X-Csrf-Itc":      "itc",
		"Accept":          "*/*",
		"Accept-Encoding": "gzip;q=1.0,deflate;q=0.6,identity;q=0.3",
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	}
	response := httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).Request(c.httpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.xAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	return response
}
func (c *IdmsaClient) saveCookiesToFile() error {
	// 获取所有cookie
	cookies := c.httpClient.Jar.Cookies(nil)
	cookieValues := map[string]string{}
	for _, cookie := range cookies {
		cookieValues[cookie.Name] = cookie.Value
	}
	return storage.Write(c.username, storage.TokenTypeItc, cookieValues)
}

func (c *IdmsaClient) VerifyCode(codeType string, code string, phoneId string) *httpz.HttpResponse {
	if codeType == VerifyCodeMode_Device {
		return c.VerifyDeviceCode(code)
	} else {
		return c.VerifySMSVoiceCode(phoneId, code, codeType)
	}
}

const _HEADER_SESSION_ID_KEY = "X-Apple-ID-Session-Id"
const _X_Apple_Auth_Attributes_KEY = "X-Apple-Auth-Attributes"
const _HEADER_SCNT_KEY = "scnt"
const VerifyCodeMode_SMS = "sms"
const VerifyCodeMode_Voice = "voice"
const VerifyCodeMode_Device = "device"
