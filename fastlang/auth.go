package fastlang

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"gitee.com/kxapp/kxapp-common/httpz"
	"gitee.com/kxapp/kxapp-common/httpz/cookiejar"
	"github.com/appuploader/apple-service-v3/srp"
	"github.com/appuploader/apple-service-v3/storage"
	"github.com/appuploader/apple-service-v3/util"
)

// IdmsaClient represents an Apple ID Management Service Authentication client
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

// NewAppleAuthClient creates a new instance of IdmsaClient with default headers
func NewAppleAuthClient() *IdmsaClient {
	// Default Headers
	var DefaultHeaders = map[string]string{
		HeaderUserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		HeaderXCsrfItc:        "itc",
		HeaderContentType:     "application/json",
		HeaderXRequestedWith:  "XMLHttpRequest",
		HeaderXAppleWidgetKey: "e0b80c3bf78523bfe80974d320935bfa30add02e1bff88ec2166c6bd5a706c42",
		HeaderAccept:          "application/json, text/javascript",
		HeaderAcceptEncoding:  "gzip;q=1.0,deflate;q=0.6,identity;q=0.3",
	}
	return &IdmsaClient{
		baseHeaders: DefaultHeaders,
	}
}

// Login authenticates the user with Apple ID
func (c *IdmsaClient) Login(username string, password string) *httpz.HttpResponse {
	username = strings.ToLower(username)
	c.username = username

	if IsSessionAlive(username) {
		return &httpz.HttpResponse{Status: http.StatusOK, Body: []byte("session is alive")}
	}

	c.httpClient = NewHttpClientWithJar(username)
	srpClient := srp.NewSRPClient(srp.GetSRPParam(srp.SRP_N_LEN_2048), nil)

	// Initialize SRP authentication
	initResponse := c.initializeSRP(username, srpClient)
	if initResponse.HasError() || initResponse.Status != http.StatusOK {
		return initResponse
	}

	// Complete SRP authentication
	return c.completeSRP(username, password, srpClient, initResponse)
}

// initializeSRP performs the initial SRP authentication step
func (c *IdmsaClient) initializeSRP(username string, srpClient *srp.SRPClient) *httpz.HttpResponse {
	basedA := base64.StdEncoding.EncodeToString(srpClient.GetA())
	initRequestBody := map[string]interface{}{
		"a":           basedA,
		"accountName": username,
		"protocols":   []string{"s2k", "s2k_fo"},
	}

	requestURL := fmt.Sprintf("%s/auth/signin/init", BaseURLIdmsa)
	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).
		AddBody(initRequestBody).
		Request(c.httpClient)

	if !response.HasError() {
		c.scnt = response.Header.Get(HeaderScnt)
	}

	return response
}

// completeSRP completes the SRP authentication process
func (c *IdmsaClient) completeSRP(username, password string, srpClient *srp.SRPClient, initResponse *httpz.HttpResponse) *httpz.HttpResponse {
	var initResponseBody struct {
		Iteration int    `json:"iteration"`
		Salt      string `json:"salt"`
		Protocol  string `json:"protocol"`
		B         string `json:"b"`
		C         string `json:"c"`
	}

	if err := json.Unmarshal(initResponse.Body, &initResponseBody); err != nil {
		return &httpz.HttpResponse{Error: err}
	}

	saltData, _ := base64.StdEncoding.DecodeString(initResponseBody.Salt)
	bData, _ := base64.StdEncoding.DecodeString(initResponseBody.B)
	hashedPassword := srp.PbkPassword(password, saltData, initResponseBody.Iteration, initResponseBody.Protocol != "s2k")

	srpClient.ProcessClientChanllenge([]byte(username), hashedPassword, saltData, bData)

	srpResult := map[string]any{
		"accountName": username,
		"rememberMe":  true,
		"m1":          base64.StdEncoding.EncodeToString(srpClient.GetM1()),
		"c":           initResponseBody.C,
		"m2":          base64.StdEncoding.EncodeToString(srpClient.M2),
	}

	c.getAuthAndDhHeaders()
	return c.postComplete(srpResult)
}

// postComplete sends the final SRP authentication request
func (c *IdmsaClient) postComplete(srpInitResult map[string]any) *httpz.HttpResponse {
	requestURL := fmt.Sprintf("%s/auth/signin/complete?isRememberMeEnabled=true", BaseURLIdmsa)
	bits, _ := strconv.Atoi(c.xAppleHCBits)
	xAppleHC := util.MakeAppleHashCash(bits, c.xAppleHCChallenge)

	requestHeaders := map[string]string{
		HeaderScnt:           c.scnt,
		HeaderXAppleAuthAttr: c.xAppleAuthAttributes,
		HeaderXAppleHC:       xAppleHC,
	}

	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).
		AddHeaders(requestHeaders).
		AddBody(srpInitResult).
		Request(c.httpClient)

	if response.HasError() {
		return response
	}

	c.updateHeadersFromResponse(response)

	switch response.Status {
	case http.StatusUnauthorized:
		if strings.Contains(string(response.Body), fmt.Sprintf("%d", ErrorCodeSessionExpired)) {
			return response
		}
	case http.StatusOK, http.StatusFound:
		c.onLoginSuccess(response)
	case http.StatusConflict:
		// Handle two-factor authentication
		return response
	}

	return response
}

// updateHeadersFromResponse updates client headers from response headers
func (c *IdmsaClient) updateHeadersFromResponse(response *httpz.HttpResponse) {
	c.scnt = response.Header.Get(HeaderScnt)
	c.xAppleIDSessionId = response.Header.Get(HeaderXAppleIDSession)
	c.xAppleAuthAttributes = response.Header.Get(HeaderXAppleAuthAttr)
	c.xAppleIDAccountCountry = response.Header.Get(HeaderXAppleIDCountry)
}

// getAuthAndDhHeaders retrieves authentication and DH headers
func (c *IdmsaClient) getAuthAndDhHeaders() {
	requestHeaders := map[string]string{
		HeaderXCsrfItc: "itc",
		HeaderAccept:   "*/*",
	}

	requestURL := fmt.Sprintf("%s/auth/signin?widgetKey=%s", BaseURLIdmsa, c.baseHeaders[HeaderXAppleWidgetKey])
	response := httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).
		AddHeaders(requestHeaders).
		Request(c.httpClient)

	if !response.HasError() {
		c.scnt = response.Header.Get(HeaderScnt)
		c.xAppleAuthAttributes = response.Header.Get(HeaderXAppleAuthAttr)
		c.xAppleHCBits = response.Header.Get(HeaderXAppleHCBits)
		c.xAppleHCChallenge = response.Header.Get(HeaderXAppleHCChallenge)
	}
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
	j := c.httpClient.Jar.(*cookiejar.Jar)
	d, e := j.ToJSON()
	if e != nil {
		return e
	}
	return storage.WriteFile(storage.TokenPath(c.username, storage.TokenTypeItc), d)
	//cookies := c.httpClient.Jar.(*cookiejar.Jar).AllCookies()
	//cookieValues := map[string]string{}
	//for _, cookie := range cookies {
	//	if strings.Index(cookie.Domain, "apple.com") < 0 {
	//		continue
	//	}
	//	cookieValues[cookie.Name] = cookie.Value
	//}
	//return storage.Write(c.username, storage.TokenTypeItc, cookieValues)
}

func (c *IdmsaClient) VerifyCode(codeType string, code string, phoneId string) *httpz.HttpResponse {
	if codeType == VerifyCodeMode_Device {
		return c.VerifyDeviceCode(code)
	} else {
		return c.VerifySMSVoiceCode(phoneId, code, codeType)
	}
}
func (c *IdmsaClient) RequestVerifyCode(codeType string, phoneId string) *httpz.HttpResponse {
	if codeType == VerifyCodeMode_Device {
		return c.RequestDeviceCode()
	} else {
		return c.RequestSMSVoiceCode(phoneId, codeType)
	}
}

const _HEADER_SESSION_ID_KEY = "X-Apple-ID-Session-Id"
const _X_Apple_Auth_Attributes_KEY = "X-Apple-Auth-Attributes"
const _HEADER_SCNT_KEY = "scnt"
const VerifyCodeMode_SMS = "sms"
const VerifyCodeMode_Voice = "voice"
const VerifyCodeMode_Device = "device"
