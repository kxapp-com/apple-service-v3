package idmsa

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/srp"
	"github.com/appuploader/apple-service-v3/util"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const _HEADER_SESSION_ID_KEY = "X-Apple-ID-Session-Id"
const _X_Apple_Auth_Attributes_KEY = "X-Apple-Auth-Attributes"
const _HEADER_SCNT_KEY = "scnt"

// X-Apple-I-FD-Client-Info https://gist.github.com/borgle/c278a56511aa5cea39bd2a5b62d5f7e9
// https://github.com/beeper/imessage/tree/main/imessage/appleid
type IdmsaClient struct {
	HttpClient *http.Client
	appConfig  AppConfig

	XAppleAuthAttributes   string
	XAppleHCBits           string
	XAppleHCChallenge      string
	XAppleIDAccountCountry string

	//initAppResult     InitAppResult
	baseHeaders       map[string]string
	username          string
	password          string
	xAppleIDSessionId string
	scnt              string

	dslang         string
	Myacinfo       string
	DesCookieName  string
	DesCookieValue string

	Dqsid string
	Itctx string

	TwoStepDevicesResponse *TwoStepDevicesResponse
}

func NewClient(cookieString string) (*IdmsaClient, error) {
	httpClient := httpz.NewHttpClient(nil)
	var c = &IdmsaClient{HttpClient: httpClient}
	c.baseHeaders = map[string]string{
		//"Sec-Fetch-User":     "?1",
		"Connection":         "keep-alive",
		"Cache-Control":      "no-cache",
		"sec-ch-ua-platform": `"Windows"`,
		"sec-ch-ua":          `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`,
		"sec-ch-ua-mobile":   "?0",
		"User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Sec-Fetch-Site":     "same-origin",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Dest":     "empty",
		"Accept-Encoding":    "gzip, deflate, br, zstd",
		//"Accept-Language":    "en,en-GB;q=0.9,en-US;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-AU;q=0.7,en-CA;q=0.6,en-US;q=0.5",
	}
	//c.baseHeaders["X-Apple-I-FD-Client-Info"] = `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0","L":"en","Z":"GMT+08:00","V":"1.1","F":"sla44j1e3NlY5BNlY5BSmHACVZXnNA96eNdTYebe5zLs2dI_AIQjvEodUW2vqBBNkrk0ugN.xL269v69WJQStbuIEpSUTlWY5BNlYJNNlY5QB4bVNjMk.C6v"}`
	if cookieString != "" {
		c.baseHeaders["Cookie"] = cookieString
	}
	_, e := c.getWidgetKey()
	return c, e
}

/*
*
登录，返回409，或者token
*/
func (c *IdmsaClient) Login(username string, password string) (*httpz.HttpResponse, error) {
	c.username = strings.ToLower(username) //srp挑战的时候发现其js代码里面有tolowcase
	c.password = password
	r, e := c.postFederate()
	if e != nil {
		return r, e
	}
	return c.startInit()
}

/*
*
get请求，为了获取一些cookie
*/
func (c *IdmsaClient) GetResource(requestURL string) {
	httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).Request(c.HttpClient)
}

/*
初始化，获取WidgetKeyResponse，里面包含了frameid，widgetid，locale等一堆信息
*/
func (c *IdmsaClient) getWidgetKey() (*httpz.HttpResponse, error) {
	//c.GetResource("https://developer.apple.com/account/")
	//requestURL := "https://idmsa.apple.com/IDMSWebAuth/signin?appIdKey=891bd3417a7776362562d2197f89480a8547b108fd934911bcbea0110d07f757&path=%2Faccount%2F&rv=1"
	//requestHeaders := map[string]string{
	//	"Sec-Fetch-Mode":            "navigate",
	//	"Sec-Fetch-Dest":            "iframe",
	//	"Upgrade-Insecure-Requests": "1",
	//	"Referer":                   "https://account.apple.com/",
	//	"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	//}
	requestURL := "https://developer.apple.com/account/"
	response := httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).AddHeaders(c.baseHeaders).Request(c.HttpClient)
	if response.HasError() {
		return response, response.Error
	}
	re := regexp.MustCompile(`<script type="application/json" id="embed_login_boot_args">\s*(.*?)\s*</script>`)
	//re := regexp.MustCompile(`<script type="application/json" class="boot_args">\s*(.*?)\s*</script>`)
	// 查找匹配的内容
	matches := re.FindAllStringSubmatch(string(response.Body), -1)

	if len(matches) > 0 {
		var appConfig AppConfig
		e := json.Unmarshal([]byte(matches[0][1]), &appConfig)
		if e != nil {
			return response, e
		}
		c.appConfig = appConfig
		c.getSign()
		return response, nil
	} else {
		return response, errors.New("load widget key fail,retry or contact us 1974527954@qq.com")
	}
}

func (c *IdmsaClient) getSign() *httpz.HttpResponse {
	authInfo := c.appConfig.Direct.AuthWidgetConfig
	requestURL := fmt.Sprintf("https://idmsa.apple.com/appleauth/auth/signin?widgetKey=%s&language=%s&skVersion=%s&iframeId=%s&appId=632&authVersion=latest",
		authInfo.WidgetKey, c.appConfig.Direct.Locale, authInfo.SkVersion, c.appConfig.Direct.IframeId)
	r := httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).AddHeaders(c.baseHeaders).Request(c.HttpClient)
	c.XAppleAuthAttributes = r.Header.Get(_X_Apple_Auth_Attributes_KEY)
	c.XAppleHCBits = r.Header.Get("X-Apple-HC-Bits")
	c.XAppleHCChallenge = r.Header.Get("X-Apple-HC-Challenge")
	c.scnt = r.Header.Get(_HEADER_SCNT_KEY)
	return r
}

/*
*
更新X-Apple-HC-Challenge
*/
func (c *IdmsaClient) postFederate() (*httpz.HttpResponse, error) {

	var requestURL = fmt.Sprintf("https://idmsa.apple.com/appleauth/auth/federate?isRememberMeEnabled=true")
	//requestHeaders := map[string]string{
	//	"X-Apple-Auth-Attributes": c.XAppleAuthAttributes,
	//	"X-Apple-App-Id":          strconv.Itoa(c.appConfig.Direct.AppId),
	//	"X-Apple-Locale":          c.appConfig.Direct.Locale,
	//	"X-Apple-Trusted-Domain":  "https://idmsa.apple.com",
	//	"X-Apple-Frame-Id":        c.appConfig.Direct.IframeId,
	//	"X-Apple-Widget-Key":      c.appConfig.Direct.AuthWidgetConfig.WidgetKey,
	//
	//	"X-Requested-With": "XMLHttpRequest",
	//	"Accept":           "application/json, text/javascript, */*; q=0.01",
	//	"Content-Type":     "application/json",
	//	"Origin":           "https://idmsa.apple.com",
	//	"Referer":          "https://idmsa.apple.com/",
	//}
	requestHeaders := map[string]string{
		"X-Apple-Auth-Attributes": c.XAppleAuthAttributes,
		"X-Apple-App-Id":          strconv.Itoa(c.appConfig.Direct.AppId),
		"X-Apple-Locale":          c.appConfig.Direct.Locale,
		"X-Apple-Frame-Id":        c.appConfig.Direct.IframeId,
		"X-Apple-Widget-Key":      c.appConfig.Direct.AuthWidgetConfig.WidgetKey,
		"X-Requested-With":        "XMLHttpRequest",
		"Accept":                  "application/json, text/javascript, */*; q=0.01",
		"Content-Type":            "application/json",
		//"User-Agent":              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	}
	//	X-Apple-Auth-Attributes: J51+y4tTkd7AjBnVvQYAJTP43yFpmA==
	//		X-Apple-App-Id: 632
	//	X-Apple-Locale: CN-ZH
	//	X-Apple-Frame-Id: daw-86400d9c-da0b-4c7e-b85a-04ace0ce692b
	//	X-Requested-With: XMLHttpRequest
	//	X-Apple-Widget-Key: 92f19b477c5c9be6ab17f3ec2b1b2b7db4d00a9a8c973e3d6c90dac08b91de71
	//Accept: application/json, text/javascript, */*; q=0.01
	//Content-Type: application/json
	//User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
	//
	//{"accountName":"yanwen1688@gmail.com","rememberMe":true}

	param := map[string]interface{}{
		"accountName": c.username,
		"rememberMe":  true,
	}
	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).AddHeaders(requestHeaders).AddBody(param).Request(c.HttpClient)

	//response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
	//	AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.HttpClient)
	if response.HasError() {
		return response, response.Error
	}
	c.XAppleHCBits = response.Header.Get("X-Apple-HC-Bits")
	c.XAppleHCChallenge = response.Header.Get("X-Apple-HC-Challenge")

	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	return response, nil
}

/*
开始srp密码校验，创建初始化init的参数，发送请求，根据返回构建complete的参数
*/
func (c *IdmsaClient) startInit() (*httpz.HttpResponse, error) {
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
		"accountName": c.username,
		"protocols":   []string{"s2k", "s2k_fo"},
	}
	initResponse := c.postInit(initRequestBody)
	if initResponse.HasError() {
		return initResponse, initResponse.Error
	}
	if initResponse.Status != http.StatusOK {
		return initResponse, errors.New("init request failed " + string(initResponse.Body))
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
	hashedPassword := srpPassword(sha256.New, initResponseBody.Protocol, c.password, saltData, initResponseBody.Iteration)
	srpClient.ProcessClientChanllenge([]byte(c.username), hashedPassword, saltData, bData)
	srpResult := map[string]any{
		"accountName": c.username,
		"rememberMe":  true,
		"m1":          base64.StdEncoding.EncodeToString(srpClient.GetM1()),
		"c":           initResponseBody.C,
		"m2":          base64.StdEncoding.EncodeToString(srpClient.M2),
	}
	return c.postComplete(initResponse, srpResult)
	//return initResponse, srpResult, nil
}

/*
发送srp的初始化请求，获取init的返回值
*/
func (c *IdmsaClient) postInit(srpInitData map[string]any) *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/signin/init"

	//requestHeaders := map[string]string{
	//	"X-Apple-Domain-Id":   strconv.Itoa(c.initAppResult.Direct.DomainId),
	//	"X-Apple-OAuth-State": c.appConfig.Direct.AppleOAuth.Requestor.State,
	//	//"X-Apple-I-FD-Client-Info":   `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"7la44j1e3NlY5BNlY5BSmHACVZXnNA9bgP3B80MLLzLu_dYV6Hycfx9MsFY5Bhw.Tf5.EKWJ9Y69D96m_UdHzJJNlY5BNp55BNlan0Os5Apw.Bbq"}`,
	//	"X-Apple-Frame-Id":            c.initAppResult.Direct.IframeId,
	//	"X-Apple-OAuth-Response-Mode": c.appConfig.Direct.AppleOAuth.Requestor.ResponseMode,
	//	"X-Apple-Widget-Key":          c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"Accept":                      "application/json, text/javascript, */*; q=0.01",
	//	"scnt":                        c.scnt,
	//	"Content-Type":                "application/json",
	//	"X-Requested-With":            "XMLHttpRequest",
	//	"X-Apple-OAuth-Client-Id":     c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"X-Apple-Auth-Attributes":     c.initAppResult.Direct.AuthAttributes,
	//	"X-Apple-OAuth-Redirect-URI":  c.appConfig.Direct.AppleOAuth.Requestor.RedirectURI,
	//	//"X-Apple-OAuth-Redirect-URI": "https://account.apple.com",
	//	"X-Apple-OAuth-Response-Type": c.appConfig.Direct.AppleOAuth.Requestor.ResponseType,
	//	"X-Apple-OAuth-Client-Type":   c.appConfig.Direct.AppleOAuth.Requestor.Type,
	//	"Origin":                      "https://idmsa.apple.com",
	//	"Referer":                     "https://idmsa.apple.com/",
	//}

	requestHeaders := map[string]string{
		"X-Apple-Auth-Attributes": c.XAppleAuthAttributes,
		"X-Apple-App-Id":          strconv.Itoa(c.appConfig.Direct.AppId),
		"X-Apple-Locale":          c.appConfig.Direct.Locale,
		"X-Apple-Trusted-Domain":  "https://idmsa.apple.com",
		"X-Apple-Frame-Id":        c.appConfig.Direct.IframeId,
		"X-Apple-Widget-Key":      c.appConfig.Direct.AuthWidgetConfig.WidgetKey,

		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"Content-Type":     "application/json",
		"Origin":           "https://idmsa.apple.com",
		"Referer":          "https://idmsa.apple.com/",
	}
	requestHeaders["scnt"] = c.scnt

	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(srpInitData).Request(c.HttpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	return response
}

/*
*
发送srp的完成请求，获取complete的返回值
包含头X-Apple-ID-Account-Country和X-Apple-ID-Session-Id,scnt
*/
func (c *IdmsaClient) postComplete(preResponse *httpz.HttpResponse, srpInitResult map[string]any) (*httpz.HttpResponse, error) {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/signin/complete?isRememberMeEnabled=true"

	requestHeaders := map[string]string{
		"X-Apple-Auth-Attributes": c.XAppleAuthAttributes,
		"X-Apple-App-Id":          strconv.Itoa(c.appConfig.Direct.AppId),
		"X-Apple-Locale":          c.appConfig.Direct.Locale,
		"X-Apple-Trusted-Domain":  "https://idmsa.apple.com",
		"X-Apple-Frame-Id":        c.appConfig.Direct.IframeId,
		"X-Apple-Widget-Key":      c.appConfig.Direct.AuthWidgetConfig.WidgetKey,

		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"Content-Type":     "application/json",
		"Origin":           "https://idmsa.apple.com",
		"Referer":          "https://idmsa.apple.com/",
	}
	requestHeaders["scnt"] = c.scnt
	//
	//requestHeaders := map[string]string{
	//	"X-Apple-Domain-Id":   strconv.Itoa(c.initAppResult.Direct.DomainId),
	//	"X-Apple-OAuth-State": c.appConfig.Direct.AppleOAuth.Requestor.State,
	//	//"X-Apple-I-FD-Client-Info":   `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"7la44j1e3NlY5BNlY5BSmHACVZXnNA9bgP3B80MLLzLu_dYV6Hycfx9MsFY5Bhw.Tf5.EKWJ9Y69D96m_UdHzJJNlY5BNp55BNlan0Os5Apw.Bbq"}`,
	//	"X-Apple-Frame-Id":            c.initAppResult.Direct.IframeId,
	//	"X-Apple-OAuth-Response-Mode": c.appConfig.Direct.AppleOAuth.Requestor.ResponseMode,
	//	"X-Apple-Widget-Key":          c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"Accept":                      "application/json, text/javascript, */*; q=0.01",
	//	"scnt":                        c.scnt,
	//	"Content-Type":                "application/json",
	//	"X-Requested-With":            "XMLHttpRequest",
	//	"X-Apple-OAuth-Client-Id":     c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"X-Apple-Auth-Attributes":     c.initAppResult.Direct.AuthAttributes,
	//	"X-Apple-OAuth-Redirect-URI":  c.appConfig.Direct.AppleOAuth.Requestor.RedirectURI,
	//	//"X-Apple-OAuth-Redirect-URI": "https://account.apple.com",
	//	"X-Apple-OAuth-Response-Type": c.appConfig.Direct.AppleOAuth.Requestor.ResponseType,
	//	"X-Apple-OAuth-Client-Type":   c.appConfig.Direct.AppleOAuth.Requestor.Type,
	//	"Origin":                      "https://idmsa.apple.com",
	//	"Referer":                     "https://idmsa.apple.com/",
	//}

	bits, _ := strconv.Atoi(c.XAppleHCBits)
	xAppleHC := util.MakeAppleHashCash(bits, c.XAppleHCChallenge)
	requestHeaders["X-Apple-HC"] = xAppleHC

	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(srpInitResult).Request(c.HttpClient)
	if response.HasError() {
		return response, response.Error
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.xAppleIDSessionId = response.Header.Get(_HEADER_SESSION_ID_KEY)
	c.XAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	c.XAppleIDAccountCountry = response.Header.Get("X-Apple-ID-Account-Country")
	//trusTw: = response.Header.Get("X-Apple-TwoSV-Trust-Eligible")
	if response.Status == http.StatusUnauthorized && strings.Contains(string(response.Body), "-20101") {
		return response, errors.New("errorPassword")
	} else if response.Status == http.StatusOK || response.Status == http.StatusFound {
		c.xAppleIDSessionId = response.Header.Get(_HEADER_SESSION_ID_KEY)
		c.Myacinfo = response.CookieValue("myacinfo")
		c.dslang = response.CookieValue("dslang")
		c.Trust()
		return response, nil
	} else if response.Status == http.StatusConflict { //二次校验，返回设备列表
		c.xAppleIDSessionId = response.Header.Get(_HEADER_SESSION_ID_KEY)
		var authType map[string]string
		e2 := json.Unmarshal(response.Body, &authType)
		if e2 != nil {
			return response, errors.New("not support auth type " + string(response.Body))
		}
		if authType["authType"] == "hsa" {
			return response, errors.New("close and reopen two step protect please")
		}
		return response, nil
	} else {
		return response, errors.New(util.ReadErrorMessage(response.Body))
	}
}

/*
*
获取设备列表
*/
func (c *IdmsaClient) LoadTwoStepDevices() (*httpz.HttpResponse, *TwoStepDevicesResponse) {
	var requestURL = "https://idmsa.apple.com/appleauth/auth"
	requestHeaders := map[string]string{
		"X-Apple-Auth-Attributes": c.XAppleAuthAttributes,
		"X-Apple-App-Id":          strconv.Itoa(c.appConfig.Direct.AppId),
		"X-Apple-Locale":          c.appConfig.Direct.Locale,
		"X-Apple-Trusted-Domain":  "https://idmsa.apple.com",
		"X-Apple-Frame-Id":        c.appConfig.Direct.IframeId,
		"X-Apple-Widget-Key":      c.appConfig.Direct.AuthWidgetConfig.WidgetKey,

		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"Content-Type":     "application/json",
		"Origin":           "https://idmsa.apple.com",
		"Referer":          "https://idmsa.apple.com/",
	}
	requestHeaders["scnt"] = c.scnt
	requestHeaders["X-Apple-ID-Session-Id"] = c.xAppleIDSessionId
	//
	//requestHeaders := map[string]string{
	//	"X-Apple-Domain-Id":     strconv.Itoa(c.initAppResult.Direct.DomainId),
	//	"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	//	"X-Apple-OAuth-State":   c.appConfig.Direct.AppleOAuth.Requestor.State,
	//	//"X-Apple-I-FD-Client-Info":   `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"7la44j1e3NlY5BNlY5BSmHACVZXnNA9bgP3B80MLLzLu_dYV6Hycfx9MsFY5Bhw.Tf5.EKWJ9Y69D96m_UdHzJJNlY5BNp55BNlan0Os5Apw.Bbq"}`,
	//	"X-Apple-Frame-Id":            c.initAppResult.Direct.IframeId,
	//	"X-Apple-OAuth-Response-Mode": c.appConfig.Direct.AppleOAuth.Requestor.ResponseMode,
	//	"X-Apple-Widget-Key":          c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"Accept":                      "application/json, text/javascript, */*; q=0.01",
	//	//"Accept":                      "text/html",
	//	"scnt":                       c.scnt,
	//	"Content-Type":               "application/json",
	//	"X-Requested-With":           "XMLHttpRequest",
	//	"X-Apple-OAuth-Client-Id":    c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"X-Apple-Auth-Attributes":    c.initAppResult.Direct.AuthAttributes,
	//	"X-Apple-OAuth-Redirect-URI": c.appConfig.Direct.AppleOAuth.Requestor.RedirectURI,
	//	//"X-Apple-OAuth-Redirect-URI": "https://account.apple.com",
	//	"X-Apple-OAuth-Response-Type": c.appConfig.Direct.AppleOAuth.Requestor.ResponseType,
	//	"X-Apple-OAuth-Client-Type":   c.appConfig.Direct.AppleOAuth.Requestor.Type,
	//	"Origin":                      "https://idmsa.apple.com",
	//	"Referer":                     "https://idmsa.apple.com/",
	//}

	response := httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).Request(c.HttpClient)
	if response.HasError() {
		return response, nil
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)

	c.XAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	//c.XAppleIDAccountCountry = response.Header.Get("X-Apple-ID-Account-Country")
	//c.xAppleIDSessionId = response.Header.Get(_HEADER_SESSION_ID_KEY)
	if (response.Status >= 200 && response.Status < 300) || response.Status == 423 {
		var twoStepDevicesResponse TwoStepDevicesResponse
		e := json.Unmarshal(response.Body, &twoStepDevicesResponse)
		if e != nil {
			return response, nil
		}
		c.TwoStepDevicesResponse = &twoStepDevicesResponse
		return response, &twoStepDevicesResponse
	}
	return response, nil
}

/*
*
发送短信码
*/
func (c *IdmsaClient) RequestSMSVoiceCode(phoneId string, mode string) (*httpz.HttpResponse, error) {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/verify/phone"

	requestHeaders := map[string]string{
		"X-Apple-Auth-Attributes": c.XAppleAuthAttributes,
		"X-Apple-App-Id":          strconv.Itoa(c.appConfig.Direct.AppId),
		"X-Apple-Locale":          c.appConfig.Direct.Locale,
		"X-Apple-Trusted-Domain":  "https://idmsa.apple.com",
		"X-Apple-Frame-Id":        c.appConfig.Direct.IframeId,
		"X-Apple-Widget-Key":      c.appConfig.Direct.AuthWidgetConfig.WidgetKey,

		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"Content-Type":     "application/json",
		"Origin":           "https://idmsa.apple.com",
		"Referer":          "https://idmsa.apple.com/",
	}
	requestHeaders["scnt"] = c.scnt
	requestHeaders["X-Apple-ID-Session-Id"] = c.xAppleIDSessionId
	//
	//requestHeaders := map[string]string{
	//	"X-Apple-Domain-Id":     strconv.Itoa(c.initAppResult.Direct.DomainId),
	//	"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	//	"X-Apple-OAuth-State":   c.appConfig.Direct.AppleOAuth.Requestor.State,
	//	"X-Apple-App-Id":        c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	//"X-Apple-I-FD-Client-Info":   `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"7la44j1e3NlY5BNlY5BSmHACVZXnNA9bgP3B80MLLzLu_dYV6Hycfx9MsFY5Bhw.Tf5.EKWJ9Y69D96m_UdHzJJNlY5BNp55BNlan0Os5Apw.Bbq"}`,
	//	"X-Apple-Frame-Id":            c.initAppResult.Direct.IframeId,
	//	"X-Apple-OAuth-Response-Mode": c.appConfig.Direct.AppleOAuth.Requestor.ResponseMode,
	//	"X-Apple-Widget-Key":          c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"Accept":                      "application/json, text/javascript, */*; q=0.01",
	//	//"Accept":                      "text/html",
	//	"scnt":                       c.scnt,
	//	"Content-Type":               "application/json",
	//	"X-Requested-With":           "XMLHttpRequest",
	//	"X-Apple-OAuth-Client-Id":    c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"X-Apple-Auth-Attributes":    c.initAppResult.Direct.AuthAttributes,
	//	"X-Apple-OAuth-Redirect-URI": c.appConfig.Direct.AppleOAuth.Requestor.RedirectURI,
	//	//"X-Apple-OAuth-Redirect-URI": "https://account.apple.com",
	//	"X-Apple-OAuth-Response-Type": c.appConfig.Direct.AppleOAuth.Requestor.ResponseType,
	//	"X-Apple-OAuth-Client-Type":   c.appConfig.Direct.AppleOAuth.Requestor.Type,
	//	"Origin":                      "https://idmsa.apple.com",
	//	"Referer":                     "https://idmsa.apple.com/",
	//}
	param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param = fmt.Sprintf(param, phoneId, mode)
	response := httpz.NewHttpRequestBuilder(http.MethodPut, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.HttpClient)
	if response.HasError() {
		return response, response.Error
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.XAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	if response.HasError() {
		return response, response.Error
	} else if response.Status == http.StatusOK || response.Status == http.StatusAccepted {
		return response, nil
	} else {
		return response, errors.New(util.ReadErrorMessage(response.Body))
	}
}

/*
验证短信码
*/
func (c *IdmsaClient) VerifySMSVoiceCode(phoneId string, code string, mode string) (*httpz.HttpResponse, error) {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/verify/phone/securitycode"

	requestHeaders := map[string]string{
		"X-Apple-Auth-Attributes": c.XAppleAuthAttributes,
		"X-Apple-App-Id":          strconv.Itoa(c.appConfig.Direct.AppId),
		"X-Apple-Locale":          c.appConfig.Direct.Locale,
		"X-Apple-Trusted-Domain":  "https://idmsa.apple.com",
		"X-Apple-Frame-Id":        c.appConfig.Direct.IframeId,
		"X-Apple-Widget-Key":      c.appConfig.Direct.AuthWidgetConfig.WidgetKey,

		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"Content-Type":     "application/json",
		"Origin":           "https://idmsa.apple.com",
		"Referer":          "https://idmsa.apple.com/",
	}
	requestHeaders["scnt"] = c.scnt
	requestHeaders["X-Apple-ID-Session-Id"] = c.xAppleIDSessionId
	//
	//requestHeaders := map[string]string{
	//	"X-Apple-Domain-Id":     strconv.Itoa(c.initAppResult.Direct.DomainId),
	//	"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	//	"X-Apple-OAuth-State":   c.appConfig.Direct.AppleOAuth.Requestor.State,
	//	"X-Apple-App-Id":        c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	//"X-Apple-I-FD-Client-Info":   `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"7la44j1e3NlY5BNlY5BSmHACVZXnNA9bgP3B80MLLzLu_dYV6Hycfx9MsFY5Bhw.Tf5.EKWJ9Y69D96m_UdHzJJNlY5BNp55BNlan0Os5Apw.Bbq"}`,
	//	"X-Apple-Frame-Id":            c.initAppResult.Direct.IframeId,
	//	"X-Apple-OAuth-Response-Mode": c.appConfig.Direct.AppleOAuth.Requestor.ResponseMode,
	//	"X-Apple-Widget-Key":          c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	//"Accept":                      "application/json, text/javascript, */*; q=0.01",
	//	"Accept": "application/json, text/plain, */*",
	//	//"Accept":                      "text/html",
	//	"scnt":         c.scnt,
	//	"Content-Type": "application/json",
	//	//"X-Requested-With":           "XMLHttpRequest",
	//	"X-Apple-OAuth-Client-Id":    c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"X-Apple-Auth-Attributes":    c.initAppResult.Direct.AuthAttributes,
	//	"X-Apple-OAuth-Redirect-URI": c.appConfig.Direct.AppleOAuth.Requestor.RedirectURI,
	//	//"X-Apple-OAuth-Redirect-URI": "https://account.apple.com",
	//	"X-Apple-OAuth-Response-Type": c.appConfig.Direct.AppleOAuth.Requestor.ResponseType,
	//	"X-Apple-OAuth-Client-Type":   c.appConfig.Direct.AppleOAuth.Requestor.Type,
	//	"Origin":                      "https://idmsa.apple.com",
	//	"Referer":                     "https://idmsa.apple.com/",
	//}
	//param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	nonFTEU := false
	for _, device := range c.TwoStepDevicesResponse.TrustedPhoneNumbers {
		if strconv.Itoa(device.Id) == phoneId {
			nonFTEU = device.NonFTEU
			break
		}
	}
	param := ""
	if nonFTEU {
		param = fmt.Sprintf(`{"phoneNumber":{"id":%v,"nonFTEU":%v},"securityCode":{"code":"%v"},"mode":"%v"}`, phoneId, nonFTEU, code, mode)
	} else {
		param = fmt.Sprintf(`{"phoneNumber":{"id":%v},"securityCode":{"code":"%v"},"mode":"%v"}`, phoneId, code, mode)
	}

	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.HttpClient)
	if response.HasError() {
		return response, response.Error
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.XAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	if response.Status == http.StatusOK || response.Status == http.StatusAccepted {
		c.Myacinfo = response.CookieValue("myacinfo")
		c.dslang = response.CookieValue("dslang")
		c.Trust()
		return response, nil
	} else {
		return response, errors.New(util.ReadErrorMessage(response.Body))
	}
}

/*
*
发送设备码，202表示发送成功
*/
func (c *IdmsaClient) RequestDeviceCode() (*httpz.HttpResponse, error) {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode"

	requestHeaders := map[string]string{
		"X-Apple-Auth-Attributes": c.XAppleAuthAttributes,
		"X-Apple-App-Id":          strconv.Itoa(c.appConfig.Direct.AppId),
		"X-Apple-Locale":          c.appConfig.Direct.Locale,
		"X-Apple-Trusted-Domain":  "https://idmsa.apple.com",
		"X-Apple-Frame-Id":        c.appConfig.Direct.IframeId,
		"X-Apple-Widget-Key":      c.appConfig.Direct.AuthWidgetConfig.WidgetKey,

		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"Content-Type":     "application/json",
		"Origin":           "https://idmsa.apple.com",
		"Referer":          "https://idmsa.apple.com/",
	}
	requestHeaders["scnt"] = c.scnt
	requestHeaders["X-Apple-ID-Session-Id"] = c.xAppleIDSessionId
	//
	//requestHeaders := map[string]string{
	//	"X-Apple-Domain-Id":     strconv.Itoa(c.initAppResult.Direct.DomainId),
	//	"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	//	"X-Apple-OAuth-State":   c.appConfig.Direct.AppleOAuth.Requestor.State,
	//	"X-Apple-App-Id":        c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	//"X-Apple-I-FD-Client-Info":   `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"7la44j1e3NlY5BNlY5BSmHACVZXnNA9bgP3B80MLLzLu_dYV6Hycfx9MsFY5Bhw.Tf5.EKWJ9Y69D96m_UdHzJJNlY5BNp55BNlan0Os5Apw.Bbq"}`,
	//	"X-Apple-Frame-Id":            c.initAppResult.Direct.IframeId,
	//	"X-Apple-OAuth-Response-Mode": c.appConfig.Direct.AppleOAuth.Requestor.ResponseMode,
	//	"X-Apple-Widget-Key":          c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"Accept":                      "application/json, text/javascript, */*; q=0.01",
	//	//"Accept":                      "text/html",
	//	"scnt":                       c.scnt,
	//	"Content-Type":               "application/json",
	//	"X-Requested-With":           "XMLHttpRequest",
	//	"X-Apple-OAuth-Client-Id":    c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"X-Apple-Auth-Attributes":    c.initAppResult.Direct.AuthAttributes,
	//	"X-Apple-OAuth-Redirect-URI": c.appConfig.Direct.AppleOAuth.Requestor.RedirectURI,
	//	//"X-Apple-OAuth-Redirect-URI": "https://account.apple.com",
	//	"X-Apple-OAuth-Response-Type": c.appConfig.Direct.AppleOAuth.Requestor.ResponseType,
	//	"X-Apple-OAuth-Client-Type":   c.appConfig.Direct.AppleOAuth.Requestor.Type,
	//	"Origin":                      "https://idmsa.apple.com",
	//	"Referer":                     "https://idmsa.apple.com/",
	//}

	//param:= map[string]interface{}{}
	param := "{}"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.HttpClient)
	if response.HasError() {
		return response, response.Error
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.XAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	if response.Status == http.StatusOK || response.Status == http.StatusAccepted {
		return response, nil
	} else {
		return response, errors.New(util.ReadErrorMessage(response.Body))
	}
}

/*
验证设备码,成功会获取trust cookie，如果失败会返回错误的具体信息
*/
func (c *IdmsaClient) VerifyDeviceCode(code string) (*httpz.HttpResponse, error) {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode"
	//requestHeaders := map[string]string{
	//	"X-Apple-Domain-Id":     strconv.Itoa(c.initAppResult.Direct.DomainId),
	//	"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	//	"X-Apple-OAuth-State":   c.appConfig.Direct.AppleOAuth.Requestor.State,
	//	"X-Apple-App-Id":        c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	//"X-Apple-I-FD-Client-Info":   `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"7la44j1e3NlY5BNlY5BSmHACVZXnNA9bgP3B80MLLzLu_dYV6Hycfx9MsFY5Bhw.Tf5.EKWJ9Y69D96m_UdHzJJNlY5BNp55BNlan0Os5Apw.Bbq"}`,
	//	"X-Apple-Frame-Id":            c.initAppResult.Direct.IframeId,
	//	"X-Apple-OAuth-Response-Mode": c.appConfig.Direct.AppleOAuth.Requestor.ResponseMode,
	//	"X-Apple-Widget-Key":          c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"Accept":                      "application/json, text/javascript, */*; q=0.01",
	//	//"Accept":                      "text/html",
	//	"scnt":                       c.scnt,
	//	"Content-Type":               "application/json",
	//	"X-Requested-With":           "XMLHttpRequest",
	//	"X-Apple-OAuth-Client-Id":    c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"X-Apple-Auth-Attributes":    c.initAppResult.Direct.AuthAttributes,
	//	"X-Apple-OAuth-Redirect-URI": c.appConfig.Direct.AppleOAuth.Requestor.RedirectURI,
	//	//"X-Apple-OAuth-Redirect-URI": "https://account.apple.com",
	//	"X-Apple-OAuth-Response-Type": c.appConfig.Direct.AppleOAuth.Requestor.ResponseType,
	//	"X-Apple-OAuth-Client-Type":   c.appConfig.Direct.AppleOAuth.Requestor.Type,
	//	"Origin":                      "https://idmsa.apple.com",
	//	"Referer":                     "https://idmsa.apple.com/",
	//}
	requestHeaders := map[string]string{
		"X-Apple-Auth-Attributes": c.XAppleAuthAttributes,
		"X-Apple-App-Id":          strconv.Itoa(c.appConfig.Direct.AppId),
		"X-Apple-Locale":          c.appConfig.Direct.Locale,
		"X-Apple-Trusted-Domain":  "https://idmsa.apple.com",
		"X-Apple-Frame-Id":        c.appConfig.Direct.IframeId,
		"X-Apple-Widget-Key":      c.appConfig.Direct.AuthWidgetConfig.WidgetKey,

		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"Content-Type":     "application/json",
		"Origin":           "https://idmsa.apple.com",
		"Referer":          "https://idmsa.apple.com/",
	}
	requestHeaders["scnt"] = c.scnt
	requestHeaders["X-Apple-ID-Session-Id"] = c.xAppleIDSessionId

	//param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param := `{"securityCode":{"code":"%s"}}`
	param = fmt.Sprintf(param, code)
	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.HttpClient)
	if response.HasError() {
		return response, response.Error
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.XAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	if response.Status == http.StatusOK || response.Status == http.StatusNoContent {
		c.Myacinfo = response.CookieValue("myacinfo")
		c.dslang = response.CookieValue("dslang")
		c.Trust()
		return response, nil
	} else {
		return response, errors.New(util.ReadErrorMessage(response.Body))
	}
}

/*
icloud登录用于信任设备
*/
func (c *IdmsaClient) Trust() *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/appleauth/auth/2sv/trust"
	requestHeaders := map[string]string{
		"X-Apple-Auth-Attributes": c.XAppleAuthAttributes,
		"X-Apple-App-Id":          strconv.Itoa(c.appConfig.Direct.AppId),
		"X-Apple-Locale":          c.appConfig.Direct.Locale,
		"X-Apple-Trusted-Domain":  "https://idmsa.apple.com",
		"X-Apple-Frame-Id":        c.appConfig.Direct.IframeId,
		"X-Apple-Widget-Key":      c.appConfig.Direct.AuthWidgetConfig.WidgetKey,

		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"Content-Type":     "application/json",
		"Origin":           "https://idmsa.apple.com",
		"Referer":          "https://idmsa.apple.com/",
	}
	requestHeaders["scnt"] = c.scnt
	requestHeaders["X-Apple-ID-Session-Id"] = c.xAppleIDSessionId
	//requestHeaders := map[string]string{
	//	"X-Apple-Domain-Id":     strconv.Itoa(c.initAppResult.Direct.DomainId),
	//	"X-Apple-ID-Session-Id": c.xAppleIDSessionId,
	//	"X-Apple-OAuth-State":   c.appConfig.Direct.AppleOAuth.Requestor.State,
	//	"X-Apple-App-Id":        c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	//"X-Apple-I-FD-Client-Info":   `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"7la44j1e3NlY5BNlY5BSmHACVZXnNA9bgP3B80MLLzLu_dYV6Hycfx9MsFY5Bhw.Tf5.EKWJ9Y69D96m_UdHzJJNlY5BNp55BNlan0Os5Apw.Bbq"}`,
	//	"X-Apple-Frame-Id":            c.initAppResult.Direct.IframeId,
	//	"X-Apple-OAuth-Response-Mode": c.appConfig.Direct.AppleOAuth.Requestor.ResponseMode,
	//	"X-Apple-Widget-Key":          c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"Accept":                      "application/json, text/javascript, */*; q=0.01",
	//	//"Accept":                      "text/html",
	//	"scnt":                       c.scnt,
	//	"Content-Type":               "application/json",
	//	"X-Requested-With":           "XMLHttpRequest",
	//	"X-Apple-OAuth-Client-Id":    c.appConfig.Direct.AppleOAuth.Requestor.Id,
	//	"X-Apple-Auth-Attributes":    c.initAppResult.Direct.AuthAttributes,
	//	"X-Apple-OAuth-Redirect-URI": c.appConfig.Direct.AppleOAuth.Requestor.RedirectURI,
	//	//"X-Apple-OAuth-Redirect-URI": "https://account.apple.com",
	//	"X-Apple-OAuth-Response-Type": c.appConfig.Direct.AppleOAuth.Requestor.ResponseType,
	//	"X-Apple-OAuth-Client-Type":   c.appConfig.Direct.AppleOAuth.Requestor.Type,
	//	"Origin":                      "https://idmsa.apple.com",
	//	"Referer":                     "https://idmsa.apple.com/",
	//}
	requestHeaders["X-Apple-OAuth-Require-Grant-Code"] = "true"
	requestHeaders["X-Apple-Offer-Security-Upgrade"] = "1"
	response := httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).Request(c.HttpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	c.XAppleAuthAttributes = response.Header.Get(_X_Apple_Auth_Attributes_KEY)
	//trust设备，会更新myacinfo和aidshd，和返回一个新的des开头的cookie。nottrust 的时候没有DESxxxxxx，只有一个_DESxxxxxxxxxx
	if mc := response.Cookie("^DES*", true); mc != nil {
		c.DesCookieName = mc.Name
		c.DesCookieValue = mc.Value
	}
	return c.signinDeveloperCenter()
}
func (c *IdmsaClient) signinDeveloperCenter() *httpz.HttpResponse {
	var requestURL = "https://idmsa.apple.com/IDMSWebAuth/signin"
	requestHeaders := map[string]string{
		"Upgrade-Insecure-Requests": "1",
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Origin":                    "https://idmsa.apple.com",
		"Referer":                   "https://idmsa.apple.com/",
	}

	params := map[string]string{
		"rememberMe": "false",
		"grantCode":  "",
		"iframeId":   c.appConfig.Direct.IframeId,
		"requestUri": "/signin",
		"appIdKey":   c.appConfig.Direct.App.AppIdKey,
		"language":   c.dslang,
		"rv":         "1",
		"scnt":       c.scnt,
	}
	urlValues := url.Values{}
	for key, value := range params {
		urlValues.Add(key, value)
	}

	//rememberMe=false&grantCode=&iframeId=daw-473c7594-2a3b-478d-86cd-bdf500d5236f&requestUri=%2Fsignin&appIdKey=891bd3417a7776362562d2197f89480a8547b108fd934911bcbea0110d07f757
	//&language=CN-ZH&path=%2Faccount%2F&rv=1&scnt=AAAA-kFCMUE1QUQzNkE5RjI4NzNFNjcwNkMyOUYxRUU2RDhCRjAzNkUwRTdGNzc4Q0JCQkFEMkNEMjcxQUE5OUYzRDZFMjFGQjlCQzZBOUZGMEIzRDk3MkE1QTU2NkJGMjk4QzgxNDcxOEMyNTA5RkIxNTA2OTFFMjNFQkExRDY0QzVFRDBFNjNBNjA2Q0ZGQUU5N0E0NzI0QTFBN0EyMjFFNjI4MTAyMDhBRkU3RDNCOENFREY4QUE2OTgwNjQyMUE4MzIwOTlDNDhFNzBERERFODIxRDY5QjkxQzcyQjc2QUZCQ0QwMzJBNzkxMzk0MDAzRXwxAAABlQSk45x7mJtf0SkOhyibUxDbRY7a2Bhq6nyaWBjdNku7r20JJ5GFbnjo2ntmAAJhCDxxgt9XLHGjW_fGPzTPm9-nUzMqTbtdmLKfQYfacKv_C9Tj-Q
	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).ContentType(httpz.ContentType_Form_URL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(urlValues).Request(c.HttpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	return httpz.NewHttpRequestBuilder(http.MethodGet, "https://developer.apple.com/account/").Request(c.HttpClient)
}

/*
account 登录用于获取token
*/
func (c *IdmsaClient) getAccountToken() *httpz.HttpResponse {
	var requestURL = "https://appleid.apple.com/account/manage/gs/ws/token"
	requestHeaders := map[string]string{
		"Accept":                    "Accept: application/json, text/plain, */*",
		"scnt":                      c.scnt,
		"Content-Type":              "application/json",
		"X-Apple-I-Request-Context": "ca",
		"Origin":                    "https://account.apple.com",
		"Referer":                   "https://account.apple.com/",
	}
	response := httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).Request(c.HttpClient)
	if response.HasError() {
		return response
	}
	c.scnt = response.Header.Get(_HEADER_SCNT_KEY)
	return response
}

/*
返回dqsid, itctx, error
*/
//func GetOlympusSession(myacinfo string, desKey string, desValue string) (string, string, error) {
func GetOlympusSession(cookieHeader string) (string, string, error) {
	header := map[string]string{
		"User-Agent":       httpz.UserAgent_GoogleChrome,
		"Accept":           "application/vnd.api+json, application/json, text/plain, */*",
		"X-Requested-With": "XMLHttpRequest",
		"X-Csrf-Itc":       "itc",
	}
	//cookies := CookiesToHeader(map[string]string{"myacinfo": myacinfo, desKey: desValue})
	header["Cookie"] = cookieHeader
	response3 := httpz.Get("https://appstoreconnect.apple.com/olympus/v1/session", header).Request(httpz.NewHttpClient(nil))
	if response3.HasError() {
		return "", "", response3.Error
	}
	dqsid := response3.CookieValue("dqsid")
	itctx := response3.CookieValue("itctx")
	if dqsid != "" && itctx != "" {
		return dqsid, itctx, nil
		//return map[string]string{"dqsid": dqsid, "itctx": itctx}, nil
	} else if response3.Status == 200 {
		return "", "", nil
	}

	return "", "", errors.New("no itc cookie found")
}

type AppConfigV1 struct {
	Direct struct {
		DestinationDomain string `json:"destinationDomain"`
		AppleOAuth        struct {
			Requestor struct {
				RedirectURI  string `json:"redirectURI"`
				ResponseMode string `json:"responseMode"`
				ResponseType string `json:"responseType"`
				FrameId      string `json:"frameId"`
				Id           string `json:"id"`
				State        string `json:"state"`
				Type         string `json:"type"`
			} `json:"requestor"`
		} `json:"appleOAuth"`
		UrlContext      string `json:"urlContext"`
		EnableAuthPopup bool   `json:"enableAuthPopup"`
	} `json:"direct"`
	Additional struct {
		SkVersion string `json:"skVersion"`
	} `json:"additional"`
}
type InitAppResult struct {
	Direct struct {
		IsPasswordSecondStep    bool   `json:"isPasswordSecondStep"`
		ScriptSk7Url            string `json:"scriptSk7Url"`
		IsFederatedAuthEnabled  bool   `json:"isFederatedAuthEnabled"`
		AccountNameAutoComplete string `json:"accountNameAutoComplete"`
		AccountName             string `json:"accountName"`
		UrlBag                  struct {
			PasswordReset        string `json:"passwordReset"`
			CreateAppleID        string `json:"createAppleID"`
			AppleId              string `json:"appleId"`
			VerificationCodeHelp string `json:"verificationCodeHelp"`
			AccountRecoveryHelp  string `json:"accountRecoveryHelp"`
			CrResetUrl           string `json:"crResetUrl"`
		} `json:"urlBag"`
		RefererUrl                       string `json:"refererUrl"`
		AuthAttributes                   string `json:"authAttributes"`
		IsRaFF                           bool   `json:"isRaFF"`
		ForgotPassword                   bool   `json:"forgotPassword"`
		SwpAuth                          bool   `json:"swpAuth"`
		TwoFactorAuthEnv                 int    `json:"twoFactorAuthEnv"`
		CountryCode                      string `json:"countryCode"`
		IsInterstitialFedAuthPageEnabled bool   `json:"isInterstitialFedAuthPageEnabled"`
		TwoFactorAuthAppKey              string `json:"twoFactorAuthAppKey"`
		IsRtl                            string `json:"isRtl"`
		Hashcash                         struct {
			HashcashGenerationTimeout int    `json:"hashcashGenerationTimeout"`
			HcChallenge               string `json:"hcChallenge"`
			HcBits                    string `json:"hcBits"`
			IsHCstrictTimeout         bool   `json:"isHCstrictTimeout"`
		} `json:"hashcash"`
		WebSRPClientWorkerScriptTag string `json:"webSRPClientWorkerScriptTag"`
		IsRaIdp                     bool   `json:"isRaIdp"`
		AcUrl                       string `json:"acUrl"`
		EnableSRPAuth               bool   `json:"enableSRPAuth"`
		DomainId                    int    `json:"domainId"`
		ShouldSuppressIForgotLink   bool   `json:"shouldSuppressIForgotLink"`
		DisableChromeAutoComplete   bool   `json:"disableChromeAutoComplete"`
		GenerateHashcashScriptTag   string `json:"generateHashcashScriptTag"`
		IframeId                    string `json:"iframeId"`
		Meta                        struct {
			FutureReservedAuthUIModes []string `json:"futureReservedAuthUIModes"`
			SupportedAuthUIModes      []string `json:"supportedAuthUIModes"`
			FEConfiguration           struct {
				PmrpcTimeout            string `json:"pmrpcTimeout"`
				EnableAllowAttribute    bool   `json:"enableAllowAttribute"`
				EnableSwpAuth           bool   `json:"enableSwpAuth"`
				IsEyebrowTextboxEnabled bool   `json:"isEyebrowTextboxEnabled"`
				SkVersion               string `json:"skVersion"`
				PmrpcRetryCount         string `json:"pmrpcRetryCount"`
				JsLogLevel              string `json:"jsLogLevel"`
				AppLoadDelay            string `json:"appLoadDelay"`
				EnablePerformanceLog    bool   `json:"enablePerformanceLog"`
			} `json:"FEConfiguration"`
		} `json:"meta"`
		EnableFpn                   bool `json:"enableFpn"`
		EnableSecurityKeyIndividual bool `json:"enableSecurityKeyIndividual"`
		ShowSwpAuth                 bool `json:"showSwpAuth"`
	} `json:"direct"`
	Additional struct {
	} `json:"additional"`
}

type trustedPhoneNumber struct {
	NonFTEU            bool   `json:"nonFTEU"`
	NumberWithDialCode string `json:"numberWithDialCode"`
	PushMode           string `json:"pushMode"`
	ObfuscatedNumber   string `json:"obfuscatedNumber"`
	LastTwoDigits      string `json:"lastTwoDigits"`
	Id                 int    `json:"id"`
}
type securityCode struct {
	Length                int  `json:"length"`
	TooManyCodesSent      bool `json:"tooManyCodesSent"`
	TooManyCodesValidated bool `json:"tooManyCodesValidated"`
	SecurityCodeLocked    bool `json:"securityCodeLocked"`
	SecurityCodeCooldown  bool `json:"securityCodeCooldown"`
}
type ServiceError struct {
	Code              string `json:"code"`
	Title             string `json:"title"`
	Message           string `json:"message"`
	SuppressDismissal bool   `json:"suppressDismissal"`
}
type trustedDevices struct {
	ID                 int    `json:"id,omitempty"`
	ObfuscatedNumber   string `json:"name,omitempty"`
	PushMode           string `json:"type,omitempty"`
	NumberWithDialCode string `json:"numberWithAreaCodeCountryDialingCode,omitempty"`
}
type TwoStepDevicesResponse struct {
	TrustedPhoneNumbers             []trustedPhoneNumber `json:"trustedPhoneNumbers"`
	PhoneNumber                     trustedPhoneNumber   `json:"phoneNumber"`
	SecurityCode                    securityCode         `json:"securityCode"`
	Mode                            string               `json:"mode"`
	Type                            string               `json:"type"`
	AuthenticationType              string               `json:"authenticationType"`
	RecoveryUrl                     string               `json:"recoveryUrl"`
	CantUsePhoneNumberUrl           string               `json:"cantUsePhoneNumberUrl"`
	RecoveryWebUrl                  string               `json:"recoveryWebUrl"`
	RepairPhoneNumberUrl            string               `json:"repairPhoneNumberUrl"`
	RepairPhoneNumberWebUrl         string               `json:"repairPhoneNumberWebUrl"`
	AboutTwoFactorAuthenticationUrl string               `json:"aboutTwoFactorAuthenticationUrl"`
	AutoVerified                    bool                 `json:"autoVerified"`
	ShowAutoVerificationUI          bool                 `json:"showAutoVerificationUI"`
	SupportsCustodianRecovery       bool                 `json:"supportsCustodianRecovery"`
	HideSendSMSCodeOption           bool                 `json:"hideSendSMSCodeOption"`
	SupervisedChangePasswordFlow    bool                 `json:"supervisedChangePasswordFlow"`
	TrustedPhoneNumber              trustedPhoneNumber   `json:"trustedPhoneNumber"`
	Hsa2Account                     bool                 `json:"hsa2Account"`
	RestrictedAccount               bool                 `json:"restrictedAccount"`
	SupportsRecovery                bool                 `json:"supportsRecovery"`
	ManagedAccount                  bool                 `json:"managedAccount"`
	TrustedDevices                  []trustedDevices     `json:"trustedDevices"`          //次项老的登录方式有
	ServiceErrors                   []ServiceError       `json:"serviceErrors,omitempty"` //次项登录失败的时候包含了错误信息
	NoTrustedDevices                bool                 `json:"noTrustedDevices"`
	EnableNonFTEU                   bool                 `json:"enableNonFTEU"`
}
