package xcode

import (
	"fmt"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/appuploader"
	"net/http"
	"time"
)

type Fa2Client struct {
	headers    map[string]string
	httpClient *http.Client
	serverURL  string
	//beforeReturnHandler func(response *http.Response)
}

func NewXcodeFa2Client(httpclient *http.Client, appleIdToken string, data *appuploader.AnisseteData) *Fa2Client {
	client := &Fa2Client{httpClient: httpclient}
	client.serverURL = "https://gsa.apple.com/auth"
	//client.headers = gsa.AddAnisseteHeaders(data, xcodeStep2Header())
	client.SetAnisetteData(data)
	client.headers["X-Apple-Identity-Token"] = appleIdToken
	return client
}

func (client *Fa2Client) SetAnisetteData(data *appuploader.AnisseteData) {
	client.headers = AddAnisseteHeaders(data, xcodeStep2Header())
}

/*
没登录状态调用返回status http.StatusUnauthorized
*/
func (client *Fa2Client) LoadTwoStepDevices() *httpz.HttpResponse {
	request := httpz.NewHttpRequestBuilder(http.MethodGet, client.serverURL).AddHeaders(client.headers)
	//request.AddHeaders(map[string]string{"Referer": "https://idmsa.apple.com/","X-Apple-I-FD-Client-Info": `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"Fla44j1e3NlY5BNlY5BSmHACVZXnNA9bgZ7Tk._HazLu_dYV6Hycfx9MsFY5CKw.Tf5.EKWJ9Y69D9fmaUeJz13NlY5BNp55BNlan0Os5Apw.38I"}`})
	request.AddHeaders(map[string]string{"Referer": "https://idmsa.apple.com/"})
	return request.Request(client.httpClient)
}

func (client *Fa2Client) VerifyCode(codeType string, code string, phoneId string) *httpz.HttpResponse {
	if codeType == "device" {
		return client.verifyDeviceCode(code)
	} else {
		return client.verifySMSVoiceCode(phoneId, code, codeType)
	}
}

/*
校验短信或者电话验证码
*/
func (client *Fa2Client) verifySMSVoiceCode(phoneId string, code string, codeType string) *httpz.HttpResponse {
	//param := `{"phoneNumber": {"id": %s}, "securityCode": {"code": %s}, "mode": "%s"}`
	param := `{"phoneNumber": {"id": %s}, "securityCode": {"code": "%s"}, "mode": "%s"}`
	param = fmt.Sprintf(param, phoneId, code, codeType)
	urlStr := client.serverURL + "/verify/phone/securitycode"
	response := httpz.NewHttpRequestBuilder(http.MethodPost, urlStr).AddHeaders(client.headers).AddBody(param).Request(client.httpClient)
	return response
}
func (client *Fa2Client) requestDeviceCode() *httpz.HttpResponse {
	urlStr := client.serverURL + "/verify/trusteddevice/securitycode"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, urlStr).AddHeaders(client.headers).Request(client.httpClient)
	return response
}

/*
校验设备码，返回423状态码的时候携带的是设备列表，和getdevice的数据一样,423表示校验码发送太多，409表示2次校验，400表示错误errorMessage
*/
func (client *Fa2Client) verifyDeviceCode(code string) *httpz.HttpResponse {
	param := `{"securityCode": {"code": "%s"}}`
	param = fmt.Sprintf(param, code)
	urlStr := client.serverURL + "/verify/trusteddevice/securitycode"
	response := httpz.NewHttpRequestBuilder(http.MethodPost, urlStr).AddHeaders(client.headers).AddBody(param).Request(client.httpClient)
	return response
}

func (client *Fa2Client) RequestVerifyCode(codeType string, phoneId string) *httpz.HttpResponse {
	if codeType == "device" {
		return client.requestDeviceCode()
	} else {
		return client.requestSMSVoiceCode(phoneId, codeType)
	}
}

func (client *Fa2Client) requestSMSVoiceCode(phoneId string, t string) *httpz.HttpResponse {
	param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param = fmt.Sprintf(param, phoneId, t)
	urlStr := client.serverURL + "/verify/phone"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, urlStr).AddHeaders(client.headers).AddBody(param).Request(client.httpClient)
	return response
}

/*
*
xcode 二次校验的时候使用的头
*/
func xcodeStep2Header() map[string]string {
	return map[string]string{
		"Content-Type":     httpz.ContentType_JSON,
		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		//"Accept-Language":  "en-US,en;q=0.9",
		"Accept-Language": "zh-cn",
		"User-Agent":      httpz.UserAgent_XCode,
		//"X-MMe-Client-Info": "<iMacPro1,1> <macOS;12.5;21G72> <com.apple.AuthKit/1 (com.apple.dt.Xcode/20504)>",
		"X-MMe-Client-Info": "<iMac20,2> <Mac OS X;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
		//"X-MMe-Client-Info": "<iMac20,2> <Mac OS X;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/21534)>",
		"X-Apple-App-Info": "com.apple.gs.xcode.auth",
		"X-Xcode-Version":  "14.2 (14C18)",
		//"X-Xcode-Version":   "12.4 (12D4e)",
	}
}
func AddAnisseteHeaders(data *appuploader.AnisseteData, headers map[string]string) map[string]string {
	const XCode_Client_Time_Format = "2006-01-02T15:04:05Z"
	headers["X-Apple-I-MD"] = data.XAppleIMD
	headers["X-Apple-I-MD-LU"] = data.XAppleIMDLU
	headers["X-Apple-I-MD-M"] = data.XAppleIMDM
	headers["X-Apple-I-MD-RINFO"] = data.XAppleIMDRINFO
	headers["X-Apple-I-TimeZone"] = data.XAppleITimeZone
	headers["X-Apple-Locale"] = data.XAppleLocale
	headers["X-Mme-Client-Info"] = data.XMmeClientInfo
	headers["X-Mme-Device-Id"] = data.XMmeDeviceId
	headers["X-Apple-I-Client-Time"] = time.Now().Format(XCode_Client_Time_Format)
	//headers["X-Apple-I-Client-Time"] = util.GetAppleClientTimeNowString3(data.XAppleIClientTime)
	//headers["X-Apple-I-Client-Time"] = time.Now().UTC().Format(util.XCode_Client_Time_Format)
	return headers
}
