package xcode

import (
	"errors"
	"fmt"
	"maps"
	"net/http"

	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/appuploader"
	"github.com/appuploader/apple-service-v3/storage"
	"github.com/appuploader/apple-service-v3/xcodeauth/gsa"

	log "github.com/sirupsen/logrus"
	"howett.net/plist"
)

// XcodeAuthClient implements AppleAuthClient for Xcode-specific authentication
type XcodeAuthClient struct {
	httpClient *http.Client
	userName   string
	password   string
	fa2Headers map[string]string
	serverURL  string
}

func NewXcodeAuthClient() *XcodeAuthClient {
	return &XcodeAuthClient{
		httpClient: httpz.NewHttpClient(nil),
		serverURL:  "https://gsa.apple.com/auth",
	}
}
func (client *XcodeAuthClient) Login(userName string, password string) *httpz.HttpResponse {
	client.userName = userName
	client.password = password
	return client.checkPassword()
}

/*
*
返回二次校验的设备列表，或者得到xctoken后返回登录成功消息，或者返回失败的提示消息
*/
func (client *XcodeAuthClient) checkPassword() *httpz.HttpResponse {
	anissete, ee := appuploader.GetAnisseteFromAu(client.userName)
	if ee != nil {
		return &httpz.HttpResponse{Error: ee, Status: 500}
	}

	result, status := gsa.Login(client.userName, client.password, anissete)
	if status != nil {
		return &httpz.HttpResponse{Error: status, Status: status.Status}
	}
	var spd gsa.ServerProvidedData
	_, e3 := plist.Unmarshal(result.SPD, &spd)
	if e3 != nil {
		return &httpz.HttpResponse{Error: e3, Status: 500}
	}
	if spd.StatusCode == http.StatusConflict {
		client.fa2Headers = xcodeStep2Header()
		maps.Copy(client.fa2Headers, anissete.ToMap())
		client.fa2Headers["X-Apple-Identity-token"] = spd.GetAppleIdToken()

	} else if spd.StatusCode == http.StatusOK {
		xt, e := gsa.FetchXCodeToken(&spd, anissete)
		if e != nil {
			log.Error("get xcode token error", e)
			return &httpz.HttpResponse{Error: e, Status: e.Status}
		}
		if xt != nil {
			token := &XcodeToken{
				XAppleGSToken: xt.Token,
				Adsid:         spd.Adsid,
			}
			saveE := storage.Write(client.userName, storage.TokenTypeXcode, token)
			if saveE != nil {
				fmt.Println("save token error", saveE)
			}
		}
		return &httpz.HttpResponse{Status: http.StatusOK, Body: []byte("login success")}
	}
	log.Error(spd)
	return &httpz.HttpResponse{Error: errors.New(fmt.Sprintf("unknown result status %v,please contact us", spd.StatusCode)), Status: spd.StatusCode}

}
func (client *XcodeAuthClient) LoadTwoStepDevices() *httpz.HttpResponse {
	request := httpz.NewHttpRequestBuilder(http.MethodGet, client.serverURL).AddHeaders(client.fa2Headers)
	//request.AddHeaders(map[string]string{"Referer": "https://idmsa.apple.com/","X-Apple-I-FD-XcodeAuthClient-Info": `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"Fla44j1e3NlY5BNlY5BSmHACVZXnNA9bgZ7Tk._HazLu_dYV6Hycfx9MsFY5CKw.Tf5.EKWJ9Y69D9fmaUeJz13NlY5BNp55BNlan0Os5Apw.38I"}`})
	request.AddHeaders(map[string]string{"Referer": "https://idmsa.apple.com/"})
	return request.Request(client.httpClient)
}
func (client *XcodeAuthClient) VerifyCode(codeType string, code string, phoneId string) *httpz.HttpResponse {
	var r *httpz.HttpResponse
	if codeType == "device" {
		r = client.verifyDeviceCode(code)
	} else {
		r = client.verifySMSVoiceCode(phoneId, code, codeType)
	}
	if r.Status == http.StatusOK {
		return client.checkPassword()
	}
	return r
}

/*
校验短信或者电话验证码
*/
func (client *XcodeAuthClient) verifySMSVoiceCode(phoneId string, code string, codeType string) *httpz.HttpResponse {
	param := `{"phoneNumber": {"id": %s}, "securityCode": {"code": "%s"}, "mode": "%s"}`
	param = fmt.Sprintf(param, phoneId, code, codeType)
	urlStr := client.serverURL + "/verify/phone/securitycode"
	response := httpz.NewHttpRequestBuilder(http.MethodPost, urlStr).AddHeaders(client.fa2Headers).AddBody(param).Request(client.httpClient)
	return response
}
func (client *XcodeAuthClient) requestDeviceCode() *httpz.HttpResponse {
	urlStr := client.serverURL + "/verify/trusteddevice/securitycode"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, urlStr).AddHeaders(client.fa2Headers).Request(client.httpClient)
	return response
}

/*
校验设备码，返回423状态码的时候携带的是设备列表，和getdevice的数据一样,423表示校验码发送太多，409表示2次校验，400表示错误errorMessage
*/
func (client *XcodeAuthClient) verifyDeviceCode(code string) *httpz.HttpResponse {
	param := `{"securityCode": {"code": "%s"}}`
	param = fmt.Sprintf(param, code)
	urlStr := client.serverURL + "/verify/trusteddevice/securitycode"
	response := httpz.NewHttpRequestBuilder(http.MethodPost, urlStr).AddHeaders(client.fa2Headers).AddBody(param).Request(client.httpClient)
	return response
}

func (client *XcodeAuthClient) RequestVerifyCode(codeType string, phoneId string) *httpz.HttpResponse {
	if codeType == "device" {
		return client.requestDeviceCode()
	} else {
		return client.requestSMSVoiceCode(phoneId, codeType)
	}
}

func (client *XcodeAuthClient) requestSMSVoiceCode(phoneId string, t string) *httpz.HttpResponse {
	param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param = fmt.Sprintf(param, phoneId, t)
	urlStr := client.serverURL + "/verify/phone"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, urlStr).AddHeaders(client.fa2Headers).AddBody(param).Request(client.httpClient)
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
		//"X-MMe-XcodeAuthClient-Info": "<iMacPro1,1> <macOS;12.5;21G72> <com.apple.AuthKit/1 (com.apple.dt.Xcode/20504)>",
		"X-MMe-XcodeAuthClient-Info": "<iMac20,2> <Mac OS X;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
		//"X-MMe-XcodeAuthClient-Info": "<iMac20,2> <Mac OS X;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/21534)>",
		"X-Apple-App-Info": "com.apple.gs.xcode.auth",
		"X-Xcode-Version":  "14.2 (14C18)",
		//"X-Xcode-Version":   "12.4 (12D4e)",
	}
}
