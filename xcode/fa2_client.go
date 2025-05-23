package xcode

import (
	"fmt"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/appuploader"
	"github.com/appuploader/apple-service-v3/xcode/gsa"
	"net/http"
)

type Fa2Client struct {
	headers             map[string]string
	httpClient          *http.Client
	serverURL           string
	beforeReturnHandler func(response *http.Response)
}

func NewXcodeFa2Client2(httpclient *http.Client, appleIdToken string, data *appuploader.AnisseteData) *Fa2Client {
	client := &Fa2Client{httpClient: httpclient}
	client.serverURL = "https://gsa.apple.com/auth"
	client.headers = gsa.AddAnisseteHeaders(data, xcodeStep2Header())
	client.headers["X-Apple-Identity-Token"] = appleIdToken
	return client
}

func (client *Fa2Client) SetAnisetteData(data *appuploader.AnisseteData) {
	client.headers = gsa.AddAnisseteHeaders(data, xcodeStep2Header())
}

/*
没登录状态调用返回status http.StatusUnauthorized
*/
func (client *Fa2Client) LoadTwoStepDevices() *httpz.HttpResponse {
	request := httpz.NewHttpRequestBuilder(http.MethodGet, client.serverURL).AddHeaders(client.headers).BeforeReturn(client.beforeReturnHandler)
	//request.AddHeaders(map[string]string{"Referer": "https://idmsa.apple.com/","X-Apple-I-FD-Client-Info": `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"Fla44j1e3NlY5BNlY5BSmHACVZXnNA9bgZ7Tk._HazLu_dYV6Hycfx9MsFY5CKw.Tf5.EKWJ9Y69D9fmaUeJz13NlY5BNp55BNlan0Os5Apw.38I"}`})
	request.AddHeaders(map[string]string{"Referer": "https://idmsa.apple.com/"})
	return request.Request(client.httpClient)
}

func (client *Fa2Client) VerifyCode(codeType string, code string, phoneId string) *httpz.HttpResponse {
	if codeType == VerifyCodeMode_Device {
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
	response := httpz.NewHttpRequestBuilder(http.MethodPost, urlStr).AddHeaders(client.headers).AddBody(param).BeforeReturn(client.beforeReturnHandler).Request(client.httpClient)
	return response
}
func (client *Fa2Client) requestDeviceCode() *httpz.HttpResponse {
	urlStr := client.serverURL + "/verify/trusteddevice/securitycode"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, urlStr).AddHeaders(client.headers).BeforeReturn(client.beforeReturnHandler).Request(client.httpClient)
	return response
}

/*
校验设备码，返回423状态码的时候携带的是设备列表，和getdevice的数据一样,423表示校验码发送太多，409表示2次校验，400表示错误errorMessage
*/
func (client *Fa2Client) verifyDeviceCode(code string) *httpz.HttpResponse {
	param := `{"securityCode": {"code": "%s"}}`
	param = fmt.Sprintf(param, code)
	urlStr := client.serverURL + "/verify/trusteddevice/securitycode"
	response := httpz.NewHttpRequestBuilder(http.MethodPost, urlStr).AddHeaders(client.headers).AddBody(param).BeforeReturn(client.beforeReturnHandler).Request(client.httpClient)
	return response
}

func (client *Fa2Client) RequestVerifyCode(codeType string, phoneId string) *httpz.HttpResponse {
	if codeType == VerifyCodeMode_Device {
		return client.requestDeviceCode()
	} else {
		return client.requestSMSVoiceCode(phoneId, codeType)
	}
}

func (client *Fa2Client) requestSMSVoiceCode(phoneId string, t string) *httpz.HttpResponse {
	param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param = fmt.Sprintf(param, phoneId, t)
	urlStr := client.serverURL + "/verify/phone"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, urlStr).AddHeaders(client.headers).AddBody(param).BeforeReturn(client.beforeReturnHandler).Request(client.httpClient)
	return response
}

//func ParseItcAuthResponseAs[T any](response *httpz.HttpResponse, successStatus ...int) (*T, *errorz.StatusError) {
//	if response.HasError() {
//		return nil, errorz.NewNetworkError(response.Error)
//	}
//	if response.Status == http.StatusUnauthorized {
//		return nil, errorz.NewUnauthorizedError(string(response.Body))
//	}
//	if len(response.Body) > 0 {
//		errorDetail := jsoniter.Get(response.Body, "serviceErrors", 0, "message")
//		if errorDetail.LastError() == nil {
//			return nil, &errorz.StatusError{Status: response.Status, Body: errorDetail.ToString()}
//		}
//		errorDetail2 := jsoniter.Get(response.Body, "service_errors", 0, "title")
//		if errorDetail2.LastError() == nil {
//			return nil, &errorz.StatusError{Status: response.Status, Body: errorDetail2.ToString()}
//		}
//		errorName := jsoniter.Get(response.Body, "serviceErrors", 0, "code")
//		if errorName.LastError() == nil {
//			return nil, &errorz.StatusError{Status: response.Status, Body: errorName.ToString()}
//		}
//	}
//	if utilz.InSlice(successStatus, response.Status) || len(successStatus) == 0 {
//		if len(response.Body) == 0 {
//			return nil, nil
//		}
//		o, e := utilz.ParseJsonAs[T](response.Body)
//		if e != nil {
//			log.Errorf("status: %v , body: %s", response.Status, string(response.Body))
//		}
//		return o, errorz.NewParseDataError(e)
//	} else {
//		log.Errorf("status: %v , body: %s", response.Status, string(response.Body))
//		return nil, &errorz.StatusError{Status: response.Status, Body: string(response.Body)}
//	}
//}
