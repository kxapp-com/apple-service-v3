package xcode

import (
	"fmt"
	"gitee.com/kxapp/kxapp-common/errorz"
	"gitee.com/kxapp/kxapp-common/httpz"
	"gitee.com/kxapp/kxapp-common/utilz"
	"github.com/appuploader/apple-service-v3/appuploader"
	"github.com/appuploader/apple-service-v3/xcode/gsa/gsasrp"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
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
	client.headers = gsasrp.AddAnisseteHeaders(data, xcodeStep2Header())
	client.headers["X-Apple-Identity-Token"] = appleIdToken
	return client
}

//	func NewItcFa2Client2(httpclient *http.Client, scnt string, sessionId string, authAttr string) *Fa2Client {
//		client := &Fa2Client{httpClient: httpclient}
//		client.serverURL = "https://idmsa.apple.com/appleauth/auth"
//		client.headers = itcAuthHeader(scnt, sessionId)
//		client.headers[_HEADER_SCNT_KEY] = scnt
//		client.headers[_HEADER_SESSION_ID_KEY] = sessionId
//		client.headers[_X_Apple_Auth_Attributes_KEY] = authAttr
//
//		//	client.headers["X-Apple-ID-Session-Id"]=sessionId
//		return client
//	}
func (client *Fa2Client) SetAnisetteData(data *appuploader.AnisseteData) {
	client.headers = gsasrp.AddAnisseteHeaders(data, xcodeStep2Header())
}

//func (client *Fa2Client) isGsaFa2Client() bool {
//	return strings.Index(client.serverURL, "gsa.apple.com") >= 0
//}

/*
没登录状态调用返回status http.StatusUnauthorized
*/
func (client *Fa2Client) LoadTwoStepDevices() *httpz.HttpResponse {
	request := httpz.NewHttpRequestBuilder(http.MethodGet, client.serverURL).AddHeaders(client.headers).BeforeReturn(client.beforeReturnHandler)
	//request.AddHeaders(map[string]string{"Referer": "https://idmsa.apple.com/","X-Apple-I-FD-Client-Info": `{"U":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36","L":"zh-CN","Z":"GMT+08:00","V":"1.1","F":"Fla44j1e3NlY5BNlY5BSmHACVZXnNA9bgZ7Tk._HazLu_dYV6Hycfx9MsFY5CKw.Tf5.EKWJ9Y69D9fmaUeJz13NlY5BNp55BNlan0Os5Apw.38I"}`})
	request.AddHeaders(map[string]string{"Referer": "https://idmsa.apple.com/"})
	return request.Request(client.httpClient)
	//r, e := ParseItcAuthResponseAs[TwoStepDevicesResponse](response, http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusPartialContent) //此处是必须有3种状态都是可以的，下面的几个函数加的状态不一定是必须的
	////if r != nil {
	////	r.HttpStatus = response.Status
	////}
	//var parsedResponse = ParsedResponse{Status: response.Status, Body: r,Header: response.Header}
	//if e != nil {
	//	parsedResponse.ErrorMessage = e.Error()
	//}
	//return parsedResponse
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
	//if response.Status == http.StatusPreconditionFailed {
	//	return ParsedResponse{Status: response.Status, Body: response.Body, ErrorMessage: "agree terms",Header: response.Header}
	//	//return response, &errorz.StatusError{Status: response.Status, Body: "agree terms"}
	//}
	//
	//v, e := ParseItcAuthResponseAs[map[string]any](response, http.StatusOK, http.StatusNoContent, http.StatusAccepted)
	//p:= ParsedResponse{Status: response.Status, Body: v, ErrorMessage: "",Header: response.Header}
	//if e != nil {
	//	p.ErrorMessage = e.Error()
	//}
	//return p
	//if result == nil {
	//	client.TrustDevice()
	//}
	//return response, result
}
func (client *Fa2Client) requestDeviceCode() *httpz.HttpResponse {
	urlStr := client.serverURL + "/verify/trusteddevice/securitycode"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, urlStr).AddHeaders(client.headers).BeforeReturn(client.beforeReturnHandler).Request(client.httpClient)
	return response
	//r, e := ParseItcAuthResponseAs[DeviceCodeResponse](response, http.StatusOK, http.StatusCreated, http.StatusAccepted)
	//if r != nil {
	//	r.PhoneNumberVerification.HttpStatus = response.Status
	//}
	//return r, e
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
	//if response.Status == http.StatusPreconditionFailed {
	//	return response, &errorz.StatusError{Status: response.Status, Body: "agree terms"}
	//}
	//_, e := ParseItcAuthResponseAs[map[string]any](response, http.StatusOK, http.StatusNoContent, http.StatusAccepted)
	//if e == nil {
	//	client.TrustDevice()
	//}
	//return response, e
}

func (client *Fa2Client) RequestVerifyCode(codeType string, phoneId string) *httpz.HttpResponse {
	if codeType == VerifyCodeMode_Device {
		return client.requestDeviceCode()
		//if s != nil {
		//	return &s.PhoneNumberVerification, re
		//} else {
		//	if re.Status == 412 {
		//		return nil, &errorz.StatusError{Status: 412, Body: "No device supported,please send SMS code"}
		//	}
		//	return nil, re
		//}
	} else {
		return client.requestSMSVoiceCode(phoneId, codeType)
	}
}

func (client *Fa2Client) requestSMSVoiceCode(phoneId string, t string) *httpz.HttpResponse {
	param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param = fmt.Sprintf(param, phoneId, t)
	//urlStr := client.serverURL + "/verify/phone/"
	urlStr := client.serverURL + "/verify/phone"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, urlStr).AddHeaders(client.headers).AddBody(param).BeforeReturn(client.beforeReturnHandler).Request(client.httpClient)
	return response
	//r, e := ParseItcAuthResponseAs[TwoStepDevicesResponse](response, http.StatusOK, http.StatusCreated, http.StatusAccepted)
	//if r != nil {
	//	r.HttpStatus = response.Status
	//}
	//return r, e
}

/*
*
获取desxxx cookie，更新myacinfo
*/
//func (client *Fa2Client) TrustDevice() *httpz.HttpResponse {
//	//if client.isGsaFa2Client() {
//	//	return nil
//	//}
//	urlStr := "https://idmsa.apple.com/appleauth/auth/2sv/trust"
//	return httpz.NewHttpRequestBuilder(http.MethodGet, urlStr).AddHeaders(client.headers).BeforeReturn(client.beforeReturnHandler).Request(client.httpClient)
//}

func ParseItcAuthResponseAs[T any](response *httpz.HttpResponse, successStatus ...int) (*T, *errorz.StatusError) {
	if response.HasError() {
		return nil, errorz.NewNetworkError(response.Error)
	}
	if response.Status == http.StatusUnauthorized {
		return nil, errorz.NewUnauthorizedError(string(response.Body))
	}
	if len(response.Body) > 0 {
		errorDetail := jsoniter.Get(response.Body, "serviceErrors", 0, "message")
		if errorDetail.LastError() == nil {
			return nil, &errorz.StatusError{Status: response.Status, Body: errorDetail.ToString()}
		}
		errorDetail2 := jsoniter.Get(response.Body, "service_errors", 0, "title")
		if errorDetail2.LastError() == nil {
			return nil, &errorz.StatusError{Status: response.Status, Body: errorDetail2.ToString()}
		}
		errorName := jsoniter.Get(response.Body, "serviceErrors", 0, "code")
		if errorName.LastError() == nil {
			return nil, &errorz.StatusError{Status: response.Status, Body: errorName.ToString()}
		}
	}
	if utilz.InSlice(successStatus, response.Status) || len(successStatus) == 0 {
		if len(response.Body) == 0 {
			return nil, nil
		}
		o, e := utilz.ParseJsonAs[T](response.Body)
		if e != nil {
			log.Errorf("status: %v , body: %s", response.Status, string(response.Body))
		}
		return o, errorz.NewParseDataError(e)
	} else {
		log.Errorf("status: %v , body: %s", response.Status, string(response.Body))
		return nil, &errorz.StatusError{Status: response.Status, Body: string(response.Body)}
	}
}
