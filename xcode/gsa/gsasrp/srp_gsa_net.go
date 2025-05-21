package gsasrp

import (
	"gitee.com/kxapp/kxapp-common/errorz"
	"gitee.com/kxapp/kxapp-common/httpz"
	log "github.com/sirupsen/logrus"

	"howett.net/plist"
	"net/http"
)

func PostLoginStep1Request(req GSAInitRequest) (*GSAInitResponse, *errorz.StatusError) {
	return parseGsaPlistResponse[GSAInitResponse](postGsaPlistRequest(req))
}
func PostLoginStep2Request(req GSACompleteRequest) (*GSACompleteResponse, *errorz.StatusError) {
	return parseGsaPlistResponse[GSACompleteResponse](postGsaPlistRequest(req))
}
func PostFetchTokenRequest(req GSAAppTokensRequest) (*GSAAppTokensResponse, *errorz.StatusError) {
	return parseGsaPlistResponse[GSAAppTokensResponse](postGsaPlistRequest(req))
}

/*
req必须是值类型，如果是指针类型，在plist编码的时候会失败
*/
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
		return nil, &errorz.StatusError{Status: statusBean.StatusCode, Body: statusBean.ErrorMessage}
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
