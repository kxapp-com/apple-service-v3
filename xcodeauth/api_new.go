package xcode

import (
	"errors"
	"fmt"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/appuploader"
	"github.com/appuploader/apple-service-v3/itcapi"
	"github.com/appuploader/apple-service-v3/storage"
	"github.com/google/uuid"
	"howett.net/plist"
	"maps"
	"net/http"
	"strings"
)

type XcodeClient struct {
	httpClient     *http.Client
	token          XcodeToken
	xcodeSessionID string
	anisseteData   *appuploader.AnisseteData
	userName       string
}

func NewXcodeClient(userName string) *XcodeClient {
	client := &XcodeClient{
		httpClient: httpz.NewHttpClient(nil),
		userName:   userName,
	}
	v, _ := storage.Read[XcodeToken](userName, storage.TokenTypeXcode)
	if v != nil {
		client.token = *v
	} else {
		client.token = XcodeToken{}
	}
	return client
}

func (client *XcodeClient) IsSessionAlive() bool {
	if client.token.XAppleGSToken == "" || client.token.Adsid == "" {
		return false
	}
	response := client.postXcode("viewDeveloper.action")
	if response.Status == http.StatusOK {
		return !strings.Contains(string(response.Body), "session has expired")
	}
	return false
}
func (client *XcodeClient) ViewTeams() *httpz.HttpResponse {
	return client.postXcode("listTeams.action")
}

/*
xcode plist request QH65B2
*/
func (client *XcodeClient) postXcode(action string) *httpz.HttpResponse {
	headers := xcodeServiceHeader(client.token.XAppleGSToken, client.token.Adsid)
	if client.xcodeSessionID != "" {
		headers["DSESSIONID"] = client.xcodeSessionID
		if client.anisseteData == nil {
			d, eee := appuploader.GetAnisseteFromAu(client.userName)
			if eee != nil {
				return &httpz.HttpResponse{Error: eee, Status: 500}
			}
			client.anisseteData = d
		}
	} else {
		d, eee := appuploader.GetAnisseteFromAu(client.userName)
		if eee != nil {
			return &httpz.HttpResponse{Error: eee, Status: 500}
		}
		client.anisseteData = d
	}
	if client.anisseteData == nil {
		return &httpz.HttpResponse{Error: errors.New("load required data fail")}
	}
	maps.Copy(headers, client.anisseteData.ToMap())
	urlStr := fmt.Sprintf("https://developerservices2.apple.com/services/QH65B2/%s?clientId=XABBG36SBA", action)
	protocolStruct := map[string]any{"clientId": "XABBG36SBA", "protocolVersion": "QH65B2", "requestId": uuid.New().String()}
	requestBody, _ := plist.Marshal(protocolStruct, plist.XMLFormat)
	response := httpz.NewHttpRequestBuilder(http.MethodPost, urlStr).AddHeaders(headers).AddBody(requestBody).Request(client.httpClient)
	DSESSIONID := response.Header.Get("DSESSIONID")
	if DSESSIONID != "" {
		client.xcodeSessionID = DSESSIONID
	}
	return response
}

/*
*
请求xcode服务器，如viewdeveloper使用的头
*/
func xcodeServiceHeader(gstoken string, adsid string) map[string]string {
	headers := make(map[string]string)
	headers["Accept"] = "text/x-xml-plist"
	headers["Content-Type"] = "text/x-xml-plist"
	headers["User-Agent"] = "Xcode"
	headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
	headers["X-Xcode-Version"] = "12.4 (12D4e)"
	headers["X-Apple-GS-token"] = gstoken
	headers["X-Apple-I-Identity-Id"] = adsid
	return headers
}
func (client *XcodeClient) DevApiV3() *itcapi.ItcApiV3 {
	header := map[string]string{
		"User-Agent":       httpz.UserAgent_XCode_Simple,
		"Accept":           "application/vnd.api+json, application/json, text/plain, */*",
		"X-Requested-With": "XMLHttpRequest",
		"Content-Type":     httpz.ContentType_VND_JSON,
		"X-Apple-App-Info": "com.apple.gs.xcode.auth",
		"X-Xcode-Version":  "14.2 (14C18)",
	}
	if client.token.XAppleGSToken != "" && client.token.Adsid != "" {
		header["X-Apple-I-Identity-Id"] = client.token.Adsid
		header["X-Apple-GS-token"] = client.token.XAppleGSToken
	}
	if client.xcodeSessionID != "" {
		header["DSESSIONID"] = client.xcodeSessionID
	}
	maps.Copy(header, client.anisseteData.ToMap())
	return &itcapi.ItcApiV3{
		HttpClient:      client.httpClient,
		ServiceURL:      "https://developerservices2.apple.com/services/v1/",
		JsonHttpHeaders: header,
		IsXcode:         true,
	}
}
