package xcode

import (
	"errors"
	"fmt"
	"gitee.com/kxapp/kxapp-common/errorz"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/storage"
	"github.com/appuploader/apple-service-v3/xcode/gsa"
	gsasrp2 "github.com/appuploader/apple-service-v3/xcode/gsa/gsasrp"
	"github.com/google/uuid"
	//gsasrp2 "github.com/kxapp-com/apple-service/pkg/gsa/gsasrp"
	log "github.com/sirupsen/logrus"
	"howett.net/plist"
	"net/http"
)

type XcodeToken struct {
	Email string `json:"email"`
	//gsa 业务逻辑请求中需要用到的头X-Apple-GS-Token
	XAppleGSToken string `json:"X-Apple-GS-Token"`
	//gsa请求中需要用到的头X-Apple-I-Identity-Id
	Adsid string `json:"Adsid"`
}
type AuthInfo struct {
	Email    string
	Password string
}
type Client struct {
	httpClient     *http.Client
	Token          *XcodeToken
	xcodeSessionID string
	anisseteData   *gsasrp2.AnisseteData
	AuthInfo       AuthInfo

	fa2Client *Fa2Client
}

func NewClient() *Client {
	//client := resty.New().
	//	SetTimeout(30*time.Second).
	//	SetRetryCount(5).
	//	SetRetryWaitTime(1*time.Second).
	//	SetRetryMaxWaitTime(30*time.Second).
	//	SetHeader("User-Agent", "Xcode")
	return &Client{
		httpClient: httpz.NewHttpClient(nil),
		//csrfTokens:        make(map[string]string),
		//additionalHeaders: make(map[string]string),
	}
}
func (client *Client) IsSessionAlive() *errorz.StatusResult {
	if client.Token.XAppleGSToken != "" {
		response := client.postXcode("viewDeveloper.action")
		if response.Status == http.StatusOK {
			var rbody map[string]any
			plist.Unmarshal(response.Body, &rbody)
			if v, ok := rbody["resultCode"].(uint64); ok {
				if v == 0 {
					return errorz.SuccessStatusResult("ok")
				}
			}
			return errorz.NewUnauthorizedError("Unauthorized").AsStatusResult()
		}
	}
	return errorz.NewUnauthorizedError("Unauthorized").AsStatusResult()
}

func (client *Client) ViewTeams() (*[]XCodeTeam, *errorz.StatusError) {
	return ParsePlistQH65B2[[]XCodeTeam](client.postXcode("listTeams.action"), http.StatusOK, "teams")
}

func (client *Client) LoadTwoStepDevices() *errorz.StatusResult {
	r, e := client.fa2Client.LoadTwoStepDevices()
	if e != nil {
		return e.AsStatusResult()
	}
	return errorz.SuccessStatusResult(r.TrustedPhoneNumbers)
}
func (client *Client) RequestVerifyCode(codeType string, phoneId string) *errorz.StatusResult {
	r, e := client.fa2Client.RequestVerifyCode(codeType, phoneId)
	if e != nil {
		return e.AsStatusResult()
	}
	return errorz.SuccessStatusResult(r.TrustedPhoneNumbers)
}
func (client *Client) CheckPassword() *errorz.StatusResult {
	return client.xcodeCheckPassword()
}

/*
在verify返回成功后请立即调用CheckPassword再次登录
*/
func (client *Client) VerifyCode(codeType string, code string, phoneId string) *errorz.StatusResult {
	_, e := client.fa2Client.VerifyCode(codeType, code, phoneId)
	if e != nil {
		return e.AsStatusResult()
	} else {
		ret1 := client.CheckPassword()
		client.ViewTeams()
		//fmt.Println(ts.Body)
		return ret1
	}
}

//func (client *Client) GetDevApiV1() *DevApiV1 {
//	if client.apiV1 != nil {
//		return client.apiV1
//	}
//	if client.AuthInfo.IsFreeAccount {
//		headers := xcodeApiV1Header(client.Token.XAppleGSToken, client.Token.Adsid, client.xcodeSessionID)
//		headers = client.anisseteData.AddAnisseteHeaders(headers)
//		client.apiV1 = &DevApiV1{
//			HttpClient:      client.httpClient,
//			ServiceURL:      "https://developerservices2.apple.com/services/v1/",
//			JsonHttpHeaders: headers,
//		}
//	} else {
//		client.apiV1 = &DevApiV1{
//			HttpClient:      client.httpClient,
//			ServiceURL:      "https://developer.apple.com/services-account/v1/",
//			JsonHttpHeaders: client.itcTokenHeader(),
//		}
//	}
//	client.apiV1.TeamId = client.teamId
//	return client.apiV1
//}

/*
*
xcode plist request QH65B2
*/
func (client *Client) postXcode(action string) *httpz.HttpResponse {
	headers := xcodeServiceHeader(client.Token.XAppleGSToken, client.Token.Adsid)
	if client.xcodeSessionID != "" {
		headers["DSESSIONID"] = client.xcodeSessionID
	} else {
		client.anisseteData, _ = gsa.GetAnisseteFromAu(client.Token.Email)
	}
	if client.anisseteData == nil {
		return &httpz.HttpResponse{Error: errors.New("Load required data fail")}
	}
	client.anisseteData.AddAnisseteHeaders(headers)
	urlStr := fmt.Sprintf("https://developerservices2.apple.com/services/QH65B2/%s?clientId=XABBG36SBA", action)
	protocolStruct := map[string]any{"clientId": "XABBG36SBA", "protocolVersion": "QH65B2", "requestId": uuid.New().String()}
	requestBody, _ := plist.Marshal(protocolStruct, plist.XMLFormat)
	response := httpz.NewHttpRequestBuilder(http.MethodPost, urlStr).AddHeaders(headers).AddBody(requestBody).Request(client.httpClient)
	DSESSIONID := response.Header.Get("DSESSIONID")
	if DSESSIONID != "" {
		if DSESSIONID != client.xcodeSessionID && client.xcodeSessionID != "" {
			fmt.Printf(" \n------------------xcodeSessionID  %s changed to %s\n", client.xcodeSessionID, DSESSIONID)
		}
		client.xcodeSessionID = DSESSIONID
	}
	return response
}

/*func parseXcodeTeams(response *httpz.HttpResponse) *errorz.StatusResult {
	re, e := ParsePlistQH65B2[[]XCodeTeam](response, http.StatusOK, "teams")
	if e != nil {
		return e.AsStatusResult()
	}
	var dteam []DevTeam
	for _, team := range *re {
		isFree := true
		for _, membership := range team.Memberships {
			if membership.MembershipProductId != "fp22" {
				isFree = false
				break
			}
		}
		dt := DevTeam{TeamId: team.TeamId, Name: team.Name, Status: team.Status, Type: team.Type, XcodeFreeOnly: isFree}
		dteam = append(dteam, dt)
	}
	return errorz.SuccessStatusResult(dteam)
}*/

/*
*
返回二次校验的设备列表，或者得到xctoken后返回登录成功消息，或者返回失败的提示消息
*/
func (client *Client) xcodeCheckPassword() *errorz.StatusResult {
	anissete, ee := gsa.GetAnisseteFromAu(client.Token.Email)
	if ee != nil {
		return errorz.NewInternalError("load required data base " + ee.Error()).AsStatusResult()
	}
	spd, status := gsasrp2.NewSrpGsaClient(client.AuthInfo.Email, client.AuthInfo.Password, anissete).Login()
	if status != nil {
		return status.AsStatusResult()
	}
	if spd.StatusCode == http.StatusConflict {
		client.fa2Client = NewXcodeFa2Client2(client.httpClient, spd.GetAppleIdToken(), anissete)
		res, e := client.fa2Client.LoadTwoStepDevices()
		if e != nil {
			return e.AsStatusResult()
		} else {
			if res.TrustedPhoneNumbers == nil && res.TrustedDevices == nil {
				statusError := errorz.StatusError{Status: errorz.StatusParseDataError, Body: "trust device and phone not found,please add trust phone or device first"}
				return statusError.AsStatusResult()
			}
			return errorz.SuccessStatusResult(res.TrustedPhoneNumbers)
		}
	} else if spd.StatusCode == http.StatusOK {
		xt, e := gsasrp2.FetchXCodeToken(spd, anissete)
		if xt != nil {
			client.Token.XAppleGSToken = xt.Token
			client.Token.Adsid = spd.Adsid
			storage.Write(client.Token, storage.TokenTypeXcode)
		}
		if e != nil {
			return e.AsStatusResult()
		} else {
			return errorz.SuccessStatusResult(nil)
		}
	} else {
		log.Error(spd)
		e := errorz.StatusError{Status: spd.StatusCode, Body: fmt.Sprintf("unknown result status %v,please contact us", spd.StatusCode)}
		return e.AsStatusResult()
	}
}
func ParsePlistQH65B2[T any](response *httpz.HttpResponse, successStatus int, dataField string) (*T, *errorz.StatusError) {
	if response.HasError() {
		return nil, errorz.NewNetworkError(response.Error)
	}
	if len(response.Body) == 0 {
		if response.Status == successStatus {
			return nil, nil
		} else {
			return nil, &errorz.StatusError{Status: response.Status, Body: ""}
		}
	}
	var resultMap map[string]any
	plist.Unmarshal(response.Body, &resultMap)
	resultCode := resultMap["resultCode"]
	if v, ok1 := resultCode.(uint64); ok1 && v != 0 {
		ustring, ok := resultMap["userString"].(string)
		if !ok {
			ustring, ok = resultMap["resultString"].(string)
		}
		if !ok {
			ustring = string(response.Body)
		}
		if v == 1100 {
			return nil, errorz.NewUnauthorizedError(ustring)
		}
		return nil, &errorz.StatusError{Status: int(v), Body: ustring}
	}
	obj := resultMap[dataField]
	bt, e := plist.Marshal(obj, plist.XMLFormat)
	result := new(T)
	_, e2 := plist.Unmarshal(bt, result)
	if e != nil || e2 != nil {
		return nil, errorz.NewParseDataError(e, e2)
	}
	return result, nil
}
