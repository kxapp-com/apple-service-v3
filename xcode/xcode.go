package xcode

import (
	"errors"
	"fmt"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/appuploader"
	"github.com/appuploader/apple-service-v3/storage"
	"github.com/appuploader/apple-service-v3/xcode/gsa"
	"github.com/google/uuid"
	//gsasrp2 "github.com/kxapp-com/apple-service/pkg/gsa/gsasrp"
	log "github.com/sirupsen/logrus"
	"howett.net/plist"
	"net/http"
)

const ErrorCodeInvalidAccount = -20751
const ErrorCodeInvalidPassword = -20101

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
	anisseteData   *appuploader.AnisseteData
	AuthInfo       AuthInfo

	fa2Client *Fa2Client
}

func NewClient() *Client {
	return &Client{
		httpClient: httpz.NewHttpClient(nil),
	}
}
func (client *Client) Login(authInfo AuthInfo) *httpz.HttpResponse {
	client.AuthInfo = authInfo
	t, e := storage.Read[XcodeToken](authInfo.Email, storage.TokenTypeXcode)
	if e == nil {
		client.Token = t
	} else {
		client.Token = &XcodeToken{Email: authInfo.Email}
	}

	if client.IsSessionAlive() {
		return &httpz.HttpResponse{Status: http.StatusOK, Body: []byte("session is alive")}
		//log.Info("login success")
		//return errorz.SuccessStatusResult(nil)
	}
	return client.CheckPassword()
}
func (client *Client) IsSessionAlive() bool {
	if client.Token.XAppleGSToken != "" {
		response := client.postXcode("viewDeveloper.action")
		return response.Status == http.StatusOK
	}
	return false
}

func (client *Client) ViewTeams() *httpz.HttpResponse {
	return client.postXcode("listTeams.action")
}

func (client *Client) LoadTwoStepDevices() *httpz.HttpResponse {
	return client.fa2Client.LoadTwoStepDevices()
	//if e != nil {
	//	return e.AsStatusResult()
	//}
	//return errorz.SuccessStatusResult(r.TrustedPhoneNumbers)
}
func (client *Client) RequestVerifyCode(codeType string, phoneId string) *httpz.HttpResponse {
	return client.fa2Client.RequestVerifyCode(codeType, phoneId)
}

/*
在verify返回成功后请立即调用CheckPassword再次登录
*/
func (client *Client) VerifyCode(codeType string, code string, phoneId string) *httpz.HttpResponse {
	r := client.fa2Client.VerifyCode(codeType, code, phoneId)
	if r.Status == http.StatusOK {
		return client.CheckPassword()
	}
	return r
}

/*
*
xcode plist request QH65B2
*/
func (client *Client) postXcode(action string) *httpz.HttpResponse {
	headers := xcodeServiceHeader(client.Token.XAppleGSToken, client.Token.Adsid)
	if client.xcodeSessionID != "" {
		headers["DSESSIONID"] = client.xcodeSessionID
	} else {
		d, eee := appuploader.GetAnisseteFromAu(client.Token.Email)
		if eee != nil {
			return &httpz.HttpResponse{Error: eee, Status: 500}
		}
		client.anisseteData = d
	}
	if client.anisseteData == nil {
		return &httpz.HttpResponse{Error: errors.New("Load required data fail")}
	}
	gsa.AddAnisseteHeaders(client.anisseteData, headers)
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

/*
*
返回二次校验的设备列表，或者得到xctoken后返回登录成功消息，或者返回失败的提示消息
*/
func (client *Client) CheckPassword() *httpz.HttpResponse {
	anissete, ee := appuploader.GetAnisseteFromAu(client.Token.Email)
	if ee != nil {
		return &httpz.HttpResponse{Error: ee, Status: 500}
		//return ParsedResponse{Status: ee.Error()}
		//return errorz.NewInternalError("load required data base " + ee.Error()).AsStatusResult()
	}
	spd, status := gsa.Login(client.AuthInfo.Email, client.AuthInfo.Password, anissete)
	if status != nil {
		return &httpz.HttpResponse{Error: status, Status: status.Status}
	}
	if spd.StatusCode == http.StatusConflict {
		client.fa2Client = NewXcodeFa2Client2(client.httpClient, spd.GetAppleIdToken(), anissete)
	} else if spd.StatusCode == http.StatusOK {
		xt, e := gsa.FetchXCodeToken(spd, anissete)
		if e != nil {
			log.Error("get xcode token error", e)
			return &httpz.HttpResponse{Error: e, Status: e.Status}
		}
		client.postXcode("listTeams.action") //发送一个请求，获取dsessionid的头
		if xt != nil {
			client.Token.XAppleGSToken = xt.Token
			client.Token.Adsid = spd.Adsid
			saveE := storage.Write(client.Token.Email, storage.TokenTypeXcode, client.Token)
			if saveE != nil {
				fmt.Println("save token error", saveE)
			}
		}
		return &httpz.HttpResponse{Status: http.StatusOK, Body: []byte("login success")}
	}
	log.Error(spd)
	return &httpz.HttpResponse{Error: errors.New(fmt.Sprintf("unknown result status %v,please contact us", spd.StatusCode)), Status: spd.StatusCode}

}
