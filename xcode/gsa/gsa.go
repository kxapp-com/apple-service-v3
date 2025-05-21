package gsa

import (
	"encoding/json"
	"errors"
	"fmt"
	"gitee.com/kxapp/kxapp-common/errorz"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/xcode/gsa/gsasrp"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"howett.net/plist"
	"net/http"
)

type GsaClient struct {
	HttpClient  *http.Client
	baseHeaders map[string]string
	username    string
	password    string

	anisseteData *gsasrp.AnisseteData

	appleIdToken string //登录2次验证用到

	XAppleGSToken  string //登录成功后获得的token
	Adsid          string //登录成功后得到的token
	XcodeSessionId string //登录成功后AnisseteData转DSESSIONID，AnisseteData无需再更新，否则每次请求要更新AnisseteData
}

func NewClient() (*GsaClient, error) {
	httpClient := httpz.NewHttpClient(nil)
	var c = &GsaClient{HttpClient: httpClient}
	c.baseHeaders = map[string]string{
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
	return c, nil
}

func (c *GsaClient) Login(username string, password string) *errorz.StatusError {
	anissete, ee := GetAnisseteFromAu(c.username)
	if ee != nil {
		return errorz.NewInternalError("load required data base " + ee.Error())
		//return errorz.NewInternalError("load required data base " + ee.Error()).AsStatusResult()
	}
	c.anisseteData = anissete
	c.username = username
	c.password = password
	spd, status := gsasrp.NewSrpGsaClient(username, password, anissete).Login()
	if status != nil {
		return status
	}
	if spd.StatusCode == http.StatusConflict {
		c.appleIdToken = spd.GetAppleIdToken()
		return &errorz.StatusError{Status: http.StatusConflict, Body: "start two step verification"}
	} else if spd.StatusCode == http.StatusOK {
		xt, e := gsasrp.FetchXCodeToken(spd, anissete)
		if xt != nil {
			c.XAppleGSToken = xt.Token
			c.Adsid = spd.Adsid
			c.ViewTeams()
		}
		return e
	} else {
		log.Error(spd)
		e := &errorz.StatusError{Status: spd.StatusCode, Body: fmt.Sprintf("unknown result status %v,please contact us", spd.StatusCode)}
		return e
	}
}
func (c *GsaClient) LoadTwoStepDevices() (*httpz.HttpResponse, *TwoStepDevicesResponse) {
	var requestURL = "https://gsa.apple.com/auth"
	requestHeaders := map[string]string{"Referer": "https://idmsa.apple.com/", "X-Apple-Identity-Token": c.appleIdToken}
	c.anisseteData.AddAnisseteHeaders(requestHeaders)
	response := httpz.NewHttpRequestBuilder(http.MethodGet, requestURL).AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).Request(c.HttpClient)
	if response.Status >= 200 && response.Status < 300 {
		var twoStepDevicesResponse TwoStepDevicesResponse
		e := json.Unmarshal(response.Body, &twoStepDevicesResponse)
		if e != nil {
			return response, nil
		}
		return response, &twoStepDevicesResponse
	}
	return response, nil
}
func (c *GsaClient) RequestSMSVoiceCode(phoneId string, mode string) (*httpz.HttpResponse, error) {
	var requestURL = "https://gsa.apple.com/auth/verify/phone"
	requestHeaders := map[string]string{"X-Apple-Identity-Token": c.appleIdToken}
	c.anisseteData.AddAnisseteHeaders(requestHeaders)

	param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param = fmt.Sprintf(param, phoneId, mode)
	response := httpz.NewHttpRequestBuilder(http.MethodPut, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.HttpClient)
	if response.HasError() {
		return response, response.Error
	} else if response.Status == http.StatusOK || response.Status == http.StatusAccepted {
		return response, nil
	} else {
		return response, errors.New(ReadErrorMessage(response.Body))
	}
}
func (c *GsaClient) VerifySMSVoiceCode(phoneId string, nonFTEU bool, code string, mode string) error {
	var requestURL = "https://gsa.apple.com/auth/verify/phone/securitycode"
	requestHeaders := map[string]string{"X-Apple-Identity-Token": c.appleIdToken}
	c.anisseteData.AddAnisseteHeaders(requestHeaders)
	//param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param := `{"phoneNumber":{"id":%v,"nonFTEU":%v},"securityCode":{"code":"%v"},"mode":"%v"}`
	param = fmt.Sprintf(param, phoneId, mode, nonFTEU, code, mode)
	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.HttpClient)
	c.ViewTeams()
	if response.HasError() {
		return response.Error
	} else if response.Status == http.StatusOK || response.Status == http.StatusAccepted {
		//c.myacinfo = response.CookieValue("myacinfo")
		//c.dslang = response.CookieValue("dslang")
		e := c.Login(c.username, c.password)
		return e
		//return response, nil
	} else {
		return errors.New(ReadErrorMessage(response.Body))
	}
}
func (c *GsaClient) RequestDeviceCode() (*httpz.HttpResponse, error) {
	var requestURL = "https://gsa.apple.com/auth/verify/trusteddevice/securitycode"
	requestHeaders := map[string]string{"X-Apple-Identity-Token": c.appleIdToken}
	c.anisseteData.AddAnisseteHeaders(requestHeaders)

	param := "{}"
	response := httpz.NewHttpRequestBuilder(http.MethodPut, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.HttpClient)
	if response.HasError() {
		return response, response.Error
	} else if response.Status == http.StatusOK || response.Status == http.StatusAccepted {
		return response, nil
	} else {
		return response, errors.New(ReadErrorMessage(response.Body))
	}
}
func (c *GsaClient) VerifyDeviceCode(code string) error {
	var requestURL = "https://gsa.apple.com/auth/verify/trusteddevice/securitycode"
	requestHeaders := map[string]string{"X-Apple-Identity-Token": c.appleIdToken}
	c.anisseteData.AddAnisseteHeaders(requestHeaders)
	//param := `{"phoneNumber": {"id": %s}, "mode": "%s"}`
	param := `{"securityCode":{"code":"%s"}}`
	param = fmt.Sprintf(param, code)
	response := httpz.NewHttpRequestBuilder(http.MethodPost, requestURL).
		AddHeaders(c.baseHeaders).AddHeaders(requestHeaders).AddBody(param).Request(c.HttpClient)
	c.ViewTeams()
	if response.HasError() {
		return response.Error
	} else if response.Status == http.StatusOK || response.Status == http.StatusAccepted {
		e := c.Login(c.username, c.password)
		return e
	} else {
		return errors.New(ReadErrorMessage(response.Body))
	}
}
func (c *GsaClient) ViewTeams() {
	c.postXcode("listTeams.action")
}
func xcodeServiceHeader(gstoken string, adsid string) map[string]string {
	headers := make(map[string]string)
	headers["Accept"] = "text/x-xml-plist"
	headers["Content-Type"] = "text/x-xml-plist"
	headers["User-Agent"] = "Xcode"
	headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
	headers["X-Xcode-Version"] = "12.4 (12D4e)"
	headers["X-Apple-GS-Token"] = gstoken
	headers["X-Apple-I-Identity-Id"] = adsid
	return headers
}
func (c *GsaClient) postXcode(action string) *httpz.HttpResponse {
	headers := xcodeServiceHeader(c.XAppleGSToken, c.Adsid)
	if c.XcodeSessionId != "" {
		headers["DSESSIONID"] = c.XcodeSessionId
	} else {
		//c.anisseteData, _ = GetAnisseteFromAu(c.username)
	}
	if c.anisseteData == nil {
		return &httpz.HttpResponse{Error: errors.New("Load required data fail")}
	}
	c.anisseteData.AddAnisseteHeaders(headers)
	urlStr := fmt.Sprintf("https://developerservices2.apple.com/services/QH65B2/%s?clientId=XABBG36SBA", action)
	protocolStruct := map[string]any{"clientId": "XABBG36SBA", "protocolVersion": "QH65B2", "requestId": uuid.New().String()}
	requestBody, _ := plist.Marshal(protocolStruct, plist.XMLFormat)
	response := httpz.NewHttpRequestBuilder(http.MethodPost, urlStr).AddHeaders(headers).AddBody(requestBody).Request(c.HttpClient)
	xcodeSessionId := response.Header.Get("DSESSIONID")
	if xcodeSessionId != "" {
		c.XcodeSessionId = xcodeSessionId
	}
	return response
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
