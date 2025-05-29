package xcode

import (
	"fmt"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"
)

type DevApiV1 struct {
	HttpClient      *http.Client
	JsonHttpHeaders map[string]string
	TeamId          string
	//https://developerservices2.apple.com/services/v1/
	//https://developer.apple.com/services-account/v1/
	ServiceURL          string
	CachedHeaderHandler func(response *http.Response)
	IsSessionTimeOut    bool
}

func NewDevApiV1(client *Client) *DevApiV1 {
	headers := xcodeApiV1Header(client.Token.XAppleGSToken, client.Token.Adsid, client.xcodeSessionID)
	headers = AddAnisseteHeaders(client.anisseteData, headers)
	return &DevApiV1{
		HttpClient:      client.httpClient,
		ServiceURL:      "https://developerservices2.apple.com/services/v1/",
		JsonHttpHeaders: headers,
	}
}

//	func (that *DevApiV1) IsXCodeAPI() bool {
//		return strings.Index(that.ServiceURL, "developerservices2.apple.com") > 0
//	}
func (that *DevApiV1) BeforeReturnAction(response *http.Response) {
	//if response == nil || response.Header == nil {
	//	return
	//}
	//csrf := response.Header.Get("csrf")
	//csrf_ts := response.Header.Get("csrf_ts")
	//if csrf != "" {
	//	that.JsonHttpHeaders["csrf"] = csrf
	//}
	//if csrf_ts != "" {
	//	that.JsonHttpHeaders["csrf_ts"] = csrf_ts
	//}
	if response.StatusCode >= http.StatusBadRequest {
		that.IsSessionTimeOut = true
	}
}
func (that *DevApiV1) ListDevices() *httpz.HttpResponse {
	urlStr := that.ServiceURL + "devices"
	requestParams := `{"urlEncodedQueryParams":"limit=1000&sort=name&filter[AND][deviceClass]=APPLE_WATCH,IPAD,IPHONE,IPOD,APPLE_SILICON_MAC","teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).SetHeader("X-HTTP-Method-Override", http.MethodGet).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//beans, e := ParseJsonResponseV1[[]ListDeviceBean](request.Request(that.HttpClient), http.StatusOK)
	//if e != nil {
	//	return nil, e
	//}
	//var devices []DeviceBean
	//for _, d := range *beans {
	//	devices = append(devices, DeviceBean{DeviceId: d.Id, Name: d.Attributes.Name, DeviceNumber: d.Attributes.Udid, DevicePlatform: d.Attributes.Platform, Status: d.Attributes.Status,
	//		DeviceClass: d.Attributes.DeviceClass, DateAdded: d.Attributes.AddedDate})
	//}
	//return devices, e
}

func (that *DevApiV1) AddDevicesValidate(udid string, deviceName string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "devices"
	return that.addAndValidateDevice(udid, deviceName, urlStr)
}
func (that *DevApiV1) AddDevices(udid string, deviceName string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "devices"
	return that.addAndValidateDevice(udid, deviceName, urlStr)
}
func (that *DevApiV1) addAndValidateDevice(udid string, deviceName string, urlStr string) *httpz.HttpResponse {
	//requestParamJS:=`{"data":{"type":"devices","attributes":{"teamId":"57W66QZCMN","name":"877028320’s Mac","udid":"564D04F2-0FCD-22A6-5252-EB8DCCEE0E95","platform":"MACOS"}}}`
	requestParamJS := `{"data":{"type":"devices","attributes":{"teamId":"%s","name":"%s","udid":"%s","platform":"%s"}}}` //MACOS
	requestParamJS = fmt.Sprintf(requestParamJS, that.TeamId, deviceName, udid, "IOS")                                   //小写ios可能失败
	//fmt.Printf(requestParamJS)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParamJS).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//devices, e := ParseJsonResponseV1[[]DeviceBean](request.Request(that.HttpClient), http.StatusCreated)
	//if e == nil && len(*devices) > 0 {
	//	return &((*devices)[0]), e
	//}
	//return nil, e
}
func (that *DevApiV1) UpdateDeviceName(deviceIdID string, deviceName string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "devices/" + deviceIdID
	//requestParamJS:=`{"data":{"type":"devices","attributes":{"teamId":"57W66QZCMN","name":"877028320’s Mac","udid":"564D04F2-0FCD-22A6-5252-EB8DCCEE0E95","platform":"MACOS"}}}`
	requestParamJS := `{"data":{"type":"devices","id":"%s","attributes":{"teamId":"%s","name":"%s"}}}` //MACOS
	requestParamJS = fmt.Sprintf(requestParamJS, deviceIdID, that.TeamId, deviceName)
	request := httpz.NewHttpRequestBuilder(http.MethodPatch, urlStr).AddHeaders(that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParamJS).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//devices, e := ParseJsonResponseV1[[]DeviceBean](request.Request(that.HttpClient), http.StatusCreated)
	//if e == nil && len(*devices) > 0 {
	//	return &((*devices)[0]), e
	//}
	//return nil, e
}
func (that *DevApiV1) UpdateDeviceStatus(deviceIdID string, enable bool) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "devices/" + deviceIdID
	status := "DISABLED"
	if enable {
		status = "ENABLED"
	}
	requestParamJS := `{"data":{"type":"devices","id":"%s","attributes":{"teamId":"%s","status":"%s"}}}` //MACOS
	requestParamJS = fmt.Sprintf(requestParamJS, deviceIdID, that.TeamId, status)
	request := httpz.NewHttpRequestBuilder(http.MethodPatch, urlStr).AddHeaders(that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParamJS).BeforeReturn(that.BeforeReturnAction).Request(that.HttpClient)
	return request
	//devices, e := ParseJsonResponseV1[ListDeviceBean](request, http.StatusOK)
	//return devices, e
	//if e == nil && len(*devices) > 0 {
	//	return &((*devices)[0]), e
	//}
	//return nil, e
}

// -------------------------------------------------------------------------------------------------------------------------------------------------------
func (that *DevApiV1) ListBundleID() *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds"
	requestParams := `{"urlEncodedQueryParams":"limit=1000&sort=name&filter[platform]=IOS,MACOS,UNIVERSAL","teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[[]BundleIDBean](request.Request(that.HttpClient), http.StatusOK)
	//return *b, e
}
func (that *DevApiV1) GetBundleID(bundleIDId string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds/" + bundleIDId
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[BundleIDBean](request.Request(that.HttpClient), http.StatusOK)
}
func (that *DevApiV1) AddBundleID(bundleId string, name string, enablepush bool) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds"
	isWild := strings.Index(bundleId, "*") >= 0
	isWild = true
	wildIDParams := `{"data":{"attributes":{"identifier":"%s","seedId":"%s","teamId":"%s","name":"%s"},"relationships":{"bundleIdCapabilities":{"data":[]}},"type":"bundleIds"}}`
	uniIDParams := `{"data":{"attributes":{"identifier":"%s","seedId":"%s","teamId":"%s","name":"%s"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","attributes":{"enabled":%v,"settings":[]},"relationships":{"capability":{"data":{"type":"capabilities","id":"IN_APP_PURCHASE"}}}}]}},"type":"bundleIds"}}`
	wildIDParams = fmt.Sprintf(wildIDParams, bundleId, that.TeamId, that.TeamId, name)
	param := wildIDParams
	if !isWild {
		param = fmt.Sprintf(uniIDParams, bundleId, that.TeamId, that.TeamId, name, enablepush)
	}
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(param).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[BundleIDBean](request.Request(that.HttpClient), http.StatusCreated)
}
func (that *DevApiV1) RemoveBundleID(bundleIDId string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds/" + bundleIDId
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodDelete)
	return request.Request(that.HttpClient)
	//_, e := ParseJsonResponseV1[map[string]any](request.Request(that.HttpClient), http.StatusNoContent)
	//return e
}
func (that *DevApiV1) UpdateBundleIDDes(bean *BundleIDBean) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds/" + bean.Id
	params := `{"data":{"type":"bundleIds","id":"%s","attributes":{"identifier":"%s","permissions":{"edit":true,"delete":true},"seedId":"%s","name":"%s","wildcard":%v,"teamId":"%s"},"relationships":{"bundleIdCapabilities":{"data":[]}}}}`
	params = fmt.Sprintf(params, bean.Id, bean.Attributes.Identifier, that.TeamId, bean.Attributes.Name, bean.Attributes.Wildcard, that.TeamId)
	request := httpz.NewHttpRequestBuilder(http.MethodPatch, urlStr).AddHeaders(that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(params).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[BundleIDBean](request.Request(that.HttpClient), http.StatusOK)
}
func (that *DevApiV1) GetBundleCapabilities(bundleIdID string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "capabilities?filter[capabilityType]=capability,service"
	requestParams := `{"urlEncodedQueryParams":"limit=1000&sort=name&filter[bundleId]=%s&filter[platform]=IOS,MACOS,UNIVERSAL","teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, bundleIdID, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
	//b, e := ParseJsonResponseV1[[]CapabilityBean](request.Request(that.HttpClient), http.StatusOK)
	//return *b, e
}
func (that *DevApiV1) UpdateBundleCapabilities(bean BundleIDBean, capacityId string, enable bool) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds/" + bean.Id
	param := `{"data":{"attributes":{"identifier":"%s","seedId":"%s","teamId":"%s","name":"%s"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","attributes":{"enabled":%v,"settings":[]},"relationships":{"capability":{"data":{"type":"capabilities","id":"%s"}}}}]}},"type":"bundleIds"}}`
	param = fmt.Sprintf(param, bean.Attributes.Identifier, bean.Attributes.SeedId, that.TeamId, bean.Attributes.Name, enable, capacityId)
	request := httpz.NewHttpRequestBuilder(http.MethodPatch, urlStr).AddHeaders(that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(param).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[BundleIDBean](request.Request(that.HttpClient), http.StatusOK)
}

func (that *DevApiV1) ListBundleIDByCertType(certTypeId string, platform string) *httpz.HttpResponse {
	return that.ListBundleID()
	/*	if that.IsXCodeAPI() {
			var result []map[string]any
			bundles, e := that.ListBundleID()
			if e != nil {
				return nil, e
			}
			for _, bean := range *bundles {
				if bean.Attributes.Platform == platform {
					bb := map[string]any{"displayId": bean.Id, "identifier": bean.Attributes.Identifier, "prefix": bean.Attributes.SeedId}
					result = append(result, bb)
				}
			}
			return &result, nil
		} else {
			urlStr := "https://developer.apple.com/services-account/QH65B2/account/%s/identifiers/listAvailableIdentifiersByCertType?pageSize=500&pageNumber=1&certificateTypeDisplayId=%s&teamId=%s"
			requestParams := ``
			urlStr = fmt.Sprintf(urlStr, platform, certTypeId, that.TeamId)
			request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_Form_URL).
				AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).Accept(httpz.AcceptType_JSON) //.SetHeader("X-HTTP-Method-Override", http.MethodGet)
			return request.Request(that.HttpClient)
			//return ParseJsonQH65B2[[]map[string]any](request.Request(that.HttpClient), "identifierList", http.StatusOK)
		}*/
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------
/*
*
type设置空的时候则获取全部profile  PROFILE_TYPE_IOS_APP_DEVELOPMENT 之类的类型
*/
func (that *DevApiV1) ListProfile(profileType string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "profiles"
	fields := "&fields[profiles]=-profileContent"
	filter := ""
	if profileType != "" {
		filter = "&filter[profileType]=" + profileType + "&"
	}
	requestParams := `{"urlEncodedQueryParams":"%sinclude=bundleId&limit=1000&sort=name%s","teamId":"%s","includeInactiveProfiles":"true"}`
	requestParams = fmt.Sprintf(requestParams, filter, fields, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).SetHeader("X-HTTP-Method-Override", http.MethodGet).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//v, e := ParseV1ListProfileResponse(request.Request(that.HttpClient), http.StatusOK)
	//return v, e
}

// ddd, e := client.GetProfile("2RA8BUG9LN")
func (that *DevApiV1) GetProfile(profileId string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "profiles/" + profileId + "?include=bundleId,certificates,bundleId.bundleIdCapabilities,bundleId.bundleIdCapabilities.macBundleId"
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[ProfileBean](request.Request(that.HttpClient), http.StatusOK)
}

func (that *DevApiV1) AddProfile(name string, profileType string, bundleIDid string, certIDs []string, deviceIDs []string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "profiles"
	requestParams := `{"data":{"type":"profiles","attributes":{"name":"%s","profileType":"%s","teamId":"%s"},
"relationships":{"bundleId":{"data":{"type":"bundleIds","id":"%s"}},"certificates":{"data":[%s]},"devices":{"data":[%s]}}}}`

	var certBuffer strings.Builder
	for _, id := range certIDs {
		certBuffer.WriteString(fmt.Sprintf(`{"type":"certificates","id":"%s"},`, id))
	}
	certIdString := strings.TrimRight(certBuffer.String(), ",")

	var devicesBuffer strings.Builder
	for _, id := range deviceIDs {
		devicesBuffer.WriteString(fmt.Sprintf(`{"type":"devices","id":"%s"},`, id))
	}
	devicesString := strings.TrimRight(devicesBuffer.String(), ",")

	requestParams = fmt.Sprintf(requestParams, name, profileType, that.TeamId, bundleIDid, certIdString, devicesString)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[ProfileBean](request.Request(that.HttpClient), http.StatusCreated)
}
func (that *DevApiV1) RemoveProfile(profileId string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "profiles/" + profileId
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodDelete)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[ProfileBean](request.Request(that.HttpClient), http.StatusNoContent)
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------

func (that *DevApiV1) ListCertifications(certificationType string) *httpz.HttpResponse {
	//fields := "&fields[certificates]=serialNumber,csrContent,certificateContent,name,certificateTypeId,certificateTypeName,displayName,platform,expirationDate,requesterFirstName,requesterLastName,requesterEmail,status,activated,ownerId,askKey,businessAccountIdentifier,~permissions.download,~permissions.revoke,~permissions.approve"

	fields := "&fields[certificates]=-certificateContent"
	//fields = "&fields[certificates]=serialNumber,csrContent,certificateContent,name,certificateTypeId,certificateTypeName,displayName,platform,expirationDate,requesterFirstName,requesterLastName,requesterEmail,status,activated,ownerId,askKey,~permissions.download,~permissions.revoke,~permissions.approve"
	//fields = "&fields[certificates]=certificateType, csrContent, displayName, expirationDate, name, platform, serialNumber"
	urlStr := that.ServiceURL + "certificates"
	filter := ""
	if certificationType != "" {
		filter = "&filter[certificateType]=" + certificationType + "&"
	}
	params := `{"urlEncodedQueryParams":"%slimit=1000&sort=displayName%s","teamId":"%s"}`
	params = fmt.Sprintf(params, filter, fields, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(params).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[[]CertificationBean](request.Request(that.HttpClient), http.StatusOK)
	//return *b, e
}
func (that *DevApiV1) GetCertification(certID string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "certificates/" + certID
	//urlStr = urlStr + "?fields[certificates]=serialNumber,csrContent,certificateContent,name,certificateTypeId,certificateTypeName,displayName,platform,expirationDate,requesterFirstName,requesterLastName,requesterEmail,status,activated,ownerId,askKey,businessAccountIdentifier,~permissions.download,~permissions.revoke,~permissions.approve"
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[CertificationBean](request.Request(that.HttpClient), http.StatusOK)
}

func (that *DevApiV1) RemoveCertification(certId string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "certificates/" + certId
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodDelete)
	return request.Request(that.HttpClient)
	//_, err := ParseJsonResponseV1[map[string]any](request.Request(that.HttpClient), http.StatusNoContent)
	//return err
}

/*
返回的是证书的id值 CertRequestId
csrContent 的数据是base64编码加头尾，
certTypeName 例子如DEVELOPMENT
IOS_DEVELOPMENT IOS_DISTRIBUTION MAC_APP_DISTRIBUTION MAC_INSTALLER_DISTRIBUTION MAC_APP_DEVELOPMENT DEVELOPER_ID_KEXT DEVELOPER_ID_APPLICATION DEVELOPMENT DISTRIBUTION PASS_TYPE_ID PASS_TYPE_ID_WITH_NFC
*/
func (that *DevApiV1) AddCertification(csrContent, certTypeName string) *httpz.HttpResponse {
	//urlStr := "https://developer.apple.com/services-account/QH65B2/account/" + certTypePlatform + "/certificate/submitCertificateRequest.action"
	urlStr := that.ServiceURL + "certificates"
	requestParams := `{"data":{"type":"certificates","attributes":{"teamId":"%s","certificateType":"%s","csrContent":"%s"}}}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId, certTypeName, csrContent)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[CertificationBean](request.Request(that.HttpClient), http.StatusCreated)
	//return ParseJsonResponseV1[CertificationRequestBean](request.Request(that.HttpClient), http.StatusOK)
}

/*
返回的是证书的id值 CertRequestId
csrContent 的数据是base64编码加头尾，
certTypeName 例子如DEVELOPMENT
IOS_DEVELOPMENT IOS_DISTRIBUTION MAC_APP_DISTRIBUTION MAC_INSTALLER_DISTRIBUTION MAC_APP_DEVELOPMENT DEVELOPER_ID_KEXT DEVELOPER_ID_APPLICATION DEVELOPMENT DISTRIBUTION PASS_TYPE_ID PASS_TYPE_ID_WITH_NFC
*/
func (that *DevApiV1) AddCertificationWithAppId(csrContent, certTypeName string, appIdId string, displayName string) *httpz.HttpResponse {
	//params.with("data").with("attributes").put("certificateType", CertTypeBean.IOS_DEVELOPMENT);
	//params.with("data").with("attributes").put("csrContent", csrContent);
	//params.with("data").with("attributes").put("machineId", UUID.randomUUID().toString());
	//params.with("data").with("attributes").put("machineName", machineName);
	////        params.with("data").with("attributes").put("certificateDisplayName", machineName);
	//params.with("data").with("attributes").put("displayName", machineName);

	urlStr := that.ServiceURL + "certificates"
	requestParams := `{"data":{"type":"certificates","attributes":{"teamId":"%s","certificateType":"%s","csrContent":"%s"%s}}}`
	moreAttr := ""
	if appIdId != "" {
		moreAttr = fmt.Sprintf(`,"ownerId":"%s"`, appIdId)
	}
	if displayName != "" {
		moreAttr = moreAttr + fmt.Sprintf(`,"displayName":"%s"`, displayName)
		moreAttr = moreAttr + fmt.Sprintf(`,"machineName":"%s"`, displayName)
		moreAttr = moreAttr + fmt.Sprintf(`,"machineId":"%s"`, uuid.New().String())
		//moreAttr = moreAttr + fmt.Sprintf(`,"name":"%s"`, displayName)
		//moreAttr = moreAttr + fmt.Sprintf(`,"requesterFirstName":"%s"`, displayName)
		//moreAttr = moreAttr + fmt.Sprintf(`,"ownerName":"%s"`, displayName)
		//moreAttr = moreAttr + fmt.Sprintf(`,"certificateDisplayName":"%s"`, displayName+"cert")

	}

	requestParams = fmt.Sprintf(requestParams, that.TeamId, certTypeName, csrContent, moreAttr)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[CertificationBean](request.Request(that.HttpClient), http.StatusCreated)
	//return ParseJsonResponseV1[CertificationRequestBean](request.Request(that.HttpClient), http.StatusOK)
}
func (that *DevApiV1) AddCertificationService(csrContent, appIdId, certTypeId string, certTypeIDFieldName string) *httpz.HttpResponse {
	//urlStr := "https://developer.apple.com/services-account/QH65B2/account/" + certTypePlatform + "/certificate/submitCertificateRequest.action"

	urlStr := that.ServiceURL + "certificates"
	//DISTRIBUTION
	moreAttr := ""
	if appIdId != "" && certTypeIDFieldName != "" {
		moreAttr = fmt.Sprintf(`"specialIdentifierDisplayId":"%s","%s":"%s"`, appIdId, certTypeIDFieldName, appIdId)

		//requestParams.Set(certTypeIDFieldName, appIdId)
		//requestParams.Set("specialIdentifierDisplayId", appIdId)
	}
	requestParams := `{"data":{"type":"certificates","attributes":{"teamId":"%s","certificateType":"%","csrContent":"%s" %s}}}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId, certTypeId, csrContent, moreAttr)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
	//return ParseJsonResponseV1[CertificationBean](request.Request(that.HttpClient), http.StatusCreated)
	//return ParseJsonResponseV1[CertificationRequestBean](request.Request(that.HttpClient), http.StatusOK)
}

/*
	func AddCertEasy(that *DevApiV1, certRoot string, email string, name string, password string, certTypeName string, saveAu bool, appidid string) (string, *errorz.StatusError) {
		tempDir := fmt.Sprintf("%s/%d", certRoot, time.Now().Unix())
		if certTypeName == "APPLE_PAY" { //required ecc
			e1 := util.CreateCertRequestEcc(tempDir, email, name)
			if e1 != nil {
				return "", errorz.NewInternalError(e1.Error())
			}
		} else { //APPLE_PAY_RSA or other cert
			e1 := util.CreateCertRequest(tempDir, email, name)
			if e1 != nil {
				return "", errorz.NewInternalError(e1.Error())
			}
		}

		csr, _ := os.ReadFile(path.Join(tempDir, "csr.pem"))
		csrStr := strings.Replace(string(csr), "\n", "\\n", -1)
		response, e2 := that.AddCertificationWithAppId(string(csrStr), certTypeName, appidid, name)
		if e2 != nil {
			ee := os.RemoveAll(tempDir)
			if ee != nil {
				log.Infof("remove fail %s", ee.Error())
			}
			return "", e2
		}
		tempDir2 := fmt.Sprintf("%s/%s", certRoot, response.Id)
		os.Rename(tempDir, tempDir2)
		tempDir = tempDir2
		util.WriteAppleCertContentToFile(response.Attributes.CertificateContent, path.Join(tempDir, "cert.pem"))
		_, e4 := util.WriteP12File(path.Join(tempDir, "pri.pem"), path.Join(tempDir, "cert.pem"), path.Join(tempDir, "cert.p12"), password)
		if e4 != nil {
			return "", errorz.NewInternalError(e4.Error())
		}
		p12Data, e := os.ReadFile(path.Join(tempDir, "cert.p12"))
		if e != nil {
			return "", errorz.NewInternalError(e.Error())
		}
		if saveAu {
			appuploaderapi.NewClient().UploadCert(email, response.Id, response.Attributes.ExpirationDate, p12Data)
		}
		return path.Join(tempDir, "cert.p12"), nil
	}
*/
type BundleIDBean struct {
	Type          string               `json:"type"`
	Id            string               `json:"id"`
	Attributes    ListBundleAttributes `json:"attributes"`
	Relationships struct {
		BundleIdCapabilities struct {
			Meta struct {
				Paging struct {
					Total int `json:"total"`
					Limit int `json:"limit"`
				} `json:"paging"`
			} `json:"meta"`
			Links struct {
				Self    string `json:"self"`
				Related string `json:"related"`
			} `json:"links"`
		} `json:"bundleIdCapabilities"`
		Profiles struct {
			Meta struct {
				Paging struct {
					Total int `json:"total"`
					Limit int `json:"limit"`
				} `json:"paging"`
			} `json:"meta"`
			Links struct {
				Self    string `json:"self"`
				Related string `json:"related"`
			} `json:"links"`
		} `json:"profiles"`
	} `json:"relationships"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}
type ListBundleAttributes struct {
	Identifier                        string      `json:"identifier"`
	DateModified                      time.Time   `json:"dateModified"`
	EntitlementGroupName              interface{} `json:"entitlementGroupName"`
	BundleType                        string      `json:"bundleType"`
	Platform                          string      `json:"platform"`
	Wildcard                          bool        `json:"wildcard"`
	DateCreated                       time.Time   `json:"dateCreated"`
	BundleIdCapabilitiesSettingOption interface{} `json:"bundleIdCapabilitiesSettingOption"`
	SeedId                            string      `json:"seedId"`
	Name                              string      `json:"name"`
	PlatformName                      string      `json:"platformName"`
	DeploymentDataNotice              interface{} `json:"deploymentDataNotice"`
	ResponseId                        string      `json:"responseId"`
}

func xcodeApiV1Header(gstoken string, adsid string, sessionId string) map[string]string {
	header := map[string]string{
		"User-Agent":       httpz.UserAgent_XCode_Simple,
		"Accept":           "application/vnd.api+json, application/json, text/plain, */*",
		"X-Requested-With": "XMLHttpRequest",
		"Content-Type":     httpz.ContentType_VND_JSON,
		"X-Apple-App-Info": "com.apple.gs.xcode.auth",
		"X-Xcode-Version":  "14.2 (14C18)",
	}
	header["X-Apple-I-Identity-Id"] = adsid
	header["X-Apple-GS-Token"] = gstoken
	if sessionId != "" {
		header["DSESSIONID"] = sessionId
	}
	return header
}
