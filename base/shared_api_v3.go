package base

import (
	"encoding/json"
	"fmt"
	"gitee.com/kxapp/kxapp-common/errorz"
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/google/uuid"
	"github.com/kxapp-com/apple-service-v3/appuploader"
	"github.com/kxapp-com/apple-service-v3/model"
	"github.com/kxapp-com/apple-service-v3/util"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

type ItcApiV3 struct {
	HttpClient      *http.Client
	JsonHttpHeaders map[string]string
	TeamId          string
	//https://developerservices2.apple.com/services/v1/
	//https://developer.apple.com/services-account/v1/
	ServiceURL string
	IsXcode    bool
}

// BeforeReturnAction handles response headers and session timeout
func (that *ItcApiV3) BeforeReturnAction(response *http.Response) {
	if !that.IsXcode {
		if response == nil || response.Header == nil {
			return
		}
		csrf := response.Header.Get("csrf")
		csrf_ts := response.Header.Get("csrf_ts")
		if csrf != "" {
			that.JsonHttpHeaders["csrf"] = csrf
		}
		if csrf_ts != "" {
			that.JsonHttpHeaders["csrf_ts"] = csrf_ts
		}
	}
}
func (that *ItcApiV3) ListBundleIDByCertType(certTypeId string, platform string) *httpz.HttpResponse {
	if that.IsXcode {
		return that.ListBundleID()
	} else {
		urlStr := "https://developer.apple.com/services-account/QH65B2/account/%s/identifiers/listAvailableIdentifiersByCertType?pageSize=500&pageNumber=1&certificateTypeDisplayId=%s&teamId=%s"
		requestParams := ``
		urlStr = fmt.Sprintf(urlStr, platform, certTypeId, that.TeamId)
		request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_Form_URL).
			AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).Accept(httpz.AcceptType_JSON) //.SetHeader("X-HTTP-Method-Override", http.MethodGet)
		return request.Request(that.HttpClient)
	}
}

// ListDevices retrieves a list of registered devices
func (that *ItcApiV3) ListDevices() *httpz.HttpResponse {
	urlStr := that.ServiceURL + "devices"
	requestParams := fmt.Sprintf(`{"urlEncodedQueryParams":"limit=1000&sort=name&filter[AND][deviceClass]=APPLE_WATCH,IPAD,IPHONE,IPOD,APPLE_SILICON_MAC","teamId":"%s"}`, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).SetHeader("X-HTTP-Method-Override", http.MethodGet).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
}

// AddDevicesValidate validates a device before adding
func (that *ItcApiV3) AddDevicesValidate(udid string, deviceName string) *httpz.HttpResponse {
	return that.addAndValidateDevice(udid, deviceName, that.ServiceURL+"devices")
}

// AddDevices adds a new device
func (that *ItcApiV3) AddDevices(udid string, deviceName string) *httpz.HttpResponse {
	return that.addAndValidateDevice(udid, deviceName, that.ServiceURL+"devices")
}

// addAndValidateDevice handles device addition and validation
func (that *ItcApiV3) addAndValidateDevice(udid string, deviceName string, urlStr string) *httpz.HttpResponse {
	requestParamJS := fmt.Sprintf(`{"data":{"type":"devices","attributes":{"teamId":"%s","name":"%s","udid":"%s","platform":"%s"}}}`,
		that.TeamId, deviceName, udid, "IOS")
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParamJS).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
}

// UpdateDeviceName updates the name of a device
func (that *ItcApiV3) UpdateDeviceName(deviceIdID string, deviceName string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "devices/" + deviceIdID
	//requestParamJS:=`{"data":{"type":"devices","attributes":{"teamId":"57W66QZCMN","name":"877028320's Mac","udid":"564D04F2-0FCD-22A6-5252-EB8DCCEE0E95","platform":"MACOS"}}}`
	requestParamJS := fmt.Sprintf(`{"data":{"type":"devices","id":"%s","attributes":{"teamId":"%s","name":"%s"}}}`,
		deviceIdID, that.TeamId, deviceName)
	request := httpz.NewHttpRequestBuilder(http.MethodPatch, urlStr).AddHeaders(that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParamJS).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
}

func (that *ItcApiV3) UpdateDeviceStatus(deviceIdID string, enable bool) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "devices/" + deviceIdID
	status := "DISABLED"
	if enable {
		status = "ENABLED"
	}
	requestParamJS := fmt.Sprintf(`{"data":{"type":"devices","id":"%s","attributes":{"teamId":"%s","status":"%s"}}}`,
		deviceIdID, that.TeamId, status)
	request := httpz.NewHttpRequestBuilder(http.MethodPatch, urlStr).AddHeaders(that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParamJS).BeforeReturn(that.BeforeReturnAction).Request(that.HttpClient)
	return request
}

// -------------------------------------------------------------------------------------------------------------------------------------------------------

// ListBundleID retrieves a list of bundle IDs
func (that *ItcApiV3) ListBundleID() *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds"
	requestParams := fmt.Sprintf(`{"urlEncodedQueryParams":"limit=1000&sort=name&filter[platform]=IOS,MACOS,UNIVERSAL","teamId":"%s"}`, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
}

func (that *ItcApiV3) GetBundleID(bundleIDId string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds/" + bundleIDId
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
}

func (that *ItcApiV3) AddBundleID(bundleId string, name string, enablepush bool) *httpz.HttpResponse {
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
}

func (that *ItcApiV3) RemoveBundleID(bundleIDId string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds/" + bundleIDId
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodDelete)
	return request.Request(that.HttpClient)
}

func (that *ItcApiV3) UpdateBundleIDDes(bean *model.BundleIDBean) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds/" + bean.Id
	params := `{"data":{"type":"bundleIds","id":"%s","attributes":{"identifier":"%s","permissions":{"edit":true,"delete":true},"seedId":"%s","name":"%s","wildcard":%v,"teamId":"%s"},"relationships":{"bundleIdCapabilities":{"data":[]}}}}`
	params = fmt.Sprintf(params, bean.Id, bean.Attributes.Identifier, that.TeamId, bean.Attributes.Name, bean.Attributes.Wildcard, that.TeamId)
	request := httpz.NewHttpRequestBuilder(http.MethodPatch, urlStr).AddHeaders(that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(params).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
}

func (that *ItcApiV3) GetBundleCapabilities(bundleIdID string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "capabilities?filter[capabilityType]=capability,service"
	requestParams := `{"urlEncodedQueryParams":"limit=1000&sort=name&filter[bundleId]=%s&filter[platform]=IOS,MACOS,UNIVERSAL","teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, bundleIdID, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
}

func (that *ItcApiV3) UpdateBundleCapabilities(bean model.BundleIDBean, capacityId string, enable bool) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "bundleIds/" + bean.Id
	param := `{"data":{"attributes":{"identifier":"%s","seedId":"%s","teamId":"%s","name":"%s"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","attributes":{"enabled":%v,"settings":[]},"relationships":{"capability":{"data":{"type":"capabilities","id":"%s"}}}}]}},"type":"bundleIds"}}`
	param = fmt.Sprintf(param, bean.Attributes.Identifier, bean.Attributes.SeedId, that.TeamId, bean.Attributes.Name, enable, capacityId)
	request := httpz.NewHttpRequestBuilder(http.MethodPatch, urlStr).AddHeaders(that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(param).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------
/*
*
type设置空的时候则获取全部profile  PROFILE_TYPE_IOS_APP_DEVELOPMENT 之类的类型
*/
func (that *ItcApiV3) ListProfile(profileType string) *httpz.HttpResponse {
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
}

// ddd, e := client.GetProfile("2RA8BUG9LN")
func (that *ItcApiV3) GetProfile(profileId string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "profiles/" + profileId + "?include=bundleId,certificates,bundleId.bundleIdCapabilities,bundleId.bundleIdCapabilities.macBundleId"
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
}

func (that *ItcApiV3) AddProfile(name string, profileType string, bundleIDid string, certIDs []string, deviceIDs []string) *httpz.HttpResponse {
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
}

func (that *ItcApiV3) RemoveProfile(profileId string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "profiles/" + profileId
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodDelete)
	return request.Request(that.HttpClient)
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------

func (that *ItcApiV3) ListCertifications(certificationType string) *httpz.HttpResponse {
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
}

func (that *ItcApiV3) GetCertification(certID string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "certificates/" + certID
	//urlStr = urlStr + "?fields[certificates]=serialNumber,csrContent,certificateContent,name,certificateTypeId,certificateTypeName,displayName,platform,expirationDate,requesterFirstName,requesterLastName,requesterEmail,status,activated,ownerId,askKey,businessAccountIdentifier,~permissions.download,~permissions.revoke,~permissions.approve"
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodGet)
	return request.Request(that.HttpClient)
}

func (that *ItcApiV3) RemoveCertification(certId string) *httpz.HttpResponse {
	urlStr := that.ServiceURL + "certificates/" + certId
	requestParams := `{"teamId":"%s"}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction).SetHeader("X-HTTP-Method-Override", http.MethodDelete)
	return request.Request(that.HttpClient)
}

/*
返回的是证书的id值 CertRequestId
csrContent 的数据是base64编码加头尾，
certTypeName 例子如DEVELOPMENT
IOS_DEVELOPMENT IOS_DISTRIBUTION MAC_APP_DISTRIBUTION MAC_INSTALLER_DISTRIBUTION MAC_APP_DEVELOPMENT DEVELOPER_ID_KEXT DEVELOPER_ID_APPLICATION DEVELOPMENT DISTRIBUTION PASS_TYPE_ID PASS_TYPE_ID_WITH_NFC
*/
func (that *ItcApiV3) AddCertification(csrContent, certTypeName string) *httpz.HttpResponse {
	//urlStr := "https://developer.apple.com/services-account/QH65B2/account/" + certTypePlatform + "/certificate/submitCertificateRequest.action"
	urlStr := that.ServiceURL + "certificates"
	requestParams := `{"data":{"type":"certificates","attributes":{"teamId":"%s","certificateType":"%s","csrContent":"%s"}}}`
	requestParams = fmt.Sprintf(requestParams, that.TeamId, certTypeName, csrContent)
	request := httpz.Post(urlStr, that.JsonHttpHeaders).ContentType(httpz.ContentType_VND_JSON).
		AddBody(requestParams).BeforeReturn(that.BeforeReturnAction)
	return request.Request(that.HttpClient)
}

/*
返回的是证书的id值 CertRequestId
csrContent 的数据是base64编码加头尾，
certTypeName 例子如DEVELOPMENT
IOS_DEVELOPMENT IOS_DISTRIBUTION MAC_APP_DISTRIBUTION MAC_INSTALLER_DISTRIBUTION MAC_APP_DEVELOPMENT DEVELOPER_ID_KEXT DEVELOPER_ID_APPLICATION DEVELOPMENT DISTRIBUTION PASS_TYPE_ID PASS_TYPE_ID_WITH_NFC
*/
func (that *ItcApiV3) AddCertificationWithAppId(csrContent, certTypeName string, appIdId string, displayName string) *httpz.HttpResponse {
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
}

func (that *ItcApiV3) AddCertificationService(csrContent, appIdId, certTypeId string, certTypeIDFieldName string) *httpz.HttpResponse {
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
}

// 指定证书根目录，创建证书并返回证书的具体路径
// 此接口包括了对证书的创建请求，和查询获取请求和存储证书到文件
/*
{
  "data" : {
    "type" : "certificates",
    "id" : "LPZ72GNF22",
    "attributes" : {
      "requesterEmail" : null,
      "serialNumber" : "33BB014E0E0A5B280FF0B999E164A43B",
      "certificateContent" : "MIIFxDCCBKygAwIBAgIQM7sBTg4KWygP8LmZ4WSkOzANBgkqhkiG9w0BAQsFADB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTIyMTExMDA4MDk1MloXDTIzMTExMDA4MDk1MVowgYoxGjAYBgoJkiaJk/IsZAEBDApRS1cyOTk0WU1XMTQwMgYDVQQDDCtBcHBsZSBEZXZlbG9wbWVudDogWWluZ2tlIFpob3UgKDJSQTNFQzhTUlgpMRMwEQYDVQQLDApDUzJBREQ5RjdGMRQwEgYDVQQKDAtZaW5na2UgWmhvdTELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOeO3Kht2DV78LL6cGfn/lbL9fdpnGlzxjwBVlkias2kseahABcfTtNRJnQaUZAIG+poDD0/Ue5Md8rrLp2wrPFz5U8UUozoqoERF8M9X+5A7VlbYjBRfRisiPmIXf97mGmbYZaYq1GTual0W55yQfo8Wa/sdc7+MvA6S6zznH+l1cW9icMFTndIMaKevQP7G2IbBxfeVnaSa0E/n3O/2uD6PpSWquluvLYFbp9QnVQ+QCOzlA7zuHb7fZZeMY/IPcfxjEVvwhD7mVWYqUDGqTbkFu13aRXGhxMej9s0eE8kIVZPfhIhQKw6nafDz8fzi8n2dAHVPFt4g9YBTOUFGBAgMBAAGjggI4MIICNDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFAn+wBWQ+a9kCpISuSYoYwyX7KeyMHAGCCsGAQUFBwEBBGQwYjAtBggrBgEFBQcwAoYhaHR0cDovL2NlcnRzLmFwcGxlLmNvbS93d2RyZzMuZGVyMDEGCCsGAQUFBzABhiVodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLXd3ZHJnMzA0MIIBHgYDVR0gBIIBFTCCAREwggENBgkqhkiG92NkBQEwgf8wgcMGCCsGAQUFBwICMIG2DIGzUmVsaWFuY2Ugb24gdGhpcyBjZXJ0aWZpY2F0ZSBieSBhbnkgcGFydHkgYXNzdW1lcyBhY2NlcHRhbmNlIG9mIHRoZSB0aGVuIGFwcGxpY2FibGUgc3RhbmRhcmQgdGVybXMgYW5kIGNvbmRpdGlvbnMgb2YgdXNlLCBjZXJ0aWZpY2F0ZSBwb2xpY3kgYW5kIGNlcnRpZmljYXRpb24gcHJhY3RpY2Ugc3RhdGVtZW50cy4wNwYIKwYBBQUHAgEWK2h0dHBzOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFNHWr/Lps26n584veHYglzMQFUPoMA4GA1UdDwEB/wQEAwIHgDATBgoqhkiG92NkBgECAQH/BAIFADATBgoqhkiG92NkBgEMAQH/BAIFADANBgkqhkiG9w0BAQsFAAOCAQEAka6gNO65q8Eb3+qgYPNbwS2inNzB6d59uqtr5YkYU4VTisfY4AJzLfFuBdyNgN4Epb5p/CAgjLK5nyj4iFoq4uAv3+kzs93kEP8uFXilWEBd0fyWhjZP03ASLhIPHmxrcHAeji3hr6FeV4ZsJwKCls6Ytcl/t8hbWOyXhtgR/vqaJ1IuHrU3J27n29tx0Q4DETmJbV+peMST3XLadnnhbEVCCW8nVT+TmpwV138AD8HTshjx34ETghEWh06CO+RNiZ0a09wORBgxi2F8BNCavSWxG6OIkPe4w23iepVpnNjbxUC1qN92A7nFJsPs+uBzqzipu5+/kiTmK/FzDpBQPg==",
      "displayName" : "Yingke Zhou",
      "requesterLastName" : null,
      "csrContent" : null,
      "machineName" : null,
      "platform" : null,
      "requesterFirstName" : null,
      "machineId" : null,
      "name" : "Apple Development: Yingke Zhou",
      "responseId" : "68bc72e3-cfc0-4fd8-8dbb-05727cbf51cb",
      "expirationDate" : "2023-11-10T08:09:51.000+00:00",
      "certificateType" : "DEVELOPMENT"
    },
    "links" : {
      "self" : "https://developerservices2.apple.com:443/services/v1/certificates/LPZ72GNF22"
    }
  },
  "links" : {
    "self" : "https://developerservices2.apple.com:443/services/v1/certificates"
  }
}
*/

func (that *ItcApiV3) AddCertEasy(certRoot string, email string, name string, password string, certTypeName string, saveAu bool, appidid string) (string, error) {
	tempDir := fmt.Sprintf("%s/%d", certRoot, time.Now().Unix())
	if certTypeName == "APPLE_PAY" { //required ecc
		e1 := util.CreateCertRequestEcc(tempDir, email, name)
		if e1 != nil {
			return "", e1
		}
	} else { //APPLE_PAY_RSA or other cert
		e1 := util.CreateCertRequest(tempDir, email, name)
		if e1 != nil {
			return "", e1
		}
	}

	csr, _ := os.ReadFile(path.Join(tempDir, "csr.pem"))
	csrStr := strings.Replace(string(csr), "\n", "\\n", -1)
	response := that.AddCertificationWithAppId(csrStr, certTypeName, appidid, name)
	if response.HasError() {
		ee := os.RemoveAll(tempDir)
		if ee != nil {
			log.Infof("remove fail %s", ee.Error())
		}
		return "", response.Error
	}

	var certResponse map[string]any
	json.Unmarshal(response.Body, &certResponse)
	var responseData = certResponse["data"].(map[string]any)
	var responseAttributes = responseData["attributes"].(map[string]any)
	var responseId = responseData["id"].(string)
	var certificateContent = responseAttributes["certificateContent"].(string)
	var expirationDate = responseAttributes["expirationDate"].(time.Time) //ExpirationDate       time.Time   `json:"expirationDate"`

	tempDir2 := fmt.Sprintf("%s/%s", certRoot, responseId)
	os.Rename(tempDir, tempDir2)
	tempDir = tempDir2
	util.WriteAppleCertContentToFile(certificateContent, path.Join(tempDir, "cert.pem"))
	_, e4 := util.WriteP12File(path.Join(tempDir, "pri.pem"), path.Join(tempDir, "cert.pem"), path.Join(tempDir, "cert.p12"), password)
	if e4 != nil {
		return "", errorz.NewInternalError(e4.Error())
	}
	p12Data, e := os.ReadFile(path.Join(tempDir, "cert.p12"))
	if e != nil {
		return "", errorz.NewInternalError(e.Error())
	}
	if saveAu {
		appuploader.NewClient().UploadCert(email, responseId, expirationDate, p12Data)
	}
	return path.Join(tempDir, "cert.p12"), nil
}
