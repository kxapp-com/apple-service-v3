package appuploader

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"gitee.com/kxapp/kxapp-common/cryptoz"
	"gitee.com/kxapp/kxapp-common/httpz"
	//"github.com/kxapp-com/apple-service/pkg/i18nz"
	"net/url"

	//"io"
	"net/http"
	//"net/url"
	"runtime"
	"time"
)

//const APPUPLOADER_CLIENT_VERSION = 20230206

type AppuploaderClient struct {
	httpClient *http.Client
	//ApiUrl     string //服务器地址
	//ApiUrl2    string //备用接口服务器地址
	ApiUrlList    []string
	lang          string
	ClientVersion int
}

func NewClient() *AppuploaderClient {
	var client = &http.Client{Timeout: time.Second * 30}
	lang := "en-US"
	//if !i18nz.LocaleName.IsRoot() {
	//	lang = i18nz.LocaleName.String()
	//} else {
	//	tag, ee := locale.Detect()
	//	if ee == nil {
	//		lang = tag.String()
	//	}
	//}
	return &AppuploaderClient{
		httpClient:    client,
		ApiUrlList:    []string{"https://api.applicationloader.net/appuploadapi2.php", "https://api.appuploader.net/appuploadapi2.php"},
		lang:          lang,
		ClientVersion: 20230206,
	}
}
func (client AppuploaderClient) GetVersionInfo() (any, error) {
	var params = map[string]any{"cv": client.ClientVersion, "sys": runtime.GOOS}
	body, e := client.CallService("versionInfo", params)
	if e != nil {
		return body, e
	}
	if bd, ok := body.(map[string]any); ok {
		bd["currentVersion"] = client.ClientVersion
		body = bd
	}
	return body, e
}
func (client AppuploaderClient) GetProvision(email string, renew bool) (string, error) {
	var params = map[string]any{"email": email, "renew": fmt.Sprintf("%v", renew)}
	str, e := client.CallService("getProvision", params)
	if e != nil {
		return "", e
	}
	if re, ok := str.(string); ok {
		return re, nil
	} else {
		v, _ := json.Marshal(str)
		return "", errors.New(string(v))
	}
	//return str.(string), e
}
func (client AppuploaderClient) GetActiveInfomation(email string) (any, error) {
	var params = map[string]any{"email": email, "cv": client.ClientVersion, "sys": runtime.GOOS, "mac": httpz.GetMacAddress()}
	body, e := client.CallService("loadAccount", params)
	if e != nil {
		return body, e
	}
	if b, ok := body.(map[string]any); ok {
		if t, ok := b["join_time"].(float64); ok {
			b["join_time"] = float64(t / 1000)
		}
	}
	return body, e
}

func (client AppuploaderClient) ActivateApp(email string, code string) (any, error) {
	var params = map[string]any{"email": email, "code": code, "cv": client.ClientVersion, "sys": runtime.GOOS, "mac": httpz.GetMacAddress()}
	body, e := client.CallService("activateApp", params)
	if e != nil {
		return body, e
	}
	if b, ok := body.(map[string]any); ok {
		if t, ok := b["join_time"].(float64); ok {
			b["join_time"] = float64(t / 1000)
		}
	}
	return body, e
}

/*
*
把p12存储到服务器上，因为没存密码，就算有人得到p12也无法使用，所以数据是安全的
*/
func (client AppuploaderClient) UploadCert(email string, certId string, expireTime time.Time, p12Bytes []byte) (any, error) {
	var params = map[string]any{"email": email, "cert_id": certId, "expire": expireTime.Unix(), "cert": base64.StdEncoding.EncodeToString(p12Bytes)}
	return client.CallService("uploadCert", params)
}

/*
获取p12的二进制数据
*/
func (client AppuploaderClient) DownloadCert(email string, certId string) ([]byte, error) {
	var params = map[string]any{"email": email, "cert_id": certId}
	result, e := client.CallService("downloadCert", params)
	if e != nil {
		return nil, e
	}
	if obj, ok := result.(map[string]any); ok {
		p12str := obj["cert"].(string)
		p12, e2 := base64.StdEncoding.DecodeString(p12str)
		if e2 != nil {
			return nil, e2
		}
		return p12, e2
	}
	return nil, e
}

/*
*
同步证书id，把无用的id清理掉
*/
func (client AppuploaderClient) SynchronizeCert(email string, certIds []string) (any, error) {
	var params = map[string]any{"email": email, "cert_ids": certIds}
	return client.CallService("synchronizeCert", params)
}
func (client AppuploaderClient) CallService(funcName string, params map[string]any) (any, error) {
	params["lang"] = client.lang
	params["cv"] = client.ClientVersion
	return CallAuApiService(client.ApiUrlList, funcName, params, "text/plain, */*", "application/json,")
}

/*
*
urls包括多个接口服务器地址，循环请求，直到有一个成功
返回的结果如果不是json，则返回解码错误的信息,如果是json，但是json内status不是0，则返回json内的错误提示作为error的消息
否则返回json的data字段作为any
*/
func CallAuApiService(urls []string, funcName string, params map[string]any, encodePassword string, decodePassword string) (any, error) {
	params["tm"] = time.Now().UnixMilli()
	jsonBytes, e1 := json.Marshal(params)
	if e1 != nil {
		return nil, e1
	}
	//fmt.Printf("request data %v \n", string(jsonBytes))
	basedParams := cryptoz.EncryptAndEncode(jsonBytes, encodePassword)
	formdata := make(url.Values)
	formdata["func"] = []string{funcName}
	formdata["data"] = []string{basedParams}

	httpClient := httpz.NewHttpClient(nil)
	var resp2 *httpz.HttpResponse
	for _, ur := range urls {

		resp2 = httpz.NewHttpRequestBuilder(http.MethodPost, ur).ContentType("application/x-www-form-urlencoded").AddBody(formdata).Request(httpClient)
		if !resp2.HasError() {
			break
		}
	}
	if resp2.HasError() {
		return nil, resp2.Error
	}
	responseData := resp2.Body

	/*
		httpClient := http.DefaultClient
		var resp *http.Response
		var e3 error
		for _, ur := range urls {
			resp, e3 = httpClient.PostForm(ur, formdata)
			if resp != nil {
				defer resp.Body.Close()
			}
			if e3 == nil {
				break
			}
		}
		if e3 != nil {
			return nil, e3
		}
		responseData, e4 := io.ReadAll(resp.Body)
		if e4 != nil {
			return nil, e4
		}*/
	bodyData, e5 := cryptoz.DecodeAndDecrypt(string(responseData), decodePassword)
	if e5 != nil {
		return nil, errors.New(string(responseData))
	}
	var bodyJson = make(map[string]any)
	e := json.Unmarshal(bodyData, &bodyJson)
	if e != nil {
		return bodyData, e
	}
	if bodyJson["status"].(float64) != 0 {
		return nil, errors.New(bodyJson["data"].(string))
	} else {
		return bodyJson["data"], nil
	}
}
