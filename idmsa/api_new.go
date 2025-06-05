package idmsa

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"gitee.com/kxapp/kxapp-common/httpz"
	"gitee.com/kxapp/kxapp-common/httpz/cookiejar"
	"github.com/appuploader/apple-service-v3/base"
	"github.com/appuploader/apple-service-v3/storage"
)

// DevClient 实现了 AppleClient 接口
type DevClient struct {
	httpClient *http.Client
	userName   string
}

func NewDevClient(userName string) *DevClient {
	userName = strings.ToLower(userName)
	return &DevClient{userName: userName, httpClient: newHttpClientWithJar(userName)}
}

func (c *DevClient) GetUserName() string {
	return c.userName
}
func (c *DevClient) IsSessionAlive() bool {
	response, err := c.httpClient.Get(fmt.Sprintf("%s/v1/profile", BaseURLItc))
	if err != nil || response.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false
	}
	return !strings.Contains(string(body), "session has expired")
}

func (c *DevClient) GetTeams() *httpz.HttpResponse {
	var itcHeader = map[string]string{
		"User-Agent":       httpz.UserAgent_GoogleChrome,
		"Accept":           "application/vnd.api+json, application/json, text/plain, */*",
		"X-Requested-With": "XMLHttpRequest",
		"X-Csrf-Itc":       "itc",
	}
	requestParams := `{"includeInMigrationTeams":1}`
	request := httpz.Post("https://developer.apple.com/services-account/QH65B2/account/getTeams", itcHeader).ContentType(httpz.ContentType_JSON).
		AddBody(requestParams).Request(c.httpClient)
	return request
}

func (c *DevClient) GetApiV3() *base.ItcApiV3 {
	var itcHeader = map[string]string{
		"User-Agent":       httpz.UserAgent_GoogleChrome,
		"Accept":           "application/vnd.api+json, application/json, text/plain, */*",
		"X-Requested-With": "XMLHttpRequest",
		"X-Csrf-Itc":       "itc",
	}
	api := &base.ItcApiV3{
		HttpClient:      c.httpClient,
		JsonHttpHeaders: itcHeader,
		ServiceURL:      "https://developer.apple.com/services-account/v1/",
		IsXcode:         false,
	}
	return api
}

func newHttpClientWithJar(userName string) *http.Client {
	userName = strings.ToLower(userName)
	cookies, err := storage.ReadFile(storage.TokenPath(userName, storage.TokenTypeItc))
	if err == nil && len(cookies) > 0 {
		jar := cookiejar.NewJarFromJSON(cookies)
		return httpz.NewHttpClient(jar)
	}
	jar, _ := cookiejar.New(nil)
	return httpz.NewHttpClient(jar)
}
