package fastapple

import (
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/storage"
	"net/http"
	"strings"
)

type DevApiV1 struct {
	httpClient *http.Client
	userName   string
	token      map[string]string
}

func NewDevApiV1(userName string) *DevApiV1 {
	hClient := httpz.NewHttpClient(http.DefaultClient.Jar)
	api := &DevApiV1{
		httpClient: hClient,
		userName:   userName,
		token:      make(map[string]string),
	}
	t, e := storage.Read[map[string]string](userName, storage.TokenTypeItc)
	if e == nil {
		api.token = *t
	}
	return api
}
func (c *DevApiV1) GetItcTeams() *httpz.HttpResponse {
	requestParams := `{"includeInMigrationTeams":1}`
	request := httpz.Post("https://developer.apple.com/services-account/QH65B2/account/getTeams", c.itcTokenHeader()).ContentType(httpz.ContentType_JSON).
		AddBody(requestParams).Request(c.httpClient)
	return request
}
func (c *DevApiV1) itcTokenHeader() map[string]string {
	var itcHeader = map[string]string{
		"User-Agent":       httpz.UserAgent_GoogleChrome,
		"Accept":           "application/vnd.api+json, application/json, text/plain, */*",
		"X-Requested-With": "XMLHttpRequest",
		"X-Csrf-Itc":       "itc",
	}
	if c.token != nil {
		itcHeader["Cookie"] = mapToCookieHeader(c.token)
	}
	return itcHeader
}

func mapToCookieHeader(m map[string]string) string {
	cookie := ""
	for k, v := range m {
		cookie = cookie + k + "=" + v + "; "
	}
	return strings.TrimSpace(strings.Trim(cookie, ";"))
}
