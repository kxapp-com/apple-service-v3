package fastapple

import (
	"gitee.com/kxapp/kxapp-common/httpz"
	"net/http"
)

type DevApiV1 struct {
	httpClient *http.Client
	userName   string
	//cookies    string
}

func NewDevApiV1(userName string) *DevApiV1 {
	//jar, _ := cookiejar.New(nil)
	//hClient := httpz.NewHttpClient(jar)
	hClient := NewHttpClientWithJar(userName)
	api := &DevApiV1{
		httpClient: hClient,
		userName:   userName,
	}
	//t, e := storage.Read[map[string]string](userName, storage.TokenTypeItc)
	//if e == nil {
	//	api.cookies = util.MapToCookieHeader(*t)
	//}
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
	//if c.cookies != "" {
	//	itcHeader["Cookie"] = c.cookies
	//}
	return itcHeader
}
