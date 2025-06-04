package fastlang

import "gitee.com/kxapp/kxapp-common/httpz"

func NewDevApiV1(userName string) *ItcApiV3 {
	var itcHeader = map[string]string{
		"User-Agent":       httpz.UserAgent_GoogleChrome,
		"Accept":           "application/vnd.api+json, application/json, text/plain, */*",
		"X-Requested-With": "XMLHttpRequest",
		"X-Csrf-Itc":       "itc",
	}
	api := &ItcApiV3{
		HttpClient:      NewHttpClientWithJar(userName),
		userName:        userName,
		JsonHttpHeaders: itcHeader,
		ServiceURL:      "https://developer.apple.com/services-account/v1/",
	}
	return api
}
func (that *ItcApiV3) GetItcTeams() *httpz.HttpResponse {
	requestParams := `{"includeInMigrationTeams":1}`
	request := httpz.Post("https://developer.apple.com/services-account/QH65B2/account/getTeams", that.JsonHttpHeaders).ContentType(httpz.ContentType_JSON).
		AddBody(requestParams).Request(that.HttpClient)
	return request
}
