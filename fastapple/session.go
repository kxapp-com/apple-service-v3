package fastapple

import (
	"gitee.com/kxapp/kxapp-common/httpz"
	"github.com/appuploader/apple-service-v3/storage"
	"github.com/appuploader/apple-service-v3/util"
	"net/http"
)

func IsSessionAlive(userName string) bool {
	t, e := storage.Read[map[string]string](userName, storage.TokenTypeItc)
	if e != nil || t == nil {
		return false
	}
	r := sendCheckRequest(util.MapToCookieHeader(*t))
	return !r.HasError() && r.Status == http.StatusOK
}
func sendCheckRequest(cookieString string) *httpz.HttpResponse {
	headers := map[string]string{
		"User-Agent": httpz.UserAgent_GoogleChrome,
		"Cookie":     cookieString,
	}
	return httpz.Get("https://developer.apple.com/services-account/QH65B2/v1/profile", headers).ContentType(httpz.ContentType_JSON).Request(httpz.NewHttpClient(nil))
}
