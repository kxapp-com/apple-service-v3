package fastapple

import (
	"gitee.com/kxapp/kxapp-common/httpz"
	"gitee.com/kxapp/kxapp-common/httpz/cookiejar"
	"github.com/appuploader/apple-service-v3/storage"
	"io"
	"net/http"
	"strings"
)

func IsSessionAlive(userName string) bool {
	r, e := NewHttpClientWithJar(userName).Get("https://developer.apple.com/services-account/QH65B2/v1/profile")
	if e == nil && r.StatusCode == http.StatusOK {
		v, e2 := io.ReadAll(r.Body)
		if e2 != nil {
			return false
		}
		ss := string(v)
		if strings.Contains(ss, "session has expired") {
			return false
		}
		return true
	}
	return false
}
func NewHttpClientWithJar(username string) *http.Client {
	username = strings.ToLower(username)                                              //srp挑战的时候发现其js代码里面有tolowcase
	cookies, e := storage.ReadFile(storage.TokenPath(username, storage.TokenTypeItc)) //读取token文件，判断是否存在
	if e == nil && len(cookies) > 0 {
		jar := cookiejar.NewJarFromJSON(cookies)
		hClient := httpz.NewHttpClient(jar)
		return hClient
	} else {
		jar, _ := cookiejar.New(nil)
		hClient := httpz.NewHttpClient(jar)
		return hClient
	}
}
