package fastlang

import (
	"fmt"
	"gitee.com/kxapp/kxapp-common/httpz"
	"gitee.com/kxapp/kxapp-common/httpz/cookiejar"
	"github.com/appuploader/apple-service-v3/storage"
	"io"
	"net/http"
	"strings"
)

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

// IsSessionAlive checks if the current session is still valid
func IsSessionAlive(userName string) bool {
	client := NewHttpClientWithJar(userName)
	response, err := client.Get(fmt.Sprintf("%s/v1/profile", BaseURLItc))

	if err != nil || response.StatusCode != http.StatusOK {
		return false
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false
	}

	return !strings.Contains(string(body), "session has expired")
}

// NewHttpClientWithJar creates a new HTTP client with cookie jar for the given username
func NewHttpClientWithJar(username string) *http.Client {
	username = strings.ToLower(username)

	// Try to load existing cookies
	cookies, err := storage.ReadFile(storage.TokenPath(username, storage.TokenTypeItc))
	if err == nil && len(cookies) > 0 {
		jar := cookiejar.NewJarFromJSON(cookies)
		return httpz.NewHttpClient(jar)
	}

	// Create new cookie jar if no existing cookies found
	jar, _ := cookiejar.New(nil)
	return httpz.NewHttpClient(jar)
}
