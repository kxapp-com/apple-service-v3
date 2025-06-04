package xcode

import "gitee.com/kxapp/kxapp-common/httpz"

func NewDevApiV1(client *Client) *XcodeApiV3 {
	header := map[string]string{
		"User-Agent":       httpz.UserAgent_XCode_Simple,
		"Accept":           "application/vnd.api+json, application/json, text/plain, */*",
		"X-Requested-With": "XMLHttpRequest",
		"Content-Type":     httpz.ContentType_VND_JSON,
		"X-Apple-App-Info": "com.apple.gs.xcode.auth",
		"X-Xcode-Version":  "14.2 (14C18)",
	}
	header["X-Apple-I-Identity-Id"] = client.Token.Adsid
	header["X-Apple-GS-Token"] = client.Token.XAppleGSToken
	if client.xcodeSessionID != "" {
		header["DSESSIONID"] = client.xcodeSessionID
	}

	//headers := xcodeApiV1Header(client.Token.XAppleGSToken, client.Token.Adsid, client.xcodeSessionID)
	header = AddAnisseteHeaders(client.anisseteData, header)
	return &XcodeApiV3{
		HttpClient:      client.httpClient,
		ServiceURL:      "https://developerservices2.apple.com/services/v1/",
		JsonHttpHeaders: header,
	}
}
