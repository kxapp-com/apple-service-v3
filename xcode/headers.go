package xcode

import "gitee.com/kxapp/kxapp-common/httpz"

/*
*
xcode 二次校验的时候使用的头
*/
func xcodeStep2Header() map[string]string {
	return map[string]string{
		"Content-Type":     httpz.ContentType_JSON,
		"X-Requested-With": "XMLHttpRequest",
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		//"Accept-Language":  "en-US,en;q=0.9",
		"Accept-Language": "zh-cn",
		"User-Agent":      httpz.UserAgent_XCode,
		//"X-MMe-Client-Info": "<iMacPro1,1> <macOS;12.5;21G72> <com.apple.AuthKit/1 (com.apple.dt.Xcode/20504)>",
		"X-MMe-Client-Info": "<iMac20,2> <Mac OS X;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
		//"X-MMe-Client-Info": "<iMac20,2> <Mac OS X;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/21534)>",
		"X-Apple-App-Info": "com.apple.gs.xcode.auth",
		"X-Xcode-Version":  "14.2 (14C18)",
		//"X-Xcode-Version":   "12.4 (12D4e)",
	}
}

/*
*
请求xcode服务器，如viewdeveloper使用的头
*/
func xcodeServiceHeader(gstoken string, adsid string) map[string]string {
	headers := make(map[string]string)
	headers["Accept"] = "text/x-xml-plist"
	headers["Content-Type"] = "text/x-xml-plist"
	headers["User-Agent"] = "Xcode"
	headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
	headers["X-Xcode-Version"] = "12.4 (12D4e)"
	headers["X-Apple-GS-Token"] = gstoken
	headers["X-Apple-I-Identity-Id"] = adsid
	return headers
}
func xcodeApiV1Header(gstoken string, adsid string, sessionId string) map[string]string {
	header := map[string]string{
		"User-Agent":       httpz.UserAgent_XCode_Simple,
		"Accept":           "application/vnd.api+json, application/json, text/plain, */*",
		"X-Requested-With": "XMLHttpRequest",
		"Content-Type":     httpz.ContentType_VND_JSON,
		"X-Apple-App-Info": "com.apple.gs.xcode.auth",
		"X-Xcode-Version":  "14.2 (14C18)",
	}
	header["X-Apple-I-Identity-Id"] = adsid
	header["X-Apple-GS-Token"] = gstoken
	if sessionId != "" {
		header["DSESSIONID"] = sessionId
	}
	return header
}
