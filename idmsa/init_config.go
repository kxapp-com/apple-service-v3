package idmsa

/*
*

	{
	    "direct": {
	        "signInRequestUrl": "https%3A%2F%2Fidmsa.apple.com%2Fsignin%3Flanguage%3DUS-EN%26rv%3D1%26path%3D%252Faccount%252F%26appIdKey%3D891bd3417a7776362562d2197f89480a8547b108fd934911bcbea0110d07f757",
	        "showGlobalFooter": true,
	        "createLinkText": "",
	        "writeAlternateCookieForOAuth": "false",
	        "signInVersion": "1",
	        "appReturnUrl": "https%3A%2F%2Fdeveloper.apple.com%2Faccount%2F",
	        "locale": "US-EN",
	        "authWidgetConfig": {
	            "authWidgetURL": "https://idmsa.apple.com/appleauth",
	            "widgetKey": "92f19b477c5c9be6ab17f3ec2b1b2b7db4d00a9a8c973e3d6c90dac08b91de71",
	            "authServiceUrl": "https://appleid.cdn-apple.com/appleauth/static/jsapi/authService.latest.min.js",
	            "widgetBackgroundColor": {
	                "defaultBackgroundColorForOAuthStandardLogin": "FFFFFF",
	                "defaultBackgroundColorForStandardLogin": "FFFFFF"
	            },
	            "skVersion": "7",
	            "oauthlogoUrlDomains": [
	                "https://is5-ssl.mzstatic.com",
	                "https://is2-ssl.mzstatic.com",
	                "https://is1-ssl.mzstatic.com"
	            ]
	        },
	        "appId": 632,
	        "appNameString": " ",
	        "dawAppData": "{\"appId\":632,\"appCustomAttributes\":{\"showAppleIDLogo\":false,\"widgetMode\":\"inline\",\"showRememberMe\":true,\"enableKeepMeSignedIn\":false,\"showCreateLink\":true,\"logoWidth\":\"auto\",\"showGlobalNav\":false,\"showGlobalFooter\":true,\"hideContrySelector\":true,\"openAppleIDLinksInNewWindow\":true,\"prePopulateAppleId\":false,\"myAccessCreateLink\":false,\"disableiForgotReturnUrl\":false,\"rememberMeChecked\":false,\"enableEyebrowTextbox\":true,\"showIForgotLink\":true,\"autoThemeAdjust\":false,\"autoFillAccountName\":true}}",
	        "hostUrl": "https://idmsa.apple.com",
	        "authUIMode": "window",
	        "signInString": "Sign in to Apple Developer",
	        "app": {
	            "appIdKey": "891bd3417a7776362562d2197f89480a8547b108fd934911bcbea0110d07f757",
	            "returnUrlVersion": "1",
	            "subPath": "/account/",
	            "language": "US-EN",
	            "accNameLocked": false,
	            "refererURL": "https://account.apple.com/",
	            "requestUri": "/signin",
	            "backgroundColor": "FFFFFF",
	            "authResponseType": "COOKIE",
	            "accountInd": 0,
	            "oauthRequest": false
	        },
	        "signInStringDescription": "",
	        "signInDetailedDescription": "",
	        "iframeId": "daw-4a8ee76f-e5d7-4641-b384-97cc6af5c05a"
	    }
	}
*/
type AppConfig struct {
	Direct struct {
		SignInRequestUrl             string `json:"signInRequestUrl"`
		ShowGlobalFooter             bool   `json:"showGlobalFooter"`
		CreateLinkText               string `json:"createLinkText"`
		WriteAlternateCookieForOAuth string `json:"writeAlternateCookieForOAuth"`
		SignInVersion                string `json:"signInVersion"`
		AppReturnUrl                 string `json:"appReturnUrl"`
		Locale                       string `json:"locale"`
		AuthWidgetConfig             struct {
			AuthWidgetURL         string `json:"authWidgetURL"`
			WidgetKey             string `json:"widgetKey"`
			AuthServiceUrl        string `json:"authServiceUrl"`
			WidgetBackgroundColor struct {
				DefaultBackgroundColorForOAuthStandardLogin string `json:"defaultBackgroundColorForOAuthStandardLogin"`
				DefaultBackgroundColorForStandardLogin      string `json:"defaultBackgroundColorForStandardLogin"`
			} `json:"widgetBackgroundColor"`
			SkVersion           string   `json:"skVersion"`
			OauthlogoUrlDomains []string `json:"oauthlogoUrlDomains"`
		} `json:"authWidgetConfig"`
		AppId         int    `json:"appId"`
		AppNameString string `json:"appNameString"`
		DawAppData    string `json:"dawAppData"`
		HostUrl       string `json:"hostUrl"`
		AuthUIMode    string `json:"authUIMode"`
		SignInString  string `json:"signInString"`
		App           struct {
			AppIdKey         string `json:"appIdKey"`
			ReturnUrlVersion string `json:"returnUrlVersion"`
			SubPath          string `json:"subPath"`
			Language         string `json:"language"`
			AccNameLocked    bool   `json:"accNameLocked"`
			RefererURL       string `json:"refererURL"`
			RequestUri       string `json:"requestUri"`
			BackgroundColor  string `json:"backgroundColor"`
			AuthResponseType string `json:"authResponseType"`
			AccountInd       int    `json:"accountInd"`
			OauthRequest     bool   `json:"oauthRequest"`
		} `json:"app"`
		SignInStringDescription   string `json:"signInStringDescription"`
		SignInDetailedDescription string `json:"signInDetailedDescription"`
		IframeId                  string `json:"iframeId"`
	} `json:"direct"`
}
