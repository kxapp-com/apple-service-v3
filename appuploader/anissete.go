package appuploader

import (
	"encoding/json"
	"errors"
	"time"
)

type AnisseteData struct {
	XAppleIMD         string    `json:"X-Apple-I-MD"`
	XAppleIMDM        string    `json:"X-Apple-I-MD-M"`
	XAppleIMDRINFO    string    `json:"X-Apple-I-MD-RINFO"` //最新mac请求的此值  84215040，老的xcode是17106176，music库返回的是50660608
	XAppleIMDLU       string    `json:"X-Apple-I-MD-LU"`
	XAppleISRLNO      string    `json:"X-Apple-I-SRL-NO"`
	XMmeClientInfo    string    `json:"X-Mme-Client-Info"`
	XAppleIClientTime time.Time `json:"X-Apple-I-Client-Time"`
	XAppleITimeZone   string    `json:"X-Apple-I-TimeZone"`
	XAppleLocale      string    `json:"X-Apple-Locale"`
	XMmeDeviceId      string    `json:"X-Mme-Device-Id"`
}

func GetAnisseteFromAu(email string) (*AnisseteData, error) {
	appuploader := NewClient()
	//appuploader.ApiUrlList = []string{"http://appuploader.net/appuploadapi2.php"}
	js, e := appuploader.GetProvision(email, true)
	if e != nil {
		//log.Error(fmt.Sprintf("load base data fail %s", e))
		return nil, e
	}
	var loginData AnisseteData
	e2 := json.Unmarshal([]byte(js), &loginData)
	if loginData.XAppleIMDM == "" {
		return &loginData, errors.New("Load login basic data fail,try again")
	}

	//loginData.XAppleIMDRINFO = RINFO_MUSIC

	//loginData.XMmeClientInfo = "<MacBookPro17,1> <macOS;12.2.1;21D62> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
	//loginData.XAppleITimeZone = "UTC"
	//loginData.XAppleIClientTime = time.Now().UTC() //.Format(util.XCode_Client_Time_Format)
	return &loginData, e2
}
