package gsa

import (
	"encoding/json"
	"errors"
	"github.com/appuploader/apple-service-v3/appuploader"
	"github.com/appuploader/apple-service-v3/xcode/gsa/gsasrp"
	"regexp"
)

const RINFO_MUSIC = "84215040"
const RINFO_JAVA = "17106176"

func GetAnisseteFromAu(email string) (*gsasrp.AnisseteData, error) {
	appuploader := appuploader.NewClient()
	//appuploader.ApiUrlList = []string{"http://appuploader.net/appuploadapi2.php"}
	js, e := appuploader.GetProvision(email, true)
	if e != nil {
		//log.Error(fmt.Sprintf("load base data fail %s", e))
		return nil, e
	}
	var loginData gsasrp.AnisseteData
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
func ReadErrorMessage(body []byte) string {
	messageReg := regexp.MustCompile(`"message"\s*:\s*"([^"]+)"`)
	matches := messageReg.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		return matches[1]
	}
	titleReg := regexp.MustCompile(`"title"\s*:\s*"([^"]+)"`)
	matches = titleReg.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		return matches[1]
	}
	return string(body)
}
