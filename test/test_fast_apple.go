package main

import (
	"fmt"
	"gitee.com/kxapp/kxapp-common/errorz"
	"github.com/appuploader/apple-service-v3/fastlang"
	"github.com/appuploader/apple-service-v3/xcode"
	"time"
)

func main() {

	account := "877028320@qq.com"
	if fastlang.IsSessionAlive(account) {
		fmt.Printf("session is alive for account %s\n", account)
		onSuccess(account)
		return
	}
	client := fastlang.NewAppleAuthClient()
	r := client.Login(account, "MzdJzm38")
	//r := client.Login(xcode.AuthInfo{Email: "yanwen1688@gmail.com", Password: "MzdJzm38"})
	//r := client.Login(xcode.AuthInfo{Email: "tanghuang1989@qq.com", Password: "MzdJzm38"})
	//r := client.Login(xcode.AuthInfo{Email: "tanghuang1989@gmail.com", Password: "MzdJzm38"})
	if r.Status == xcode.ErrorCodeInvalidAccount {
		fmt.Printf("invalid account %+v", r)
		return
	} else if r.Status == xcode.ErrorCodeInvalidPassword {
		fmt.Printf("invalid password %+v", r)
		return
	}
	if r.Status == 200 || r.Status == errorz.StatusSuccess {
		onSuccess(account)
	} else if r.Status == 401 {
		fmt.Printf("login failed")
	} else if r.Status == 409 {
		fmt.Printf("fa2 required\n")
		deviceResult := client.LoadTwoStepDevices()
		if deviceResult.HasError() {
			fmt.Printf("load device failed %+v %v\n", deviceResult.Error, deviceResult.Body)
			return
		}
		tdStatus := deviceResult.Status
		fmt.Printf("load device success\n")
		fmt.Printf("%+v", deviceResult)
		var phoneId = "3"
		if tdStatus == 201 {
			fmt.Println("please input device code")
			var deviceCode string
			fmt.Scanln(&deviceCode)
			verifyResult := client.VerifyCode("sms", deviceCode, phoneId)
			fmt.Println(verifyResult)
			for {
				if verifyResult.Status == 200 || verifyResult.Status == 0 {
					break
				}
				fmt.Println("please input device code")
				fmt.Scanln(&deviceCode)
				verifyResult = client.VerifyCode("sms", deviceCode, phoneId)
				fmt.Println(verifyResult)
			}
			if verifyResult.Status == 200 {
				onSuccess(account)
			}
		} else if tdStatus == 200 {
			fmt.Println("please input device id")
			var deviceId string = "1"
			fmt.Scanln(&deviceId)
			requestCodeResult := client.RequestVerifyCode("sms", deviceId)
			if requestCodeResult.HasError() {
				fmt.Printf("request code failed %+v", requestCodeResult.Error)
				return
			}
			fmt.Printf("request code success %+v\n", requestCodeResult)
			if requestCodeResult.Status == 200 || requestCodeResult.Status == 201 {
				//fmt.Println(requestCodeResult.Body)
				fmt.Println("please input device code")
				var deviceCode string
				fmt.Scanln(&deviceCode)
				verifyResult := client.VerifyCode("sms", deviceCode, deviceId)
				fmt.Println(verifyResult)
				for {
					if verifyResult.Status == 200 || verifyResult.Status == 0 {
						break
					}
					fmt.Println("please input device code")
					fmt.Scanln(&deviceCode)
					verifyResult = client.VerifyCode("sms", deviceCode, deviceId)
					fmt.Println(verifyResult)
				}
				if verifyResult.Status == 200 {
					onSuccess(account)
				}
			} else {
				fmt.Printf("request code failed %+v", requestCodeResult)
			}

		} else {
			fmt.Printf("load device failed %+v", deviceResult)
		}
	} else {
		fmt.Printf("%+v", r)
	}
	time.Sleep(time.Minute * 5)
}
func onSuccess(account string) {
	a := fastlang.NewDevApiV1(account)
	t := a.GetItcTeams()
	fmt.Printf("get itc teams %+v %v\n", string(t.Body), t.Status)
	a.TeamId = "CS2ADD9F7F"
	dvs := a.ListDevices()

	fmt.Printf("list devices %+v %v\n", string(dvs.Body), dvs.Status)
}
