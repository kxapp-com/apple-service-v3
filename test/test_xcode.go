package main

import (
	"fmt"
	"gitee.com/kxapp/kxapp-common/errorz"
	"github.com/appuploader/apple-service-v3/xcode"
)

func main() {
	client := xcode.NewClient()
	//r := client.Login(xcode.AuthInfo{Email: "877028320@qq.com", Password: "MzdJzm38"})
	r := client.Login(xcode.AuthInfo{Email: "yanwen1688@gmail.com", Password: "MzdJzm38"})
	//r := client.Login(xcode.AuthInfo{Email: "tanghuang1989@qq.com", Password: "MzdJzm38"})
	if r.Status == xcode.ErrorCodeInvalidAccount {
		fmt.Printf("invalid account %+v", r)
		return
	} else if r.Status == xcode.ErrorCodeInvalidPassword {
		fmt.Printf("invalid password %+v", r)
		return
	}
	if r.Status == 200 || r.Status == errorz.StatusSuccess {
		t, e := client.ViewTeams()
		if e == nil {
			for _, v := range *t {
				fmt.Printf(v.Name)
			}
		} else {
			fmt.Printf(e.Error())
		}
	} else if r.Status == 401 {
		fmt.Printf("login failed")
	} else if r.Status == 409 {
		fmt.Printf("fa2 required")
		deviceResult := client.LoadTwoStepDevices()
		if deviceResult.Status == 201 {
			fmt.Printf("load device success")
			fmt.Println(deviceResult.Body)
			fmt.Println("please input device code")
			var deviceCode string
			fmt.Scanln(&deviceCode)
			verifyResult := client.VerifyCode("sms", deviceCode, "1")
			fmt.Println(verifyResult)
			if verifyResult.Status == 200 {
				vvv, e := client.ViewTeams()
				fmt.Println(vvv, e)
			}
		} else if deviceResult.Status == 200 {
			fmt.Println(deviceResult.Body)
			fmt.Println("please input device id")
			var deviceId string
			fmt.Scanln(&deviceId)
			requestCodeResult := client.RequestVerifyCode("sms", deviceId)
			if requestCodeResult.Status == 200 {
				fmt.Println(requestCodeResult.Body)
				fmt.Println("please input device code")
				var deviceCode string
				fmt.Scanln(&deviceCode)
				verifyResult := client.VerifyCode("sms", deviceCode, deviceId)
				fmt.Println(verifyResult)
				if verifyResult.Status == 200 {
					vvv, e := client.ViewTeams()
					fmt.Println(vvv, e)
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
}
