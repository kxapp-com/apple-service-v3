package main

import (
	"fmt"
	"gitee.com/kxapp/kxapp-common/errorz"
	"gitee.com/kxapp/kxapp-common/httpz"
	beans "github.com/kxapp-com/apple-service-v3/model"
	"github.com/kxapp-com/apple-service-v3/xcode"
	"time"
)

var account = "877028320@qq.com"

func main() {

	api := xcode.NewXcodeClient(account)
	if api.IsSessionAlive() {
		fmt.Println("session is alive")
		t := api.GetTeams()
		fmt.Println(t.Status, string(t.Body))
		return
	} else {
		fmt.Println("session is not alive, try to login")
	}
	client := xcode.NewXcodeAuthClient()
	r := client.Login(account, "MzdJzm38")
	//r := client.Login(xcode.AuthInfo{Email: "yanwen1688@gmail.com", Password: "MzdJzm38"})
	//r := client.Login(xcode.AuthInfo{Email: "tanghuang1989@qq.com", Password: "MzdJzm38"})
	//r := client.Login(xcode.AuthInfo{Email: "tanghuang1989@gmail.com", Password: "MzdJzm38"})
	if r.Status == beans.ErrorCodeInvalidAccount {
		fmt.Printf("invalid account %+v", r)
		return
	} else if r.Status == beans.ErrorCodeInvalidPassword {
		fmt.Printf("invalid password %+v", r)
		return
	}
	if r.Status == 200 || r.Status == errorz.StatusSuccess {
		onSuccessXcode(client, r)
	} else if r.Status == 401 {
		fmt.Printf("login failed")
	} else if r.Status == 409 {
		fmt.Printf("fa2 required\n")
		deviceResult := client.LoadTwoStepDevices()
		if deviceResult.HasError() {
			fmt.Printf("load device failed %+v %v\n", deviceResult.Error, deviceResult.Body)
			return
		}
		//if deviceResult.Status != 0 {
		//	fmt.Printf("load device failed %+v\n", deviceResult)
		//	return
		//}
		//td := deviceResult.Body.(*xcode.TwoStepDevicesResponse)
		tdStatus := deviceResult.Status
		//if deviceResult.Status == 401 {
		//	fmt.Printf("login failed with 401 %+v\n", deviceResult)
		//	return
		//}
		fmt.Printf("load device success\n")
		fmt.Printf("%+v", deviceResult)
		var phoneId = "1"
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
				onSuccessXcode(client, verifyResult)
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
					onSuccessXcode(client, verifyResult)
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

func onSuccessXcode(client *xcode.XcodeAuthClient, r *httpz.HttpResponse) {
	fmt.Println("login success")
	c := xcode.NewXcodeClient(account)
	f := c.GetTeams()
	fmt.Println(f.Status, string(f.Body))
	api := c.GetApiV3()
	api.TeamId = "CS2ADD9F7F"
	t := api.ListDevices()
	fmt.Println(t.Status, string(t.Body))
	//t := client.GetTeams()
	//fmt.Println(t.Status, string(t.Body))
	//apiClient := xcode.NewDevApiV1(client)
	//apiClient.TeamId = "CS2ADD9F7F"
	////apiClient.TeamId = t.Body.(*xcode.ViewTeamsResponse).Teams[0].TeamId
	//t = apiClient.ListDevices()
	//fmt.Println(t.Status, string(t.Body))
	//t = apiClient.ListBundleID()
	//
	//fmt.Println(t.Status, string(t.Body))
}
