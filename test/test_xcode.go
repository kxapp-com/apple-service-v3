package main

import (
	"fmt"
	"gitee.com/kxapp/kxapp-common/errorz"
	"github.com/appuploader/apple-service-v3/xcode"
	"time"
)

func main() {
	client := xcode.NewClient()
	r := client.Login(xcode.AuthInfo{Email: "877028320@qq.com", Password: "MzdJzm38"})
	//r := client.Login(xcode.AuthInfo{Email: "yanwen1688@gmail.com", Password: "MzdJzm38"})
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
		fmt.Printf("fa2 required\n")
		deviceResult, e := client.LoadTwoStepDevices()
		if e != nil {
			fmt.Printf("load device failed %+v\n", e)
			return
		}
		//if deviceResult.Status != 0 {
		//	fmt.Printf("load device failed %+v\n", deviceResult)
		//	return
		//}
		//td := deviceResult.Body.(*xcode.TwoStepDevicesResponse)
		tdStatus := deviceResult.HttpStatus
		//if deviceResult.Status == 401 {
		//	fmt.Printf("login failed with 401 %+v\n", deviceResult)
		//	return
		//}
		fmt.Printf("load device success\n")
		fmt.Printf("%+v", deviceResult)
		if tdStatus == 201 {
			fmt.Println("please input device code")
			var deviceCode string
			fmt.Scanln(&deviceCode)
			verifyResult := client.VerifyCode("sms", deviceCode, "3")
			fmt.Println(verifyResult)
			for {
				if verifyResult.Status == 200 || verifyResult.Status == 0 {
					break
				}
				fmt.Println("please input device code")
				fmt.Scanln(&deviceCode)
				verifyResult = client.VerifyCode("sms", deviceCode, "3")
				fmt.Println(verifyResult)
			}
			if verifyResult.Status == 200 {
				vvv, e := client.ViewTeams()
				fmt.Println(vvv, e)
			}
		} else if tdStatus == 200 {
			fmt.Println("please input device id")
			var deviceId string = "1"
			fmt.Scanln(&deviceId)
			requestCodeResult, eee := client.RequestVerifyCode("sms", deviceId)
			if eee != nil {
				fmt.Printf("request code failed %+v", eee)
				return
			}
			fmt.Printf("request code success %+v\n", requestCodeResult)
			if requestCodeResult.HttpStatus == 200 || requestCodeResult.HttpStatus == 201 {
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
	time.Sleep(time.Minute * 5)
}
