package main

import (
	"bufio"
	"fmt"
	"github.com/appuploader/apple-service-v3/idmsa"
	"os"
	"strconv"
	"strings"
)

func main() {
	var idmsaClient, e = idmsa.NewClient("")
	if e != nil {
		fmt.Println(e)
		return
	}
	r, e2 := idmsaClient.Login("yanwen1688test@gmail.com", "MzdJzm382")
	//r, e2 := idmsaClient.Login("yanwen1688@gmail.com", "MzdJzm38")
	//r, e2 := idmsaClient.Login("liya1550120@163.com", "Li123123.")
	if e2 != nil {
		fmt.Println(e2)
		return
	} else {
		fmt.Println(string(r.Body))
		if r.Status == 200 {
			fmt.Println("Login success")
		} else {
			r, devices := idmsaClient.LoadTwoStepDevices()
			if r.HasError() {
				fmt.Println(r.Error)
			} else {
				fmt.Println(string(r.Body))
				//r = idmsaClient.RequestSMSVoiceCode("1", "sms")
				var phoneID = strconv.Itoa(devices.TrustedPhoneNumber.Id)
				r, e = idmsaClient.RequestSMSVoiceCode(phoneID, "sms")
				if e != nil {
					fmt.Println(e)
				} else {
					reader := bufio.NewReader(os.Stdin)
					input, err := reader.ReadString('\n')
					if err != nil {
						fmt.Println("读取输入失败:", err)
						return
					}
					// 去掉输入内容末尾的换行符
					input = strings.TrimSpace(input)
					result, e2 := idmsaClient.VerifySMSVoiceCode(phoneID, input, "sms")
					if e2 != nil {
						fmt.Println(result.Error)
					} else {
						fmt.Println(string(result.Body))
						fmt.Printf("headers %+v", result.Header)
					}
				}

			}
		}
	}

}
