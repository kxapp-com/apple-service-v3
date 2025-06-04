package main

import (
	"fmt"
	"gitee.com/kxapp/kxapp-common/httpz"
	"gitee.com/kxapp/kxapp-common/httpz/cookiejar"
)

func main() {
	jar, _ := cookiejar.New(nil)
	hClient := httpz.NewHttpClient(jar)
	httpz.Get("https://idmsa.apple.com/IDMSWebAuth/signin?appIdKey=891bd3417a7776362562d2197f89480a8547b108fd934911bcbea0110d07f757&path=%2Faccount%2F&rv=1", nil).Request(hClient)
	b, e := jar.ToJSON()
	if e != nil {
		panic(e)
	} else {
		println(string(b))
	}
	jar2 := cookiejar.NewJarFromJSON(b)
	cookies := jar2.AllCookies()
	fmt.Println(cookies)

}
