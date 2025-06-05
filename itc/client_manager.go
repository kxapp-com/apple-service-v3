package itc

import (
	"github.com/appuploader/apple-service-v3/base"
	fastlang "github.com/appuploader/apple-service-v3/idmsa"
	xcode "github.com/appuploader/apple-service-v3/xcode"
)

type ClientManager struct {
	appleClient map[string]base.AppleClient
	authClient  map[string]base.AppleAuthClient
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		appleClient: make(map[string]base.AppleClient),
	}
}

func (c *ClientManager) GetClient(userName string) base.AppleClient {
	return c.appleClient[userName]
}
func (c *ClientManager) GetAuthClient(userName string, xcodeApi bool) base.AppleClient {
	return c.appleClient[userName]
}
func NewAppleClient(userName string, useXcodeApi bool) base.AppleClient {
	if useXcodeApi {
		return xcode.NewXcodeClient(userName)
	} else {
		return fastlang.NewDevClient(userName)
	}
}
func NewAppleAuthClient(useXcodeApi bool) base.AppleAuthClient {
	if useXcodeApi {
		return xcode.NewXcodeAuthClient()
	} else {
		return fastlang.NewDevAuthClient()
	}
}
