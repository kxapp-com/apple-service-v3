package itc

import (
	fastlang "github.com/appuploader/apple-service-v3/idmsaauth"
	"github.com/appuploader/apple-service-v3/itcbase"
	xcode "github.com/appuploader/apple-service-v3/xcodeauth"
)

type ClientManager struct {
	appleClient map[string]itcbase.AppleClient
	authClient  map[string]itcbase.AppleAuthClient
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		appleClient: make(map[string]itcbase.AppleClient),
	}
}

func (c *ClientManager) GetClient(userName string) itcbase.AppleClient {
	return c.appleClient[userName]
}
func (c *ClientManager) GetAuthClient(userName string, xcodeApi bool) itcbase.AppleClient {
	return c.appleClient[userName]
}
func NewAppleClient(userName string, useXcodeApi bool) itcbase.AppleClient {
	if useXcodeApi {
		return xcode.NewXcodeClient(userName)
	} else {
		return fastlang.NewDevClient(userName)
	}
}
func NewAppleAuthClient(useXcodeApi bool) itcbase.AppleAuthClient {
	if useXcodeApi {
		return xcode.NewXcodeAuthClient()
	} else {
		return fastlang.NewDevAuthClient()
	}
}
