package base

import "gitee.com/kxapp/kxapp-common/httpz"

// AppleClient 定义了苹果开发者相关操作的通用接口
// 由 XcodeClient、DevClient 等实现
type AppleClient interface {
	IsSessionAlive() bool
	GetTeams() *httpz.HttpResponse
	GetApiV3() *ItcApiV3
	GetUserName() string
}

// AppleAuthClient defines the common interface for Apple authentication clients
type AppleAuthClient interface {
	// Login attempts to authenticate with Apple using username and password
	Login(userName string, password string) *httpz.HttpResponse

	// LoadTwoStepDevices retrieves the list of trusted devices for 2FA
	LoadTwoStepDevices() *httpz.HttpResponse

	// RequestVerifyCode requests a verification code to be sent
	// codeType can be "device", "sms", or "voice"
	// phoneId is required for sms/voice verification
	RequestVerifyCode(codeType string, phoneId string) *httpz.HttpResponse

	// VerifyCode verifies the provided code
	// codeType can be "device", "sms", or "voice"
	// phoneId is required for sms/voice verification
	VerifyCode(codeType string, code string, phoneId string) *httpz.HttpResponse
}
