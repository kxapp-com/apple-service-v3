package beans

const VerifyCodeMode_SMS = "sms"
const VerifyCodeMode_Voice = "voice"
const VerifyCodeMode_Device = "device"

type ServiceError struct {
	Code              string `json:"code,omitempty"`
	Title             string `json:"title,omitempty"`
	Message           string `json:"message,omitempty"`
	SuppressDismissal bool   `json:"suppressDismissal,omitempty"`
}

type trustedDevices struct {
	ID                 int    `json:"id,omitempty"`
	ObfuscatedNumber   string `json:"name,omitempty"`
	PushMode           string `json:"type,omitempty"`
	NumberWithDialCode string `json:"numberWithAreaCodeCountryDialingCode,omitempty"`
}

type trustedPhoneNumber struct {
	NumberWithDialCode string `json:"numberWithDialCode"`
	PushMode           string `json:"pushMode"`
	nonFTEU            bool   `json:"nonFTEU"`
	ObfuscatedNumber   string `json:"obfuscatedNumber"`
	LastTwoDigits      string `json:"lastTwoDigits"`
	ID                 int    `json:"id"`
}

type securityCode struct {
	Code                  string `json:"code,omitempty"`
	Length                int    `json:"length,omitempty"`
	TooManyCodesSent      bool   `json:"tooManyCodesSent,omitempty"`
	TooManyCodesValidated bool   `json:"tooManyCodesValidated,omitempty"`
	SecurityCodeLocked    bool   `json:"securityCodeLocked,omitempty"`
	SecurityCodeCooldown  bool   `json:"securityCodeCooldown,omitempty"`
}

// 有信任设备的时候默认是会返回此消息，并且自动发送验证码到设备
type DeviceCodeResponse struct {
	TrustedDeviceCount              int                    `json:"trustedDeviceCount"`
	SecurityCode                    securityCode           `json:"securityCode,omitempty"`
	PhoneNumberVerification         TwoStepDevicesResponse `json:"phoneNumberVerification"`
	AboutTwoFactorAuthenticationUrl string                 `json:"aboutTwoFactorAuthenticationUrl"`
	ServiceErrors                   []ServiceError         `json:"serviceErrors,omitempty"`
}

type TwoStepDevicesResponse struct {
	TrustedPhoneNumbers             []trustedPhoneNumber `json:"trustedPhoneNumbers"`
	PhoneNumber                     trustedPhoneNumber   `json:"phoneNumber"`
	SecurityCode                    securityCode         `json:"securityCode"`
	Mode                            string               `json:"mode"`
	Type                            string               `json:"type"`
	AuthenticationType              string               `json:"authenticationType"`
	RecoveryUrl                     string               `json:"recoveryUrl"`
	CantUsePhoneNumberUrl           string               `json:"cantUsePhoneNumberUrl"`
	RecoveryWebUrl                  string               `json:"recoveryWebUrl"`
	RepairPhoneNumberUrl            string               `json:"repairPhoneNumberUrl"`
	RepairPhoneNumberWebUrl         string               `json:"repairPhoneNumberWebUrl"`
	AboutTwoFactorAuthenticationUrl string               `json:"aboutTwoFactorAuthenticationUrl"`
	AutoVerified                    bool                 `json:"autoVerified"`
	ShowAutoVerificationUI          bool                 `json:"showAutoVerificationUI"`
	SupportsCustodianRecovery       bool                 `json:"supportsCustodianRecovery"`
	HideSendSMSCodeOption           bool                 `json:"hideSendSMSCodeOption"`
	SupervisedChangePasswordFlow    bool                 `json:"supervisedChangePasswordFlow"`
	TrustedPhoneNumber              trustedPhoneNumber   `json:"trustedPhoneNumber"`
	Hsa2Account                     bool                 `json:"hsa2Account"`
	RestrictedAccount               bool                 `json:"restrictedAccount"`
	SupportsRecovery                bool                 `json:"supportsRecovery"`
	ManagedAccount                  bool                 `json:"managedAccount"`
	TrustedDevices                  []trustedDevices     `json:"trustedDevices"`          //次项老的登录方式有
	ServiceErrors                   []ServiceError       `json:"serviceErrors,omitempty"` //次项登录失败的时候包含了错误信息
	HttpStatus                      int                  `json:"httpStatusCode"`          //http状态码
}
