package idmsa

// HTTP Headers
const (
	HeaderUserAgent         = "User-Agent"
	HeaderContentType       = "Content-Type"
	HeaderAccept            = "Accept"
	HeaderAcceptEncoding    = "Accept-Encoding"
	HeaderXRequestedWith    = "X-Requested-With"
	HeaderXAppleWidgetKey   = "X-Apple-Widget-Key"
	HeaderXCsrfItc          = "X-Csrf-Itc"
	HeaderScnt              = "scnt"
	HeaderXAppleAuthAttr    = "X-Apple-Auth-Attributes"
	HeaderXAppleHC          = "X-Apple-HC"
	HeaderXAppleHCBits      = "X-Apple-HC-Bits"
	HeaderXAppleHCChallenge = "X-Apple-HC-Challenge"
	HeaderXAppleIDSession   = "X-Apple-ID-Session-Id"
	HeaderXAppleIDCountry   = "X-Apple-ID-Account-Country"
)

// API URLs
const (
	BaseURLIdmsa = "https://idmsa.apple.com/appleauth"
	BaseURLItc   = "https://developer.apple.com/services-account/QH65B2"
)

// Response Status
//const (
//	StatusOK           = 200
//	StatusFound        = 302
//	StatusBadRequest   = 400
//	StatusUnauthorized = 401
//	StatusConflict     = 409
//)

// Error Codes
const (
	ErrorCodeSessionExpired = -20101
)
