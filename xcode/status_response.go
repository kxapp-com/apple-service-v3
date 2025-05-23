package xcode

type StatusResponse struct {
	StatusCode   int    `json:"status_code"`
	ErrorMessage string `json:"error_message"`
	ResponseBody string `json:"response_body"`
}
