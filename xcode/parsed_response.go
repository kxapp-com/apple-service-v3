package xcode

import "net/http"

type ParsedResponse struct {
	Status       int         //200,201之类表示成功
	Body         any         //如果成功，body存放解码后的对象
	Header       http.Header //响应头
	ErrorMessage string      //错误信息
}
