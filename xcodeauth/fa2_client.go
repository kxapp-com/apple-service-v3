package xcode

//type Fa2Client struct {
//	headers    map[string]string
//	httpClient *http.Client
//	serverURL  string
//	//beforeReturnHandler func(response *http.Response)
//}
//
//func NewXcodeFa2Client(httpclient *http.Client, appleIdToken string, data *appuploader.AnisseteData) *Fa2Client {
//	client := &Fa2Client{httpClient: httpclient}
//	client.serverURL = "https://gsa.apple.com/auth"
//	//client.headers = gsa.AddAnisseteHeaders(data, xcodeStep2Header())
//	client.SetAnisetteData(data)
//	client.headers["X-Apple-Identity-Token"] = appleIdToken
//	return client
//}
//
//func (client *Fa2Client) SetAnisetteData(data *appuploader.AnisseteData) {
//	client.headers = AddAnisseteHeaders(data, xcodeStep2Header())
//}
