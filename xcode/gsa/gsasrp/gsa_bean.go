package gsasrp

import (
	"encoding/base64"
	"fmt"
	"github.com/appuploader/apple-service-v3/appuploader"
	"time"
)

const Status_GSA_Response_OK = 200                            //Request accepted
const Status_GSA_Response_SecondaryActionRequired = 409       //Secondary authentication (2FA) is required
const Status_GSA_Response_AnisetteResyncRequired = 434        //Anisette headers have expired
const Status_GSA_Response_Anisette_Reprovision_Required = 433 //Anisette machine data has changed

func AddAnisseteHeaders(data *appuploader.AnisseteData, headers map[string]string) map[string]string {
	const XCode_Client_Time_Format = "2006-01-02T15:04:05Z"
	headers["X-Apple-I-MD"] = data.XAppleIMD
	headers["X-Apple-I-MD-LU"] = data.XAppleIMDLU
	headers["X-Apple-I-MD-M"] = data.XAppleIMDM
	headers["X-Apple-I-MD-RINFO"] = data.XAppleIMDRINFO
	headers["X-Apple-I-TimeZone"] = data.XAppleITimeZone
	headers["X-Apple-Locale"] = data.XAppleLocale
	headers["X-Mme-Client-Info"] = data.XMmeClientInfo
	headers["X-Mme-Device-Id"] = data.XMmeDeviceId
	headers["X-Apple-I-Client-Time"] = time.Now().Format(XCode_Client_Time_Format)
	//headers["X-Apple-I-Client-Time"] = util.GetAppleClientTimeNowString3(data.XAppleIClientTime)
	//headers["X-Apple-I-Client-Time"] = time.Now().UTC().Format(util.XCode_Client_Time_Format)
	return headers
}

type GSARequestCPD struct {
	CID          string `plist:"AppleIDClientIdentifier"`
	ClientTime   string `plist:"X-Apple-I-Client-Time"` //rfc3330
	IMD          string `plist:"X-Apple-I-MD"`
	IMDM         string `plist:"X-Apple-I-MD-M"`
	RInfo        int    `plist:"X-Apple-I-MD-RINFO"`
	SerialNumber string `plist:"X-Apple-I-SRL-NO,omitempty"`
	UDID         string `plist:"X-Mme-Device-Id"`
	BootStrap    bool   `plist:"bootstrap"`
	CApp         string `plist:"capp,omitempty"`
	CKGen        bool   `plist:"ckgen,omitempty"`
	DC           string `plist:"dc,omitempty"`
	DEC          string `plist:"dec,omitempty"`
	Loc          string `plist:"loc,omitempty"`
	PApp         string `plist:"papp,omitempty"`
	PBE          bool   `plist:"pbe,omitempty"`
	PRKGEN       bool   `plist:"prkgen,omitempty"`
	PRTN         string `plist:"prtn,omitempty"`
	SVCT         string `plist:"svct,omitempty"`

	ClientTimeZone string `plist:"X-Apple-I-TimeZone"`
	Icscrec        bool   `plist:"icscrec"`
}

type GSAInitRequest struct {
	A2K        []byte         `plist:"A2k"` //Client Public Key (A2 Key)	Computed according to SRP-6a standard
	Operation  string         `plist:"o"`   //Operation	Set to init for this stage
	ProtoStyle []string       `plist:"ps"`  //Protocols Supported	See table below
	UserName   string         `plist:"u"`   //Username	Account e-mail
	CPD        *GSARequestCPD `plist:"cpd"` //Client Provided Data	Anisette headers for client identification
}

// GSAInitResponse step1 resp
type GSAInitResponse struct {
	Status         GSAStatus `plist:"Status"` //Used to store the response status
	IterationCount int       `plist:"i"`      //Iterations	Iteration count for PBKDF2 password derivation, must be > 999
	Salt           []byte    `plist:"s"`      //Salt	User's unique salt, used for further SRP-6a challenges
	SeverProto     string    `plist:"sp"`     //Selected  Protocol, from table above, the server wishes to use
	Cookie         string    `plist:"c"`      //Cookie	Unique identification cookie for further API requests
	SRPB           []byte    `plist:"B"`      //Server Public Key (B Key)	To be used according to SRP-6a standard
}

// GSAStatus status
type GSAStatus struct {
	StatusCode      int    `plist:"hsc"` //HTTP Status Code	HTTP-compatible status code
	ErrorDescrption string `plist:"ed"`  //Error Description	GSA-specific error description  0表示没错误，-20101表示密码错误
	ErrorCode       int    `plist:"ec"`  //Error Code	GSA-specific error code
	ErrorMessage    string `plist:"em"`  //Error Message	GSA-specific error message

	RSH               bool   `plist:"rsh"`
	AuthenticationURL string `plist:"au"` // If server-driven, URL of 2FA capture page  au=trustedDeviceSecondaryAuth status=409
}

type GSACompleteRequest struct {
	M1        []byte        `plist:"M1"`  //Client Proof (M1 Hash)	Computed according to SRP-6a standard, with variation described below
	Cookie    string        `plist:"c"`   //Cookie	Unique identification cookie from initial API request
	Operation string        `plist:"o"`   //Operation	Set to complete for this stage
	UserName  string        `plist:"u"`   //Username	Account e-mail
	CPD       GSARequestCPD `plist:"cpd"` //Client Provided Data	Anisette headers for client identification
	//ServerCertificate string          `plist:"sc"`  //SHA-256 digest of SSL certificate chain
}

/*
	type GsaResponse[T any] struct {
		Response T `plist:"Response"`
	}
*/
type GSACompleteResponse struct {
	Status GSAStatus `plist:"Status"` //Response Status	Used to store the response status
	SPD    []byte    `plist:"spd"`    //Server Provided Data	User token information, AES-CBC encrypted using session key
	M2     []byte    `plist:"M2"`     //Server Proof (M2 Hash)	Used to verify server also has correct password
	NP     []byte    `plist:"np"`     //Negociation Proof	Used to verify both client and server used the same protocol settings
}
type ReqVersion struct {
	Version string `plist:"Version"` //Version String	Set to 1.0.1
}
type GSAToken struct {
	Duration int    `plist:"duration" json:"duration"`
	Expiry   int64  `plist:"expiry" json:"expiry"`
	Token    string `plist:"token" json:"token"`
}
type ServerProvidedData struct {
	DsPrsId        int    `plist:"DsPrsId" json:"DsPrsId"`
	GsIdmsToken    string `plist:"GsIdmsToken" json:"GsIdmsToken"`
	Acname         string `plist:"acname" json:"acname"`
	AdditionalInfo struct {
		ObfuscatedPhoneNumbers []struct {
			MaskedPhoneNumber string `plist:"maskedPhoneNumber" json:"masked_phone_number"`
			RecentlyUsed      int    `plist:"recentlyUsed" json:"recentlyUsed"`
		} `plist:"obfuscatedPhoneNumbers" json:"obfuscatedPhoneNumbers"`
		PhoneNumbers []struct {
			PhoneNumber  string `plist:"phoneNumber" json:"phoneNumber"`
			RecentlyUsed int    `plist:"recentlyUsed" json:"recentlyUsed"`
			Type         string `plist:"type" json:"type"`
		} `plist:"phoneNumbers" json:"phoneNumbers"`
		SilentEscrowRecordRepairEnabled int `plist:"silentEscrowRecordRepairEnabled" json:"silentEscrowRecordRepairEnabled"`
	} `plist:"additionalInfo" json:"additionalInfo"`
	Adsid                      string               `plist:"adsid" json:"adsid"` // Alternate Directory Services Identifier
	AgeOfMajority              int                  `plist:"ageOfMajority" json:"ageOfMajority"`
	Authmode                   int                  `plist:"authmode" json:"authmode"`
	BeneficiaryListVersion     string               `plist:"beneficiaryListVersion" json:"beneficiaryListVersion"`
	C                          []byte               `plist:"c" json:"c"`
	CountryCode                string               `plist:"countryCode" json:"countryCode"`
	CustodianEnabled           int                  `plist:"custodianEnabled" json:"custodianEnabled"`
	Duration                   int                  `plist:"duration" json:"duration"`
	Fn                         string               `plist:"fn" json:"fn"`
	IsSenior                   string               `plist:"isSenior" json:"isSenior"`
	Ln                         string               `plist:"ln" json:"ln"`
	PrimaryEmail               string               `plist:"primaryEmail" json:"primaryEmail"`
	PrimaryEmailVetted         int                  `plist:"primaryEmailVetted" json:"primaryEmailVetted"`
	PrivateAttestationEnabled  int                  `plist:"privateAttestationEnabled" json:"privateAttestationEnabled"`
	ServerExperimentalFeatures int                  `plist:"serverExperimentalFeatures" json:"serverExperimentalFeatures"`
	Sk                         []byte               `plist:"sk" json:"sk"`
	StatusCode                 int                  `plist:"status-code" json:"statusCode"`
	TokenBundles               map[string]*GSAToken `plist:"t" json:"tokenBundles"` //tokenBundles
	UnderAge                   int                  `plist:"underAge" json:"underAge"`
	Url                        string               `plist:"url" json:"url"`
	Ut                         int                  `plist:"ut" json:"ut"`
	WebAccessEnabled           int                  `plist:"webAccessEnabled" json:"webAccessEnabled"`
}

func (spd *ServerProvidedData) GetAppleIdToken() string {
	//String identityToken = getAdsid() + ":" + getaGsIdmsToken();
	//return Base64.getEncoder().encodeToString(identityToken.getBytes(StandardCharsets.UTF_8));
	ss := fmt.Sprintf("%s:%s", spd.Adsid, spd.GsIdmsToken)
	return base64.StdEncoding.EncodeToString([]byte(ss))
}

type GSAAppTokensRequest struct {
	U         string         `plist:"u"`
	T         string         `plist:"t"`
	Checksum  []byte         `plist:"checksum"`
	C         []byte         `plist:"c"`
	App       []string       `plist:"app"`
	Operation string         `plist:"o"`
	CPD       *GSARequestCPD `plist:"cpd"`
}
type GSAAppTokensResponse struct {
	Status GSAStatus `plist:"Status"` //Response Status	Used to store the response status
	ET     []byte    `plist:"et"`     //encripted token
}
type DecryptedAppToken struct {
	statusCode   int                  `plist:"status-code" json:"statusCode"`
	TokenBundles map[string]*GSAToken `plist:"t" json:"tokenBundles"` //tokenBundles
}
