package util

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

var dataRootDirectory string

/*
*
设置data目录在home目录下的名称，最好是设置为bundleid或者应用名称之类
*/
func SetDataDirectoryName(dataRootName string) {
	dataRootDirectory = dataRootName
}

/*
*
获取home/appuploader/rpath路径
*/
func DataPath(rpath string) string {
	h, e := os.UserHomeDir()
	if e != nil {
		h = "./"
	}
	return filepath.Join(h, dataRootDirectory, rpath)
}

func NewPKIXName(name string, email string, country string) pkix.Name {
	//country := "CN"
	var (
		oidCountry = []int{2, 5, 4, 6}
		//oidOrganization       = []int{2, 5, 4, 10}
		//oidOrganizationalUnit = []int{2, 5, 4, 11}
		oidCommonName = []int{2, 5, 4, 3}
		oidEmail      = []int{1, 2, 840, 113549, 1, 9, 1}
	)
	subject := pkix.Name{
		Country:    []string{country},
		CommonName: name,
		Names: []pkix.AttributeTypeAndValue{
			{
				Type:  oidEmail,
				Value: email,
			},
			{
				Type:  oidCommonName,
				Value: name,
			},
			{
				Type:  oidCountry,
				Value: country,
			},
		},
	}
	return subject
}

// keypair is the private key to sign the CSR with, and the corresponding public
// key will be included in the CSR. It must implement crypto.Signer and its
// Public() method must return a *rsa.PublicKey or a *ecdsa.PublicKey or a
// ed25519.PublicKey. (A *rsa.PrivateKey, *ecdsa.PrivateKey or
// ed25519.PrivateKey satisfies this.)
func NewCSR(keypair any, email string, name string) ([]byte, error) {
	var alg = x509.SHA256WithRSA
	if _, ok := keypair.(*ecdsa.PrivateKey); ok {
		alg = x509.ECDSAWithSHA256
	}
	pkiName := NewPKIXName(name, email, "CN")
	var csrTemplate = x509.CertificateRequest{
		Subject:            pkiName,
		SignatureAlgorithm: alg,
	}

	//csrTemplate.EmailAddresses
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, keypair)
	if err != nil {
		return nil, err
		//fmt.Printf("%s", err)
	}
	csr := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
	})
	return csr, nil
	//fmt.Printf("%s", string(csr))
}

/*
*
创建证书请求，并且把证书请求，私钥，公钥存放到指定目录下，名称分别是csr.pem,pri.pem,pub.pem ,创建失败返回错误
*/
func CreateCertRequest(tempDir string, email string, name string) error {
	keys, e0 := rsa.GenerateKey(rand.Reader, 2048)
	csr, e1 := NewCSR(keys, email, name)
	e2 := os.MkdirAll(tempDir, fs.ModePerm)
	csrPath := path.Join(tempDir, "csr.pem")
	priPath := path.Join(tempDir, "pri.pem")
	pubPath := path.Join(tempDir, "pub.pem")
	e3 := os.WriteFile(csrPath, csr, fs.ModePerm)
	e4 := WritePrivateKey(keys, priPath)
	e5 := WritePublicKey(&keys.PublicKey, pubPath)
	if e0 != nil || e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return fmt.Errorf("%s%s%s%s%s%s", e0, e1, e2, e3, e4, e5)
	}
	return nil
}
func CreateCertRequestEcc(tempDir string, email string, name string) error {
	//// 初始化椭圆曲线
	//pubkeyCurve := elliptic.P256()
	//// 随机挑选基点,生成私钥
	//p, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)

	keys, e0 := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, e1 := NewCSR(keys, email, name)
	e2 := os.MkdirAll(tempDir, fs.ModePerm)
	csrPath := path.Join(tempDir, "csr.pem")
	priPath := path.Join(tempDir, "pri.pem")
	pubPath := path.Join(tempDir, "pub.pem")
	e3 := os.WriteFile(csrPath, csr, fs.ModePerm)
	e4 := WritePrivateKeyEcc(keys, priPath)
	e5 := WritePublicKeyEcc(&keys.PublicKey, pubPath)
	if e0 != nil || e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return fmt.Errorf("%s%s%s%s%s%s", e0, e1, e2, e3, e4, e5)
	}
	return nil
}

func CertificationContentToPEM(basedContent string) ([]byte, error) {
	certData, e := base64.StdEncoding.DecodeString(basedContent)
	if e != nil {
		return nil, e
	}
	var certBin bytes.Buffer
	e2 := pem.Encode(&certBin, &pem.Block{Type: "RSA CERTIFICATE", Bytes: certData})
	return certBin.Bytes(), e2
}
func ReadCertification(pemCertificationPath string) (*x509.Certificate, error) {
	certificationData, _ := os.ReadFile(pemCertificationPath)
	block, _ := pem.Decode(certificationData)
	return x509.ParseCertificate(block.Bytes)
}
func WriteCertification(cert *x509.Certificate, path string) error {
	var certBin bytes.Buffer
	e := pem.Encode(&certBin, &pem.Block{Type: "RSA CERTIFICATE", Bytes: cert.Raw})
	if e != nil {
		return e
	}
	return os.WriteFile(path, certBin.Bytes(), fs.ModePerm)
}
func WriteAppleCertContentToFile(basedCertContent string, pemCertPath string) error {
	data, e := CertificationContentToPEM(basedCertContent)
	if e != nil {
		return e
	}
	return os.WriteFile(pemCertPath, data, fs.ModePerm)
}

/*
*
从pem格式的privatekey里面解析出对象来
*/
func ReadPrivateKey(pemPrivateKeyPath string) (*rsa.PrivateKey, error) {
	privateKeyBinary, _ := os.ReadFile(pemPrivateKeyPath)
	priblock, _ := pem.Decode(privateKeyBinary)
	if priblock == nil {
		return nil, fmt.Errorf("devoce %s to pem format private key fail", pemPrivateKeyPath)
	}
	return x509.ParsePKCS1PrivateKey(priblock.Bytes)
}
func ReadPrivateKeyEcc(pemPrivateKeyPath string) (*ecdsa.PrivateKey, error) {
	privateKeyBinary, _ := os.ReadFile(pemPrivateKeyPath)
	priblock, _ := pem.Decode(privateKeyBinary)
	if priblock == nil {
		return nil, fmt.Errorf("devoce %s to pem format private key fail", pemPrivateKeyPath)
	}
	return x509.ParseECPrivateKey(priblock.Bytes)
}

/*
*
把对象编码写入文件
*/
func WritePrivateKey(keys *rsa.PrivateKey, path string) error {
	var privateKey bytes.Buffer
	e4 := pem.Encode(&privateKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keys)})
	if e4 == nil {
		return os.WriteFile(path, privateKey.Bytes(), fs.ModePerm)
	} else {
		return e4
	}
}
func WritePublicKey(keys *rsa.PublicKey, path string) error {
	var pubKey bytes.Buffer
	e5 := pem.Encode(&pubKey, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(keys)})
	if e5 == nil {
		return os.WriteFile(path, pubKey.Bytes(), fs.ModePerm)
	}
	return e5
}
func WritePrivateKeyEcc(keys *ecdsa.PrivateKey, path string) error {
	data, e := x509.MarshalECPrivateKey(keys)
	if e != nil {
		return e
	}
	var privateKey bytes.Buffer
	e4 := pem.Encode(&privateKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: data})
	if e4 == nil {
		return os.WriteFile(path, privateKey.Bytes(), fs.ModePerm)
	} else {
		return e4
	}
}
func WritePublicKeyEcc(keys *ecdsa.PublicKey, path string) error {
	data, e := x509.MarshalPKIXPublicKey(keys)
	if e != nil {
		return e
	}
	var pubKey bytes.Buffer
	e5 := pem.Encode(&pubKey, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: data})
	if e5 == nil {
		return os.WriteFile(path, pubKey.Bytes(), fs.ModePerm)
	}
	return e5
}

/*
*
把privatekey和证书的内容合并为p12
privatekey 是符合pem编码的
*/

func GenerateP12(priKey *rsa.PrivateKey, cert *x509.Certificate, password string) (pfxData []byte, err error) {
	return gopkcs12.Encode(rand.Reader, priKey, cert, nil, password)
}

/**证书+私钥合并为p12并保存到文件中**/
func WriteP12File(priKeyPath string, certPath string, p12path string, password string) (pfxData []byte, err error) {
	var privateKey any
	var e error
	privateKey, e = ReadPrivateKey(priKeyPath)
	if e != nil {
		privateKey, e = ReadPrivateKeyEcc(priKeyPath)
		if e != nil {
			return nil, e
		}

	}
	certification, e2 := ReadCertification(certPath)
	if e2 != nil {
		return nil, e2
	}
	p12Bytes, e3 := gopkcs12.Encode(rand.Reader, privateKey, certification, nil, password)
	if e3 != nil {
		return nil, e3
	}
	os.MkdirAll(filepath.Dir(p12path), os.ModePerm)
	return p12Bytes, os.WriteFile(p12path, p12Bytes, fs.ModePerm)
}

func OCSPStatusCheck(certt *x509.Certificate) (*ocsp.Response, error) {
	ocspURL := certt.OCSPServer[0]
	issuerCertURL := ocspURL
	if certt.IssuingCertificateURL != nil {
		issuerCertURL = certt.IssuingCertificateURL[0]
	}

	// download the issuer certificate
	issuer, err := getCertFromURL(issuerCertURL)
	if err != nil {
		return nil, fmt.Errorf("getting issuer certificate: %w", err)
	}

	// Build OCSP request
	buffer, err := ocsp.CreateRequest(certt, issuer, &ocsp.RequestOptions{
		Hash: crypto.SHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("creating ocsp request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, ocspURL, bytes.NewBuffer(buffer))
	if err != nil {
		return nil, fmt.Errorf("creating http request: %w", err)
	}

	ocspUrl, err := url.Parse(ocspURL)
	if err != nil {
		return nil, fmt.Errorf("parsing ocsp url: %w", err)
	}

	req.Header.Add("Content-Type", "application/ocsp-request")
	req.Header.Add("Accept", "application/ocsp-response")
	req.Header.Add("host", ocspUrl.Host)
	//req = req.WithContext(ctx)

	// Make OCSP request
	httpResponse, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making ocsp request: %w", err)
	}

	defer httpResponse.Body.Close()

	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Parse response
	ocspResponse, err := ocsp.ParseResponse(output, issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing ocsp response: %w", err)
	}
	return ocspResponse, nil
}

func getCertFromURL(url string) (*x509.Certificate, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	//req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting cert from %s: %w", url, err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	cert, err := x509.ParseCertificate(body)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

func OCSPStatusName(status int) string {
	switch status {
	case ocsp.Revoked:
		return "Revoked"
	case ocsp.Good:
		return "Good"
	case ocsp.Unknown:
		return "Unknown"
	case ocsp.ServerFailed:
		return "ServerFailed"
	default:
		return "Unknown"
	}
}
func OCSPRevokeReasonName(reason int) string {
	switch reason {
	case ocsp.Unspecified:
		return "Unspecified"
	case ocsp.KeyCompromise:
		return "KeyCompromise"
	case ocsp.CACompromise:
		return "CACompromise"
	case ocsp.AffiliationChanged:
		return "AffiliationChanged"
	case ocsp.Superseded:
		return "Superseded"
	case ocsp.CessationOfOperation:
		return "CessationOfOperation"
	case ocsp.CertificateHold:
		return "CertificateHold"
	case ocsp.RemoveFromCRL:
		return "RemoveFromCRL"
	case ocsp.PrivilegeWithdrawn:
		return "PrivilegeWithdrawn"
	case ocsp.AACompromise:
		return "AACompromise"
	default:
		return "Unknown"
	}
}
