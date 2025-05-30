package storage

import (
	"gitee.com/kxapp/kxapp-common/cryptoz"
	"gitee.com/kxapp/kxapp-common/utilz"
	"os"
	"path/filepath"
)

const (
	TokenTypeXcode = "xcode"
	TokenTypeItc   = "itc"
	tokenPassword  = ""
)

func TokenPath(email, tokenType string) string {
	//p := "./" + email + "/token." + tokenType
	p := filepath.Join(".", "cookies", email, "token."+tokenType)
	os.MkdirAll(filepath.Dir(p), 0755)
	return p
}
func Read[T any](email string, tokenType string) (*T, error) {
	return utilz.ReadFromJsonFileSec[T](TokenPath(email, tokenType), tokenPassword)
}
func Write(email string, tokenType string, token any) error {
	return utilz.WriteToJsonFileSec(TokenPath(email, tokenType), token, tokenPassword)
}
func ReadFile(fp string) ([]byte, error) {
	d, e := os.ReadFile(fp)
	if e != nil {
		return nil, e
	}
	if tokenPassword != "" {
		return cryptoz.RC4Crypto(d, tokenPassword), nil
	}
	return d, nil
}
func WriteFile(fp string, data []byte) error {
	if tokenPassword != "" {
		data = cryptoz.RC4Crypto(data, tokenPassword)
	}
	return os.WriteFile(fp, data, os.ModePerm)
}
