package storage

import (
	"gitee.com/kxapp/kxapp-common/utilz"
	"os"
	"path/filepath"
)

const (
	TokenTypeXcode = "xcode"
	TokenTypeItc   = "itc"
	tokenPassword  = ""
)

func tokenPath(email, tokenType string) string {
	//p := "./" + email + "/token." + tokenType
	p := filepath.Join(".", "cookies", email, "token."+tokenType)
	os.MkdirAll(filepath.Dir(p), 0755)
	return p
}
func Read[T any](email string, tokenType string) (*T, error) {
	return utilz.ReadFromJsonFileSec[T](tokenPath(email, tokenType), tokenPassword)
}
func Write(email string, tokenType string, token any) error {
	return utilz.WriteToJsonFileSec(tokenPath(email, tokenType), token, tokenPassword)
}
