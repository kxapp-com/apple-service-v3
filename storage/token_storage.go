package storage

import (
	"gitee.com/kxapp/kxapp-common/utilz"
)

const (
	TokenTypeXcode = "xcode"
	TokenTypeItc   = "itc"
	tokenPassword  = ""
)

func tokenPath(email, tokenType string) string {
	return "./" + email + "/token." + tokenType
}
func Read[T any](email string, tokenType string) (*T, error) {
	return utilz.ReadFromJsonFileSec[T](tokenPath(email, tokenType), tokenPassword)
}
func Write(token any, tokenType string) error {
	return utilz.WriteToJsonFileSec(tokenPath(tokenType, tokenType), token, tokenPassword)
}
