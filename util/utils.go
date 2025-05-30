package util

import (
	"crypto/sha1"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func generateIframeId() string {
	rand.Seed(time.Now().UnixNano()) // 初始化随机种子
	// 生成随机字符串的函数
	randomString := func(length int) string {
		const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, length)
		for i := range b {
			b[i] = charset[rand.Intn(len(charset))]
		}
		return string(b)
	}
	// 生成固定格式的字符串
	result := "auth-" + randomString(7) // 第一部分
	for i := 1; i <= 3; i++ {           // 中间的三部分
		result += "-" + randomString(4)
	}
	result += "-" + randomString(8) // 最后一部分
	return result
}
func ReadErrorMessage(body []byte) string {
	messageReg := regexp.MustCompile(`"message"\s*:\s*"([^"]+)"`)
	matches := messageReg.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		return matches[1]
	}
	titleReg := regexp.MustCompile(`"title"\s*:\s*"([^"]+)"`)
	matches = titleReg.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		return matches[1]
	}
	return string(body)
}

func CookiesToHeader(cookies map[string]string) string {
	cookie := ""
	for k, v := range cookies {
		cookie = cookie + k + "=" + v + "; "
	}
	return strings.TrimSpace(strings.Trim(cookie, ";"))
}

// https://github.com/fastlane/fastlane/blob/master/spaceship/lib/spaceship/hashcash.rb#L4
/*
# This App Store Connect hashcash spec was generously donated by...
#
#                         __  _
#    __ _  _ __   _ __   / _|(_)  __ _  _   _  _ __  ___  ___
#   / _` || '_ \ | '_ \ | |_ | | / _` || | | || '__|/ _ \/ __|
#  | (_| || |_) || |_) ||  _|| || (_| || |_| || |  |  __/\__ \
#   \__,_|| .__/ | .__/ |_|  |_| \__, | \__,_||_|   \___||___/
#         |_|    |_|             |___/
#
#
# <summary>
#             1:11:20230223170600:4d74fb15eb23f465f1f6fcbf534e5877::6373
# X-APPLE-HC: 1:11:20230223170600:4d74fb15eb23f465f1f6fcbf534e5877::6373
#             ^  ^      ^                       ^                     ^
#             |  |      |                       |                     +-- Counter
#             |  |      |                       +-- Resource
#             |  |      +-- Date YYMMDD[hhmm[ss]]
#             |  +-- Bits (number of leading zeros)
#             +-- Version
#
# We can't use an off-the-shelf Hashcash because Apple's implementation is not quite the same as the spec/convention.
#  1. The spec calls for a nonce called "Rand" to be inserted between the Ext and Counter. They don't do that at all.
#  2. The Counter conventionally encoded as base-64 but Apple just uses the decimal number's string representation.
#
# Iterate from Counter=0 to Counter=N finding an N that makes the SHA1(X-APPLE-HC) lead with Bits leading zero bits
#
#
# We get the "Resource" from the X-Apple-HC-Challenge header and Bits from X-Apple-HC-Bits
#
# </summary>
*/
func MakeAppleHashCash(bits int, challenge string) string {
	version := 1
	date := time.Now().Format("20060102150405")

	counter := 0
	for {
		hc := fmt.Sprintf("%d:%d:%s:%s:%d", version, bits, date, challenge, counter)
		sha1hash := sha1.Sum([]byte(hc))
		sha1bits, _ := strconv.ParseInt(fmt.Sprintf("%08b", sha1hash[0]), 2, 64)
		if sha1bits < int64(bits) {
			return hc
		}
		counter++
	}
}
