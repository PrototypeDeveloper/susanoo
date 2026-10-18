package flow

import (
	"bytes"
	"net"
	"strings"
)

const maxHTTPHeader = 8192

var httpMethods = []string{"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"}

// parseHTTPRequest は平文の HTTP の要求の先頭から、メソッドと Host を取り出す。
// 要求の行で始まらなければ ok は false。ヘッダーの終わりまで届いていなければ more が true。
func parseHTTPRequest(b []byte) (method, host string, ok, more bool) {
	if len(b) > maxHTTPHeader {
		b = b[:maxHTTPHeader]
	}
	sp := bytes.IndexByte(b, ' ')
	if sp <= 0 {
		return "", "", false, len(b) < 8 && couldBeMethod(b)
	}
	m := string(b[:sp])
	known := false
	for _, k := range httpMethods {
		if m == k {
			known = true
		}
	}
	if !known {
		return "", "", false, false
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		return m, "", true, len(b) < maxHTTPHeader
	}
	for _, line := range bytes.Split(b[:end], []byte("\r\n"))[1:] {
		name, value, found := bytes.Cut(line, []byte(":"))
		if found && strings.EqualFold(string(bytes.TrimSpace(name)), "host") {
			h := string(bytes.TrimSpace(value))
			if hp, _, err := net.SplitHostPort(h); err == nil {
				h = hp
			}
			return m, sanitizeHost(h), true, false
		}
	}
	return m, "", true, false
}

func couldBeMethod(b []byte) bool {
	for _, k := range httpMethods {
		if strings.HasPrefix(k, string(b)) {
			return true
		}
	}
	return false
}
