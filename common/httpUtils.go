package common

import (
	"net/http"
	"strings"
)

func BuildUrlString(address string, path string) string {
	if strings.HasSuffix(address, "/") {
		if strings.HasPrefix(path, "/") {
			return address + strings.TrimPrefix(path, "/")
		} else {
			return address + path
		}
	} else {
		if strings.HasPrefix(path, "/") {
			return address + path
		} else {
			return address + "/" + path
		}
	}
}

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}
