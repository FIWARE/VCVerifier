package config

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAllowedRedirectUri(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		wantErr bool
	}{
		{"an exact https uri", "https://rp.example/callback", false},
		{"an exact uri with a port and a query", "http://localhost:8080/callback?tenant=a", false},
		{"http with localhost", "http://localhost/callback", false},
		{"http with IPv4 loopback", "http://127.0.0.1:8080/callback", false},
		{"http with IPv6 loopback", "http://[::1]:8080/callback", false},
		{"http with a public host", "http://rp.example/callback", true},
		{"http with a private network host", "http://192.168.1.10/callback", true},
		{"a wildcard below a path", "https://rp.example/callback/*", false},
		{"a wildcard for the whole host", "https://rp.example/*", false},
		{"a star inside the path", "https://rp.example/*/callback", true},
		{"a star in the host", "https://*.rp.example/callback", true},
		{"a star without a slash before it", "https://rp.example/callback*", true},
		{"an encoded separator in a wildcard prefix", "https://rp.example/callback%2Ftenant/*", true},
		{"an encoded dot segment in a wildcard prefix", "https://rp.example/callback/%252e%252e/*", true},
		{"a path parameter in a wildcard prefix", "https://rp.example/callback;v=1/*", true},
		{"a path parameter in an exact entry", "https://rp.example/callback;v=1", false},
		{"a regular expression", "https://rp.example/.+", false},
		{"a relative uri", "/callback", true},
		{"another scheme", "openid4vp://callback", true},
		{"user info", "https://user@rp.example/callback", true},
		{"a fragment", "https://rp.example/callback#x", true},
		{"a wildcard with a query", "https://rp.example/callback/*?x=1", true},
		{"an empty entry", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAllowedRedirectUri(tc.entry)
			if tc.wantErr {
				assert.True(t, errors.Is(err, ErrorInvalidAllowedRedirectUri), "expected an invalid entry, got %v", err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRedirectUriAllowed(t *testing.T) {
	tests := []struct {
		name        string
		allowed     []string
		redirectUri string
		want        bool
	}{
		{"an exact match", []string{"https://rp.example/callback"}, "https://rp.example/callback", true},
		{"one of several entries", []string{"https://a.example/cb", "https://rp.example/callback"}, "https://rp.example/callback", true},
		{"an exact entry does not accept a longer path", []string{"https://rp.example/callback"}, "https://rp.example/callback/x", false},
		{"an exact entry does not accept a trailing slash", []string{"https://rp.example/callback"}, "https://rp.example/callback/", false},
		{"an exact entry is case sensitive", []string{"https://rp.example/callback"}, "https://rp.example/Callback", false},
		{"a path below a wildcard", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/tenant-a", true},
		{"a deeper path below a wildcard", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/a/b", true},
		{"the wildcard prefix itself", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/", true},
		{"a wildcard ignores the case of scheme and host", []string{"https://rp.example/callback/*"}, "HTTPS://RP.example/callback/a", true},
		{"a sibling path is not below the wildcard", []string{"https://rp.example/callback/*"}, "https://rp.example/callbackevil", false},
		{"the parent path is not below the wildcard", []string{"https://rp.example/callback/*"}, "https://rp.example/callback", false},
		{"another host with the entry's host as prefix", []string{"https://rp.example/*"}, "https://rp.example.evil.com/callback", false},
		{"another port", []string{"https://rp.example/*"}, "https://rp.example:8443/callback", false},
		{"another scheme", []string{"https://rp.example/*"}, "http://rp.example/callback", false},
		{"user info pointing elsewhere", []string{"https://rp.example/*"}, "https://rp.example@evil.com/callback", false},
		{"user info on the right host", []string{"https://rp.example/*"}, "https://user@rp.example/callback", false},
		{"a query below a wildcard", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/a?next=https://evil.com", false},
		{"a fragment below a wildcard", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/a#x", false},
		{"a dot segment leaving the prefix", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/../admin/redirect", false},
		{"an encoded dot segment", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/%2e%2e/admin", false},
		{"an encoded slash", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/a%2F..%2Fadmin", false},
		{"a double-encoded dot segment", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/%252e%252e/admin", false},
		{"a triple-encoded dot segment", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/%25252e%25252e/admin", false},
		{"a dot segment with a path parameter", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/..;/admin", false},
		{"a path parameter", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/a;jsessionid=x", false},
		{"an encoded path parameter", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/..%3b/admin", false},
		{"a double-encoded path parameter", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/..%253b/admin", false},
		{"a listed exact uri with a path parameter", []string{"https://rp.example/callback;v=1"}, "https://rp.example/callback;v=1", true},
		{"a double-encoded slash", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/a%252F..%252Fadmin", false},
		{"a backslash", []string{"https://rp.example/callback/*"}, "https://rp.example/callback/..\\admin", false},
		{"a regular expression is a literal", []string{"https://rp.example/.+"}, "https://rp.example/callback", false},
		{"an invalid entry matches nothing", []string{"https://*.rp.example/callback"}, "https://a.rp.example/callback", false},
		{"no redirect uri", []string{"https://rp.example/*"}, "", false},
		{"an empty list allows nothing by itself", []string{}, "https://rp.example/callback", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RedirectUriAllowed(tc.allowed, tc.redirectUri))
		})
	}
}

func TestValidateServicesAllowedRedirectUris(t *testing.T) {
	tests := []struct {
		name     string
		services []ConfiguredService
		wantErr  string
	}{
		{"no services", nil, ""},
		{"services without a list", []ConfiguredService{{Id: "a"}, {Id: "b", AllowedRedirectUris: []string{}}}, ""},
		{"valid entries", []ConfiguredService{{Id: "a", AllowedRedirectUris: []string{"https://rp.example/cb", "https://rp.example/t/*"}}}, ""},
		{"an invalid entry names its service", []ConfiguredService{{Id: "a"}, {Id: "b", AllowedRedirectUris: []string{"https://rp.example/cb", "https://*.rp.example/cb"}}}, `service "b"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateServicesAllowedRedirectUris(tc.services)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, ErrorInvalidAllowedRedirectUri)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
