package openapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func TestCheckWebSocketOrigin(t *testing.T) {
	tests := []struct {
		testName     string
		mockHost     string
		originHeader string
		expected     bool
	}{
		{"matching scheme and host is allowed", "https://verifier.dev.seamware.io", "https://verifier.dev.seamware.io", true},
		{"matching scheme and host with different case is allowed", "https://verifier.dev.seamware.io", "https://Verifier.Dev.Seamware.IO", true},
		{"different host is rejected", "https://verifier.dev.seamware.io", "https://attacker.example", false},
		{"different scheme is rejected", "https://verifier.dev.seamware.io", "http://verifier.dev.seamware.io", false},
		{"missing Origin header is rejected", "https://verifier.dev.seamware.io", "", false},
		{"unparseable Origin is rejected", "https://verifier.dev.seamware.io", "not a url\x7f", false},
		{"unparseable configured host is rejected", "not a url\x7f", "https://verifier.dev.seamware.io", false},
		{"a configured host with a path prefix still matches on scheme+host", "https://verifier.dev.seamware.io/myservice", "https://verifier.dev.seamware.io", true},
		{"a configured default https port matches an Origin without it", "https://verifier.dev.seamware.io:443", "https://verifier.dev.seamware.io", true},
		{"a configured default http port matches an Origin without it", "http://verifier.dev.seamware.io:80", "http://verifier.dev.seamware.io", true},
		{"an explicit default port in the Origin matches a configured host without it", "https://verifier.dev.seamware.io", "https://verifier.dev.seamware.io:443", true},
		{"a matching non-default port is allowed", "https://verifier.dev.seamware.io:8443", "https://verifier.dev.seamware.io:8443", true},
		{"a different port is rejected", "https://verifier.dev.seamware.io:8443", "https://verifier.dev.seamware.io", false},
		{"the http default port does not carry over to https", "https://verifier.dev.seamware.io:80", "https://verifier.dev.seamware.io", false},
		{"an IPv6 host with a default port matches", "https://[::1]:443", "https://[::1]", true},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			frontendVerifier = &mockVerifier{mockHost: tc.mockHost}
			t.Cleanup(func() { frontendVerifier = nil })

			req := httptest.NewRequest(http.MethodGet, "/ws", nil)
			if tc.originHeader != "" {
				req.Header.Set("Origin", tc.originHeader)
			}

			if got := checkWebSocketOrigin(req); got != tc.expected {
				t.Errorf("checkWebSocketOrigin() = %v, want %v", got, tc.expected)
			}
		})
	}
}

// TestWsHandler_RejectsCrossOriginUpgrade drives the handshake through a real HTTP server,
// since the gorilla/websocket upgrade needs a hijackable connection that httptest.Recorder
// doesn't provide.
func TestWsHandler_RejectsCrossOriginUpgrade(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ws", WsHandler)

	server := httptest.NewServer(router)
	defer server.Close()

	frontendVerifier = &mockVerifier{mockHost: server.URL}
	t.Cleanup(func() { frontendVerifier = nil })

	wsURL := "ws" + server.URL[len("http"):] + "/ws?state=some-state"

	t.Run("matching origin is accepted", func(t *testing.T) {
		header := http.Header{"Origin": {server.URL}}
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
		if err != nil {
			t.Fatalf("Expected the upgrade to succeed, got %v (status %v)", err, statusOf(resp))
		}
		defer func() { _ = conn.Close() }()
	})

	t.Run("cross-origin is rejected", func(t *testing.T) {
		header := http.Header{"Origin": {"https://attacker.example"}}
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("Expected the upgrade to be rejected, got a successful connection")
		}
		if statusOf(resp) != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %v", statusOf(resp))
		}
	})

	t.Run("missing origin is rejected", func(t *testing.T) {
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("Expected the upgrade to be rejected, got a successful connection")
		}
		if statusOf(resp) != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %v", statusOf(resp))
		}
	})
}

func statusOf(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

func TestCheckWebSocketOrigin_AdditionalOrigins(t *testing.T) {
	const configuredHost = "https://verifier.dev.seamware.io"

	tests := []struct {
		testName          string
		additionalOrigins []string
		originHeader      string
		expected          bool
	}{
		{"the configured host is still allowed", []string{"https://login.example.org"}, configuredHost, true},
		{"a listed alias is allowed", []string{"https://login.example.org"}, "https://login.example.org", true},
		{"a listed alias matches regardless of case and default port", []string{"HTTPS://Login.Example.org:443"}, "https://login.example.org", true},
		{"an alias that is not listed is rejected", []string{"https://login.example.org"}, "https://other.example.org", false},
		{"a listed alias with a different scheme is rejected", []string{"https://login.example.org"}, "http://login.example.org", false},
		{"a listed alias with a different port is rejected", []string{"https://login.example.org:8443"}, "https://login.example.org", false},
		{"without additional origins an alias is rejected", nil, "https://login.example.org", false},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			frontendVerifier = &mockVerifier{mockHost: configuredHost}
			t.Cleanup(func() { frontendVerifier = nil })
			if _, err := SetAdditionalWebSocketOrigins(tc.additionalOrigins); err != nil {
				t.Fatalf("Unexpected error configuring additional origins: %v", err)
			}
			t.Cleanup(func() { _, _ = SetAdditionalWebSocketOrigins(nil) })

			req := httptest.NewRequest(http.MethodGet, "/ws", nil)
			req.Header.Set("Origin", tc.originHeader)

			if got := checkWebSocketOrigin(req); got != tc.expected {
				t.Errorf("checkWebSocketOrigin() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestSetAdditionalWebSocketOrigins(t *testing.T) {
	tests := []struct {
		testName    string
		origins     []string
		expected    []string
		expectError bool
	}{
		{"no origins", nil, nil, false},
		{"origins are normalized and deduplicated", []string{"https://Login.Example.org", "https://login.example.org:443/", "http://alias.example.org:8080"}, []string{"https://login.example.org:443", "http://alias.example.org:8080"}, false},
		{"surrounding whitespace is ignored", []string{"  https://login.example.org  "}, []string{"https://login.example.org:443"}, false},
		{"a wildcard is rejected", []string{"*"}, nil, true},
		{"a missing scheme is rejected", []string{"login.example.org"}, nil, true},
		{"a non-http scheme is rejected", []string{"wss://login.example.org"}, nil, true},
		{"a path is rejected", []string{"https://login.example.org/login"}, nil, true},
		{"a query is rejected", []string{"https://login.example.org?x=1"}, nil, true},
		{"a fragment is rejected", []string{"https://login.example.org#x"}, nil, true},
		{"userinfo is rejected", []string{"https://user@login.example.org"}, nil, true},
		{"an unparseable entry is rejected", []string{"https://login.example.org\x7f"}, nil, true},
		{"one invalid entry rejects the whole list", []string{"https://login.example.org", "*"}, nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Cleanup(func() { _, _ = SetAdditionalWebSocketOrigins(nil) })

			got, err := SetAdditionalWebSocketOrigins(tc.origins)
			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected an error, got origins %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(got) != len(tc.expected) {
				t.Fatalf("SetAdditionalWebSocketOrigins() = %v, want %v", got, tc.expected)
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					t.Errorf("SetAdditionalWebSocketOrigins() = %v, want %v", got, tc.expected)
				}
			}
		})
	}
}
