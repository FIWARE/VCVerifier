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
		defer conn.Close()
	})

	t.Run("cross-origin is rejected", func(t *testing.T) {
		header := http.Header{"Origin": {"https://attacker.example"}}
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
		if err == nil {
			conn.Close()
			t.Fatalf("Expected the upgrade to be rejected, got a successful connection")
		}
		if statusOf(resp) != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %v", statusOf(resp))
		}
	})

	t.Run("missing origin is rejected", func(t *testing.T) {
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err == nil {
			conn.Close()
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
