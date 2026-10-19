package openapi

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/logging"
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

// startWsTestServer serves WsHandler on a real HTTP server, with the verifier host set to the
// server itself so the origin check passes, and returns a dialer for a given session id.
func startWsTestServer(t *testing.T) func(sessionId string) *websocket.Conn {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ws", WsHandler)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	frontendVerifier = &mockVerifier{mockHost: server.URL}
	t.Cleanup(func() { frontendVerifier = nil })

	return func(sessionId string) *websocket.Conn {
		t.Helper()
		previous := registeredClient(sessionId)
		wsURL := "ws" + server.URL[len("http"):] + "/ws?state=" + sessionId
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": {server.URL}})
		if err != nil {
			t.Fatalf("Expected the upgrade to succeed, got %v (status %v)", err, statusOf(resp))
		}
		waitFor(t, func() bool { c := registeredClient(sessionId); return c != nil && c != previous }, "the connection was registered")
		client := registeredClient(sessionId)
		// the server-side goroutines outlive the client; let them finish before the next test
		// reconfigures shared state such as the logger
		t.Cleanup(func() {
			_ = conn.Close()
			select {
			case <-client.closed:
			case <-time.After(3 * time.Second):
				t.Errorf("The server side of session %s did not shut down.", sessionId)
			}
		})
		return conn
	}
}

// withWsTiming shortens the keepalive timing for the duration of a test.
func withWsTiming(t *testing.T, pingPeriod, pongWait time.Duration) {
	t.Helper()
	oldPing, oldPong := wsPingPeriod, wsPongWait
	wsPingPeriod, wsPongWait = pingPeriod, pongWait
	t.Cleanup(func() { wsPingPeriod, wsPongWait = oldPing, oldPong })
}

// registeredClient returns the connection registered for a session, or nil.
func registeredClient(sessionId string) *wsClient {
	client, found := sessions.Load(sessionId)
	if !found {
		return nil
	}
	return client.(*wsClient)
}

func waitFor(t *testing.T, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("Timed out waiting until %s.", description)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWsHandler_PingsClient(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	withWsTiming(t, 20*time.Millisecond, time.Second)
	dial := startWsTestServer(t)

	conn := dial("ping-session")
	var pings atomic.Int32
	conn.SetPingHandler(func(appData string) error {
		pings.Add(1)
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
	})
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	waitFor(t, func() bool { return pings.Load() >= 3 }, "the server pinged the client repeatedly")
	if registeredClient("ping-session") == nil {
		t.Errorf("A client answering pings must stay registered.")
	}
}

func TestWsHandler_DropsUnresponsivePeer(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	withWsTiming(t, 20*time.Millisecond, 100*time.Millisecond)
	dial := startWsTestServer(t)

	// never reading means never answering a ping, like a peer whose network went away
	dial("silent-session")

	waitFor(t, func() bool { return registeredClient("silent-session") == nil }, "the unresponsive connection was unregistered")
}

func TestWsHandler_ReconnectKeepsNewerConnection(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	dial := startWsTestServer(t)

	first := dial("reconnect-session")
	firstClient := registeredClient("reconnect-session")

	second := dial("reconnect-session")
	secondClient := registeredClient("reconnect-session")
	if secondClient == firstClient {
		t.Fatalf("The reconnect did not replace the first connection.")
	}

	// the old connection going away must not unregister the newer one
	_ = first.Close()
	<-firstClient.closed
	if registeredClient("reconnect-session") != secondClient {
		t.Fatalf("Closing the replaced connection unregistered the current one.")
	}

	_ = second.Close()
	waitFor(t, func() bool { return registeredClient("reconnect-session") == nil }, "the current connection was unregistered after closing")
}

func TestSendRedirect_DeliversWhileKeepAliveRuns(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	// ping as fast as possible, so the notification is written while pings are in flight
	withWsTiming(t, time.Millisecond, time.Second)
	dial := startWsTestServer(t)

	conn := dial("redirect-session")
	var message map[string]interface{}
	if err := conn.ReadJSON(&message); err != nil || message["type"] != "session" {
		t.Fatalf("Expected the session message first, got %v (err %v)", message, err)
	}

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	sendRedirect(c, "redirect-session", "external-state", "the-code", "https://rp.example/callback")

	if err := conn.ReadJSON(&message); err != nil {
		t.Fatalf("Expected the authenticated message, got err %v", err)
	}
	if message["type"] != "authenticated" || message["redirectUrl"] != "https://rp.example/callback?state=external-state&code=the-code" {
		t.Errorf("Unexpected notification %v", message)
	}
}

func TestSetWebSocketKeepAlive(t *testing.T) {
	tests := []struct {
		testName     string
		pingInterval time.Duration
		pongTimeout  time.Duration
		expectError  bool
	}{
		{"the defaults are accepted", 25 * time.Second, 60 * time.Second, false},
		{"a short interval for a strict proxy is accepted", 10 * time.Second, 20 * time.Second, false},
		{"a zero ping interval is rejected", 0, 60 * time.Second, true},
		{"a zero pong timeout is rejected", 25 * time.Second, 0, true},
		{"a negative value is rejected", -1 * time.Second, 60 * time.Second, true},
		{"a pong timeout equal to the interval is rejected", 30 * time.Second, 30 * time.Second, true},
		{"a pong timeout below the interval is rejected", 60 * time.Second, 25 * time.Second, true},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			withWsTiming(t, wsPingPeriod, wsPongWait)
			err := SetWebSocketKeepAlive(tc.pingInterval, tc.pongTimeout)
			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected an error for interval %v and timeout %v.", tc.pingInterval, tc.pongTimeout)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if wsPingPeriod != tc.pingInterval || wsPongWait != tc.pongTimeout {
				t.Errorf("Expected interval %v and timeout %v to be applied, got %v and %v.", tc.pingInterval, tc.pongTimeout, wsPingPeriod, wsPongWait)
			}
		})
	}
}

func TestWsHandler_RejectsUnknownSession(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ws", WsHandler)
	server := httptest.NewServer(router)
	defer server.Close()

	frontendVerifier = &mockVerifier{mockHost: server.URL, mockMissingSessions: map[string]bool{"gone-session": true}}
	t.Cleanup(func() { frontendVerifier = nil })

	wsURL := "ws" + server.URL[len("http"):] + "/ws?state=gone-session"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": {server.URL}})
	if err != nil {
		t.Fatalf("Expected the upgrade to succeed so the page can be told why, got %v (status %v)", err, statusOf(resp))
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var message map[string]interface{}
	if err := conn.ReadJSON(&message); err != nil {
		t.Fatalf("Expected an error message, got err %v", err)
	}
	if message["type"] != "error" || message["reason"] != "session_not_found" {
		t.Errorf("Unexpected message %v", message)
	}

	_, _, err = conn.ReadMessage()
	if !websocket.IsCloseError(err, wsCloseSessionInvalid) {
		t.Errorf("Expected the connection to be closed with %d, got %v", wsCloseSessionInvalid, err)
	}
	if registeredClient("gone-session") != nil {
		t.Errorf("A connection to an unknown session must not be registered.")
	}
}
