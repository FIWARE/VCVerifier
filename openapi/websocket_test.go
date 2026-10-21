package openapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	"github.com/fiware/VCVerifier/verifier"
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

	frontendVerifier = &mockVerifier{mockHost: server.URL, mockPageSecret: testPageSecret}
	t.Cleanup(func() { frontendVerifier = nil })

	return func(sessionId string) *websocket.Conn {
		t.Helper()
		previous := registeredClient(sessionId)
		conn := dialWebSocket(t, server.URL, sessionId, testPageSecret)
		waitFor(t, func() bool { c := registeredClient(sessionId); return c != nil && c != previous }, "the connection was registered")
		awaitServerSide(t, sessionId, conn)
		return conn
	}
}

// awaitServerSide closes a registered connection when the test ends and waits for its server-side
// goroutines: they outlive the client, and must finish before the next test reconfigures shared
// state such as the logger.
func awaitServerSide(t *testing.T, sessionId string, conn *websocket.Conn) {
	t.Helper()
	client := registeredClient(sessionId)
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-client.closed:
		case <-time.After(3 * time.Second):
			t.Errorf("The server side of session %s did not shut down.", sessionId)
		}
	})
}

// testPageSecret is the login page secret the mock verifier accepts in the WebSocket tests.
const testPageSecret = "the-page-secret"

// dialWebSocket opens the login WebSocket of a session the way the login page does: from the
// verifier's own origin, presenting the page secret as its first message.
func dialWebSocket(t *testing.T, serverURL string, sessionId string, secret string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + serverURL[len("http"):] + "/ws?state=" + sessionId
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": {serverURL}})
	if err != nil {
		t.Fatalf("Expected the upgrade to succeed, got %v (status %v)", err, statusOf(resp))
	}
	if err := conn.WriteJSON(map[string]string{"type": "auth", "secret": secret}); err != nil {
		t.Fatalf("Expected the authentication message to be sent, got %v", err)
	}
	return conn
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

	if err := sendRedirect("redirect-session", "external-state", "the-code", "https://rp.example/callback"); err != nil {
		t.Fatalf("Expected the notification to be delivered, got %v", err)
	}

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

	frontendVerifier = &mockVerifier{mockHost: server.URL, mockPageSecret: testPageSecret, mockMissingSessions: map[string]bool{"gone-session": true}}
	t.Cleanup(func() { frontendVerifier = nil })

	conn := dialWebSocket(t, server.URL, "gone-session", testPageSecret)
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var message map[string]interface{}
	if err := conn.ReadJSON(&message); err != nil {
		t.Fatalf("Expected an error message, got err %v", err)
	}
	if message["type"] != "error" || message["reason"] != "session_not_found" {
		t.Errorf("Unexpected message %v", message)
	}

	_, _, err := conn.ReadMessage()
	if !websocket.IsCloseError(err, wsCloseSessionInvalid) {
		t.Errorf("Expected the connection to be closed with %d, got %v", wsCloseSessionInvalid, err)
	}
	if registeredClient("gone-session") != nil {
		t.Errorf("A connection to an unknown session must not be registered.")
	}
}

func TestSendRedirect_NoConnection(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	err := sendRedirect("no-such-session", "external-state", "the-code", "https://rp.example/callback")
	if !errors.Is(err, errNoWebSocketConnection) {
		t.Errorf("Expected %v, got %v", errNoWebSocketConnection, err)
	}
}

// TestHandleAuthenticationResponse_UndeliveredCodeIsReleased checks that a cross-device v2 login
// whose result cannot be handed to the browser releases the code - so the session is restored and
// the wallet can retry - and answers with an error rather than a success.
func TestHandleAuthenticationResponse_UndeliveredCodeIsReleased(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	gin.SetMode(gin.TestMode)

	mock := &mockVerifier{mockSameDevice: verifier.Response{FlowVersion: verifier.CROSS_DEVICE_V2, RedirectTarget: "https://rp.example/callback", Code: "the-code", ExternalState: "external-state"}}
	apiVerifier = mock
	t.Cleanup(func() { apiVerifier = nil })

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/authentication_response", nil)
	handleAuthenticationResponse(c, "unconnected-session", &common.Presentation{})

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", recorder.Code)
	}
	var body ErrorMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Summary != ErrorMessageNoWebsocketConnection.Summary {
		t.Errorf("Expected %v, got %s (err %v)", ErrorMessageNoWebsocketConnection, recorder.Body.String(), err)
	}
	if mock.releasedCodes["unconnected-session"] != "the-code" {
		t.Errorf("Expected the undelivered code to be released, released %v", mock.releasedCodes)
	}
}

func TestHandleAuthenticationResponse_DeliveredCodeIsKept(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	dial := startWsTestServer(t)
	conn := dial("delivered-session")
	var message map[string]interface{}
	if err := conn.ReadJSON(&message); err != nil || message["type"] != "session" {
		t.Fatalf("Expected the session message first, got %v (err %v)", message, err)
	}

	mock := &mockVerifier{mockSameDevice: verifier.Response{FlowVersion: verifier.CROSS_DEVICE_V2, RedirectTarget: "https://rp.example/callback", Code: "the-code", ExternalState: "external-state"}}
	apiVerifier = mock
	t.Cleanup(func() { apiVerifier = nil })

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/authentication_response", nil)
	handleAuthenticationResponse(c, "delivered-session", &common.Presentation{})

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}
	if len(mock.releasedCodes) != 0 {
		t.Errorf("A delivered code must not be released, released %v", mock.releasedCodes)
	}
	if err := conn.ReadJSON(&message); err != nil || message["type"] != "authenticated" {
		t.Errorf("Expected the authenticated message, got %v (err %v)", message, err)
	}
}

// TestWsHandler_SessionCompletingDuringCheck covers a login completing while the page connects:
// the connection is registered before the session is checked, and a result racing the rejection
// fails instead of reaching a page that was told its session is gone.
func TestWsHandler_SessionCompletingDuringCheck(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	// not startWsTestServer: its dialer waits for a registration, which a rejected connection
	// only has briefly
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ws", WsHandler)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	t.Cleanup(func() { frontendVerifier = nil })

	delivery := make(chan error, 1)
	mock := &mockVerifier{mockHost: server.URL, mockPageSecret: testPageSecret, mockMissingSessions: map[string]bool{}}
	frontendVerifier = mock
	mock.mockOnHasLoginSession = func(sessionId string) {
		// the wallet's response completes the session right after the page authenticated
		mock.mockMissingSessions[sessionId] = true
		client := registeredClient(sessionId)
		if client == nil {
			t.Errorf("The connection must be registered before the session is checked.")
			delivery <- errNoWebSocketConnection
			return
		}
		// sendRedirect found this connection; its write waits for the check
		go func() {
			delivery <- client.deliverLogin(gin.H{"type": "authenticated", "redirectUrl": "https://rp.example/callback?state=external-state&code=the-code"})
		}()
	}

	conn := dialWebSocket(t, server.URL, "racing-session", testPageSecret)
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var message map[string]interface{}
	if err := conn.ReadJSON(&message); err != nil || message["type"] != "error" {
		t.Fatalf("Expected the session_not_found error, got %v (err %v)", message, err)
	}
	if _, _, err := conn.ReadMessage(); !websocket.IsCloseError(err, wsCloseSessionInvalid) {
		t.Errorf("Expected the connection to be closed with %d, got %v", wsCloseSessionInvalid, err)
	}
	select {
	case err := <-delivery:
		if !errors.Is(err, errWebSocketRejected) {
			t.Errorf("Expected the racing result to fail with %v, got %v", errWebSocketRejected, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("The racing result was never answered.")
	}
	waitFor(t, func() bool { return registeredClient("racing-session") == nil }, "the rejected connection was unregistered")
}

// TestWsClient_NotRejectedAfterDelivery checks that a connection that got the login result is not
// told afterwards that its session is gone - the session is gone because the login completed.
func TestWsClient_NotRejectedAfterDelivery(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	dial := startWsTestServer(t)
	conn := dial("delivered-first")
	var message map[string]interface{}
	if err := conn.ReadJSON(&message); err != nil || message["type"] != "session" {
		t.Fatalf("Expected the session message first, got %v (err %v)", message, err)
	}

	if err := sendRedirect("delivered-first", "external-state", "the-code", "https://rp.example/callback"); err != nil {
		t.Fatalf("Expected the notification to be delivered, got %v", err)
	}
	frontendVerifier.(*mockVerifier).mockMissingSessions = map[string]bool{"delivered-first": true}

	if registeredClient("delivered-first").rejectIfSessionGone("delivered-first") {
		t.Errorf("A connection that got the login result must not be rejected.")
	}
}

// readUntilClosed reads the messages a connection gets until it is closed, and returns them with
// the close error.
func readUntilClosed(t *testing.T, conn *websocket.Conn) ([]map[string]interface{}, error) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var messages []map[string]interface{}
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return messages, err
		}
		var message map[string]interface{}
		_ = json.Unmarshal(data, &message)
		messages = append(messages, message)
	}
}

// TestWsHandler_SessionBinding covers the connections that may not wait for a login: whoever only
// knows the session id (it is in the QR code) gets an error and close code 4403 and is never
// registered, so the page's own connection keeps getting the result.
func TestWsHandler_SessionBinding(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	oldTimeout := wsAuthTimeout
	wsAuthTimeout = 200 * time.Millisecond
	t.Cleanup(func() { wsAuthTimeout = oldTimeout })

	tests := []struct {
		testName string
		send     func(conn *websocket.Conn)
	}{
		{"a wrong secret", func(conn *websocket.Conn) {
			_ = conn.WriteJSON(map[string]string{"type": "auth", "secret": "guessed"})
		}},
		{"no secret", func(conn *websocket.Conn) {
			_ = conn.WriteJSON(map[string]string{"type": "auth"})
		}},
		{"another first message", func(conn *websocket.Conn) {
			_ = conn.WriteJSON(map[string]string{"type": "session"})
		}},
		{"no message at all", func(conn *websocket.Conn) {}},
		{"a message that is not JSON", func(conn *websocket.Conn) {
			_ = conn.WriteMessage(websocket.TextMessage, []byte("hello"))
		}},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			dial := startWsTestServer(t)
			page := dial("bound-session")
			var message map[string]interface{}
			if err := page.ReadJSON(&message); err != nil || message["type"] != "session" {
				t.Fatalf("Expected the session message, got %v (err %v)", message, err)
			}
			pageClient := registeredClient("bound-session")

			serverURL := frontendVerifier.(*mockVerifier).mockHost
			wsURL := "ws" + serverURL[len("http"):] + "/ws?state=bound-session"
			intruder, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": {serverURL}})
			if err != nil {
				t.Fatalf("Expected the upgrade to succeed, got %v (status %v)", err, statusOf(resp))
			}
			defer func() { _ = intruder.Close() }()
			tc.send(intruder)

			messages, err := readUntilClosed(t, intruder)
			if len(messages) != 1 || messages[0]["type"] != "error" || messages[0]["reason"] != "unauthorized" {
				t.Errorf("Expected a single unauthorized error, got %v", messages)
			}
			if !websocket.IsCloseError(err, wsCloseSessionInvalid) {
				t.Errorf("Expected the connection to be closed with %d, got %v", wsCloseSessionInvalid, err)
			}
			if registeredClient("bound-session") != pageClient {
				t.Fatalf("A connection without the page secret must not replace the page's connection.")
			}

			if err := sendRedirect("bound-session", "external-state", "the-code", "https://rp.example/callback"); err != nil {
				t.Fatalf("Expected the result to be delivered to the page, got %v", err)
			}
			if err := page.ReadJSON(&message); err != nil || message["type"] != "authenticated" {
				t.Errorf("Expected the page to get the result, got %v (err %v)", message, err)
			}
		})
	}
}

// TestWsHandler_NewerTabTakesOver checks that a second connection with the page secret - the page
// duplicated into another tab - takes the login over, and that the older one is told so with close
// code 4409 instead of being dropped silently.
func TestWsHandler_NewerTabTakesOver(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	dial := startWsTestServer(t)

	first := dial("tab-session")
	var message map[string]interface{}
	if err := first.ReadJSON(&message); err != nil || message["type"] != "session" {
		t.Fatalf("Expected the session message, got %v (err %v)", message, err)
	}
	second := dial("tab-session")
	if err := second.ReadJSON(&message); err != nil || message["type"] != "session" {
		t.Fatalf("Expected the session message, got %v (err %v)", message, err)
	}

	messages, err := readUntilClosed(t, first)
	if len(messages) != 1 || messages[0]["type"] != "replaced" {
		t.Errorf("Expected the older tab to be told it was replaced, got %v", messages)
	}
	if !websocket.IsCloseError(err, wsCloseReplaced) {
		t.Errorf("Expected the older tab to be closed with %d, got %v", wsCloseReplaced, err)
	}

	if err := sendRedirect("tab-session", "external-state", "the-code", "https://rp.example/callback"); err != nil {
		t.Fatalf("Expected the result to be delivered, got %v", err)
	}
	if err := second.ReadJSON(&message); err != nil || message["type"] != "authenticated" {
		t.Errorf("Expected the newer tab to get the result, got %v (err %v)", message, err)
	}
}

// TestWsHandler_WarnMode checks the escape hatch for customised login pages: a connection is
// registered without the page secret, and one that presents it later is authenticated.
func TestWsHandler_WarnMode(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	if err := SetWebSocketSessionBinding(WebSocketBindingWarn); err != nil {
		t.Fatalf("Expected warn to be accepted, got %v", err)
	}
	t.Cleanup(func() { _ = SetWebSocketSessionBinding(WebSocketBindingEnforce) })
	dial := startWsTestServer(t)
	serverURL := frontendVerifier.(*mockVerifier).mockHost
	wsURL := "ws" + serverURL[len("http"):] + "/ws?state=warn-session"

	custom, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": {serverURL}})
	if err != nil {
		t.Fatalf("Expected the upgrade to succeed, got %v (status %v)", err, statusOf(resp))
	}
	var message map[string]interface{}
	_ = custom.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := custom.ReadJSON(&message); err != nil || message["type"] != "session" {
		_ = custom.Close()
		t.Fatalf("Expected a page that sends no secret to be registered, got %v (err %v)", message, err)
	}
	awaitServerSide(t, "warn-session", custom)
	if registeredClient("warn-session").isAuthenticated() {
		t.Errorf("A connection without the page secret must not count as authenticated.")
	}

	_ = custom.WriteJSON(map[string]string{"type": "auth", "secret": "guessed"})
	time.Sleep(50 * time.Millisecond)
	if registeredClient("warn-session").isAuthenticated() {
		t.Errorf("A wrong secret must not authenticate the connection.")
	}

	page := dial("warn-session")
	if err := page.ReadJSON(&message); err != nil || message["type"] != "session" {
		t.Fatalf("Expected the session message, got %v (err %v)", message, err)
	}
	waitFor(t, func() bool { return registeredClient("warn-session").isAuthenticated() }, "the page presenting its secret was authenticated")
}

func TestSetWebSocketSessionBinding(t *testing.T) {
	t.Cleanup(func() { _ = SetWebSocketSessionBinding(WebSocketBindingEnforce) })
	for _, mode := range []string{WebSocketBindingEnforce, WebSocketBindingWarn} {
		if err := SetWebSocketSessionBinding(mode); err != nil {
			t.Errorf("Expected %q to be accepted, got %v", mode, err)
		}
	}
	for _, mode := range []string{"", "off", "Enforce"} {
		if err := SetWebSocketSessionBinding(mode); err == nil {
			t.Errorf("Expected %q to be rejected", mode)
		}
	}
}

func TestRejectionCategory(t *testing.T) {
	tests := []struct {
		err      error
		expected string
	}{
		{verifier.ErrorInvalidVC, rejectionCredentialNotAccepted},
		{verifier.ErrorInvalidVCHolder, rejectionCredentialNotAccepted},
		{verifier.ErrorNoValidCredentialTypeProvided, rejectionCredentialTypeNotRequested},
		{verifier.ErrorVerficationContextSetup, rejectionCredentialTypeNotRequested},
		{errors.New("ld_proof_challenge_mismatch"), rejectionVerificationFailed},
		{errors.New("was not able to sign the token"), rejectionVerificationFailed},
	}
	for _, tc := range tests {
		if category := rejectionCategory(tc.err); category != tc.expected {
			t.Errorf("Expected %v to map to %s, got %s", tc.err, tc.expected, category)
		}
	}
}

// postAuthenticationResponse runs the wallet's authentication response for a session against a
// mock verifier answering with the given error, and returns the HTTP status.
func postAuthenticationResponse(t *testing.T, sessionId string, verifierErr error) int {
	t.Helper()
	apiVerifier = &mockVerifier{mockError: verifierErr}
	t.Cleanup(func() { apiVerifier = nil })
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/authentication_response", nil)
	handleAuthenticationResponse(c, sessionId, &common.Presentation{})
	return recorder.Code
}

// TestHandleAuthenticationResponse_RejectionReachesThePage checks that the page waiting for a
// login learns that a presentation was rejected - only as a coarse category - and keeps waiting,
// so the next presentation can still complete the login.
func TestHandleAuthenticationResponse_RejectionReachesThePage(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	dial := startWsTestServer(t)
	page := dial("rejected-session")
	var message map[string]interface{}
	if err := page.ReadJSON(&message); err != nil || message["type"] != "session" {
		t.Fatalf("Expected the session message, got %v (err %v)", message, err)
	}

	if status := postAuthenticationResponse(t, "rejected-session", verifier.ErrorInvalidVC); status != http.StatusBadRequest {
		t.Errorf("Expected the wallet to get 400, got %d", status)
	}
	_ = page.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := page.ReadJSON(&message); err != nil || message["type"] != "rejected" || message["reason"] != rejectionCredentialNotAccepted {
		t.Fatalf("Expected the page to be told about the rejection, got %v (err %v)", message, err)
	}

	if err := sendRedirect("rejected-session", "external-state", "the-code", "https://rp.example/callback"); err != nil {
		t.Fatalf("Expected the page to still wait for the login, got %v", err)
	}
	if err := page.ReadJSON(&message); err != nil || message["type"] != "authenticated" {
		t.Errorf("Expected the login result, got %v (err %v)", message, err)
	}
}

// TestHandleAuthenticationResponse_RejectionNotSent covers the answers no page is told about: a
// session that does not exist (or was just completed by a concurrent response), and a connection
// that did not present the page secret - which only exists with warn.
func TestHandleAuthenticationResponse_RejectionNotSent(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	t.Run("no such session", func(t *testing.T) {
		dial := startWsTestServer(t)
		page := dial("completed-session")
		var message map[string]interface{}
		if err := page.ReadJSON(&message); err != nil || message["type"] != "session" {
			t.Fatalf("Expected the session message, got %v (err %v)", message, err)
		}
		postAuthenticationResponse(t, "completed-session", verifier.ErrorNoSuchSession)
		if err := sendRedirect("completed-session", "external-state", "the-code", "https://rp.example/callback"); err != nil {
			t.Fatalf("Expected the result to be delivered, got %v", err)
		}
		if err := page.ReadJSON(&message); err != nil || message["type"] != "authenticated" {
			t.Errorf("Expected no rejection before the login result, got %v (err %v)", message, err)
		}
	})

	t.Run("unauthenticated connection", func(t *testing.T) {
		if err := SetWebSocketSessionBinding(WebSocketBindingWarn); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = SetWebSocketSessionBinding(WebSocketBindingEnforce) })
		startWsTestServer(t)
		serverURL := frontendVerifier.(*mockVerifier).mockHost
		wsURL := "ws" + serverURL[len("http"):] + "/ws?state=custom-session"
		custom, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": {serverURL}})
		if err != nil {
			t.Fatalf("Expected the upgrade to succeed, got %v (status %v)", err, statusOf(resp))
		}
		var message map[string]interface{}
		_ = custom.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err := custom.ReadJSON(&message); err != nil || message["type"] != "session" {
			_ = custom.Close()
			t.Fatalf("Expected the session message, got %v (err %v)", message, err)
		}
		awaitServerSide(t, "custom-session", custom)

		postAuthenticationResponse(t, "custom-session", verifier.ErrorInvalidVC)
		if err := sendRedirect("custom-session", "external-state", "the-code", "https://rp.example/callback"); err != nil {
			t.Fatalf("Expected the result to be delivered, got %v", err)
		}
		if err := custom.ReadJSON(&message); err != nil || message["type"] != "authenticated" {
			t.Errorf("An unauthenticated connection must not learn about rejections, got %v (err %v)", message, err)
		}
	})
}
