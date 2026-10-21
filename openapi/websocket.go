package openapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fiware/VCVerifier/logging"
	"github.com/fiware/VCVerifier/verifier"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var (
	wsUpgrader = websocket.Upgrader{
		CheckOrigin: checkWebSocketOrigin,
	}
	sessions = sync.Map{} // map[string]*wsClient
	// additionalWebSocketOrigins holds the normalized server.webSocketAllowedOrigins. It is set
	// once at startup, before the server accepts connections.
	additionalWebSocketOrigins = map[string]struct{}{}
)

// SetAdditionalWebSocketOrigins configures the origins accepted for WebSocket upgrades on top
// of the verifier's own host. Every entry must be a bare http(s) origin; anything else, the
// "*" wildcard included, is a configuration error, since this channel must never be open.
// It returns the normalized origins, for logging.
func SetAdditionalWebSocketOrigins(origins []string) ([]string, error) {
	normalized := map[string]struct{}{}
	var accepted []string
	for _, origin := range origins {
		key, err := parseConfiguredOrigin(origin)
		if err != nil {
			return nil, err
		}
		if _, seen := normalized[key]; !seen {
			normalized[key] = struct{}{}
			accepted = append(accepted, key)
		}
	}
	additionalWebSocketOrigins = normalized
	return accepted, nil
}

func parseConfiguredOrigin(origin string) (string, error) {
	origin = strings.TrimSpace(origin)
	if origin == "*" {
		return "", errors.New("invalid server.webSocketAllowedOrigins entry \"*\": a wildcard is not allowed, list each origin explicitly")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return "", fmt.Errorf("invalid server.webSocketAllowedOrigins entry %q: %w", origin, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Hostname() == "" || u.User != nil ||
		strings.TrimSuffix(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid server.webSocketAllowedOrigins entry %q: expected an origin of the form http(s)://host[:port]", origin)
	}
	return normalizeOrigin(u), nil
}

// checkWebSocketOrigin restricts WebSocket upgrades to the verifier's own configured host,
// plus any origin explicitly listed in server.webSocketAllowedOrigins.
// Unlike the general CORS policy (ResolveAllowedOrigins in main.go), which defaults to "*"
// for API compatibility, this channel eventually hands over the authorization code needed
// to complete a login - it must never default to open. The only legitimate opener of this
// connection is the verifier's own frontend page, so the check is against the verifier's
// configured host, not against any request-supplied value.
func checkWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		logging.Log().Warnf("Rejected WebSocket upgrade for %s: no Origin header.", r.URL.RequestURI())
		return false
	}

	originURL, err := url.Parse(origin)
	if err != nil {
		logging.Log().Warnf("Rejected WebSocket upgrade for %s: unparseable Origin %q.", r.URL.RequestURI(), origin)
		return false
	}

	configuredHost := getFrontendVerifier().GetHost()
	allowedURL, err := url.Parse(configuredHost)
	if err != nil {
		logging.Log().Errorf("Was not able to parse the configured verifier host %q for the WebSocket origin check: %v", configuredHost, err)
		return false
	}

	allowedOrigin := normalizeOrigin(allowedURL)
	requestOrigin := normalizeOrigin(originURL)
	if requestOrigin == allowedOrigin {
		return true
	}
	if _, listed := additionalWebSocketOrigins[requestOrigin]; listed {
		return true
	}
	logging.Log().Warnf("Rejected WebSocket upgrade for %s: origin %q is neither the configured verifier host %q nor listed in server.webSocketAllowedOrigins.", r.URL.RequestURI(), origin, allowedOrigin)
	return false
}

// normalizeOrigin reduces a URL to the scheme://host:port triple that identifies a web origin.
// Scheme and host are lowercased and the port is made explicit, since browsers omit a default
// port in the Origin header while an operator may well configure it (https://verifier:443).
func normalizeOrigin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = defaultPorts[scheme]
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

var defaultPorts = map[string]string{"http": "80", "https": "443"}

// Keepalive timing for the login WebSocket. The browser sends nothing on this channel, so
// without pings a proxy or ingress closes it as idle (nginx after 60s by default) while the user
// is still getting their phone out, and a dead peer is never noticed. The ping period must stay
// below the shortest idle timeout of anything in between; a peer that answers no ping within
// wsPongWait is considered gone. Ping period and pong wait are set at startup from
// server.webSocketPingInterval / server.webSocketPongTimeout via SetWebSocketKeepAlive.
var (
	wsPingPeriod = 25 * time.Second
	wsPongWait   = 60 * time.Second
	wsWriteWait  = 10 * time.Second
)

// SetWebSocketKeepAlive configures the keepalive timing of the login WebSocket. Both values must
// be positive and the pong timeout must exceed the ping interval, otherwise a healthy connection
// would be dropped before its next ping could be answered. It must be called before the server
// accepts connections.
func SetWebSocketKeepAlive(pingInterval time.Duration, pongTimeout time.Duration) error {
	if pingInterval <= 0 || pongTimeout <= 0 {
		return fmt.Errorf("invalid WebSocket keepalive: server.webSocketPingInterval (%v) and server.webSocketPongTimeout (%v) must be positive", pingInterval, pongTimeout)
	}
	if pongTimeout <= pingInterval {
		return fmt.Errorf("invalid WebSocket keepalive: server.webSocketPongTimeout (%v) must be greater than server.webSocketPingInterval (%v)", pongTimeout, pingInterval)
	}
	wsPingPeriod = pingInterval
	wsPongWait = pongTimeout
	return nil
}

// wsMaxMessageSize bounds what a client may send - the frontend sends nothing but its
// authentication message and pongs.
const wsMaxMessageSize = 512

// wsCloseSessionInvalid is the close code for a connection that may not wait for the login
// session: the session no longer exists (expired or already completed) or the page did not
// present its secret. The page must not reconnect, as no reconnect can succeed.
const wsCloseSessionInvalid = 4403

// wsCloseReplaced is the close code for a connection replaced by a newer one of the same login
// page, e.g. the page duplicated into another tab. The page must not reconnect on its own, or the
// two would keep replacing each other.
const wsCloseReplaced = 4409

// Session binding modes for the login WebSocket (server.webSocketSessionBinding).
const (
	// a connection is registered only after it presented the login page's secret
	WebSocketBindingEnforce = "enforce"
	// a connection is registered at once; one that does not authenticate is logged
	WebSocketBindingWarn = "warn"
)

var (
	// wsSessionBinding is set once at startup via SetWebSocketSessionBinding.
	wsSessionBinding = WebSocketBindingEnforce
	// wsAuthTimeout is the time a new connection has to present the login page's secret.
	wsAuthTimeout = 5 * time.Second
)

// SetWebSocketSessionBinding configures whether the login WebSocket must present the login page's
// secret before it is registered. It must be called before the server accepts connections.
func SetWebSocketSessionBinding(mode string) error {
	switch mode {
	case WebSocketBindingEnforce, WebSocketBindingWarn:
		wsSessionBinding = mode
		return nil
	default:
		return fmt.Errorf("invalid server.webSocketSessionBinding %q: must be %q or %q", mode, WebSocketBindingEnforce, WebSocketBindingWarn)
	}
}

// wsAuthMessage is the first message the login page sends on every connection.
type wsAuthMessage struct {
	Type   string `json:"type"`
	Secret string `json:"secret"`
}

// wsClient is a login WebSocket connection. gorilla/websocket allows a single concurrent writer
// (control frames excepted), and the initial session message and the login notification are
// written from different goroutines, so data writes go through writeJSON. The timing is fixed
// per connection when it is opened.
type wsClient struct {
	conn       *websocket.Conn
	writeMu    sync.Mutex
	pingPeriod time.Duration
	pongWait   time.Duration
	writeWait  time.Duration
	// closed once the connection is closed, unregistered and its goroutines have finished
	closed chan struct{}
	// guarded by writeMu: the login result was written to the page, or the page was told that
	// it may no longer wait for it (session gone, connection replaced). Never both, so the page
	// does not get contradicting answers.
	notified bool
	rejected bool
	// guarded by writeMu: the connection presented the login page's secret
	authenticated bool
}

// errWebSocketRejected is returned for a login result that reaches a connection which was already
// told that it may no longer wait for it.
var errWebSocketRejected = errors.New("the WebSocket was closed by the verifier: its session is gone or a newer connection replaced it")

// errNoWebSocketConnection is returned when no page waits for the result of the session.
var errNoWebSocketConnection = errors.New("no WebSocket connection for the session")

func (c *wsClient) writeJSON(message interface{}) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeJSONLocked(message)
}

func (c *wsClient) writeJSONLocked(message interface{}) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.writeWait)); err != nil {
		return err
	}
	return c.conn.WriteJSON(message)
}

// deliverLogin writes the login result to the page, unless the page was rejected meanwhile.
func (c *wsClient) deliverLogin(message interface{}) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.rejected {
		return errWebSocketRejected
	}
	if err := c.writeJSONLocked(message); err != nil {
		return err
	}
	c.notified = true
	return nil
}

// rejectIfSessionGone rejects the connection if its login session no longer exists and no login
// result was delivered to it, and reports whether it did. The check runs under writeMu, so a
// result is either delivered before it - and the session being gone is expected - or fails after
// it, which releases the code again (see handleAuthenticationResponse).
// A connection that was already closed by the verifier counts as rejected too.
func (c *wsClient) rejectIfSessionGone(sessionId string) bool {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.rejected {
		return true
	}
	if c.notified || getFrontendVerifier().HasLoginSession(sessionId) {
		return false
	}
	c.rejected = true
	logging.Log().Infof("Rejected WebSocket for session %s: the session does not exist (expired, completed or never created).", sessionId)
	closeWebSocket(c.conn, sessionId, gin.H{"type": "error", "reason": "session_not_found"}, wsCloseSessionInvalid, "session_not_found")
	return true
}

// replace tells the page that the login continues on a newer connection and closes this one,
// unless it already got its answer.
func (c *wsClient) replace(sessionId string) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.notified || c.rejected {
		return
	}
	c.rejected = true
	logging.Log().Infof("WebSocket for session %s was replaced by a newer connection of its login page.", sessionId)
	closeWebSocket(c.conn, sessionId, gin.H{"type": "replaced"}, wsCloseReplaced, "replaced")
}

func (c *wsClient) isAuthenticated() bool {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.authenticated
}

// handleMessage processes a message the page sent after the connection was registered. Only an
// authentication message means anything: in warn mode the connection is registered before the
// page authenticated, and authenticates here.
func (c *wsClient) handleMessage(sessionId string, data []byte) {
	var message wsAuthMessage
	if err := json.Unmarshal(data, &message); err != nil || message.Type != "auth" || c.isAuthenticated() {
		return
	}
	if err := getFrontendVerifier().CheckLoginPageSecret(sessionId, message.Secret); err != nil {
		logging.Log().Warnf("WebSocket for session %s presented no valid page secret (%v); accepted because server.webSocketSessionBinding is %q.", sessionId, err, WebSocketBindingWarn)
		return
	}
	c.writeMu.Lock()
	c.authenticated = true
	c.writeMu.Unlock()
}

// keepAlive pings the client until done is closed or a ping cannot be written. WriteControl may
// be called concurrently with the other write methods, so it needs no lock.
func (c *wsClient) keepAlive(sessionId string, done <-chan struct{}) {
	ticker := time.NewTicker(c.pingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(c.writeWait)); err != nil {
				logging.Log().Debugf("Stopped pinging the WebSocket of session %s: %v", sessionId, err)
				return
			}
		}
	}
}

// sendRedirect notifies the browser waiting on the WebSocket that the login completed.
// sessionId is the verifier's own internal session id - it's what the WS connection was
// registered under (see WsHandler) and has nothing to do with the external OIDC client.
// externalState is that client's original state value, and is only ever used in the
// redirect URL handed back to the browser, never to look anything up.
// It returns an error if the page did not get the result.
func sendRedirect(sessionId string, externalState string, code string, redirectUrl string) error {
	connection, exists := sessions.Load(sessionId)
	if !exists {
		logging.Log().Warnf("No connection for session %s exists.", sessionId)
		return errNoWebSocketConnection
	}

	// The connection is closed and unregistered by WsHandler's reader once the browser leaves the
	// page, so nothing else is to be done here - in particular no second reader on it.
	err := connection.(*wsClient).deliverLogin(gin.H{"type": "authenticated", "redirectUrl": redirectUrl + "?state=" + externalState + "&code=" + code})
	if err != nil {
		logging.Log().Warnf("Was not able to notify the frontend for session %s. Err: %v", sessionId, err)
		return err
	}
	logging.Log().Infof("Notified session %s of successful authentication.", sessionId)
	return nil
}

// Categories of a rejected presentation, as shown on the login page. They are coarse on purpose:
// the exact error helps debugging, so it goes to the logs, but it would also tell anyone probing
// the verifier which check a forged presentation failed.
const (
	rejectionCredentialNotAccepted      = "credential_not_accepted"
	rejectionCredentialTypeNotRequested = "credential_type_not_requested"
	rejectionVerificationFailed         = "verification_failed"
)

// rejectionCategory maps the error a presentation was rejected with to what the page is told.
func rejectionCategory(err error) string {
	switch {
	case errors.Is(err, verifier.ErrorNoValidCredentialTypeProvided), errors.Is(err, verifier.ErrorVerficationContextSetup):
		return rejectionCredentialTypeNotRequested
	case errors.Is(err, verifier.ErrorInvalidVC):
		return rejectionCredentialNotAccepted
	default:
		return rejectionVerificationFailed
	}
}

// sendRejection tells the page that a presentation for its session was rejected, if the
// connection authenticated with the page secret and is still waiting. It reports whether it did.
func (c *wsClient) sendRejection(category string) (bool, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !c.authenticated || c.notified || c.rejected {
		return false, nil
	}
	return true, c.writeJSONLocked(gin.H{"type": "rejected", "reason": category})
}

// notifyRejected tells the page waiting for a login that a presentation for it was rejected,
// whether it failed while the vp_token was parsed or while it was verified. The session stays
// open, so the page keeps its QR code and the user can try again. A registered connection can
// outlive its session until the page notices, so nothing is sent for a session that is gone. Only a connection
// that presented the page secret is told - in warn mode an unauthenticated one may be registered,
// and anyone who knows the session id could otherwise read why presentations fail. Anyone can
// post a bad presentation for a session whose id they saw, so the page's wording stays neutral.
func notifyRejected(sessionId string, err error) {
	connection, exists := sessions.Load(sessionId)
	if !exists {
		return
	}
	if !getFrontendVerifier().HasLoginSession(sessionId) {
		logging.Log().Debugf("Did not tell the login page of session %s about a rejected presentation: the session no longer exists.", sessionId)
		return
	}
	category := rejectionCategory(err)
	sent, writeErr := connection.(*wsClient).sendRejection(category)
	switch {
	case writeErr != nil:
		logging.Log().Warnf("Was not able to tell the login page of session %s that a presentation was rejected. Err: %v", sessionId, writeErr)
	case sent:
		logging.Log().Infof("Told the login page of session %s that a presentation was rejected (%s).", sessionId, category)
	default:
		logging.Log().Debugf("Did not tell the login page of session %s about a rejected presentation: its connection is not authenticated or no longer waiting.", sessionId)
	}
}

// closeWebSocket tells the page why it may no longer wait for its login, then closes the
// connection with the given close code.
func closeWebSocket(connection *websocket.Conn, sessionId string, message gin.H, closeCode int, reason string) {
	defer func() { _ = connection.Close() }()

	_ = connection.SetWriteDeadline(time.Now().Add(wsWriteWait))
	if err := connection.WriteJSON(message); err != nil {
		logging.Log().Debugf("Was not able to tell the page of session %s why its WebSocket is closed (%s): %v", sessionId, reason, err)
		return
	}
	closeMessage := websocket.FormatCloseMessage(closeCode, reason)
	_ = connection.WriteControl(websocket.CloseMessage, closeMessage, time.Now().Add(wsWriteWait))
}

// authenticateWebSocket waits for the page's authentication message and checks its secret. It
// returns verifier.ErrorNoSuchSession for a session that no longer exists. A read that fails or
// times out leaves the connection unusable, so this is only for connections that are rejected
// when it fails.
func authenticateWebSocket(connection *websocket.Conn, sessionId string) error {
	connection.SetReadLimit(wsMaxMessageSize)
	_ = connection.SetReadDeadline(time.Now().Add(wsAuthTimeout))
	var message wsAuthMessage
	if err := connection.ReadJSON(&message); err != nil {
		return fmt.Errorf("no authentication message within %v: %w", wsAuthTimeout, err)
	}
	if message.Type != "auth" {
		return fmt.Errorf("the first message is %q, not an authentication message", message.Type)
	}
	return getFrontendVerifier().CheckLoginPageSecret(sessionId, message.Secret)
}

// warnIfUnauthenticated logs a connection that was registered in warn mode and did not present
// the login page's secret in time - with enforce it would have been rejected.
func warnIfUnauthenticated(client *wsClient, sessionId string) {
	time.AfterFunc(wsAuthTimeout, func() {
		select {
		case <-client.closed:
			return
		default:
		}
		if !client.isAuthenticated() {
			logging.Log().Warnf("WebSocket for session %s did not present the login page's secret within %v; accepted because server.webSocketSessionBinding is %q.", sessionId, wsAuthTimeout, WebSocketBindingWarn)
		}
	})
}

func WsHandler(c *gin.Context) {
	state, stateExists := c.GetQuery("state")
	if !stateExists {
		c.AbortWithStatusJSON(400, ErrorMessageNoState)
		// early exit
		return
	}

	connection, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	client := &wsClient{conn: connection, pingPeriod: wsPingPeriod, pongWait: wsPongWait, writeWait: wsWriteWait, closed: make(chan struct{})}

	// The session id is in the QR, so anyone who saw it can connect. Only the page that started
	// the login knows its secret, and only a connection that presents it may wait for the result.
	if wsSessionBinding == WebSocketBindingEnforce {
		if err := authenticateWebSocket(connection, state); err != nil {
			reason := "unauthorized"
			if errors.Is(err, verifier.ErrorNoSuchSession) {
				reason = "session_not_found"
				logging.Log().Infof("Rejected WebSocket for session %s: the session does not exist (expired, completed or never created).", state)
			} else {
				logging.Log().Warnf("Rejected WebSocket for session %s: %v", state, err)
			}
			closeWebSocket(connection, state, gin.H{"type": "error", "reason": reason}, wsCloseSessionInvalid, reason)
			return
		}
		client.authenticated = true
	}

	// The newest connection of the login page wins: a reconnect, or the page duplicated into
	// another tab. With enforce, only a holder of the page secret can get here.
	previous, replaced := sessions.Swap(state, client)

	// A page reconnecting after its session was completed (with the notification lost) or has
	// expired would otherwise keep showing a QR code that can only yield no_such_session. This is
	// checked only once the connection is registered: a login completing before the check finds
	// no session left, one completing after it finds this connection.
	if client.rejectIfSessionGone(state) {
		sessions.CompareAndDelete(state, client)
		if replaced {
			previous.(*wsClient).rejectIfSessionGone(state)
		}
		return
	}
	if replaced && previous != client {
		previous.(*wsClient).replace(state)
	}
	if client.authenticated {
		logging.Log().Infof("WebSocket connected for session %s.", state)
	} else {
		logging.Log().Infof("WebSocket connected for session %s, not yet authenticated (server.webSocketSessionBinding is %q).", state, WebSocketBindingWarn)
		warnIfUnauthenticated(client, state)
	}

	connection.SetReadLimit(wsMaxMessageSize)
	_ = connection.SetReadDeadline(time.Now().Add(client.pongWait))
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(time.Now().Add(client.pongWait))
	})

	done := make(chan struct{})
	keepAliveStopped := make(chan struct{})
	go func() {
		defer close(keepAliveStopped)
		client.keepAlive(state, done)
	}()
	go func() {
		defer func() {
			close(done)
			_ = connection.Close()
			<-keepAliveStopped
			// only unregister this connection - after a reconnect the entry is a newer one
			sessions.CompareAndDelete(state, client)
			close(client.closed)
		}()
		for {
			_, data, err := connection.ReadMessage()
			if err != nil {
				// the browser closing or leaving the page is routine; anything else - a missed
				// pong, a dropped connection - means it will have to reconnect
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
					logging.Log().Debugf("WebSocket for session %s was closed: %v", state, err)
				} else {
					logging.Log().Infof("WebSocket for session %s was lost: %v", state, err)
				}
				return
			}
			client.handleMessage(state, data)
		}
	}()

	if err := client.writeJSON(gin.H{"type": "session"}); err != nil {
		logging.Log().Warnf("Was not able to send session message for session %s. Err: %v", state, err)
	}
}
