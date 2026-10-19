package openapi

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/fiware/VCVerifier/logging"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var (
	wsUpgrader = websocket.Upgrader{
		CheckOrigin: checkWebSocketOrigin,
	}
	sessions = sync.Map{} // map[string]*websocket.Conn
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

func sendRedirect(c *gin.Context, state string, code string, redirectUrl string) {
	connection, exists := sessions.Load(state)
	if !exists {
		logging.Log().Warnf("No connection for %s exists.", state)
		c.Copy().AbortWithStatusJSON(500, ErrorMessageNoWebsocketConnection)
		return
	}
	wsConnection := connection.(*websocket.Conn)

	err := wsConnection.WriteJSON(gin.H{"type": "authenticated", "redirectUrl": redirectUrl + "?state=" + state + "&code=" + code})
	if err != nil {
		logging.Log().Warnf("Was not able to notify the frontend for session %s. Err: %v", state, err)
	} else {
		logging.Log().Infof("Notified session %s of successful authentication.", state)
	}
	go func() {
		defer func() { _ = wsConnection.Close() }()
		for {
			_, _, err := wsConnection.ReadMessage()
			if err != nil {
				sessions.Delete(state)
				break
			}
		}
	}()
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
	sessions.Store(state, connection)
	logging.Log().Infof("WebSocket connected for session %s.", state)
	if err := connection.WriteJSON(gin.H{"type": "session"}); err != nil {
		logging.Log().Warnf("Was not able to send session message for session %s. Err: %v", state, err)
	}

	go func() {
		defer func() { _ = connection.Close() }()
		for {
			_, _, err := connection.ReadMessage()
			if err != nil {
				sessions.Delete(state)
				break
			}
		}
	}()
}
