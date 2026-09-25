package openapi

import (
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
)

// checkWebSocketOrigin restricts WebSocket upgrades to the verifier's own configured host.
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

	allowed := strings.EqualFold(originURL.Scheme, allowedURL.Scheme) && strings.EqualFold(originURL.Host, allowedURL.Host)
	if !allowed {
		logging.Log().Warnf("Rejected WebSocket upgrade for %s: origin %q does not match the configured verifier host %q.", r.URL.RequestURI(), origin, allowedURL.Scheme+"://"+allowedURL.Host)
	}
	return allowed
}

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
