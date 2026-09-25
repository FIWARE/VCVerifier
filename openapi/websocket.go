package openapi

import (
	"net/http"
	"sync"

	"github.com/fiware/VCVerifier/logging"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var (
	wsUpgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	sessions = sync.Map{} // map[string]*websocket.Conn
)

// sendRedirect notifies the browser waiting on the WebSocket that the login completed.
// sessionId is the verifier's own internal session id - it's what the WS connection was
// registered under (see WsHandler) and has nothing to do with the external OIDC client.
// externalState is that client's original state value, and is only ever used in the
// redirect URL handed back to the browser, never to look anything up.
func sendRedirect(c *gin.Context, sessionId string, externalState string, code string, redirectUrl string) {
	connection, exists := sessions.Load(sessionId)
	if !exists {
		logging.Log().Warnf("No connection for session %s exists.", sessionId)
		c.Copy().AbortWithStatusJSON(500, ErrorMessageNoWebsocketConnection)
		return
	}
	wsConnection := connection.(*websocket.Conn)

	err := wsConnection.WriteJSON(gin.H{"type": "authenticated", "redirectUrl": redirectUrl + "?state=" + externalState + "&code=" + code})
	if err != nil {
		logging.Log().Warnf("Was not able to notify frontend for session %s. Err: %v", sessionId, err)
	}
	go func() {
		defer func() { _ = wsConnection.Close() }()
		for {
			_, _, err := wsConnection.ReadMessage()
			if err != nil {
				sessions.Delete(sessionId)
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
	if err := connection.WriteJSON(gin.H{"type": "session"}); err != nil {
		logging.Log().Warnf("Was not able to send session message to frontend. Err: %v", err)
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
