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
		logging.Log().Warnf("Was not able to notify frontend. Err: %v", err)
	}
	go func() {
		defer wsConnection.Close()
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
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	sessions.Store(state, connection)
	connection.WriteJSON(gin.H{"type": "session"})

	go func() {
		defer connection.Close()
		for {
			_, _, err := connection.ReadMessage()
			if err != nil {
				sessions.Delete(state)
				break
			}
		}
	}()
}
