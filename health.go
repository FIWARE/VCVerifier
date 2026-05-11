package main

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/fiware/VCVerifier/logging"
	"github.com/gin-gonic/gin"
	"github.com/hellofresh/health-go/v5"
)

// healthCheckDBPingTimeout is the maximum time allowed for a database health check ping.
const healthCheckDBPingTimeout = 5 * time.Second

// healthCheckDBComponentName is the component name used when registering database health checks.
const healthCheckDBComponentName = "database"

// healthCheck is the global health check instance for the verifier server.
// Additional components can be registered via Health().
var healthCheck *health.Health

func init() {
	healthCheck, _ = health.New(health.WithComponent(health.Component{
		Name: "vcverifier",
	}))
}

// HealthReq is a Gin handler that returns the health check status of the verifier server.
// Returns HTTP 200 when healthy, HTTP 503 when unhealthy.
func HealthReq(c *gin.Context) {
	checkResult := healthCheck.Measure(c.Request.Context())
	if checkResult.Status == health.StatusOK {
		c.AbortWithStatusJSON(http.StatusOK, checkResult)
	} else {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, checkResult)
	}
}

// Health returns the global health check instance for the verifier server.
func Health() *health.Health {
	return healthCheck
}

// RegisterDBHealth adds a database ping check to the verifier's global health
// check instance. Safe to call once per unique database connection.
func RegisterDBHealth(db *sql.DB) {
	if err := healthCheck.Register(health.Config{
		Name:      healthCheckDBComponentName,
		Timeout:   healthCheckDBPingTimeout,
		SkipOnErr: false,
		Check: func(ctx context.Context) error {
			return db.PingContext(ctx)
		},
	}); err != nil {
		logging.Log().Errorf("Failed to register database health check: %v", err)
	}
}

// NewConfigServerHealth creates a new health check instance for the config server,
// including a database connectivity check that pings the given database connection.
func NewConfigServerHealth(db *sql.DB) *health.Health {
	h, _ := health.New(health.WithComponent(health.Component{
		Name: "config-server",
	}))
	if err := h.Register(health.Config{
		Name:      healthCheckDBComponentName,
		Timeout:   healthCheckDBPingTimeout,
		SkipOnErr: false,
		Check: func(ctx context.Context) error {
			return db.PingContext(ctx)
		},
	}); err != nil {
		logging.Log().Errorf("Failed to register config-server database health check: %v", err)
	}
	return h
}

// ConfigServerHealthReq returns a Gin handler that reports the health status of the
// config server, including its database connectivity.
func ConfigServerHealthReq(h *health.Health) gin.HandlerFunc {
	return func(c *gin.Context) {
		checkResult := h.Measure(c.Request.Context())
		if checkResult.Status == health.StatusOK {
			c.AbortWithStatusJSON(http.StatusOK, checkResult)
		} else {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, checkResult)
		}
	}
}
