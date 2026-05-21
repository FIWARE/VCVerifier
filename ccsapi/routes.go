package ccsapi

import (
	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/database"
	"github.com/gin-gonic/gin"
)

// RegisterRoutes registers all CCS API routes on the given Gin engine.
// Routes are registered under the /service path prefix, matching the
// Credentials Config Service OpenAPI specification:
//
//	POST   /service          — Create a new service
//	GET    /service          — List services (paginated)
//	GET    /service/:id      — Get a single service
//	PUT    /service/:id      — Update a service
//	DELETE /service/:id      — Delete a service
//	GET    /service/:id/scope — Get credential types for a scope
//
// When notifier is non-nil, write operations (create, update, delete) trigger
// an immediate cache refresh via notifier.NotifyConfigUpdate().
func RegisterRoutes(router *gin.Engine, repo database.ServiceRepository, notifier common.ConfigUpdateNotifier) {
	router.POST("/service", CreateService(repo, notifier))
	router.GET("/service", GetAllServices(repo))
	router.GET("/service/:id", GetService(repo))
	router.PUT("/service/:id", UpdateService(repo, notifier))
	router.DELETE("/service/:id", DeleteService(repo, notifier))
	router.GET("/service/:id/scope", GetServiceScopes(repo))
}
