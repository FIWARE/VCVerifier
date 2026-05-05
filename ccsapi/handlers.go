package ccsapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
	"github.com/fiware/VCVerifier/logging"
	"github.com/gin-gonic/gin"
)

// Problem type URIs used in ProblemDetails responses.
const (
	// ProblemTypeValidation is the problem type for request validation failures.
	ProblemTypeValidation = "https://fiware.github.io/VCVerifier/problem/validation-error"
	// ProblemTypeNotFound is the problem type for resource-not-found errors.
	ProblemTypeNotFound = "https://fiware.github.io/VCVerifier/problem/not-found"
	// ProblemTypeConflict is the problem type for resource-already-exists errors.
	ProblemTypeConflict = "https://fiware.github.io/VCVerifier/problem/conflict"
	// ProblemTypeInternal is the problem type for unexpected server errors.
	ProblemTypeInternal = "https://fiware.github.io/VCVerifier/problem/internal-error"
)

// CreateService returns a Gin handler that creates a new service configuration.
// POST /service
//
// On success, returns 201 Created with a Location header pointing to the new
// resource. Returns 400 for invalid input, 409 if the service ID already exists.
func CreateService(repo database.ServiceRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ServiceRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			respondProblem(c, http.StatusBadRequest, ProblemTypeValidation,
				"Invalid request body", fmt.Sprintf("Failed to parse request body: %s", err.Error()))
			return
		}

		if err := validateServiceRequest(req, true); err != nil {
			respondProblem(c, http.StatusBadRequest, ProblemTypeValidation,
				"Validation error", err.Error())
			return
		}

		svc := ServiceRequestToConfiguredService(req, req.ID)
		if err := repo.CreateService(c.Request.Context(), svc); err != nil {
			if errors.Is(err, database.ErrServiceAlreadyExists) {
				respondProblem(c, http.StatusConflict, ProblemTypeConflict,
					"Service already exists",
					fmt.Sprintf("A service with id %q already exists.", req.ID))
				return
			}
			logging.Log().Errorf("Failed to create service %q: %v", req.ID, err)
			respondProblem(c, http.StatusInternalServerError, ProblemTypeInternal,
				"Internal server error", "Failed to create the service.")
			return
		}

		location := fmt.Sprintf("/service/%s", req.ID)
		c.Header("Location", location)
		c.JSON(http.StatusCreated, ConfiguredServiceToResponse(svc))
	}
}

// GetAllServices returns a Gin handler that lists services with pagination.
// GET /service?page=0&pageSize=100
//
// Returns 200 with a ServicesListResponse containing the requested page.
func GetAllServices(repo database.ServiceRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, err := parseIntQueryParam(c, "page", DefaultPage)
		if err != nil {
			respondProblem(c, http.StatusBadRequest, ProblemTypeValidation,
				"Invalid page parameter", err.Error())
			return
		}

		pageSize, err := parseIntQueryParam(c, "pageSize", DefaultPageSize)
		if err != nil {
			respondProblem(c, http.StatusBadRequest, ProblemTypeValidation,
				"Invalid pageSize parameter", err.Error())
			return
		}

		services, total, err := repo.GetAllServices(c.Request.Context(), page, pageSize)
		if err != nil {
			logging.Log().Errorf("Failed to list services: %v", err)
			respondProblem(c, http.StatusInternalServerError, ProblemTypeInternal,
				"Internal server error", "Failed to retrieve services.")
			return
		}

		c.JSON(http.StatusOK, ServicesListResponse{
			Total:      total,
			PageNumber: page,
			PageSize:   pageSize,
			Services:   ConfiguredServicesToResponses(services),
		})
	}
}

// GetService returns a Gin handler that retrieves a single service by ID.
// GET /service/:id
//
// Returns 200 with the service or 404 if not found.
func GetService(repo database.ServiceRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")

		svc, err := repo.GetService(c.Request.Context(), id)
		if err != nil {
			if errors.Is(err, database.ErrServiceNotFound) {
				respondProblem(c, http.StatusNotFound, ProblemTypeNotFound,
					"Service not found",
					fmt.Sprintf("No service with id %q exists.", id))
				return
			}
			logging.Log().Errorf("Failed to get service %q: %v", id, err)
			respondProblem(c, http.StatusInternalServerError, ProblemTypeInternal,
				"Internal server error", "Failed to retrieve the service.")
			return
		}

		c.JSON(http.StatusOK, ConfiguredServiceToResponse(svc))
	}
}

// UpdateService returns a Gin handler that replaces an existing service.
// PUT /service/:id
//
// Returns 200 with the updated service, 400 for invalid input, or 404 if not found.
func UpdateService(repo database.ServiceRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")

		var req ServiceRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			respondProblem(c, http.StatusBadRequest, ProblemTypeValidation,
				"Invalid request body", fmt.Sprintf("Failed to parse request body: %s", err.Error()))
			return
		}

		if err := validateServiceRequest(req, false); err != nil {
			respondProblem(c, http.StatusBadRequest, ProblemTypeValidation,
				"Validation error", err.Error())
			return
		}

		svc := ServiceRequestToConfiguredService(req, id)
		updated, err := repo.UpdateService(c.Request.Context(), id, svc)
		if err != nil {
			if errors.Is(err, database.ErrServiceNotFound) {
				respondProblem(c, http.StatusNotFound, ProblemTypeNotFound,
					"Service not found",
					fmt.Sprintf("No service with id %q exists.", id))
				return
			}
			logging.Log().Errorf("Failed to update service %q: %v", id, err)
			respondProblem(c, http.StatusInternalServerError, ProblemTypeInternal,
				"Internal server error", "Failed to update the service.")
			return
		}

		c.JSON(http.StatusOK, ConfiguredServiceToResponse(updated))
	}
}

// DeleteService returns a Gin handler that removes a service by ID.
// DELETE /service/:id
//
// Returns 204 on success or 404 if not found.
func DeleteService(repo database.ServiceRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")

		if err := repo.DeleteService(c.Request.Context(), id); err != nil {
			if errors.Is(err, database.ErrServiceNotFound) {
				respondProblem(c, http.StatusNotFound, ProblemTypeNotFound,
					"Service not found",
					fmt.Sprintf("No service with id %q exists.", id))
				return
			}
			logging.Log().Errorf("Failed to delete service %q: %v", id, err)
			respondProblem(c, http.StatusInternalServerError, ProblemTypeInternal,
				"Internal server error", "Failed to delete the service.")
			return
		}

		c.Status(http.StatusNoContent)
	}
}

// GetServiceScopes returns a Gin handler that retrieves credential types for a
// service's scope.
// GET /service/:id/scope?oidcScope=<scope>
//
// When oidcScope is omitted, the service's default scope is used. Returns 200
// with a JSON array of credential type strings, or 404 if the service or scope
// is not found.
func GetServiceScopes(repo database.ServiceRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")

		var oidcScope *string
		if scopeParam := c.Query("oidcScope"); scopeParam != "" {
			oidcScope = &scopeParam
		}

		types, err := repo.GetServiceScopes(c.Request.Context(), id, oidcScope)
		if err != nil {
			if errors.Is(err, database.ErrServiceNotFound) {
				respondProblem(c, http.StatusNotFound, ProblemTypeNotFound,
					"Service not found",
					fmt.Sprintf("No service with id %q exists.", id))
				return
			}
			if errors.Is(err, config.ErrorNoSuchScope) {
				respondProblem(c, http.StatusNotFound, ProblemTypeNotFound,
					"Scope not found",
					fmt.Sprintf("The requested scope does not exist for service %q.", id))
				return
			}
			logging.Log().Errorf("Failed to get scopes for service %q: %v", id, err)
			respondProblem(c, http.StatusInternalServerError, ProblemTypeInternal,
				"Internal server error", "Failed to retrieve service scopes.")
			return
		}

		c.JSON(http.StatusOK, types)
	}
}

// validateServiceRequest checks that the required fields are present in a
// ServiceRequest. When requireID is true, the ID field must be non-empty
// (used for POST; PUT takes the ID from the URL path).
func validateServiceRequest(req ServiceRequest, requireID bool) error {
	if requireID && req.ID == "" {
		return fmt.Errorf("field 'id' is required")
	}

	if req.DefaultOidcScope == "" {
		return fmt.Errorf("field 'defaultOidcScope' is required")
	}

	if len(req.OidcScopes) == 0 {
		return fmt.Errorf("field 'oidcScopes' is required and must contain at least one scope")
	}

	if _, ok := req.OidcScopes[req.DefaultOidcScope]; !ok {
		return fmt.Errorf("Default scope %q must exist in OIDC scopes list", req.DefaultOidcScope)
	}

	for scopeKey, scope := range req.OidcScopes {
		if len(scope.Credentials) == 0 {
			return fmt.Errorf("scope %q must contain at least one credential", scopeKey)
		}
		for idx, cred := range scope.Credentials {
			if cred.Type == "" {
				return fmt.Errorf("Type of the Credential[%d] of scope %q cannot be null", idx, scopeKey)
			}
		}
	}

	return nil
}

// parseIntQueryParam reads an integer query parameter from the request, returning
// the defaultVal when the parameter is absent or empty.
func parseIntQueryParam(c *gin.Context, name string, defaultVal int) (int, error) {
	raw := c.Query(name)
	if raw == "" {
		return defaultVal, nil
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("query parameter %q must be an integer, got %q", name, raw)
	}
	return val, nil
}

// respondProblem writes an RFC 7807 ProblemDetails JSON response with the given
// HTTP status code and problem metadata.
func respondProblem(c *gin.Context, status int, problemType, title, detail string) {
	c.JSON(status, ProblemDetails{
		Type:   problemType,
		Title:  title,
		Status: status,
		Detail: detail,
	})
}
