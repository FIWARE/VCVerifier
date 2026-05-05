// Package ccsapi implements the HTTP handlers for the Credentials Config Service
// REST API. It provides CRUD operations for service configurations, matching
// the CCS OpenAPI specification for request/response formats.
package ccsapi

import (
	"github.com/fiware/VCVerifier/config"
)

// Default pagination parameters used when query parameters are omitted.
const (
	// DefaultPage is the default zero-based page index.
	DefaultPage = 0
	// DefaultPageSize is the default number of services per page.
	DefaultPageSize = 100
)

// ServiceRequest represents the JSON body for creating or updating a service.
// Fields match the CCS OpenAPI specification.
type ServiceRequest struct {
	// ID is the unique service identifier. Required for POST; ignored for PUT
	// (the URL path parameter is used instead).
	ID string `json:"id,omitempty"`
	// DefaultOidcScope is the default OIDC scope name to use when none is specified.
	DefaultOidcScope string `json:"defaultOidcScope"`
	// OidcScopes maps scope names to their credential requirements.
	OidcScopes map[string]config.ScopeEntry `json:"oidcScopes"`
	// AuthorizationType describes the authorization mode (e.g., "oidc").
	AuthorizationType string `json:"authorizationType,omitempty"`
}

// ServiceResponse represents the JSON response body for a single service.
type ServiceResponse struct {
	// ID is the unique service identifier.
	ID string `json:"id"`
	// DefaultOidcScope is the default OIDC scope name.
	DefaultOidcScope string `json:"defaultOidcScope"`
	// OidcScopes maps scope names to their credential requirements.
	OidcScopes map[string]config.ScopeEntryVO `json:"oidcScopes"`
	// AuthorizationType describes the authorization mode.
	AuthorizationType string `json:"authorizationType,omitempty"`
}

// ServicesListResponse represents the paginated JSON response for listing services.
type ServicesListResponse struct {
	// Total is the total number of services across all pages.
	Total int `json:"total"`
	// PageNumber is the zero-based page index returned.
	PageNumber int `json:"pageNumber"`
	// PageSize is the maximum number of services per page.
	PageSize int `json:"pageSize"`
	// Services is the list of services for the current page.
	Services []ServiceResponse `json:"services"`
}

// ProblemDetails represents an RFC 7807 Problem Details response used for
// error reporting. All CCS API error responses use this format.
type ProblemDetails struct {
	// Type is a URI reference that identifies the problem type.
	Type string `json:"type"`
	// Title is a short human-readable summary of the problem.
	Title string `json:"title"`
	// Status is the HTTP status code.
	Status int `json:"status"`
	// Detail is a human-readable explanation specific to this occurrence.
	Detail string `json:"detail"`
	// Instance is a URI reference that identifies the specific occurrence.
	Instance string `json:"instance,omitempty"`
}

// ServiceRequestToConfiguredService converts a ServiceRequest into a
// config.ConfiguredService for persistence via the repository layer.
func ServiceRequestToConfiguredService(req ServiceRequest, id string) config.ConfiguredService {
	return config.ConfiguredService{
		Id:                id,
		DefaultOidcScope:  req.DefaultOidcScope,
		ServiceScopes:     req.OidcScopes,
		AuthorizationType: req.AuthorizationType,
	}
}

// ConfiguredServiceToResponse converts a config.ConfiguredService into a
// ServiceResponse for the API response body.
func ConfiguredServiceToResponse(svc config.ConfiguredService) ServiceResponse {
	scopes := make(map[string]config.ScopeEntryVO, len(svc.ServiceScopes))
	for k, v := range svc.ServiceScopes {
		scopes[k] = v.VO()
	}
	return ServiceResponse{
		ID:                svc.Id,
		DefaultOidcScope:  svc.DefaultOidcScope,
		OidcScopes:        scopes,
		AuthorizationType: svc.AuthorizationType,
	}
}

// ConfiguredServicesToResponses converts a slice of config.ConfiguredService
// into a slice of ServiceResponse values.
func ConfiguredServicesToResponses(services []config.ConfiguredService) []ServiceResponse {
	responses := make([]ServiceResponse, 0, len(services))
	for _, svc := range services {
		responses = append(responses, ConfiguredServiceToResponse(svc))
	}
	return responses
}
