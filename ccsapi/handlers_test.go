package ccsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

// mockServiceRepository is a test double implementing database.ServiceRepository.
// Each method field can be overridden per-test; unset methods panic to surface
// unexpected calls.
type mockServiceRepository struct {
	createServiceFn    func(ctx context.Context, svc config.ConfiguredService) error
	getServiceFn       func(ctx context.Context, id string) (config.ConfiguredService, error)
	getAllServicesFn    func(ctx context.Context, page, pageSize int) ([]config.ConfiguredService, int, error)
	updateServiceFn    func(ctx context.Context, id string, svc config.ConfiguredService) (config.ConfiguredService, error)
	deleteServiceFn    func(ctx context.Context, id string) error
	getServiceScopesFn func(ctx context.Context, id string, oidcScope *string) ([]string, error)
	serviceExistsFn    func(ctx context.Context, id string) (bool, error)
}

func (m *mockServiceRepository) CreateService(ctx context.Context, svc config.ConfiguredService) error {
	if m.createServiceFn != nil {
		return m.createServiceFn(ctx, svc)
	}
	panic("CreateService not mocked")
}

func (m *mockServiceRepository) GetService(ctx context.Context, id string) (config.ConfiguredService, error) {
	if m.getServiceFn != nil {
		return m.getServiceFn(ctx, id)
	}
	panic("GetService not mocked")
}

func (m *mockServiceRepository) GetAllServices(ctx context.Context, page, pageSize int) ([]config.ConfiguredService, int, error) {
	if m.getAllServicesFn != nil {
		return m.getAllServicesFn(ctx, page, pageSize)
	}
	panic("GetAllServices not mocked")
}

func (m *mockServiceRepository) UpdateService(ctx context.Context, id string, svc config.ConfiguredService) (config.ConfiguredService, error) {
	if m.updateServiceFn != nil {
		return m.updateServiceFn(ctx, id, svc)
	}
	panic("UpdateService not mocked")
}

func (m *mockServiceRepository) DeleteService(ctx context.Context, id string) error {
	if m.deleteServiceFn != nil {
		return m.deleteServiceFn(ctx, id)
	}
	panic("DeleteService not mocked")
}

func (m *mockServiceRepository) GetServiceScopes(ctx context.Context, id string, oidcScope *string) ([]string, error) {
	if m.getServiceScopesFn != nil {
		return m.getServiceScopesFn(ctx, id, oidcScope)
	}
	panic("GetServiceScopes not mocked")
}

func (m *mockServiceRepository) ServiceExists(ctx context.Context, id string) (bool, error) {
	if m.serviceExistsFn != nil {
		return m.serviceExistsFn(ctx, id)
	}
	panic("ServiceExists not mocked")
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func init() {
	gin.SetMode(gin.TestMode)
}

// setupRouter creates a Gin engine with CCS routes registered against the mock.
func setupRouter(repo database.ServiceRepository) *gin.Engine {
	router := gin.New()
	RegisterRoutes(router, repo)
	return router
}

// validServiceJSON returns a well-formed service creation request body.
func validServiceJSON() string {
	return `{
		"id": "my-service",
		"defaultOidcScope": "default",
		"oidcScopes": {
			"default": {
				"credentials": [{"type": "VerifiableCredential"}]
			}
		}
	}`
}

// validUpdateJSON returns a well-formed service update request body (no id).
func validUpdateJSON() string {
	return `{
		"defaultOidcScope": "updated",
		"oidcScopes": {
			"updated": {
				"credentials": [{"type": "UpdatedCredential"}]
			}
		}
	}`
}

// sampleConfiguredService returns a config.ConfiguredService for mock responses.
func sampleConfiguredService(id string) config.ConfiguredService {
	return config.ConfiguredService{
		Id:               id,
		DefaultOidcScope: "default",
		ServiceScopes: map[string]config.ScopeEntry{
			"default": {
				Credentials: []config.Credential{{Type: "VerifiableCredential"}},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// CreateService tests
// ---------------------------------------------------------------------------

func TestCreateService_Success(t *testing.T) {
	repo := &mockServiceRepository{
		createServiceFn: func(_ context.Context, svc config.ConfiguredService) error {
			assert.Equal(t, "my-service", svc.Id)
			assert.Equal(t, "default", svc.DefaultOidcScope)
			assert.Len(t, svc.ServiceScopes, 1)
			return nil
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/service", strings.NewReader(validServiceJSON()))
	req.Header.Set("Content-Type", "application/json")
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "/service/my-service", w.Header().Get("Location"))

	var resp ServiceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "my-service", resp.ID)
	assert.Equal(t, "default", resp.DefaultOidcScope)
}

func TestCreateService_Conflict(t *testing.T) {
	repo := &mockServiceRepository{
		createServiceFn: func(_ context.Context, _ config.ConfiguredService) error {
			return database.ErrServiceAlreadyExists
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/service", strings.NewReader(validServiceJSON()))
	req.Header.Set("Content-Type", "application/json")
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var pd ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
	assert.Equal(t, http.StatusConflict, pd.Status)
	assert.Contains(t, pd.Detail, "already exists")
}

func TestCreateService_ValidationErrors(t *testing.T) {
	// The repository should never be called for validation failures.
	repo := &mockServiceRepository{}

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing id",
			body: `{"defaultOidcScope": "default", "oidcScopes": {"default": {"credentials": [{"type": "VC"}]}}}`,
			want: "'id' is required",
		},
		{
			name: "missing defaultOidcScope",
			body: `{"id": "svc", "oidcScopes": {"default": {"credentials": [{"type": "VC"}]}}}`,
			want: "'defaultOidcScope' is required",
		},
		{
			name: "missing oidcScopes",
			body: `{"id": "svc", "defaultOidcScope": "default"}`,
			want: "'oidcScopes' is required",
		},
		{
			name: "empty oidcScopes",
			body: `{"id": "svc", "defaultOidcScope": "default", "oidcScopes": {}}`,
			want: "'oidcScopes' is required",
		},
		{
			name: "scope with no credentials",
			body: `{"id": "svc", "defaultOidcScope": "default", "oidcScopes": {"default": {"credentials": []}}}`,
			want: "at least one credential",
		},
		{
			name: "invalid JSON",
			body: `not json`,
			want: "Failed to parse",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r, _ := http.NewRequest(http.MethodPost, "/service", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			setupRouter(repo).ServeHTTP(w, r)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var pd ProblemDetails
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
			assert.Equal(t, http.StatusBadRequest, pd.Status)
			assert.Contains(t, pd.Detail, tc.want)
		})
	}
}

// ---------------------------------------------------------------------------
// GetAllServices tests
// ---------------------------------------------------------------------------

func TestGetAllServices_Success(t *testing.T) {
	repo := &mockServiceRepository{
		getAllServicesFn: func(_ context.Context, page, pageSize int) ([]config.ConfiguredService, int, error) {
			assert.Equal(t, 0, page)
			assert.Equal(t, 100, pageSize)
			return []config.ConfiguredService{sampleConfiguredService("svc-1")}, 1, nil
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ServicesListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 0, resp.PageNumber)
	assert.Equal(t, 100, resp.PageSize)
	assert.Len(t, resp.Services, 1)
	assert.Equal(t, "svc-1", resp.Services[0].ID)
}

func TestGetAllServices_CustomPagination(t *testing.T) {
	repo := &mockServiceRepository{
		getAllServicesFn: func(_ context.Context, page, pageSize int) ([]config.ConfiguredService, int, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, pageSize)
			return []config.ConfiguredService{}, 25, nil
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service?page=2&pageSize=10", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ServicesListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 25, resp.Total)
	assert.Equal(t, 2, resp.PageNumber)
	assert.Equal(t, 10, resp.PageSize)
	assert.Empty(t, resp.Services)
}

func TestGetAllServices_EmptyResult(t *testing.T) {
	repo := &mockServiceRepository{
		getAllServicesFn: func(_ context.Context, _, _ int) ([]config.ConfiguredService, int, error) {
			return []config.ConfiguredService{}, 0, nil
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ServicesListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 0, resp.Total)
	assert.Empty(t, resp.Services)
}

func TestGetAllServices_InvalidPageParam(t *testing.T) {
	repo := &mockServiceRepository{}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service?page=abc", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var pd ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
	assert.Contains(t, pd.Detail, "page")
}

func TestGetAllServices_InvalidPageSizeParam(t *testing.T) {
	repo := &mockServiceRepository{}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service?pageSize=xyz", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var pd ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
	assert.Contains(t, pd.Detail, "pageSize")
}

// ---------------------------------------------------------------------------
// GetService tests
// ---------------------------------------------------------------------------

func TestGetService_Success(t *testing.T) {
	repo := &mockServiceRepository{
		getServiceFn: func(_ context.Context, id string) (config.ConfiguredService, error) {
			assert.Equal(t, "my-service", id)
			return sampleConfiguredService("my-service"), nil
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service/my-service", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ServiceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "my-service", resp.ID)
	assert.Equal(t, "default", resp.DefaultOidcScope)
}

func TestGetService_NotFound(t *testing.T) {
	repo := &mockServiceRepository{
		getServiceFn: func(_ context.Context, _ string) (config.ConfiguredService, error) {
			return config.ConfiguredService{}, database.ErrServiceNotFound
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service/unknown", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var pd ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
	assert.Equal(t, http.StatusNotFound, pd.Status)
	assert.Contains(t, pd.Detail, "unknown")
}

// ---------------------------------------------------------------------------
// UpdateService tests
// ---------------------------------------------------------------------------

func TestUpdateService_Success(t *testing.T) {
	updated := config.ConfiguredService{
		Id:               "my-service",
		DefaultOidcScope: "updated",
		ServiceScopes: map[string]config.ScopeEntry{
			"updated": {
				Credentials: []config.Credential{{Type: "UpdatedCredential"}},
			},
		},
	}

	repo := &mockServiceRepository{
		updateServiceFn: func(_ context.Context, id string, svc config.ConfiguredService) (config.ConfiguredService, error) {
			assert.Equal(t, "my-service", id)
			assert.Equal(t, "updated", svc.DefaultOidcScope)
			return updated, nil
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/service/my-service", strings.NewReader(validUpdateJSON()))
	req.Header.Set("Content-Type", "application/json")
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ServiceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "my-service", resp.ID)
	assert.Equal(t, "updated", resp.DefaultOidcScope)
}

func TestUpdateService_NotFound(t *testing.T) {
	repo := &mockServiceRepository{
		updateServiceFn: func(_ context.Context, _ string, _ config.ConfiguredService) (config.ConfiguredService, error) {
			return config.ConfiguredService{}, database.ErrServiceNotFound
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/service/unknown", strings.NewReader(validUpdateJSON()))
	req.Header.Set("Content-Type", "application/json")
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var pd ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
	assert.Equal(t, http.StatusNotFound, pd.Status)
}

func TestUpdateService_ValidationErrors(t *testing.T) {
	repo := &mockServiceRepository{}

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing defaultOidcScope",
			body: `{"oidcScopes": {"default": {"credentials": [{"type": "VC"}]}}}`,
			want: "'defaultOidcScope' is required",
		},
		{
			name: "empty oidcScopes",
			body: `{"defaultOidcScope": "default", "oidcScopes": {}}`,
			want: "'oidcScopes' is required",
		},
		{
			name: "invalid JSON",
			body: `{invalid`,
			want: "Failed to parse",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r, _ := http.NewRequest(http.MethodPut, "/service/my-service", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			setupRouter(repo).ServeHTTP(w, r)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var pd ProblemDetails
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
			assert.Contains(t, pd.Detail, tc.want)
		})
	}
}

// ---------------------------------------------------------------------------
// DeleteService tests
// ---------------------------------------------------------------------------

func TestDeleteService_Success(t *testing.T) {
	repo := &mockServiceRepository{
		deleteServiceFn: func(_ context.Context, id string) error {
			assert.Equal(t, "my-service", id)
			return nil
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/service/my-service", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestDeleteService_NotFound(t *testing.T) {
	repo := &mockServiceRepository{
		deleteServiceFn: func(_ context.Context, _ string) error {
			return database.ErrServiceNotFound
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/service/unknown", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var pd ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
	assert.Equal(t, http.StatusNotFound, pd.Status)
}

// ---------------------------------------------------------------------------
// GetServiceScopes tests
// ---------------------------------------------------------------------------

func TestGetServiceScopes_DefaultScope(t *testing.T) {
	repo := &mockServiceRepository{
		getServiceScopesFn: func(_ context.Context, id string, oidcScope *string) ([]string, error) {
			assert.Equal(t, "my-service", id)
			assert.Nil(t, oidcScope)
			return []string{"VerifiableCredential", "EmailCredential"}, nil
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service/my-service/scope", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var types []string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &types))
	assert.Equal(t, []string{"VerifiableCredential", "EmailCredential"}, types)
}

func TestGetServiceScopes_ExplicitScope(t *testing.T) {
	repo := &mockServiceRepository{
		getServiceScopesFn: func(_ context.Context, id string, oidcScope *string) ([]string, error) {
			assert.Equal(t, "my-service", id)
			require.NotNil(t, oidcScope)
			assert.Equal(t, "custom", *oidcScope)
			return []string{"CustomCredential"}, nil
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service/my-service/scope?oidcScope=custom", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var types []string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &types))
	assert.Equal(t, []string{"CustomCredential"}, types)
}

func TestGetServiceScopes_ServiceNotFound(t *testing.T) {
	repo := &mockServiceRepository{
		getServiceScopesFn: func(_ context.Context, _ string, _ *string) ([]string, error) {
			return nil, database.ErrServiceNotFound
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service/unknown/scope", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var pd ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
	assert.Contains(t, pd.Detail, "unknown")
}

func TestGetServiceScopes_ScopeNotFound(t *testing.T) {
	repo := &mockServiceRepository{
		getServiceScopesFn: func(_ context.Context, _ string, _ *string) ([]string, error) {
			return nil, config.ErrorNoSuchScope
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service/my-service/scope?oidcScope=nonexistent", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var pd ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
	assert.Contains(t, pd.Title, "Scope not found")
}

// ---------------------------------------------------------------------------
// Internal server error tests
// ---------------------------------------------------------------------------

func TestCreateService_InternalError(t *testing.T) {
	repo := &mockServiceRepository{
		createServiceFn: func(_ context.Context, _ config.ConfiguredService) error {
			return fmt.Errorf("db connection lost")
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/service", strings.NewReader(validServiceJSON()))
	req.Header.Set("Content-Type", "application/json")
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var pd ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))
	assert.Equal(t, http.StatusInternalServerError, pd.Status)
}

func TestGetAllServices_InternalError(t *testing.T) {
	repo := &mockServiceRepository{
		getAllServicesFn: func(_ context.Context, _, _ int) ([]config.ConfiguredService, int, error) {
			return nil, 0, fmt.Errorf("db error")
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetService_InternalError(t *testing.T) {
	repo := &mockServiceRepository{
		getServiceFn: func(_ context.Context, _ string) (config.ConfiguredService, error) {
			return config.ConfiguredService{}, fmt.Errorf("db error")
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service/svc", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateService_InternalError(t *testing.T) {
	repo := &mockServiceRepository{
		updateServiceFn: func(_ context.Context, _ string, _ config.ConfiguredService) (config.ConfiguredService, error) {
			return config.ConfiguredService{}, fmt.Errorf("db error")
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/service/svc", strings.NewReader(validUpdateJSON()))
	req.Header.Set("Content-Type", "application/json")
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteService_InternalError(t *testing.T) {
	repo := &mockServiceRepository{
		deleteServiceFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("db error")
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/service/svc", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetServiceScopes_InternalError(t *testing.T) {
	repo := &mockServiceRepository{
		getServiceScopesFn: func(_ context.Context, _ string, _ *string) ([]string, error) {
			return nil, fmt.Errorf("db error")
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service/svc/scope", nil)
	setupRouter(repo).ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// ProblemDetails format tests
// ---------------------------------------------------------------------------

func TestProblemDetails_Format(t *testing.T) {
	repo := &mockServiceRepository{
		getServiceFn: func(_ context.Context, _ string) (config.ConfiguredService, error) {
			return config.ConfiguredService{}, database.ErrServiceNotFound
		},
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/service/test-id", nil)
	setupRouter(repo).ServeHTTP(w, req)

	var pd ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pd))

	// Verify all ProblemDetails fields are populated.
	assert.NotEmpty(t, pd.Type, "type must be set")
	assert.NotEmpty(t, pd.Title, "title must be set")
	assert.Equal(t, http.StatusNotFound, pd.Status, "status must match HTTP code")
	assert.NotEmpty(t, pd.Detail, "detail must be set")
}

// ---------------------------------------------------------------------------
// Model conversion tests
// ---------------------------------------------------------------------------

func TestServiceRequestToConfiguredService(t *testing.T) {
	req := ServiceRequest{
		ID:                "svc-1",
		DefaultOidcScope:  "scope-a",
		AuthorizationType: "oidc",
		OidcScopes: map[string]config.ScopeEntry{
			"scope-a": {
				Credentials: []config.Credential{{Type: "TypeA"}},
				FlatClaims:  true,
			},
		},
	}

	svc := ServiceRequestToConfiguredService(req, "svc-1")

	assert.Equal(t, "svc-1", svc.Id)
	assert.Equal(t, "scope-a", svc.DefaultOidcScope)
	assert.Equal(t, "oidc", svc.AuthorizationType)
	assert.Len(t, svc.ServiceScopes, 1)
	assert.True(t, svc.ServiceScopes["scope-a"].FlatClaims)
}

func TestConfiguredServiceToResponse(t *testing.T) {
	svc := config.ConfiguredService{
		Id:                "svc-1",
		DefaultOidcScope:  "scope-a",
		AuthorizationType: "oidc",
		ServiceScopes: map[string]config.ScopeEntry{
			"scope-a": {
				Credentials: []config.Credential{{Type: "TypeA"}},
			},
		},
	}

	resp := ConfiguredServiceToResponse(svc)

	assert.Equal(t, "svc-1", resp.ID)
	assert.Equal(t, "scope-a", resp.DefaultOidcScope)
	assert.Equal(t, "oidc", resp.AuthorizationType)
	assert.Len(t, resp.OidcScopes, 1)
}

func TestConfiguredServiceToResponse_NilScopes(t *testing.T) {
	svc := config.ConfiguredService{
		Id:               "svc-1",
		DefaultOidcScope: "default",
	}

	resp := ConfiguredServiceToResponse(svc)
	assert.NotNil(t, resp.OidcScopes, "nil scopes should be converted to empty map")
	assert.Empty(t, resp.OidcScopes)
}

func TestConfiguredServicesToResponses(t *testing.T) {
	services := []config.ConfiguredService{
		sampleConfiguredService("svc-1"),
		sampleConfiguredService("svc-2"),
	}

	responses := ConfiguredServicesToResponses(services)

	assert.Len(t, responses, 2)
	assert.Equal(t, "svc-1", responses[0].ID)
	assert.Equal(t, "svc-2", responses[1].ID)
}

// ---------------------------------------------------------------------------
// Route registration test
// ---------------------------------------------------------------------------

func TestRegisterRoutes_AllEndpoints(t *testing.T) {
	repo := &mockServiceRepository{}
	router := setupRouter(repo)

	routes := router.Routes()

	// Build a set of method+path pairs for verification.
	registered := make(map[string]bool)
	for _, r := range routes {
		registered[r.Method+" "+r.Path] = true
	}

	expectedRoutes := []string{
		"POST /service",
		"GET /service",
		"GET /service/:id",
		"PUT /service/:id",
		"DELETE /service/:id",
		"GET /service/:id/scope",
	}

	for _, route := range expectedRoutes {
		assert.True(t, registered[route], "expected route %q to be registered", route)
	}
}

// ---------------------------------------------------------------------------
// Validation function tests
// ---------------------------------------------------------------------------

func TestValidateServiceRequest(t *testing.T) {
	tests := []struct {
		name      string
		req       ServiceRequest
		requireID bool
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid with ID",
			req: ServiceRequest{
				ID:               "svc",
				DefaultOidcScope: "default",
				OidcScopes: map[string]config.ScopeEntry{
					"default": {Credentials: []config.Credential{{Type: "VC"}}},
				},
			},
			requireID: true,
			wantErr:   false,
		},
		{
			name: "valid without ID requirement",
			req: ServiceRequest{
				DefaultOidcScope: "default",
				OidcScopes: map[string]config.ScopeEntry{
					"default": {Credentials: []config.Credential{{Type: "VC"}}},
				},
			},
			requireID: false,
			wantErr:   false,
		},
		{
			name: "missing ID when required",
			req: ServiceRequest{
				DefaultOidcScope: "default",
				OidcScopes: map[string]config.ScopeEntry{
					"default": {Credentials: []config.Credential{{Type: "VC"}}},
				},
			},
			requireID: true,
			wantErr:   true,
			errMsg:    "'id' is required",
		},
		{
			name: "missing defaultOidcScope",
			req: ServiceRequest{
				ID: "svc",
				OidcScopes: map[string]config.ScopeEntry{
					"default": {Credentials: []config.Credential{{Type: "VC"}}},
				},
			},
			requireID: true,
			wantErr:   true,
			errMsg:    "'defaultOidcScope' is required",
		},
		{
			name: "nil oidcScopes",
			req: ServiceRequest{
				ID:               "svc",
				DefaultOidcScope: "default",
			},
			requireID: true,
			wantErr:   true,
			errMsg:    "'oidcScopes' is required",
		},
		{
			name: "scope with empty credentials",
			req: ServiceRequest{
				ID:               "svc",
				DefaultOidcScope: "default",
				OidcScopes: map[string]config.ScopeEntry{
					"default": {Credentials: []config.Credential{}},
				},
			},
			requireID: true,
			wantErr:   true,
			errMsg:    "at least one credential",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateServiceRequest(tc.req, tc.requireID)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
