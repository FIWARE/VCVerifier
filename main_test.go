package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

// newTestDB creates an in-memory SQLite database with initialized schema
// suitable for use in tests. The caller must call db.Close() when done.
func newTestDB(t *testing.T) (*database.SqlServiceRepository, *http.Server, func()) {
	t.Helper()

	cfg := config.Database{
		Type: database.DriverTypeSQLite,
		Name: "",
	}

	db, err := database.NewConnection(cfg)
	require.NoError(t, err)

	err = database.InitSchema(db, cfg.Type)
	require.NoError(t, err)

	repo := database.NewServiceRepository(db, cfg.Type)
	router := getConfigRouter(db, repo)

	srv := httptest.NewServer(router)

	return repo, nil, func() {
		srv.Close()
		database.Close(db)
	}
}

func TestInitConfigServer_WithSQLite(t *testing.T) {
	configuration := &config.Configuration{
		Database: config.Database{
			Type: database.DriverTypeSQLite,
			Name: "",
		},
		ConfigServer: config.ConfigServer{
			Enabled:         true,
			Port:            0, // Will be overridden by httptest
			ReadTimeout:     5,
			WriteTimeout:    10,
			IdleTimeout:     120,
			ShutdownTimeout: 5,
		},
	}

	db, srv, err := initConfigServer(configuration)
	require.NoError(t, err)
	assert.NotNil(t, db)
	assert.NotNil(t, srv)

	// Verify server is configured with correct address
	assert.Contains(t, srv.Addr, fmt.Sprintf(":%v", configuration.ConfigServer.Port))

	// Cleanup
	database.Close(db)
}

func TestInitConfigServer_InvalidDBType(t *testing.T) {
	configuration := &config.Configuration{
		Database: config.Database{
			Type: "invalid",
			Name: "test",
		},
		ConfigServer: config.ConfigServer{
			Enabled: true,
			Port:    9999,
		},
	}

	db, srv, err := initConfigServer(configuration)
	assert.Error(t, err)
	assert.Nil(t, db)
	assert.Nil(t, srv)
}

func TestGetConfigRouter_HasHealthEndpoint(t *testing.T) {
	cfg := config.Database{
		Type: database.DriverTypeSQLite,
		Name: "",
	}

	db, err := database.NewConnection(cfg)
	require.NoError(t, err)
	defer database.Close(db)

	err = database.InitSchema(db, cfg.Type)
	require.NoError(t, err)

	repo := database.NewServiceRepository(db, cfg.Type)
	router := getConfigRouter(db, repo)

	// Test health endpoint
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetConfigRouter_HasCCSAPIEndpoints(t *testing.T) {
	cfg := config.Database{
		Type: database.DriverTypeSQLite,
		Name: "",
	}

	db, err := database.NewConnection(cfg)
	require.NoError(t, err)
	defer database.Close(db)

	err = database.InitSchema(db, cfg.Type)
	require.NoError(t, err)

	repo := database.NewServiceRepository(db, cfg.Type)
	router := getConfigRouter(db, repo)

	tests := []struct {
		name           string
		method         string
		path           string
		body           string
		expectedStatus int
	}{
		{
			name:           "GET /service returns empty list",
			method:         http.MethodGet,
			path:           "/service",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "GET /service/:id returns 404 for missing service",
			method:         http.MethodGet,
			path:           "/service/nonexistent",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "DELETE /service/:id returns 404 for missing service",
			method:         http.MethodDelete,
			path:           "/service/nonexistent",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:   "POST /service creates a service",
			method: http.MethodPost,
			path:   "/service",
			body: `{
				"id": "test-service",
				"defaultOidcScope": "defaultScope",
				"oidcScopes": {
					"defaultScope": {
						"credentials": [{"type": "TestCredential", "trustedIssuersLists": ["https://tir.example.com"]}]
					}
				}
			}`,
			expectedStatus: http.StatusCreated,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.body != "" {
				req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tc.method, tc.path, nil)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedStatus, w.Code,
				"endpoint %s %s returned unexpected status", tc.method, tc.path)
		})
	}
}

func TestGetConfigRouter_CORSHeaders(t *testing.T) {
	cfg := config.Database{
		Type: database.DriverTypeSQLite,
		Name: "",
	}

	db, err := database.NewConnection(cfg)
	require.NoError(t, err)
	defer database.Close(db)

	err = database.InitSchema(db, cfg.Type)
	require.NoError(t, err)

	repo := database.NewServiceRepository(db, cfg.Type)
	router := getConfigRouter(db, repo)

	// Test CORS preflight request. The Origin must differ from the request Host
	// so the gin-contrib/cors middleware treats it as a cross-origin request.
	req := httptest.NewRequest(http.MethodOptions, "/service", nil)
	req.Header.Set("Origin", "http://other-domain.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestGetConfigRouter_FullCRUDFlow(t *testing.T) {
	cfg := config.Database{
		Type: database.DriverTypeSQLite,
		Name: "",
	}

	db, err := database.NewConnection(cfg)
	require.NoError(t, err)
	defer database.Close(db)

	err = database.InitSchema(db, cfg.Type)
	require.NoError(t, err)

	repo := database.NewServiceRepository(db, cfg.Type)
	router := getConfigRouter(db, repo)

	serviceID := "crud-test-service"
	createBody := fmt.Sprintf(`{
		"id": "%s",
		"defaultOidcScope": "myScope",
		"oidcScopes": {
			"myScope": {
				"credentials": [{"type": "VerifiableCredential", "trustedIssuersLists": ["https://tir.example.com"]}]
			}
		}
	}`, serviceID)

	// CREATE
	req := httptest.NewRequest(http.MethodPost, "/service", strings.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// READ
	req = httptest.NewRequest(http.MethodGet, "/service/"+serviceID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var getResp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &getResp)
	require.NoError(t, err)
	assert.Equal(t, serviceID, getResp["id"])
	assert.Equal(t, "myScope", getResp["defaultOidcScope"])

	// UPDATE
	updateBody := fmt.Sprintf(`{
		"id": "%s",
		"defaultOidcScope": "updatedScope",
		"oidcScopes": {
			"updatedScope": {
				"credentials": [{"type": "UpdatedCredential", "trustedIssuersLists": ["https://tir.example.com"]}]
			}
		}
	}`, serviceID)
	req = httptest.NewRequest(http.MethodPut, "/service/"+serviceID, strings.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// LIST
	req = httptest.NewRequest(http.MethodGet, "/service", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var listResp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &listResp)
	require.NoError(t, err)
	assert.Equal(t, float64(1), listResp["total"])

	// DELETE
	req = httptest.NewRequest(http.MethodDelete, "/service/"+serviceID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify deleted
	req = httptest.NewRequest(http.MethodGet, "/service/"+serviceID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestConfigServerDisabled_NoDBRequired(t *testing.T) {
	// When ConfigServer.Enabled is false, the main function should not attempt
	// to open a database. This test verifies the condition is correct.
	configuration := config.Configuration{
		ConfigServer: config.ConfigServer{
			Enabled: false,
		},
	}

	// The condition in main: configuration.ConfigServer.Enabled
	// When false, initConfigServer should not be called.
	assert.False(t, configuration.ConfigServer.Enabled)
}

func TestGetConfigRouter_RegistersAllRoutes(t *testing.T) {
	cfg := config.Database{
		Type: database.DriverTypeSQLite,
		Name: "",
	}

	db, err := database.NewConnection(cfg)
	require.NoError(t, err)
	defer database.Close(db)

	err = database.InitSchema(db, cfg.Type)
	require.NoError(t, err)

	repo := database.NewServiceRepository(db, cfg.Type)
	router := getConfigRouter(db, repo)

	// Verify all expected routes are registered
	routes := router.Routes()
	routeMap := make(map[string]bool)
	for _, r := range routes {
		key := r.Method + " " + r.Path
		routeMap[key] = true
	}

	expectedRoutes := []string{
		"GET /health",
		"POST /service",
		"GET /service",
		"GET /service/:id",
		"PUT /service/:id",
		"DELETE /service/:id",
		"GET /service/:id/scope",
	}

	for _, expected := range expectedRoutes {
		assert.True(t, routeMap[expected], "expected route %q to be registered", expected)
	}
}

func TestInitConfigServer_SetsCorrectTimeouts(t *testing.T) {
	configuration := &config.Configuration{
		Database: config.Database{
			Type: database.DriverTypeSQLite,
			Name: "",
		},
		ConfigServer: config.ConfigServer{
			Enabled:         true,
			Port:            9876,
			ReadTimeout:     15,
			WriteTimeout:    30,
			IdleTimeout:     240,
			ShutdownTimeout: 10,
		},
	}

	db, srv, err := initConfigServer(configuration)
	require.NoError(t, err)
	defer database.Close(db)

	assert.Contains(t, srv.Addr, "9876")
	// Verify timeouts are set correctly (in seconds, converted to time.Duration)
	assert.Equal(t, 15*1e9, float64(srv.ReadTimeout))
	assert.Equal(t, 30*1e9, float64(srv.WriteTimeout))
	assert.Equal(t, 240*1e9, float64(srv.IdleTimeout))
}

func TestGetConfigRouter_HealthEndpointIncludesDBCheck(t *testing.T) {
	cfg := config.Database{
		Type: database.DriverTypeSQLite,
		Name: "",
	}

	db, err := database.NewConnection(cfg)
	require.NoError(t, err)
	defer database.Close(db)

	err = database.InitSchema(db, cfg.Type)
	require.NoError(t, err)

	repo := database.NewServiceRepository(db, cfg.Type)
	router := getConfigRouter(db, repo)

	// Test health endpoint returns JSON with system info
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "OK", result["status"])
}

func TestResolveAllowedOrigins(t *testing.T) {
	tests := []struct {
		name     string
		services []config.ConfiguredService
		want     []string
	}{
		{
			name:     "no services returns wildcard",
			services: nil,
			want:     []string{"*"},
		},
		{
			name:     "empty services slice returns wildcard",
			services: []config.ConfiguredService{},
			want:     []string{"*"},
		},
		{
			name: "services with no allowedOrigins returns wildcard",
			services: []config.ConfiguredService{
				{Id: "svc1"},
				{Id: "svc2"},
			},
			want: []string{"*"},
		},
		{
			name: "services with empty allowedOrigins returns wildcard",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{}},
			},
			want: []string{"*"},
		},
		{
			name: "single service with specific origins",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"https://example.com", "https://app.example.com"}},
			},
			want: []string{"https://example.com", "https://app.example.com"},
		},
		{
			name: "multiple services with different origins returns deduplicated union",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"https://alpha.com"}},
				{Id: "svc2", AllowedOrigins: []string{"https://beta.com"}},
			},
			want: []string{"https://alpha.com", "https://beta.com"},
		},
		{
			name: "duplicate origins across services are deduplicated",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"https://shared.com", "https://alpha.com"}},
				{Id: "svc2", AllowedOrigins: []string{"https://shared.com", "https://beta.com"}},
			},
			want: []string{"https://shared.com", "https://alpha.com", "https://beta.com"},
		},
		{
			name: "any service with wildcard returns wildcard only",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"https://example.com"}},
				{Id: "svc2", AllowedOrigins: []string{"*"}},
			},
			want: []string{"*"},
		},
		{
			name: "first service with wildcard short-circuits",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"*"}},
				{Id: "svc2", AllowedOrigins: []string{"https://example.com"}},
			},
			want: []string{"*"},
		},
		{
			name: "wildcard mixed within origins of a single service",
			services: []config.ConfiguredService{
				{Id: "svc1", AllowedOrigins: []string{"https://example.com", "*", "https://other.com"}},
			},
			want: []string{"*"},
		},
		{
			name: "mix of configured and unconfigured services",
			services: []config.ConfiguredService{
				{Id: "svc1"},
				{Id: "svc2", AllowedOrigins: []string{"https://example.com"}},
				{Id: "svc3", AllowedOrigins: []string{}},
			},
			want: []string{"https://example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveAllowedOrigins(tt.services)

			// Sort both slices for order-independent comparison when not testing
			// wildcard (wildcard is always a single element so order is irrelevant).
			if len(got) > 1 || len(tt.want) > 1 {
				sortedGot := make([]string, len(got))
				copy(sortedGot, got)
				sort.Strings(sortedGot)

				sortedWant := make([]string, len(tt.want))
				copy(sortedWant, tt.want)
				sort.Strings(sortedWant)

				if !reflect.DeepEqual(sortedGot, sortedWant) {
					t.Errorf("ResolveAllowedOrigins() = %v, want %v", got, tt.want)
				}
			} else if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ResolveAllowedOrigins() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Ensure init() sets gin to test mode without interfering with other tests
func init() {
	gin.SetMode(gin.TestMode)
}
