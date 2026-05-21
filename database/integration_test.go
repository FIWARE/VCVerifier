package database_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fiware/VCVerifier/ccsapi"
	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
	"github.com/fiware/VCVerifier/verifier"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var TRUE_OPTION bool = true
var FALSE_OPTION bool = false

func init() {
	gin.SetMode(gin.TestMode)
}

// setupIntegrationEnv creates a fresh SQLite-backed database, CCS API router, and
// a service repository for integration testing. The returned cleanup function
// closes the database connection.
func setupIntegrationEnv(t *testing.T) (*gin.Engine, database.ServiceRepository, func()) {
	t.Helper()

	cfg := config.Database{
		Type: database.DriverTypeSQLite,
		Name: "", // in-memory
	}

	db, err := database.NewConnection(cfg)
	require.NoError(t, err)

	err = database.InitSchema(db, cfg.Type)
	require.NoError(t, err)

	repo := database.NewServiceRepository(db, cfg.Type)

	router := gin.New()
	ccsapi.RegisterRoutes(router, repo)

	return router, repo, func() {
		database.Close(db)
	}
}

// resetGlobalCache resets the global service cache to a clean state for test isolation.
func resetGlobalCache() {
	common.GlobalCache.ServiceCache = cache.New(cache.DefaultExpiration, cache.NoExpiration)
}

// buildServiceJSON creates a JSON body for the CCS API POST/PUT endpoints with the given parameters.
func buildServiceJSON(id, defaultScope, authType string, scopes map[string]config.ScopeEntry) ([]byte, error) {
	req := ccsapi.ServiceRequest{
		ID:                id,
		DefaultOidcScope:  defaultScope,
		OidcScopes:        scopes,
		AuthorizationType: authType,
	}
	return json.Marshal(req)
}

// TestIntegration_FullCRUDToCacheFlow exercises the complete lifecycle:
// CCS API → Database → DbBackedCredentialsConfig cache → verifier reads.
func TestIntegration_FullCRUDToCacheFlow(t *testing.T) {
	router, repo, cleanup := setupIntegrationEnv(t)
	defer cleanup()

	resetGlobalCache()

	// --- Step 1: Create a service via CCS API ---
	serviceID := "integration-service"
	scopes := map[string]config.ScopeEntry{
		"defaultScope": {
			Credentials: []config.Credential{
				{
					Type:                "VerifiableCredential",
					TrustedIssuersLists: []string{"https://tir.example.com"},
					HolderVerification:  config.HolderVerification{Enabled: true, Claim: "sub"},
					RequireCompliance:   true,
					JwtInclusion: config.JwtInclusion{
						Enabled:       &TRUE_OPTION,
						FullInclusion: false,
						ClaimsToInclude: []config.ClaimInclusion{
							{OriginalKey: "email", NewKey: "userEmail"},
						},
					},
				},
			},
			PresentationDefinition: &config.PresentationDefinition{
				Id: "pd-1",
				InputDescriptors: []config.InputDescriptor{
					{
						Id: "id-1",
						Constraints: config.Constraints{
							Fields: []config.Fields{
								{Id: "f1", Path: []string{"$.credentialSubject.email"}},
							},
						},
					},
				},
			},
			DCQL: &config.DCQL{
				Credentials: []config.CredentialQuery{
					{Id: "cred-1", Format: "jwt_vp"},
				},
			},
			FlatClaims: true,
		},
	}

	body, err := buildServiceJSON(serviceID, "defaultScope", "oidc4vp", scopes)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/service", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "expected 201 Created, got body: %s", w.Body.String())

	// Verify the Location header
	assert.Contains(t, w.Header().Get("Location"), serviceID)

	// --- Step 2: Verify persisted in DB ---
	svc, err := repo.GetService(context.Background(), serviceID)
	require.NoError(t, err)
	assert.Equal(t, serviceID, svc.Id)
	assert.Equal(t, "defaultScope", svc.DefaultOidcScope)
	assert.Equal(t, "oidc4vp", svc.AuthorizationType)
	assert.Len(t, svc.ServiceScopes, 1)

	// --- Step 3: Verify DbBackedCredentialsConfig cache sees the service ---
	resetGlobalCache()

	repoConfig := &config.ConfigRepo{
		UpdateInterval: 300, // long interval — we manually call fillCache
	}
	credConfig, err := verifier.InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// Verify all CredentialsConfig interface methods work through the cache

	// GetScope
	scopeList, err := credConfig.GetScope(serviceID)
	require.NoError(t, err)
	assert.Contains(t, scopeList, "defaultScope")

	// GetDefaultScope
	defScope, err := credConfig.GetDefaultScope(serviceID)
	require.NoError(t, err)
	assert.Equal(t, "defaultScope", defScope)

	// GetAuthorizationType
	authType, err := credConfig.GetAuthorizationType(serviceID)
	require.NoError(t, err)
	assert.Equal(t, "oidc4vp", authType)

	// RequiredCredentialTypes
	credTypes, err := credConfig.RequiredCredentialTypes(serviceID, "defaultScope")
	require.NoError(t, err)
	assert.Equal(t, []string{"VerifiableCredential"}, credTypes)

	// GetPresentationDefinition
	pd, err := credConfig.GetPresentationDefinition(serviceID, "defaultScope")
	require.NoError(t, err)
	require.NotNil(t, pd)
	assert.Equal(t, "pd-1", pd.Id)
	assert.Len(t, pd.InputDescriptors, 1)

	// GetDcqlQuery
	dcql, err := credConfig.GetDcqlQuery(serviceID, "defaultScope")
	require.NoError(t, err)
	require.NotNil(t, dcql)
	assert.Len(t, dcql.Credentials, 1)
	assert.Equal(t, "cred-1", dcql.Credentials[0].Id)

	// GetHolderVerification
	holderEnabled, holderClaim, err := credConfig.GetHolderVerification(serviceID, "defaultScope", "VerifiableCredential")
	require.NoError(t, err)
	assert.True(t, holderEnabled)
	assert.Equal(t, "sub", holderClaim)

	// GetComplianceRequired
	compRequired, err := credConfig.GetComplianceRequired(serviceID, "defaultScope", "VerifiableCredential")
	require.NoError(t, err)
	assert.True(t, compRequired)

	// GetJwtInclusion
	jwtInc, err := credConfig.GetJwtInclusion(serviceID, "defaultScope", "VerifiableCredential")
	require.NoError(t, err)
	assert.True(t, jwtInc.IsEnabled())
	assert.False(t, jwtInc.FullInclusion)
	assert.Len(t, jwtInc.ClaimsToInclude, 1)
	assert.Equal(t, "email", jwtInc.ClaimsToInclude[0].OriginalKey)
	assert.Equal(t, "userEmail", jwtInc.ClaimsToInclude[0].NewKey)

	// GetFlatClaims
	flatClaims, err := credConfig.GetFlatClaims(serviceID, "defaultScope")
	require.NoError(t, err)
	assert.True(t, flatClaims)

	// GetTrustedIssuersLists
	issuersLists, err := credConfig.GetTrustedIssuersLists(serviceID, "defaultScope", "VerifiableCredential")
	require.NoError(t, err)
	assert.Equal(t, []string{"https://tir.example.com"}, issuersLists)

	// --- Step 4: Update the service → verify changes propagate ---
	updatedScopes := map[string]config.ScopeEntry{
		"updatedScope": {
			Credentials: []config.Credential{
				{
					Type:                "UpdatedCredential",
					TrustedIssuersLists: []string{"https://tir-updated.example.com"},
					RequireCompliance:   false,
				},
			},
			FlatClaims: false,
		},
	}
	updateBody, err := buildServiceJSON("", "updatedScope", "oidc4vp-updated", updatedScopes)
	require.NoError(t, err)

	req = httptest.NewRequest(http.MethodPut, "/service/"+serviceID, bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "expected 200 OK, got body: %s", w.Body.String())

	// Re-read from DB
	updatedSvc, err := repo.GetService(context.Background(), serviceID)
	require.NoError(t, err)
	assert.Equal(t, "updatedScope", updatedSvc.DefaultOidcScope)
	assert.Equal(t, "oidc4vp-updated", updatedSvc.AuthorizationType)
	assert.Len(t, updatedSvc.ServiceScopes, 1)
	assert.Contains(t, updatedSvc.ServiceScopes, "updatedScope")

	// Reinitialize cache to pick up changes
	resetGlobalCache()
	credConfig2, err := verifier.InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	credTypes2, err := credConfig2.RequiredCredentialTypes(serviceID, "updatedScope")
	require.NoError(t, err)
	assert.Equal(t, []string{"UpdatedCredential"}, credTypes2)

	// Old scope should no longer exist
	_, err = credConfig2.RequiredCredentialTypes(serviceID, "defaultScope")
	assert.Error(t, err)

	// --- Step 5: Delete service → verify removal ---
	req = httptest.NewRequest(http.MethodDelete, "/service/"+serviceID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)

	// Verify via API that it's gone
	req = httptest.NewRequest(http.MethodGet, "/service/"+serviceID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// Verify via repository
	_, err = repo.GetService(context.Background(), serviceID)
	assert.ErrorIs(t, err, database.ErrServiceNotFound)
}

// TestIntegration_PaginationWithMultipleServices verifies that pagination
// works correctly with multiple services created via the CCS API.
func TestIntegration_PaginationWithMultipleServices(t *testing.T) {
	router, _, cleanup := setupIntegrationEnv(t)
	defer cleanup()

	// Number of services to create
	const totalServices = 5

	// Create multiple services
	for i := 0; i < totalServices; i++ {
		scopes := map[string]config.ScopeEntry{
			"scope": {
				Credentials: []config.Credential{
					{Type: fmt.Sprintf("Cred%d", i)},
				},
			},
		}
		body, err := buildServiceJSON(
			fmt.Sprintf("svc-%02d", i),
			"scope",
			"",
			scopes,
		)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/service", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code, "failed to create service svc-%02d: %s", i, w.Body.String())
	}

	// Fetch page 0 with pageSize=2
	req := httptest.NewRequest(http.MethodGet, "/service?page=0&pageSize=2", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var page0 ccsapi.ServicesListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page0))
	assert.Equal(t, totalServices, page0.Total)
	assert.Equal(t, 0, page0.PageNumber)
	assert.Equal(t, 2, page0.PageSize)
	assert.Len(t, page0.Services, 2)

	// Fetch page 1 with pageSize=2
	req = httptest.NewRequest(http.MethodGet, "/service?page=1&pageSize=2", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var page1 ccsapi.ServicesListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page1))
	assert.Equal(t, totalServices, page1.Total)
	assert.Len(t, page1.Services, 2)

	// Fetch page 2 with pageSize=2 (should have 1 result)
	req = httptest.NewRequest(http.MethodGet, "/service?page=2&pageSize=2", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var page2 ccsapi.ServicesListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page2))
	assert.Equal(t, totalServices, page2.Total)
	assert.Len(t, page2.Services, 1)

	// Fetch all in one page
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/service?page=0&pageSize=%d", totalServices+10), nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var allPage ccsapi.ServicesListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &allPage))
	assert.Equal(t, totalServices, allPage.Total)
	assert.Len(t, allPage.Services, totalServices)
}

// TestIntegration_DbBackedCacheIncludesStaticServices verifies that static
// services from the ConfigRepo.Services list remain accessible in the cache
// when database mode is active, even though they are not stored in the DB.
func TestIntegration_DbBackedCacheIncludesStaticServices(t *testing.T) {
	_, repo, cleanup := setupIntegrationEnv(t)
	defer cleanup()

	resetGlobalCache()

	staticService := config.ConfiguredService{
		Id:               "static-svc",
		DefaultOidcScope: "staticScope",
		ServiceScopes: map[string]config.ScopeEntry{
			"staticScope": {
				Credentials: []config.Credential{
					{Type: "StaticCredential"},
				},
			},
		},
	}

	repoConfig := &config.ConfigRepo{
		Services:       []config.ConfiguredService{staticService},
		UpdateInterval: 300,
	}

	credConfig, err := verifier.InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// Static service should be accessible
	credTypes, err := credConfig.RequiredCredentialTypes("static-svc", "staticScope")
	require.NoError(t, err)
	assert.Equal(t, []string{"StaticCredential"}, credTypes)

	// Create a DB-backed service and verify both exist
	dbService := config.ConfiguredService{
		Id:               "db-svc",
		DefaultOidcScope: "dbScope",
		ServiceScopes: map[string]config.ScopeEntry{
			"dbScope": {
				Credentials: []config.Credential{
					{Type: "DbCredential"},
				},
			},
		},
	}
	err = repo.CreateService(context.Background(), dbService)
	require.NoError(t, err)

	// Reinitialize to refresh cache
	resetGlobalCache()
	credConfig2, err := verifier.InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// Both should be accessible
	credTypesStatic, err := credConfig2.RequiredCredentialTypes("static-svc", "staticScope")
	require.NoError(t, err)
	assert.Equal(t, []string{"StaticCredential"}, credTypesStatic)

	credTypesDb, err := credConfig2.RequiredCredentialTypes("db-svc", "dbScope")
	require.NoError(t, err)
	assert.Equal(t, []string{"DbCredential"}, credTypesDb)
}

// TestIntegration_CredentialTypeLookupsFullChain tests that credential
// type lookups, presentation definitions, DCQL queries, holder verification,
// compliance requirements, and JWT inclusion settings all work through
// the full CCS API → DB → CredentialsConfig chain.
func TestIntegration_CredentialTypeLookupsFullChain(t *testing.T) {
	router, repo, cleanup := setupIntegrationEnv(t)
	defer cleanup()

	resetGlobalCache()

	// Create a service with rich configuration via CCS API
	serviceID := "lookup-test-svc"
	scopes := map[string]config.ScopeEntry{
		"scopeA": {
			Credentials: []config.Credential{
				{
					Type:                     "CredTypeA",
					TrustedIssuersLists:      []string{"https://til-a.example.com"},
					TrustedParticipantsLists: []config.TrustedParticipantsList{{Type: "ebsi", Url: "https://tpl-a.example.com"}},
					HolderVerification:       config.HolderVerification{Enabled: true, Claim: "holderId"},
					RequireCompliance:        true,
					JwtInclusion:             config.JwtInclusion{Enabled: &TRUE_OPTION, FullInclusion: true},
				},
				{
					Type:                "CredTypeB",
					TrustedIssuersLists: []string{"https://til-b.example.com"},
					RequireCompliance:   false,
					JwtInclusion:        config.JwtInclusion{Enabled: &FALSE_OPTION},
				},
			},
			PresentationDefinition: &config.PresentationDefinition{
				Id: "pd-lookup",
				InputDescriptors: []config.InputDescriptor{
					{Id: "desc-1", Constraints: config.Constraints{Fields: []config.Fields{{Id: "f1", Path: []string{"$.type"}}}}},
				},
				Format: map[string]config.FormatObject{"jwt_vp": {Alg: []string{"ES256"}}},
			},
			DCQL: &config.DCQL{
				Credentials: []config.CredentialQuery{
					{Id: "dcql-cred-1", Format: "jwt_vp", Multiple: true},
				},
				CredentialSets: []config.CredentialSetQuery{
					{Options: [][]string{{"dcql-cred-1"}}, Required: true},
				},
			},
			FlatClaims: true,
		},
		"scopeB": {
			Credentials: []config.Credential{
				{Type: "CredTypeC"},
			},
			FlatClaims: false,
		},
	}

	body, err := buildServiceJSON(serviceID, "scopeA", "oidc4vp", scopes)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/service", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Initialize cache from DB
	repoConfig := &config.ConfigRepo{UpdateInterval: 300}
	credConfig, err := verifier.InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// --- Verify all lookups ---

	// Scope A credential types
	credTypesA, err := credConfig.RequiredCredentialTypes(serviceID, "scopeA")
	require.NoError(t, err)
	assert.Len(t, credTypesA, 2)
	assert.Contains(t, credTypesA, "CredTypeA")
	assert.Contains(t, credTypesA, "CredTypeB")

	// Scope B credential types
	credTypesB, err := credConfig.RequiredCredentialTypes(serviceID, "scopeB")
	require.NoError(t, err)
	assert.Equal(t, []string{"CredTypeC"}, credTypesB)

	// Presentation definition for scopeA
	pd, err := credConfig.GetPresentationDefinition(serviceID, "scopeA")
	require.NoError(t, err)
	require.NotNil(t, pd)
	assert.Equal(t, "pd-lookup", pd.Id)
	assert.Len(t, pd.InputDescriptors, 1)
	assert.Equal(t, "desc-1", pd.InputDescriptors[0].Id)
	require.Contains(t, pd.Format, "jwt_vp")
	assert.Equal(t, []string{"ES256"}, pd.Format["jwt_vp"].Alg)

	// DCQL for scopeA
	dcql, err := credConfig.GetDcqlQuery(serviceID, "scopeA")
	require.NoError(t, err)
	require.NotNil(t, dcql)
	assert.Len(t, dcql.Credentials, 1)
	assert.Equal(t, "dcql-cred-1", dcql.Credentials[0].Id)
	assert.True(t, dcql.Credentials[0].Multiple)
	assert.Len(t, dcql.CredentialSets, 1)
	assert.True(t, dcql.CredentialSets[0].Required)

	// Holder verification — CredTypeA has it enabled
	holderEnabled, holderClaim, err := credConfig.GetHolderVerification(serviceID, "scopeA", "CredTypeA")
	require.NoError(t, err)
	assert.True(t, holderEnabled)
	assert.Equal(t, "holderId", holderClaim)

	// Holder verification — CredTypeB has it disabled (default)
	holderEnabled2, _, err := credConfig.GetHolderVerification(serviceID, "scopeA", "CredTypeB")
	require.NoError(t, err)
	assert.False(t, holderEnabled2)

	// Compliance — CredTypeA requires it
	compA, err := credConfig.GetComplianceRequired(serviceID, "scopeA", "CredTypeA")
	require.NoError(t, err)
	assert.True(t, compA)

	// Compliance — CredTypeB does not require it
	compB, err := credConfig.GetComplianceRequired(serviceID, "scopeA", "CredTypeB")
	require.NoError(t, err)
	assert.False(t, compB)

	// JWT inclusion — CredTypeA
	jwtA, err := credConfig.GetJwtInclusion(serviceID, "scopeA", "CredTypeA")
	require.NoError(t, err)
	assert.True(t, jwtA.IsEnabled())
	assert.True(t, jwtA.FullInclusion)

	// JWT inclusion — CredTypeB
	jwtB, err := credConfig.GetJwtInclusion(serviceID, "scopeA", "CredTypeB")
	require.NoError(t, err)
	assert.False(t, jwtB.IsEnabled())

	// Flat claims — scopeA has it true
	flatA, err := credConfig.GetFlatClaims(serviceID, "scopeA")
	require.NoError(t, err)
	assert.True(t, flatA)

	// Flat claims — scopeB has it false
	flatB, err := credConfig.GetFlatClaims(serviceID, "scopeB")
	require.NoError(t, err)
	assert.False(t, flatB)

	// Trusted issuers lists
	tilA, err := credConfig.GetTrustedIssuersLists(serviceID, "scopeA", "CredTypeA")
	require.NoError(t, err)
	assert.Equal(t, []string{"https://til-a.example.com"}, tilA)

	// Trusted participants lists
	tplA, err := credConfig.GetTrustedParticipantLists(serviceID, "scopeA", "CredTypeA")
	require.NoError(t, err)
	require.Len(t, tplA, 1)
	assert.Equal(t, "ebsi", tplA[0].Type)
	assert.Equal(t, "https://tpl-a.example.com", tplA[0].Url)
}

// TestIntegration_ServiceScopeEndpoint verifies the GET /service/:id/scope
// endpoint works through the full stack.
func TestIntegration_ServiceScopeEndpoint(t *testing.T) {
	router, _, cleanup := setupIntegrationEnv(t)
	defer cleanup()

	// Create a service with multiple scopes
	serviceID := "scope-endpoint-svc"
	scopes := map[string]config.ScopeEntry{
		"alpha": {
			Credentials: []config.Credential{
				{Type: "AlphaCredential"},
				{Type: "AlphaCredential2"},
			},
		},
		"beta": {
			Credentials: []config.Credential{
				{Type: "BetaCredential"},
			},
		},
	}

	body, err := buildServiceJSON(serviceID, "alpha", "", scopes)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/service", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Query default scope (should resolve to "alpha")
	req = httptest.NewRequest(http.MethodGet, "/service/"+serviceID+"/scope", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var defaultTypes []string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &defaultTypes))
	assert.Len(t, defaultTypes, 2)
	assert.Contains(t, defaultTypes, "AlphaCredential")
	assert.Contains(t, defaultTypes, "AlphaCredential2")

	// Query specific scope "beta"
	req = httptest.NewRequest(http.MethodGet, "/service/"+serviceID+"/scope?oidcScope=beta", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var betaTypes []string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &betaTypes))
	assert.Equal(t, []string{"BetaCredential"}, betaTypes)

	// Query non-existent scope
	req = httptest.NewRequest(http.MethodGet, "/service/"+serviceID+"/scope?oidcScope=nonexistent", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// Query non-existent service
	req = httptest.NewRequest(http.MethodGet, "/service/no-such-svc/scope", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestIntegration_ConflictOnDuplicateCreate verifies that creating a service
// with an existing ID returns 409 Conflict.
func TestIntegration_ConflictOnDuplicateCreate(t *testing.T) {
	router, _, cleanup := setupIntegrationEnv(t)
	defer cleanup()

	scopes := map[string]config.ScopeEntry{
		"s": {Credentials: []config.Credential{{Type: "T"}}},
	}
	body, err := buildServiceJSON("dup-svc", "s", "", scopes)
	require.NoError(t, err)

	// First creation should succeed
	req := httptest.NewRequest(http.MethodPost, "/service", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Second creation with same ID should conflict
	req = httptest.NewRequest(http.MethodPost, "/service", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)

	// Verify ProblemDetails response
	var problem ccsapi.ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &problem))
	assert.Equal(t, http.StatusConflict, problem.Status)
	assert.Contains(t, problem.Detail, "dup-svc")
}

// TestIntegration_InitCredentialsConfigFactory verifies that the factory
// function selects the correct backend based on whether a repo is provided.
func TestIntegration_InitCredentialsConfigFactory(t *testing.T) {
	_, repo, cleanup := setupIntegrationEnv(t)
	defer cleanup()

	resetGlobalCache()

	repoConfig := &config.ConfigRepo{
		UpdateInterval: 300,
	}

	// With repo → should use DB-backed
	cc, err := verifier.InitCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)
	assert.NotNil(t, cc)

	// Without repo → should use HTTP/static-backed
	resetGlobalCache()
	cc2, err := verifier.InitCredentialsConfig(repoConfig, nil)
	require.NoError(t, err)
	assert.NotNil(t, cc2)
}
