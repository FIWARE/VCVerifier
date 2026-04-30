package verifier

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	logging.Configure(LOGGING_CONFIG)
}

// mockServiceRepository is a test double for database.ServiceRepository that
// returns preconfigured results. All methods are safe for concurrent use.
type mockServiceRepository struct {
	services      []config.ConfiguredService
	total         int
	getAllError    error
	getError      error
	createError   error
	deleteError   error
	updateError   error
	existsResult  bool
	existsError   error
	scopeResult   []string
	scopeError    error
	getAllCallCount int
}

func (m *mockServiceRepository) CreateService(_ context.Context, _ config.ConfiguredService) error {
	return m.createError
}

func (m *mockServiceRepository) GetService(_ context.Context, id string) (config.ConfiguredService, error) {
	if m.getError != nil {
		return config.ConfiguredService{}, m.getError
	}
	for _, svc := range m.services {
		if svc.Id == id {
			return svc, nil
		}
	}
	return config.ConfiguredService{}, errors.New("service not found")
}

func (m *mockServiceRepository) GetAllServices(_ context.Context, page, pageSize int) ([]config.ConfiguredService, int, error) {
	m.getAllCallCount++
	if m.getAllError != nil {
		return nil, 0, m.getAllError
	}
	start := page * pageSize
	if start >= len(m.services) {
		return []config.ConfiguredService{}, m.total, nil
	}
	end := start + pageSize
	if end > len(m.services) {
		end = len(m.services)
	}
	total := m.total
	if total == 0 {
		total = len(m.services)
	}
	return m.services[start:end], total, nil
}

func (m *mockServiceRepository) UpdateService(_ context.Context, _ string, svc config.ConfiguredService) (config.ConfiguredService, error) {
	if m.updateError != nil {
		return config.ConfiguredService{}, m.updateError
	}
	return svc, nil
}

func (m *mockServiceRepository) DeleteService(_ context.Context, _ string) error {
	return m.deleteError
}

func (m *mockServiceRepository) GetServiceScopes(_ context.Context, _ string, _ *string) ([]string, error) {
	return m.scopeResult, m.scopeError
}

func (m *mockServiceRepository) ServiceExists(_ context.Context, _ string) (bool, error) {
	return m.existsResult, m.existsError
}

// resetGlobalCache clears the global service cache between tests to avoid
// cross-test pollution.
func resetGlobalCache() {
	common.GlobalCache.ServiceCache = cache.New(60*time.Second, 120*time.Second)
	common.GlobalCache.TirEndpoints = cache.New(60*time.Second, 120*time.Second)
}

// testService creates a ConfiguredService with the given ID and a single scope
// containing one credential of the given type.
func testService(id, scopeName, credentialType string) config.ConfiguredService {
	return config.ConfiguredService{
		Id:               id,
		DefaultOidcScope: scopeName,
		ServiceScopes: map[string]config.ScopeEntry{
			scopeName: {
				Credentials: []config.Credential{
					{
						Type:                     credentialType,
						TrustedIssuersLists:      []string{"https://tir.example.com"},
						TrustedParticipantsLists: []config.TrustedParticipantsList{{Type: "ebsi", Url: "https://tpl.example.com"}},
						HolderVerification:       config.HolderVerification{Enabled: true, Claim: "sub"},
						RequireCompliance:        true,
						JwtInclusion:             config.JwtInclusion{Enabled: true, FullInclusion: false},
					},
				},
				FlatClaims: true,
			},
		},
		AuthorizationType: "oidc4vp",
	}
}

func TestDbBackedCredentialsConfig_CachePopulationFromDB(t *testing.T) {
	resetGlobalCache()

	svc := testService("db-svc-1", "defaultScope", "VerifiableCredential")
	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc},
	}

	repoConfig := &config.ConfigRepo{
		UpdateInterval: 30,
	}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)
	require.NotNil(t, cc)

	// Verify service is in cache
	scopes, err := cc.GetScope("db-svc-1")
	require.NoError(t, err)
	assert.Contains(t, scopes, "defaultScope")
}

func TestDbBackedCredentialsConfig_AllInterfaceMethods(t *testing.T) {
	resetGlobalCache()

	svc := testService("test-svc", "myScope", "TestCredential")
	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc},
	}

	repoConfig := &config.ConfigRepo{
		UpdateInterval: 60,
	}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	t.Run("GetScope", func(t *testing.T) {
		scopes, err := cc.GetScope("test-svc")
		require.NoError(t, err)
		assert.Contains(t, scopes, "myScope")
	})

	t.Run("GetDefaultScope", func(t *testing.T) {
		scope, err := cc.GetDefaultScope("test-svc")
		require.NoError(t, err)
		assert.Equal(t, "myScope", scope)
	})

	t.Run("GetAuthorizationType", func(t *testing.T) {
		authType, err := cc.GetAuthorizationType("test-svc")
		require.NoError(t, err)
		assert.Equal(t, "oidc4vp", authType)
	})

	t.Run("GetAuthorizationPath", func(t *testing.T) {
		path := cc.GetAuthorizationPath("test-svc")
		assert.Equal(t, "", path) // not set in testService
	})

	t.Run("RequiredCredentialTypes", func(t *testing.T) {
		types, err := cc.RequiredCredentialTypes("test-svc", "myScope")
		require.NoError(t, err)
		assert.Equal(t, []string{"TestCredential"}, types)
	})

	t.Run("GetPresentationDefinition", func(t *testing.T) {
		pd, err := cc.GetPresentationDefinition("test-svc", "myScope")
		require.NoError(t, err)
		assert.Nil(t, pd) // not set in testService
	})

	t.Run("GetDcqlQuery", func(t *testing.T) {
		dcql, err := cc.GetDcqlQuery("test-svc", "myScope")
		require.NoError(t, err)
		assert.Nil(t, dcql) // not set in testService
	})

	t.Run("GetTrustedParticipantLists", func(t *testing.T) {
		tpl, err := cc.GetTrustedParticipantLists("test-svc", "myScope", "TestCredential")
		require.NoError(t, err)
		require.Len(t, tpl, 1)
		assert.Equal(t, "ebsi", tpl[0].Type)
		assert.Equal(t, "https://tpl.example.com", tpl[0].Url)
	})

	t.Run("GetTrustedIssuersLists", func(t *testing.T) {
		til, err := cc.GetTrustedIssuersLists("test-svc", "myScope", "TestCredential")
		require.NoError(t, err)
		assert.Equal(t, []string{"https://tir.example.com"}, til)
	})

	t.Run("GetHolderVerification", func(t *testing.T) {
		enabled, claim, err := cc.GetHolderVerification("test-svc", "myScope", "TestCredential")
		require.NoError(t, err)
		assert.True(t, enabled)
		assert.Equal(t, "sub", claim)
	})

	t.Run("GetComplianceRequired", func(t *testing.T) {
		required, err := cc.GetComplianceRequired("test-svc", "myScope", "TestCredential")
		require.NoError(t, err)
		assert.True(t, required)
	})

	t.Run("GetJwtInclusion", func(t *testing.T) {
		ji, err := cc.GetJwtInclusion("test-svc", "myScope", "TestCredential")
		require.NoError(t, err)
		assert.True(t, ji.Enabled)
		assert.False(t, ji.FullInclusion)
	})

	t.Run("GetFlatClaims", func(t *testing.T) {
		flat, err := cc.GetFlatClaims("test-svc", "myScope")
		require.NoError(t, err)
		assert.True(t, flat)
	})
}

func TestDbBackedCredentialsConfig_ServiceNotFound(t *testing.T) {
	resetGlobalCache()

	repo := &mockServiceRepository{
		services: []config.ConfiguredService{},
	}

	repoConfig := &config.ConfigRepo{UpdateInterval: 30}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	t.Run("GetDefaultScope_NotFound", func(t *testing.T) {
		_, err := cc.GetDefaultScope("nonexistent")
		assert.ErrorIs(t, err, ErrorNoDefaultScope)
	})

	t.Run("GetScope_NotFound", func(t *testing.T) {
		scopes, err := cc.GetScope("nonexistent")
		require.NoError(t, err)
		assert.Empty(t, scopes)
	})

	t.Run("RequiredCredentialTypes_NotFound", func(t *testing.T) {
		_, err := cc.RequiredCredentialTypes("nonexistent", "scope")
		assert.Error(t, err)
	})
}

func TestDbBackedCredentialsConfig_FallbackToStaticConfig(t *testing.T) {
	resetGlobalCache()

	staticSvc := testService("static-svc", "staticScope", "StaticCredential")

	repo := &mockServiceRepository{
		services: []config.ConfiguredService{},
	}

	repoConfig := &config.ConfigRepo{
		Services:       []config.ConfiguredService{staticSvc},
		UpdateInterval: 30,
	}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// Static service should be available even though DB has no services.
	scopes, err := cc.GetScope("static-svc")
	require.NoError(t, err)
	assert.Contains(t, scopes, "staticScope")

	defaultScope, err := cc.GetDefaultScope("static-svc")
	require.NoError(t, err)
	assert.Equal(t, "staticScope", defaultScope)
}

func TestDbBackedCredentialsConfig_DBOverridesStaticConfig(t *testing.T) {
	resetGlobalCache()

	staticSvc := config.ConfiguredService{
		Id:               "shared-svc",
		DefaultOidcScope: "oldScope",
		ServiceScopes:    map[string]config.ScopeEntry{"oldScope": {Credentials: []config.Credential{{Type: "OldCred"}}}},
	}

	dbSvc := config.ConfiguredService{
		Id:               "shared-svc",
		DefaultOidcScope: "newScope",
		ServiceScopes:    map[string]config.ScopeEntry{"newScope": {Credentials: []config.Credential{{Type: "NewCred"}}}},
	}

	repo := &mockServiceRepository{
		services: []config.ConfiguredService{dbSvc},
	}

	repoConfig := &config.ConfigRepo{
		Services:       []config.ConfiguredService{staticSvc},
		UpdateInterval: 30,
	}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// DB version should take precedence after cache fill.
	defaultScope, err := cc.GetDefaultScope("shared-svc")
	require.NoError(t, err)
	assert.Equal(t, "newScope", defaultScope)

	types, err := cc.RequiredCredentialTypes("shared-svc", "newScope")
	require.NoError(t, err)
	assert.Equal(t, []string{"NewCred"}, types)
}

func TestDbBackedCredentialsConfig_DBErrorPreservesCache(t *testing.T) {
	resetGlobalCache()

	svc := testService("cached-svc", "scope1", "Cred1")

	callCount := 0
	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc},
	}

	repoConfig := &config.ConfigRepo{UpdateInterval: 30}

	// Initial fill succeeds (services are loaded).
	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// Verify service is cached.
	scopes, err := cc.GetScope("cached-svc")
	require.NoError(t, err)
	assert.Contains(t, scopes, "scope1")
	_ = callCount

	// Now simulate DB failure on next fill.
	repo.getAllError = errors.New("connection refused")
	dbc := cc.(DbBackedCredentialsConfig)
	dbc.fillCache(context.Background())

	// Cache should still have the previously loaded service.
	scopes, err = cc.GetScope("cached-svc")
	require.NoError(t, err)
	assert.Contains(t, scopes, "scope1")
}

func TestDbBackedCredentialsConfig_MultipleServicesFromDB(t *testing.T) {
	resetGlobalCache()

	svc1 := testService("svc-a", "scopeA", "CredA")
	svc2 := testService("svc-b", "scopeB", "CredB")

	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc1, svc2},
	}

	repoConfig := &config.ConfigRepo{UpdateInterval: 30}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// Both services should be available.
	scopesA, err := cc.GetScope("svc-a")
	require.NoError(t, err)
	assert.Contains(t, scopesA, "scopeA")

	scopesB, err := cc.GetScope("svc-b")
	require.NoError(t, err)
	assert.Contains(t, scopesB, "scopeB")
}

func TestDbBackedCredentialsConfig_PaginatedFetch(t *testing.T) {
	resetGlobalCache()

	// Create more services than the default page size to test pagination.
	// We use a small page size via the mock's behavior.
	var services []config.ConfiguredService
	for i := 0; i < 3; i++ {
		services = append(services, testService(
			"paginated-svc-"+string(rune('0'+i)),
			"scope",
			"Cred",
		))
	}

	repo := &mockServiceRepository{
		services: services,
		total:    3,
	}

	repoConfig := &config.ConfigRepo{UpdateInterval: 30}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// All three services should be fetchable.
	for i := 0; i < 3; i++ {
		id := "paginated-svc-" + string(rune('0'+i))
		scopes, err := cc.GetScope(id)
		require.NoError(t, err, "service %s should be available", id)
		assert.Contains(t, scopes, "scope")
	}
}

func TestDbBackedCredentialsConfig_DefaultUpdateInterval(t *testing.T) {
	resetGlobalCache()

	repo := &mockServiceRepository{
		services: []config.ConfiguredService{},
	}

	// UpdateInterval of 0 should default to 30s (no panic).
	repoConfig := &config.ConfigRepo{UpdateInterval: 0}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)
	require.NotNil(t, cc)
}

func TestDbBackedCredentialsConfig_TIREndpointsCached(t *testing.T) {
	resetGlobalCache()

	svc := testService("tir-svc", "scope1", "CredWithTIR")

	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc},
	}

	repoConfig := &config.ConfigRepo{UpdateInterval: 30}

	_, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// TIR endpoints should have been cached during fillCache.
	entry, found := common.GlobalCache.TirEndpoints.Get("tirEndpoints")
	assert.True(t, found, "TIR endpoints should be cached")
	if found {
		endpoints := entry.([]string)
		assert.Contains(t, endpoints, "https://tir.example.com")
	}
}

func TestInitCredentialsConfig_SelectsDbWhenRepoProvided(t *testing.T) {
	resetGlobalCache()

	svc := testService("factory-db-svc", "scope", "Cred")
	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc},
	}

	repoConfig := &config.ConfigRepo{UpdateInterval: 30}

	cc, err := InitCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// Should be a DbBackedCredentialsConfig.
	_, ok := cc.(DbBackedCredentialsConfig)
	assert.True(t, ok, "expected DbBackedCredentialsConfig when repo is provided")

	// Service from DB should be available.
	scopes, err := cc.GetScope("factory-db-svc")
	require.NoError(t, err)
	assert.Contains(t, scopes, "scope")
}

func TestInitCredentialsConfig_SelectsHTTPWhenNoRepo(t *testing.T) {
	resetGlobalCache()

	repoConfig := &config.ConfigRepo{
		ConfigEndpoint: "http://localhost:9999/ccs",
		UpdateInterval: 30,
	}

	cc, err := InitCredentialsConfig(repoConfig, nil)
	require.NoError(t, err)

	// Should be a ServiceBackedCredentialsConfig.
	_, ok := cc.(ServiceBackedCredentialsConfig)
	assert.True(t, ok, "expected ServiceBackedCredentialsConfig when repo is nil and endpoint is set")
}

func TestInitCredentialsConfig_SelectsStaticWhenNoRepoNoEndpoint(t *testing.T) {
	resetGlobalCache()

	staticSvc := testService("static-only", "scope", "Cred")
	repoConfig := &config.ConfigRepo{
		Services:       []config.ConfiguredService{staticSvc},
		UpdateInterval: 30,
	}

	cc, err := InitCredentialsConfig(repoConfig, nil)
	require.NoError(t, err)

	// Should be a ServiceBackedCredentialsConfig (static mode).
	_, ok := cc.(ServiceBackedCredentialsConfig)
	assert.True(t, ok, "expected ServiceBackedCredentialsConfig in static mode")

	// Static service should be available.
	scopes, err := cc.GetScope("static-only")
	require.NoError(t, err)
	assert.Contains(t, scopes, "scope")
}

func TestDbBackedCredentialsConfig_RefreshUpdatesCache(t *testing.T) {
	resetGlobalCache()

	svc := testService("refresh-svc", "scope1", "Cred1")
	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc},
	}

	repoConfig := &config.ConfigRepo{UpdateInterval: 30}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// Initial data present.
	defaultScope, err := cc.GetDefaultScope("refresh-svc")
	require.NoError(t, err)
	assert.Equal(t, "scope1", defaultScope)

	// Simulate a service update in the database.
	updatedSvc := config.ConfiguredService{
		Id:               "refresh-svc",
		DefaultOidcScope: "updatedScope",
		ServiceScopes:    map[string]config.ScopeEntry{"updatedScope": {Credentials: []config.Credential{{Type: "UpdatedCred"}}}},
	}
	repo.services = []config.ConfiguredService{updatedSvc}

	// Trigger a manual cache refresh.
	dbc := cc.(DbBackedCredentialsConfig)
	dbc.fillCache(context.Background())

	// Updated data should be visible.
	defaultScope, err = cc.GetDefaultScope("refresh-svc")
	require.NoError(t, err)
	assert.Equal(t, "updatedScope", defaultScope)

	types, err := cc.RequiredCredentialTypes("refresh-svc", "updatedScope")
	require.NoError(t, err)
	assert.Equal(t, []string{"UpdatedCred"}, types)
}

func TestDbBackedCredentialsConfig_StaticServicePreservedWhenNotInDB(t *testing.T) {
	resetGlobalCache()

	staticSvc := testService("static-only-svc", "staticScope", "StaticCred")
	dbSvc := testService("db-only-svc", "dbScope", "DbCred")

	repo := &mockServiceRepository{
		services: []config.ConfiguredService{dbSvc},
	}

	repoConfig := &config.ConfigRepo{
		Services:       []config.ConfiguredService{staticSvc},
		UpdateInterval: 30,
	}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// DB service should be available.
	dbScopes, err := cc.GetScope("db-only-svc")
	require.NoError(t, err)
	assert.Contains(t, dbScopes, "dbScope")

	// Static service should still be available (preserved by fetchAllServices).
	staticScopes, err := cc.GetScope("static-only-svc")
	require.NoError(t, err)
	assert.Contains(t, staticScopes, "staticScope")
}
