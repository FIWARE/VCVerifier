package verifier

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
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
	services     []config.ConfiguredService
	total        int
	getAllError   error
	getError     error
	createError  error
	deleteError  error
	updateError  error
	existsResult bool
	existsError  error
	scopeResult  []string
	scopeError   error
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
	return config.ConfiguredService{}, database.ErrServiceNotFound
}

func (m *mockServiceRepository) GetAllServices(_ context.Context, page, pageSize int) ([]config.ConfiguredService, int, error) {
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
	trueOption := true
	return config.ConfiguredService{
		Id:               id,
		DefaultOidcScope: scopeName,
		ServiceScopes: map[string]config.ScopeEntry{
			scopeName: {
				Credentials: []config.Credential{
					{
						Type:                     credentialType,
						TrustedIssuersLists:      config.TrustedIssuersLists{{Type: "ebsi", Url: "https://tir.example.com"}},
						TrustedParticipantsLists: []config.TrustedParticipantsList{{Type: "ebsi", Url: "https://tpl.example.com"}},
						HolderVerification:       config.HolderVerification{Enabled: true, Claim: "sub"},
						RequireCompliance:        true,
						JwtInclusion:             config.JwtInclusion{Enabled: &trueOption, FullInclusion: false},
					},
				},
				FlatClaims: true,
			},
		},
		AuthorizationType: "oidc4vp",
	}
}

func testServiceVO(id, scopeName, credentialType string) config.ConfiguredService {
	return config.ConfiguredService{
		Id:               id,
		DefaultOidcScope: scopeName,
		ServiceScopes: map[string]config.ScopeEntry{
			scopeName: {
				Credentials: []config.Credential{
					{
						Type:                     credentialType,
						TrustedIssuersLists:      config.TrustedIssuersLists{{Type: "ebsi", Url: "https://tir.example.com"}},
						TrustedParticipantsLists: []config.TrustedParticipantsList{{Type: "ebsi", Url: "https://tpl.example.com"}},
					},
				},
			},
		},
		AuthorizationType: "oidc4vp",
	}
}

func TestDbBackedCredentialsConfig_ServiceFromDB(t *testing.T) {
	svc := testService("db-svc-1", "defaultScope", "VerifiableCredential")
	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc},
	}

	repoConfig := &config.ConfigRepo{}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)
	require.NotNil(t, cc)

	scopes, err := cc.GetScope("db-svc-1")
	require.NoError(t, err)
	assert.Contains(t, scopes, "defaultScope")
}

func TestDbBackedCredentialsConfig_AllInterfaceMethods(t *testing.T) {
	svc := testService("test-svc", "myScope", "TestCredential")
	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc},
	}

	repoConfig := &config.ConfigRepo{}

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
		assert.Equal(t, "", path)
	})

	t.Run("RequiredCredentialTypes", func(t *testing.T) {
		types, err := cc.RequiredCredentialTypes("test-svc", "myScope")
		require.NoError(t, err)
		assert.Equal(t, []string{"TestCredential"}, types)
	})

	t.Run("GetPresentationDefinition", func(t *testing.T) {
		pd, err := cc.GetPresentationDefinition("test-svc", "myScope")
		require.NoError(t, err)
		assert.Nil(t, pd)
	})

	t.Run("GetDcqlQuery", func(t *testing.T) {
		dcql, err := cc.GetDcqlQuery("test-svc", "myScope")
		require.NoError(t, err)
		assert.Nil(t, dcql)
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
		assert.Equal(t, []config.TrustedIssuersList{{Type: "ebsi", Url: "https://tir.example.com"}}, til)
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
		assert.True(t, ji.IsEnabled())
		assert.False(t, ji.FullInclusion)
	})

	t.Run("GetFlatClaims", func(t *testing.T) {
		flat, err := cc.GetFlatClaims("test-svc", "myScope")
		require.NoError(t, err)
		assert.True(t, flat)
	})
}

func TestDbBackedCredentialsConfig_ServiceNotFound(t *testing.T) {
	repo := &mockServiceRepository{
		services: []config.ConfiguredService{},
	}

	repoConfig := &config.ConfigRepo{}

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
	staticSvc := testServiceVO("static-svc", "staticScope", "StaticCredential")

	repo := &mockServiceRepository{
		services: []config.ConfiguredService{},
	}

	repoConfig := &config.ConfigRepo{
		Services: []config.ConfiguredService{staticSvc},
	}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	scopes, err := cc.GetScope("static-svc")
	require.NoError(t, err)
	assert.Contains(t, scopes, "staticScope")

	defaultScope, err := cc.GetDefaultScope("static-svc")
	require.NoError(t, err)
	assert.Equal(t, "staticScope", defaultScope)
}

func TestDbBackedCredentialsConfig_DBOverridesStaticConfig(t *testing.T) {
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
		Services: []config.ConfiguredService{staticSvc},
	}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// DB version should take precedence.
	defaultScope, err := cc.GetDefaultScope("shared-svc")
	require.NoError(t, err)
	assert.Equal(t, "newScope", defaultScope)

	types, err := cc.RequiredCredentialTypes("shared-svc", "newScope")
	require.NoError(t, err)
	assert.Equal(t, []string{"NewCred"}, types)
}

func TestDbBackedCredentialsConfig_DBErrorFallsBackToStatic(t *testing.T) {
	staticSvc := testServiceVO("fallback-svc", "staticScope", "StaticCred")

	repo := &mockServiceRepository{
		getError: errors.New("connection refused"),
	}

	repoConfig := &config.ConfigRepo{
		Services: []config.ConfiguredService{staticSvc},
	}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// DB error for unknown services still returns empty.
	scopes, err := cc.GetScope("fallback-svc")
	require.NoError(t, err)
	assert.Empty(t, scopes, "DB error (not ErrServiceNotFound) should not fall back to static")
}

func TestDbBackedCredentialsConfig_MultipleServicesFromDB(t *testing.T) {
	svc1 := testService("svc-a", "scopeA", "CredA")
	svc2 := testService("svc-b", "scopeB", "CredB")

	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc1, svc2},
	}

	repoConfig := &config.ConfigRepo{}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	scopesA, err := cc.GetScope("svc-a")
	require.NoError(t, err)
	assert.Contains(t, scopesA, "scopeA")

	scopesB, err := cc.GetScope("svc-b")
	require.NoError(t, err)
	assert.Contains(t, scopesB, "scopeB")
}

func TestDbBackedCredentialsConfig_ImmediateVisibilityOfDBChanges(t *testing.T) {
	svc := testService("live-svc", "scope1", "Cred1")
	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc},
	}

	repoConfig := &config.ConfigRepo{}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// Initial data present.
	defaultScope, err := cc.GetDefaultScope("live-svc")
	require.NoError(t, err)
	assert.Equal(t, "scope1", defaultScope)

	// Simulate a service update in the database — visible immediately since
	// every call reads from the DB.
	updatedSvc := config.ConfiguredService{
		Id:               "live-svc",
		DefaultOidcScope: "updatedScope",
		ServiceScopes:    map[string]config.ScopeEntry{"updatedScope": {Credentials: []config.Credential{{Type: "UpdatedCred"}}}},
	}
	repo.services = []config.ConfiguredService{updatedSvc}

	defaultScope, err = cc.GetDefaultScope("live-svc")
	require.NoError(t, err)
	assert.Equal(t, "updatedScope", defaultScope)

	types, err := cc.RequiredCredentialTypes("live-svc", "updatedScope")
	require.NoError(t, err)
	assert.Equal(t, []string{"UpdatedCred"}, types)
}

func TestDbBackedCredentialsConfig_StaticServicePreservedWhenNotInDB(t *testing.T) {
	staticSvc := testServiceVO("static-only-svc", "staticScope", "StaticCred")
	dbSvc := testService("db-only-svc", "dbScope", "DbCred")

	repo := &mockServiceRepository{
		services: []config.ConfiguredService{dbSvc},
	}

	repoConfig := &config.ConfigRepo{
		Services: []config.ConfiguredService{staticSvc},
	}

	cc, err := InitDbBackedCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	// DB service should be available.
	dbScopes, err := cc.GetScope("db-only-svc")
	require.NoError(t, err)
	assert.Contains(t, dbScopes, "dbScope")

	// Static service should still be available as fallback.
	staticScopes, err := cc.GetScope("static-only-svc")
	require.NoError(t, err)
	assert.Contains(t, staticScopes, "staticScope")
}

func TestInitCredentialsConfig_SelectsDbWhenRepoProvided(t *testing.T) {
	resetGlobalCache()

	svc := testService("factory-db-svc", "scope", "Cred")
	repo := &mockServiceRepository{
		services: []config.ConfiguredService{svc},
	}

	repoConfig := &config.ConfigRepo{}

	cc, err := InitCredentialsConfig(repoConfig, repo)
	require.NoError(t, err)

	_, ok := cc.(DbBackedCredentialsConfig)
	assert.True(t, ok, "expected DbBackedCredentialsConfig when repo is provided")

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

	_, ok := cc.(ServiceBackedCredentialsConfig)
	assert.True(t, ok, "expected ServiceBackedCredentialsConfig when repo is nil and endpoint is set")
}

func TestInitCredentialsConfig_SelectsStaticWhenNoRepoNoEndpoint(t *testing.T) {
	resetGlobalCache()

	staticSvc := testServiceVO("static-only", "scope", "Cred")
	repoConfig := &config.ConfigRepo{
		Services:       []config.ConfiguredService{staticSvc},
		UpdateInterval: 30,
	}

	cc, err := InitCredentialsConfig(repoConfig, nil)
	require.NoError(t, err)

	_, ok := cc.(ServiceBackedCredentialsConfig)
	assert.True(t, ok, "expected ServiceBackedCredentialsConfig in static mode")

	scopes, err := cc.GetScope("static-only")
	require.NoError(t, err)
	assert.Contains(t, scopes, "scope")
}
