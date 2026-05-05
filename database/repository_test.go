package database

import (
	"context"
	"testing"

	"github.com/fiware/VCVerifier/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRepo creates a fresh SQLite-backed ServiceRepository for a test.
func newTestRepo(t *testing.T) *SqlServiceRepository {
	t.Helper()
	db := openTestDB(t)
	err := InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)
	return NewServiceRepository(db, DriverTypeSQLite)
}

// sampleService builds a ConfiguredService for testing.
func sampleService(id string) config.ConfiguredService {
	return config.ConfiguredService{
		Id:               id,
		DefaultOidcScope: "default",
		ServiceScopes: map[string]config.ScopeEntry{
			"default": {
				Credentials: []config.Credential{
					{
						Type:                "VerifiableCredential",
						TrustedIssuersLists: []config.EndpointEntry{{Type: config.TrustedIssuers, Endpoint: "https://tir.example.com"}},
						HolderVerification:  config.HolderVerification{Enabled: true, Claim: "sub"},
					},
				},
				FlatClaims: true,
			},
		},
		AuthorizationType: "oidc4vp",
	}
}

// sampleServiceWithPD builds a ConfiguredService that includes a
// PresentationDefinition and a DCQL query for round-trip testing.
func sampleServiceWithPD(id string) config.ConfiguredService {
	return config.ConfiguredService{
		Id:               id,
		DefaultOidcScope: "pd-scope",
		ServiceScopes: map[string]config.ScopeEntry{
			"pd-scope": {
				Credentials: []config.Credential{
					{
						Type: "PacketDeliveryService",
						TrustedIssuersLists: []config.EndpointEntry{
							{Type: config.TrustedParticipants, ListType: "ebsi", Endpoint: "https://tpl.example.com"},
						},
						HolderVerification: config.HolderVerification{Enabled: false},
						RequireCompliance:  true,
						JwtInclusion: config.JwtInclusion{
							Enabled:       true,
							FullInclusion: false,
							ClaimsToInclude: []config.ClaimInclusion{
								{OriginalKey: "name", NewKey: "preferred_name"},
							},
						},
					},
				},
				PresentationDefinition: &config.PresentationDefinition{
					Id: "pd-1",
					InputDescriptors: []config.InputDescriptor{
						{
							Id: "desc-1",
							Constraints: config.Constraints{
								Fields: []config.Fields{
									{Id: "f1", Path: []string{"$.type"}, Optional: false},
								},
							},
						},
					},
					Format: []config.FormatObject{
						{FormatKey: "jwt_vp", Alg: []string{"ES256"}},
					},
				},
				DCQL: &config.DCQL{
					Credentials: []config.CredentialQuery{
						{Id: "cq-1", Format: "jwt_vc", Multiple: false},
					},
				},
				FlatClaims: false,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// CreateService tests
// ---------------------------------------------------------------------------

func TestCreateService_Success(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	err := repo.CreateService(ctx, sampleService("svc-1"))
	require.NoError(t, err)

	// Verify persisted.
	svc, err := repo.GetService(ctx, "svc-1")
	require.NoError(t, err)
	assert.Equal(t, "svc-1", svc.Id)
	assert.Equal(t, "default", svc.DefaultOidcScope)
	assert.Equal(t, "oidc4vp", svc.AuthorizationType)
	require.Contains(t, svc.ServiceScopes, "default")
	require.Len(t, svc.ServiceScopes["default"].Credentials, 1)
	assert.Equal(t, "VerifiableCredential", svc.ServiceScopes["default"].Credentials[0].Type)
	assert.True(t, svc.ServiceScopes["default"].FlatClaims)
}

func TestCreateService_DuplicateID(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	err := repo.CreateService(ctx, sampleService("dup"))
	require.NoError(t, err)

	err = repo.CreateService(ctx, sampleService("dup"))
	assert.ErrorIs(t, err, ErrServiceAlreadyExists)
}

func TestCreateService_NoScopes(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	svc := config.ConfiguredService{Id: "no-scopes"}
	err := repo.CreateService(ctx, svc)
	require.NoError(t, err)

	got, err := repo.GetService(ctx, "no-scopes")
	require.NoError(t, err)
	assert.Empty(t, got.ServiceScopes)
}

// ---------------------------------------------------------------------------
// GetService tests
// ---------------------------------------------------------------------------

func TestGetService_NotFound(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	_, err := repo.GetService(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrServiceNotFound)
}

// ---------------------------------------------------------------------------
// GetAllServices tests
// ---------------------------------------------------------------------------

func TestGetAllServices_Empty(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	services, total, err := repo.GetAllServices(ctx, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, services)
}

func TestGetAllServices_Pagination(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// Create 5 services.
	for i := 0; i < 5; i++ {
		id := string(rune('a'+i)) + "-svc"
		svc := config.ConfiguredService{
			Id:               id,
			DefaultOidcScope: "s",
			ServiceScopes: map[string]config.ScopeEntry{
				"s": {Credentials: []config.Credential{{Type: "T"}}},
			},
		}
		require.NoError(t, repo.CreateService(ctx, svc))
	}

	// Page 0, size 2 → 2 services, total 5.
	page0, total, err := repo.GetAllServices(ctx, 0, 2)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, page0, 2)

	// Page 1, size 2 → 2 services.
	page1, total, err := repo.GetAllServices(ctx, 1, 2)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, page1, 2)

	// Page 2, size 2 → 1 service.
	page2, total, err := repo.GetAllServices(ctx, 2, 2)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, page2, 1)

	// All IDs should be unique across pages.
	ids := make(map[string]bool)
	for _, s := range append(append(page0, page1...), page2...) {
		ids[s.Id] = true
	}
	assert.Len(t, ids, 5)
}

func TestGetAllServices_IncludesScopes(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateService(ctx, sampleService("with-scopes")))

	services, total, err := repo.GetAllServices(ctx, 0, 100)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, services, 1)
	assert.Contains(t, services[0].ServiceScopes, "default")
}

// ---------------------------------------------------------------------------
// UpdateService tests
// ---------------------------------------------------------------------------

func TestUpdateService_Success(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateService(ctx, sampleService("upd")))

	updated := config.ConfiguredService{
		Id:               "upd",
		DefaultOidcScope: "new-scope",
		ServiceScopes: map[string]config.ScopeEntry{
			"new-scope": {
				Credentials: []config.Credential{
					{Type: "NewCredType"},
				},
			},
		},
		AuthorizationType: "oidc4vp_v2",
	}

	result, err := repo.UpdateService(ctx, "upd", updated)
	require.NoError(t, err)
	assert.Equal(t, "new-scope", result.DefaultOidcScope)
	assert.Equal(t, "oidc4vp_v2", result.AuthorizationType)
	require.Contains(t, result.ServiceScopes, "new-scope")
	// Old scope should be gone.
	assert.NotContains(t, result.ServiceScopes, "default")
}

func TestUpdateService_NotFound(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	_, err := repo.UpdateService(ctx, "missing", sampleService("missing"))
	assert.ErrorIs(t, err, ErrServiceNotFound)
}

// ---------------------------------------------------------------------------
// DeleteService tests
// ---------------------------------------------------------------------------

func TestDeleteService_Success(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateService(ctx, sampleService("del")))

	err := repo.DeleteService(ctx, "del")
	require.NoError(t, err)

	_, err = repo.GetService(ctx, "del")
	assert.ErrorIs(t, err, ErrServiceNotFound)
}

func TestDeleteService_CascadesScopeEntries(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateService(ctx, sampleService("cas")))

	// Verify scope entries exist.
	svc, err := repo.GetService(ctx, "cas")
	require.NoError(t, err)
	require.NotEmpty(t, svc.ServiceScopes)

	// Delete and check scope entries are gone too.
	require.NoError(t, repo.DeleteService(ctx, "cas"))

	// Direct DB check via a fresh select on the underlying db.
	var count int
	err = repo.db.QueryRow(`SELECT COUNT(*) FROM scope_entry WHERE service_id = 'cas'`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestDeleteService_NotFound(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	err := repo.DeleteService(ctx, "ghost")
	assert.ErrorIs(t, err, ErrServiceNotFound)
}

// ---------------------------------------------------------------------------
// ServiceExists tests
// ---------------------------------------------------------------------------

func TestServiceExists(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	exists, err := repo.ServiceExists(ctx, "nope")
	require.NoError(t, err)
	assert.False(t, exists)

	require.NoError(t, repo.CreateService(ctx, sampleService("yes")))

	exists, err = repo.ServiceExists(ctx, "yes")
	require.NoError(t, err)
	assert.True(t, exists)
}

// ---------------------------------------------------------------------------
// GetServiceScopes tests
// ---------------------------------------------------------------------------

func TestGetServiceScopes_DefaultScope(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateService(ctx, sampleService("scopes")))

	types, err := repo.GetServiceScopes(ctx, "scopes", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"VerifiableCredential"}, types)
}

func TestGetServiceScopes_ExplicitScope(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateService(ctx, sampleService("scopes2")))

	scope := "default"
	types, err := repo.GetServiceScopes(ctx, "scopes2", &scope)
	require.NoError(t, err)
	assert.Equal(t, []string{"VerifiableCredential"}, types)
}

func TestGetServiceScopes_NonexistentScope(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateService(ctx, sampleService("scopes3")))

	scope := "does-not-exist"
	_, err := repo.GetServiceScopes(ctx, "scopes3", &scope)
	assert.ErrorIs(t, err, config.ErrorNoSuchScope)
}

func TestGetServiceScopes_ServiceNotFound(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	_, err := repo.GetServiceScopes(ctx, "absent", nil)
	assert.ErrorIs(t, err, ErrServiceNotFound)
}

func TestGetServiceScopes_NoDefaultScope(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// Service with no default scope and we pass nil.
	svc := config.ConfiguredService{
		Id: "no-default",
		ServiceScopes: map[string]config.ScopeEntry{
			"only": {Credentials: []config.Credential{{Type: "T"}}},
		},
	}
	require.NoError(t, repo.CreateService(ctx, svc))

	_, err := repo.GetServiceScopes(ctx, "no-default", nil)
	assert.ErrorIs(t, err, config.ErrorNoSuchScope)
}

// ---------------------------------------------------------------------------
// JSON round-trip tests
// ---------------------------------------------------------------------------

func TestJSONRoundTrip_PresentationDefinition(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	original := sampleServiceWithPD("pd-rt")
	require.NoError(t, repo.CreateService(ctx, original))

	got, err := repo.GetService(ctx, "pd-rt")
	require.NoError(t, err)

	require.Contains(t, got.ServiceScopes, "pd-scope")
	entry := got.ServiceScopes["pd-scope"]

	// PresentationDefinition round-trip.
	require.NotNil(t, entry.PresentationDefinition)
	assert.Equal(t, "pd-1", entry.PresentationDefinition.Id)
	require.Len(t, entry.PresentationDefinition.InputDescriptors, 1)
	assert.Equal(t, "desc-1", entry.PresentationDefinition.InputDescriptors[0].Id)
	require.Len(t, entry.PresentationDefinition.Format, 1)
	assert.Equal(t, "jwt_vp", entry.PresentationDefinition.Format[0].FormatKey)
	assert.Equal(t, []string{"ES256"}, entry.PresentationDefinition.Format[0].Alg)
}

func TestJSONRoundTrip_DCQL(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	original := sampleServiceWithPD("dcql-rt")
	require.NoError(t, repo.CreateService(ctx, original))

	got, err := repo.GetService(ctx, "dcql-rt")
	require.NoError(t, err)

	entry := got.ServiceScopes["pd-scope"]
	require.NotNil(t, entry.DCQL)
	require.Len(t, entry.DCQL.Credentials, 1)
	assert.Equal(t, "cq-1", entry.DCQL.Credentials[0].Id)
	assert.Equal(t, "jwt_vc", entry.DCQL.Credentials[0].Format)
}

func TestJSONRoundTrip_Credentials(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	original := sampleServiceWithPD("cred-rt")
	require.NoError(t, repo.CreateService(ctx, original))

	got, err := repo.GetService(ctx, "cred-rt")
	require.NoError(t, err)

	entry := got.ServiceScopes["pd-scope"]
	require.Len(t, entry.Credentials, 1)
	cred := entry.Credentials[0]
	assert.Equal(t, "PacketDeliveryService", cred.Type)
	assert.True(t, cred.RequireCompliance)

	require.Len(t, cred.TrustedIssuersLists, 1)
	assert.Equal(t, "ebsi", cred.TrustedIssuersLists[0].ListType)
	assert.Equal(t, config.TrustedParticipants, cred.TrustedIssuersLists[0].Type)

	assert.True(t, cred.JwtInclusion.Enabled)
	assert.False(t, cred.JwtInclusion.FullInclusion)
	require.Len(t, cred.JwtInclusion.ClaimsToInclude, 1)
	assert.Equal(t, "name", cred.JwtInclusion.ClaimsToInclude[0].OriginalKey)
	assert.Equal(t, "preferred_name", cred.JwtInclusion.ClaimsToInclude[0].NewKey)
}

func TestJSONRoundTrip_HolderVerification(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateService(ctx, sampleService("hv-rt")))

	got, err := repo.GetService(ctx, "hv-rt")
	require.NoError(t, err)

	entry := got.ServiceScopes["default"]
	require.Len(t, entry.Credentials, 1)
	assert.True(t, entry.Credentials[0].HolderVerification.Enabled)
	assert.Equal(t, "sub", entry.Credentials[0].HolderVerification.Claim)
}

func TestJSONRoundTrip_NilOptionalFields(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// Service with scope that has no PresentationDefinition or DCQL.
	svc := sampleService("nil-opt")
	require.NoError(t, repo.CreateService(ctx, svc))

	got, err := repo.GetService(ctx, "nil-opt")
	require.NoError(t, err)

	entry := got.ServiceScopes["default"]
	assert.Nil(t, entry.PresentationDefinition)
	assert.Nil(t, entry.DCQL)
}

// ---------------------------------------------------------------------------
// Full CRUD cycle test
// ---------------------------------------------------------------------------

func TestCRUDCycle(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// 1. Create
	svc := sampleService("crud")
	require.NoError(t, repo.CreateService(ctx, svc))

	// 2. Read
	got, err := repo.GetService(ctx, "crud")
	require.NoError(t, err)
	assert.Equal(t, "crud", got.Id)

	// 3. Update
	svc.DefaultOidcScope = "updated-scope"
	svc.ServiceScopes = map[string]config.ScopeEntry{
		"updated-scope": {
			Credentials: []config.Credential{{Type: "NewType"}},
		},
	}
	updated, err := repo.UpdateService(ctx, "crud", svc)
	require.NoError(t, err)
	assert.Equal(t, "updated-scope", updated.DefaultOidcScope)
	require.Contains(t, updated.ServiceScopes, "updated-scope")

	// 4. List
	list, total, err := repo.GetAllServices(ctx, 0, 100)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, list, 1)

	// 5. Delete
	require.NoError(t, repo.DeleteService(ctx, "crud"))

	exists, err := repo.ServiceExists(ctx, "crud")
	require.NoError(t, err)
	assert.False(t, exists)
}

// ---------------------------------------------------------------------------
// adapt / ph helper tests
// ---------------------------------------------------------------------------

func TestAdapt_Postgres(t *testing.T) {
	repo := &SqlServiceRepository{dbType: DriverTypePostgres}

	query := `SELECT * FROM service WHERE id = ? AND scope = ?`
	adapted := repo.adapt(query)
	assert.Equal(t, `SELECT * FROM service WHERE id = $1 AND scope = $2`, adapted)
}

func TestAdapt_SQLite_Unchanged(t *testing.T) {
	repo := &SqlServiceRepository{dbType: DriverTypeSQLite}

	query := `SELECT * FROM service WHERE id = ?`
	adapted := repo.adapt(query)
	assert.Equal(t, query, adapted)
}

func TestPh_Postgres(t *testing.T) {
	repo := &SqlServiceRepository{dbType: DriverTypePostgres}
	assert.Equal(t, "$1", repo.ph(1))
	assert.Equal(t, "$3", repo.ph(3))
}

func TestPh_SQLite(t *testing.T) {
	repo := &SqlServiceRepository{dbType: DriverTypeSQLite}
	assert.Equal(t, "?", repo.ph(1))
	assert.Equal(t, "?", repo.ph(99))
}
