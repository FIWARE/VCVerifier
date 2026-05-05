package database

import (
	"context"
	"testing"
	"time"

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
						TrustedIssuersLists: []string{"https://tir.example.com"},
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
						TrustedParticipantsLists: []config.TrustedParticipantsList{
							{Type: "ebsi", Url: "https://tpl.example.com"},
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
					Format: map[string]config.FormatObject{
						"jwt_vp": {Alg: []string{"ES256"}},
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
	require.Contains(t, entry.PresentationDefinition.Format, "jwt_vp")
	assert.Equal(t, []string{"ES256"}, entry.PresentationDefinition.Format["jwt_vp"].Alg)
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
	require.Len(t, cred.TrustedParticipantsLists, 1)
	assert.Equal(t, "ebsi", cred.TrustedParticipantsLists[0].Type)
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

// ---------------------------------------------------------------------------
// RefreshTokenRepository tests
// ---------------------------------------------------------------------------

// newTestRefreshRepo creates a fresh SQLite-backed RefreshTokenRepository
// for a test.
func newTestRefreshRepo(t *testing.T) *SqlRefreshTokenRepository {
	t.Helper()
	db := openTestDB(t)
	err := InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)
	return NewRefreshTokenRepository(db, DriverTypeSQLite)
}

// sampleRefreshToken builds a RefreshTokenRow for testing.
func sampleRefreshToken(token string, expiresAt int64) RefreshTokenRow {
	return RefreshTokenRow{
		Token:      token,
		ClientID:   "client-1",
		Claims: `{"iss":"https://verifier.example.com","sub":"did:key:holder123","aud":"aud-1"}`,
		ExpiresAt:  expiresAt,
	}
}

func TestStoreRefreshToken_Success(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	row := sampleRefreshToken("tok-1", 9999999999)
	err := repo.StoreRefreshToken(ctx, row)
	require.NoError(t, err)
}

func TestStoreRefreshToken_DuplicateToken(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	row := sampleRefreshToken("tok-dup", 9999999999)
	require.NoError(t, repo.StoreRefreshToken(ctx, row))

	err := repo.StoreRefreshToken(ctx, row)
	assert.Error(t, err, "inserting duplicate token should fail")
}

func TestGetAndDeleteRefreshToken_Success(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	row := sampleRefreshToken("tok-2", 9999999999)
	require.NoError(t, repo.StoreRefreshToken(ctx, row))

	got, err := repo.GetAndDeleteRefreshToken(ctx, "tok-2")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "tok-2", got.Token)
	assert.Equal(t, "tok-2", got.TokenSuffix) // len("tok-2") == 5, so suffix equals the token itself
	assert.Equal(t, "client-1", got.ClientID)
	assert.Equal(t, `{"iss":"https://verifier.example.com","sub":"did:key:holder123","aud":"aud-1"}`, got.Claims)
	assert.Equal(t, int64(9999999999), got.ExpiresAt)

	// Second retrieval must return not-found (single-use).
	_, err = repo.GetAndDeleteRefreshToken(ctx, "tok-2")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)
}

func TestGetAndDeleteRefreshToken_NotFound(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	_, err := repo.GetAndDeleteRefreshToken(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)
}

func TestGetAndDeleteRefreshToken_SingleUse(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	row := sampleRefreshToken("tok-single", 9999999999)
	require.NoError(t, repo.StoreRefreshToken(ctx, row))

	// First get-and-delete succeeds.
	got, err := repo.GetAndDeleteRefreshToken(ctx, "tok-single")
	require.NoError(t, err)
	assert.Equal(t, "tok-single", got.Token)

	// Subsequent attempts must fail.
	_, err = repo.GetAndDeleteRefreshToken(ctx, "tok-single")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)
}

func TestDeleteExpiredTokens(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	// Store two expired and one valid token.
	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("expired-1", 1)))
	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("expired-2", 2)))
	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("valid-1", 9999999999)))

	n, err := repo.DeleteExpiredTokens(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)

	// The valid token should still be retrievable.
	got, err := repo.GetAndDeleteRefreshToken(ctx, "valid-1")
	require.NoError(t, err)
	assert.Equal(t, "valid-1", got.Token)
}

func TestDeleteExpiredTokens_NoneExpired(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("future-tok", 9999999999)))

	n, err := repo.DeleteExpiredTokens(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

func TestRefreshTokenAdapt_Postgres(t *testing.T) {
	repo := &SqlRefreshTokenRepository{dbType: DriverTypePostgres}
	adapted := repo.adapt("INSERT INTO t (a, b) VALUES (?, ?)")
	assert.Equal(t, "INSERT INTO t (a, b) VALUES ($1, $2)", adapted)
}

func TestRefreshTokenAdapt_SQLite(t *testing.T) {
	repo := &SqlRefreshTokenRepository{dbType: DriverTypeSQLite}
	original := "INSERT INTO t (a, b) VALUES (?, ?)"
	assert.Equal(t, original, repo.adapt(original))
}

// TestRefreshTokenAdapt_MySQL verifies that MySQL queries are unchanged
// (MySQL uses ? placeholders like SQLite).
func TestRefreshTokenAdapt_MySQL(t *testing.T) {
	repo := &SqlRefreshTokenRepository{dbType: DriverTypeMySQL}
	original := "INSERT INTO t (a, b) VALUES (?, ?)"
	assert.Equal(t, original, repo.adapt(original))
}

// ---------------------------------------------------------------------------
// Additional refresh token repository tests
// ---------------------------------------------------------------------------

// TestStoreRefreshToken_FieldRoundTrip stores a token with specific field
// values and verifies every field survives the database round-trip.
func TestStoreRefreshToken_FieldRoundTrip(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	claimsJSON := `eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ2ZXJpZmllciIsInN1YiI6ImRpZDprZXk6aG9sZGVyIiwiYXVkIjoiYXVkLTEifQ.sig`
	row := RefreshTokenRow{
		Token:      "field-roundtrip-tok",
		ClientID:   "client-roundtrip",
		Claims: claimsJSON,
		ExpiresAt:  1893456000, // 2030-01-01
	}
	require.NoError(t, repo.StoreRefreshToken(ctx, row))

	got, err := repo.GetAndDeleteRefreshToken(ctx, "field-roundtrip-tok")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "field-roundtrip-tok", got.Token)
	assert.Equal(t, "p-tok", got.TokenSuffix) // last 5 chars of "field-roundtrip-tok"
	assert.Equal(t, "client-roundtrip", got.ClientID)
	assert.Equal(t, claimsJSON, got.Claims)
	assert.Equal(t, int64(1893456000), got.ExpiresAt)
}

// TestRefreshTokenIsolation verifies that storing and retrieving multiple
// tokens with different client IDs does not cause cross-contamination.
func TestRefreshTokenIsolation(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	// Store two tokens for different clients.
	row1 := RefreshTokenRow{
		Token:      "iso-tok-1",
		ClientID:   "client-alpha",
		Claims: `{"client":"alpha"}`,
		ExpiresAt:  9999999999,
	}
	row2 := RefreshTokenRow{
		Token:      "iso-tok-2",
		ClientID:   "client-beta",
		Claims: `{"client":"beta"}`,
		ExpiresAt:  9999999999,
	}
	require.NoError(t, repo.StoreRefreshToken(ctx, row1))
	require.NoError(t, repo.StoreRefreshToken(ctx, row2))

	// Retrieve token 1 — should get client-alpha data.
	got1, err := repo.GetAndDeleteRefreshToken(ctx, "iso-tok-1")
	require.NoError(t, err)
	assert.Equal(t, "client-alpha", got1.ClientID)
	assert.Equal(t, `{"client":"alpha"}`, got1.Claims)

	// Token 1 consumed — should be gone.
	_, err = repo.GetAndDeleteRefreshToken(ctx, "iso-tok-1")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)

	// Token 2 should still be available and correct.
	got2, err := repo.GetAndDeleteRefreshToken(ctx, "iso-tok-2")
	require.NoError(t, err)
	assert.Equal(t, "client-beta", got2.ClientID)
	assert.Equal(t, `{"client":"beta"}`, got2.Claims)
}

// TestDeleteExpiredTokens_MixedExpiry verifies that only tokens past their
// expiry are removed, leaving tokens with future expiry untouched.
func TestDeleteExpiredTokens_MixedExpiry(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	// Store three tokens: two expired (in the past) and one far in the future.
	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("expired-a", 100)))
	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("expired-b", 200)))
	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("valid-a", 9999999999)))
	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("valid-b", 9999999998)))

	n, err := repo.DeleteExpiredTokens(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "should delete exactly 2 expired tokens")

	// Valid tokens remain.
	gotA, err := repo.GetAndDeleteRefreshToken(ctx, "valid-a")
	require.NoError(t, err)
	assert.Equal(t, "valid-a", gotA.Token)

	gotB, err := repo.GetAndDeleteRefreshToken(ctx, "valid-b")
	require.NoError(t, err)
	assert.Equal(t, "valid-b", gotB.Token)

	// Expired tokens gone.
	_, err = repo.GetAndDeleteRefreshToken(ctx, "expired-a")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)

	_, err = repo.GetAndDeleteRefreshToken(ctx, "expired-b")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)
}

// TestRefreshTokenRepository_TableDriven is a table-driven test that covers
// the core store → retrieve → verify pattern for multiple scenarios.
func TestRefreshTokenRepository_TableDriven(t *testing.T) {
	type testCase struct {
		name       string
		token      string
		wantSuffix string
		clientID   string
		payload    string
		expiresAt  int64
	}

	tests := []testCase{
		{
			name:       "standard token",
			token:      "td-standard",
			wantSuffix: "ndard", // last 5 of "td-standard"
			clientID:   "client-std",
			payload:    `{"iss":"verifier","sub":"holder"}`,
			expiresAt:  9999999999,
		},
		{
			name:       "token with long JWT payload",
			token:      "td-long-payload",
			wantSuffix: "yload", // last 5 of "td-long-payload"
			clientID:   "client-long",
			payload:    `{"iss":"verifier","sub":"holder","verifiableCredential":[{"type":"VerifiableCredential","credentialSubject":{"firstName":"Test","lastName":"User","roles":["GOLD_CUSTOMER","STANDARD_CUSTOMER"]}}]}`,
			expiresAt:  1893456000,
		},
		{
			name:       "token with minimal fields",
			token:      "td-minimal",
			wantSuffix: "nimal", // last 5 of "td-minimal"
			clientID:   "c",
			payload:    `{}`,
			expiresAt:  1,
		},
	}

	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := RefreshTokenRow{
				Token:      tc.token,
				ClientID:   tc.clientID,
				Claims: tc.payload,
				ExpiresAt:  tc.expiresAt,
			}
			require.NoError(t, repo.StoreRefreshToken(ctx, row))

			got, err := repo.GetAndDeleteRefreshToken(ctx, tc.token)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tc.token, got.Token)
			assert.Equal(t, tc.wantSuffix, got.TokenSuffix)
			assert.Equal(t, tc.clientID, got.ClientID)
			assert.Equal(t, tc.payload, got.Claims)
			assert.Equal(t, tc.expiresAt, got.ExpiresAt)
		})
	}
}

// ---------------------------------------------------------------------------
// Integrity tests
// ---------------------------------------------------------------------------

// TestRefreshTokenIntegrity_TamperingDetected verifies that modifying the
// stored claims after insertion causes GetAndDeleteRefreshToken to return
// ErrRefreshTokenInvalidIntegrity.
func TestRefreshTokenIntegrity_TamperingDetected(t *testing.T) {
	db := openTestDB(t)
	err := InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)

	repo := NewRefreshTokenRepository(db, DriverTypeSQLite)
	repo.ConfigureHashing([]byte("test-integrity-salt"))

	ctx := context.Background()
	row := RefreshTokenRow{
		Token:     "integrity-tok",
		ClientID:  "client-1",
		Claims:    `{"iss":"verifier","sub":"holder"}`,
		ExpiresAt: 9999999999,
	}
	require.NoError(t, repo.StoreRefreshToken(ctx, row))

	// Directly overwrite the claims column to simulate database-level tampering.
	_, err = db.ExecContext(ctx, `UPDATE refresh_token SET claims = '{"iss":"attacker","sub":"elevated"}' WHERE token_suffix = 'y-tok'`)
	require.NoError(t, err)

	_, err = repo.GetAndDeleteRefreshToken(ctx, "integrity-tok")
	assert.ErrorIs(t, err, ErrRefreshTokenInvalidIntegrity)
}

// TestRefreshTokenIntegrity_ValidRoundTrip verifies that a normally stored
// token passes the integrity check on retrieval when a salt is configured.
func TestRefreshTokenIntegrity_ValidRoundTrip(t *testing.T) {
	db := openTestDB(t)
	err := InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)

	repo := NewRefreshTokenRepository(db, DriverTypeSQLite)
	repo.ConfigureHashing([]byte("test-integrity-salt"))

	ctx := context.Background()
	row := RefreshTokenRow{
		Token:     "valid-integrity-tok",
		ClientID:  "client-1",
		Claims:    `{"iss":"verifier","sub":"holder"}`,
		ExpiresAt: 9999999999,
	}
	require.NoError(t, repo.StoreRefreshToken(ctx, row))

	got, err := repo.GetAndDeleteRefreshToken(ctx, "valid-integrity-tok")
	require.NoError(t, err)
	assert.Equal(t, `{"iss":"verifier","sub":"holder"}`, got.Claims)
}

// ---------------------------------------------------------------------------
// SetCleanupInterval tests
// ---------------------------------------------------------------------------

func TestSetCleanupInterval_DeletesExpiredTokens(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("expired", -1)))
	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("active", 9999999999)))

	repo.SetCleanupInterval(ctx, time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	_, err := repo.GetAndDeleteRefreshToken(ctx, "expired")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound, "expired token should have been removed by cleanup")

	got, err := repo.GetAndDeleteRefreshToken(ctx, "active")
	require.NoError(t, err)
	assert.Equal(t, "active", got.Token, "active token must not be removed")
}

func TestSetCleanupInterval_ZeroOrNegativeDoesNotStart(t *testing.T) {
	for _, interval := range []time.Duration{0, -1, -time.Minute} {
		t.Run(interval.String(), func(t *testing.T) {
			repo := newTestRefreshRepo(t)
			ctx := context.Background()

			require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("expired", -1)))

			repo.SetCleanupInterval(ctx, interval)
			time.Sleep(20 * time.Millisecond)

			// Token must still be present — no cleanup goroutine was started.
			got, err := repo.GetAndDeleteRefreshToken(ctx, "expired")
			require.NoError(t, err)
			assert.Equal(t, "expired", got.Token)
		})
	}
}

func TestSetCleanupInterval_StopsOnContextCancel(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx, cancel := context.WithCancel(context.Background())

	repo.SetCleanupInterval(ctx, time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	cancel()
	time.Sleep(10 * time.Millisecond) // let goroutine exit

	// Store expired token with a fresh context after the goroutine stopped.
	bg := context.Background()
	require.NoError(t, repo.StoreRefreshToken(bg, sampleRefreshToken("after-cancel", -1)))
	time.Sleep(20 * time.Millisecond)

	got, err := repo.GetAndDeleteRefreshToken(bg, "after-cancel")
	require.NoError(t, err, "cleanup goroutine should have stopped; token must still exist")
	assert.Equal(t, "after-cancel", got.Token)
}

func TestSetCleanupInterval_SetToZeroCancelsRunning(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	// Start cleanup, let it run at least once.
	repo.SetCleanupInterval(ctx, time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	// Stop cleanup.
	repo.SetCleanupInterval(ctx, 0)
	time.Sleep(10 * time.Millisecond) // let goroutine exit

	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("after-stop", -1)))
	time.Sleep(20 * time.Millisecond)

	got, err := repo.GetAndDeleteRefreshToken(ctx, "after-stop")
	require.NoError(t, err, "cleanup should have stopped; token must still exist")
	assert.Equal(t, "after-stop", got.Token)
}

func TestSetCleanupInterval_ReconfigureReplacesRunning(t *testing.T) {
	repo := newTestRefreshRepo(t)
	ctx := context.Background()

	// Start with a short interval, then replace with a very long one.
	repo.SetCleanupInterval(ctx, time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	repo.SetCleanupInterval(ctx, time.Hour)
	time.Sleep(10 * time.Millisecond) // let old goroutine exit

	require.NoError(t, repo.StoreRefreshToken(ctx, sampleRefreshToken("after-reconfig", -1)))
	time.Sleep(20 * time.Millisecond)

	// With a 1-hour interval the new goroutine won't tick; token must still exist.
	got, err := repo.GetAndDeleteRefreshToken(ctx, "after-reconfig")
	require.NoError(t, err, "long interval should not have cleaned up yet")
	assert.Equal(t, "after-reconfig", got.Token)
}

// Compile-time check: SqlRefreshTokenRepository satisfies RefreshTokenRepository.
var _ RefreshTokenRepository = (*SqlRefreshTokenRepository)(nil)

// ---------------------------------------------------------------------------
// ConfigureHashing tests
// ---------------------------------------------------------------------------

// TestConfigureHashing_TokenRetrievableByRawToken verifies that when hashing is
// enabled, the raw token string is still used for retrieval (the lookup hashes
// it too), but the value stored in the DB is the HMAC digest.
func TestConfigureHashing_TokenRetrievableByRawToken(t *testing.T) {
	repo := newTestRefreshRepo(t)
	salt, err := GenerateSalt()
	require.NoError(t, err)
	repo.ConfigureHashing(salt)

	ctx := context.Background()
	row := sampleRefreshToken("hash-test-token", 9999999999)
	require.NoError(t, repo.StoreRefreshToken(ctx, row))

	got, err := repo.GetAndDeleteRefreshToken(ctx, "hash-test-token")
	require.NoError(t, err)
	require.NotNil(t, got)
	// The primary key stored in DB is the HMAC hex digest, not the raw token.
	assert.NotEqual(t, "hash-test-token", got.Token)
	assert.Len(t, got.Token, 64) // HMAC-SHA256 hex = 64 chars
}

// TestConfigureHashing_SuffixAlwaysFromRawToken verifies that token_suffix is
// always derived from the raw plaintext token, even when hashing is enabled.
func TestConfigureHashing_SuffixAlwaysFromRawToken(t *testing.T) {
	repo := newTestRefreshRepo(t)
	salt, err := GenerateSalt()
	require.NoError(t, err)
	repo.ConfigureHashing(salt)

	ctx := context.Background()
	row := sampleRefreshToken("abc12345xyz", 9999999999)
	require.NoError(t, repo.StoreRefreshToken(ctx, row))

	got, err := repo.GetAndDeleteRefreshToken(ctx, "abc12345xyz")
	require.NoError(t, err)
	// Suffix is the last 5 chars of the raw token, regardless of hashing.
	assert.Equal(t, "45xyz", got.TokenSuffix)
}

// TestConfigureHashing_DifferentSaltsProduceDifferentKeys stores a token using
// one salt and verifies that a second repository configured with a different salt
// cannot find it (the two HMAC digests differ).
func TestConfigureHashing_DifferentSaltsProduceDifferentKeys(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, InitSchema(db, DriverTypeSQLite))

	repo1 := NewRefreshTokenRepository(db, DriverTypeSQLite)
	salt1, err := GenerateSalt()
	require.NoError(t, err)
	repo1.ConfigureHashing(salt1)

	repo2 := NewRefreshTokenRepository(db, DriverTypeSQLite)
	salt2, err := GenerateSalt()
	require.NoError(t, err)
	repo2.ConfigureHashing(salt2)

	ctx := context.Background()
	row := sampleRefreshToken("shared-secret-token", 9999999999)
	require.NoError(t, repo1.StoreRefreshToken(ctx, row))

	// repo2 computes a different hash → different primary key → not found.
	_, err = repo2.GetAndDeleteRefreshToken(ctx, "shared-secret-token")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)

	// The token was not consumed by repo2, so repo1 can still retrieve it.
	got, err := repo1.GetAndDeleteRefreshToken(ctx, "shared-secret-token")
	require.NoError(t, err)
	require.NotNil(t, got)
}

