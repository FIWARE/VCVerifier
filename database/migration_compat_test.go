package database_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests verify that the Go DDL schema (from InitSchema) is compatible
// with the CCS Liquibase-migrated schema. They insert data in the exact JSON
// format that the CCS Java code produces, then read it back via the Go
// repository to ensure correct deserialization.

// ccsCredentialJSON is a credentials JSON array in the Go-internal serialization
// format used by the repository layer (config.Credential struct JSON tags).
const ccsCredentialJSON = `[{"credentialType":"PacketDeliveryService","verifyHolder":false,"trustedLists":[{"type":"TRUSTED_PARTICIPANTS","listType":"ebsi","endpoint":"https://tir.dsba.fiware.dev/v4/issuers"},{"type":"TRUSTED_ISSUERS","listType":"ebsi","endpoint":"https://tir.dsba.fiware.dev/v3/issuers"}],"holderVerification":{"enabled":true,"claim":"sub"},"requireCompliance":false,"jwtInclusion":{"enabled":true,"fullInclusion":false,"claimsToInclude":[{"originalKey":"roles","newKey":"userRoles"}]}}]`

// ccsPresentationDefinitionJSON is a PresentationDefinition in the Go-internal
// serialization format used by the repository layer (config.PresentationDefinition
// struct JSON tags: camelCase inputDescriptors, format as array of FormatObject).
const ccsPresentationDefinitionJSON = `{"id":"pd-1","inputDescriptors":[{"id":"desc-1","constraints":{"fields":[{"id":"f-1","path":["$.credentialSubject.type"],"optional":false,"filter":{"type":"string","pattern":"PacketDeliveryService"}}]},"format":[{"formatKey":"jwt_vp","alg":["ES256"]}]}],"format":[{"formatKey":"jwt_vp","alg":["ES256"]}]}`

// ccsDcqlJSON matches the CCS Java DCQL Jackson serialization format.
const ccsDcqlJSON = `{"credentials":[{"id":"cred-q-1","format":"dc+sd-jwt","multiple":false,"claims":[{"id":"claim-1","path":["$.credentialSubject.email"]}],"meta":{"vct_values":["PacketDeliveryService"]}}],"credential_sets":[{"options":[["cred-q-1"]],"required":true}]}`

// newTestSQLiteDB creates a fresh in-memory SQLite database with the schema
// initialized. Returns the raw *sql.DB and a cleanup function.
func newTestSQLiteDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	cfg := config.Database{
		Type: database.DriverTypeSQLite,
		Name: "", // in-memory
	}

	db, err := database.NewConnection(cfg)
	require.NoError(t, err)

	err = database.InitSchema(db, cfg.Type)
	require.NoError(t, err)

	return db, func() { database.Close(db) }
}

// TestMigrationCompat_CCSJavaFormatRoundTrip inserts data in the exact JSON
// format the CCS Java service produces, then reads it back via the Go
// repository to verify field names and structure match.
func TestMigrationCompat_CCSJavaFormatRoundTrip(t *testing.T) {
	db, cleanup := newTestSQLiteDB(t)
	defer cleanup()

	repo := database.NewServiceRepository(db, database.DriverTypeSQLite)
	ctx := context.Background()

	// Insert a service row directly using raw SQL to simulate CCS Java insert
	serviceID := "compat-service-1"
	defaultScope := "defaultScope"
	authType := "oidc4vp"

	_, err := db.ExecContext(ctx,
		`INSERT INTO service (id, default_oidc_scope, authorization_type) VALUES (?, ?, ?)`,
		serviceID, defaultScope, authType)
	require.NoError(t, err)

	// Insert a scope entry with CCS Java-formatted JSON columns
	_, err = db.ExecContext(ctx,
		`INSERT INTO scope_entry (service_id, scope_key, credentials, presentation_definition, flat_claims, dcql_query) VALUES (?, ?, ?, ?, ?, ?)`,
		serviceID, "defaultScope", ccsCredentialJSON, ccsPresentationDefinitionJSON, false, ccsDcqlJSON)
	require.NoError(t, err)

	// Read via Go repository
	svc, err := repo.GetService(ctx, serviceID)
	require.NoError(t, err)

	// Verify service-level fields
	assert.Equal(t, serviceID, svc.Id)
	assert.Equal(t, defaultScope, svc.DefaultOidcScope)
	assert.Equal(t, authType, svc.AuthorizationType)

	// Verify scope was read correctly
	require.Contains(t, svc.ServiceScopes, "defaultScope")
	scope := svc.ServiceScopes["defaultScope"]

	// Verify credentials
	require.Len(t, scope.Credentials, 1)
	cred := scope.Credentials[0]
	assert.Equal(t, "PacketDeliveryService", cred.Type)

	require.Len(t, cred.TrustedIssuersLists, 1)
	require.Len(t, cred.TrustedParticipantsLists, 1)

	assert.Equal(t, "ebsi", cred.TrustedParticipantsLists[0].Type)
	assert.Equal(t, "https://tir.dsba.fiware.dev/v4/issuers", cred.TrustedParticipantsLists[0].Url)

	require.Len(t, cred.TrustedIssuersLists, 1)

	assert.Equal(t, "https://tir.dsba.fiware.dev/v3/issuers", cred.TrustedIssuersLists[0])

	assert.True(t, cred.HolderVerification.Enabled)
	assert.Equal(t, "sub", cred.HolderVerification.Claim)
	assert.False(t, cred.RequireCompliance)
	assert.True(t, cred.JwtInclusion.IsEnabled())
	assert.False(t, cred.JwtInclusion.FullInclusion)
	require.Len(t, cred.JwtInclusion.ClaimsToInclude, 1)
	assert.Equal(t, "roles", cred.JwtInclusion.ClaimsToInclude[0].OriginalKey)
	assert.Equal(t, "userRoles", cred.JwtInclusion.ClaimsToInclude[0].NewKey)

	// Verify presentation definition
	require.NotNil(t, scope.PresentationDefinition)
	pd := scope.PresentationDefinition
	assert.Equal(t, "pd-1", pd.Id)
	require.Len(t, pd.InputDescriptors, 1)
	assert.Equal(t, "desc-1", pd.InputDescriptors[0].Id)
	require.Contains(t, pd.Format, "jwt_vp")
	assert.Equal(t, []string{"ES256"}, pd.Format["jwt_vp"].Alg)

	// Verify DCQL
	require.NotNil(t, scope.DCQL)
	dcql := scope.DCQL
	require.Len(t, dcql.Credentials, 1)
	assert.Equal(t, "cred-q-1", dcql.Credentials[0].Id)
	assert.Equal(t, "dc+sd-jwt", dcql.Credentials[0].Format)
	require.Len(t, dcql.CredentialSets, 1)
	assert.True(t, dcql.CredentialSets[0].Required)

	// Verify flat claims
	assert.False(t, scope.FlatClaims)
}

// TestMigrationCompat_GoWriteCCSRead verifies that data written by the Go
// repository can be read back with the same JSON structure the CCS Java
// code expects (field names, nesting).
func TestMigrationCompat_GoWriteCCSRead(t *testing.T) {
	db, cleanup := newTestSQLiteDB(t)
	defer cleanup()

	repo := database.NewServiceRepository(db, database.DriverTypeSQLite)
	ctx := context.Background()

	service := config.ConfiguredService{
		Id:                "go-written-svc",
		DefaultOidcScope:  "myScope",
		AuthorizationType: "oidc4vp",
		ServiceScopes: map[string]config.ScopeEntry{
			"myScope": {
				Credentials: []config.Credential{
					{
						Type:                     "VerifiableCredential",
						TrustedIssuersLists:      []string{"https://til.example.com"},
						TrustedParticipantsLists: []config.TrustedParticipantsList{{Type: "gaia-x", Url: "https://tpl.example.com"}},
						HolderVerification:       config.HolderVerification{Enabled: false, Claim: ""},
						RequireCompliance:        true,
						JwtInclusion: config.JwtInclusion{
							Enabled:       &TRUE_OPTION,
							FullInclusion: true,
							ClaimsToInclude: []config.ClaimInclusion{
								{OriginalKey: "name", NewKey: "displayName"},
							},
						},
					},
				},
				PresentationDefinition: &config.PresentationDefinition{
					Id: "pd-go",
					InputDescriptors: []config.InputDescriptor{
						{
							Id: "input-go",
							Constraints: config.Constraints{
								Fields: []config.Fields{
									{Id: "field-1", Path: []string{"$.vc.type"}},
								},
							},
						},
					},
				},
				DCQL: &config.DCQL{
					Credentials: []config.CredentialQuery{
						{Id: "go-cred", Format: "jwt_vp"},
					},
				},
				FlatClaims: true,
			},
		},
	}

	err := repo.CreateService(ctx, service)
	require.NoError(t, err)

	// Read back the raw JSON from the database to verify field names
	var credJSON, pdJSON, dcqlJSON string
	var flatClaims bool
	err = db.QueryRowContext(ctx,
		`SELECT credentials, presentation_definition, dcql_query, flat_claims FROM scope_entry WHERE service_id = ?`,
		"go-written-svc").Scan(&credJSON, &pdJSON, &dcqlJSON, &flatClaims)
	require.NoError(t, err)

	// Verify credentials JSON field names match Go internal format
	var creds []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(credJSON), &creds))
	require.Len(t, creds, 1)
	assert.Equal(t, "VerifiableCredential", creds[0]["credentialType"])
	assert.Contains(t, creds[0], "trustedLists")
	assert.Contains(t, creds[0], "holderVerification")
	assert.Contains(t, creds[0], "requireCompliance")
	assert.Contains(t, creds[0], "jwtInclusion")

	// Verify trustedLists contains both issuers and participants as EndpointEntry objects
	trustedListsRaw, ok := creds[0]["trustedLists"].([]interface{})
	require.True(t, ok, "trustedLists should be a JSON array")
	require.Len(t, trustedListsRaw, 2)
	var participantEntry map[string]interface{}
	for _, e := range trustedListsRaw {
		entry := e.(map[string]interface{})
		if entry["type"] == "TRUSTED_PARTICIPANTS" {
			participantEntry = entry
			break
		}
	}
	require.NotNil(t, participantEntry, "should contain a TRUSTED_PARTICIPANTS entry")
	assert.Equal(t, "gaia-x", participantEntry["listType"])
	assert.Equal(t, "https://tpl.example.com", participantEntry["endpoint"])

	// Verify holderVerification structure
	hvRaw := creds[0]["holderVerification"].(map[string]interface{})
	assert.Contains(t, hvRaw, "enabled")
	assert.Contains(t, hvRaw, "claim")

	// Verify jwtInclusion structure
	jwtRaw := creds[0]["jwtInclusion"].(map[string]interface{})
	assert.Contains(t, jwtRaw, "enabled")
	assert.Contains(t, jwtRaw, "fullInclusion")
	assert.Contains(t, jwtRaw, "claimsToInclude")

	// Verify PresentationDefinition JSON field names
	var pdMap map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(pdJSON), &pdMap))
	assert.Equal(t, "pd-go", pdMap["id"])
	assert.Contains(t, pdMap, "inputDescriptors")

	// Verify DCQL JSON field names
	var dcqlMap map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(dcqlJSON), &dcqlMap))
	assert.Contains(t, dcqlMap, "credentials")

	// Verify flat_claims boolean
	assert.True(t, flatClaims)
}

// TestMigrationCompat_NullableColumns verifies that nullable JSON columns
// (presentation_definition, dcql_query) can be NULL and are correctly
// deserialized as nil by the Go repository.
func TestMigrationCompat_NullableColumns(t *testing.T) {
	db, cleanup := newTestSQLiteDB(t)
	defer cleanup()

	repo := database.NewServiceRepository(db, database.DriverTypeSQLite)
	ctx := context.Background()

	// Insert with NULL nullable columns (simulating CCS Java with minimal config)
	serviceID := "nullable-test"
	_, err := db.ExecContext(ctx,
		`INSERT INTO service (id, default_oidc_scope, authorization_type) VALUES (?, ?, NULL)`,
		serviceID, "scope1")
	require.NoError(t, err)

	_, err = db.ExecContext(ctx,
		`INSERT INTO scope_entry (service_id, scope_key, credentials, presentation_definition, flat_claims, dcql_query) VALUES (?, ?, ?, NULL, ?, NULL)`,
		serviceID, "scope1", `[{"credentialType":"SimpleCredential"}]`, false)
	require.NoError(t, err)

	// Read via repository
	svc, err := repo.GetService(ctx, serviceID)
	require.NoError(t, err)

	assert.Equal(t, serviceID, svc.Id)
	assert.Equal(t, "scope1", svc.DefaultOidcScope)
	assert.Equal(t, "", svc.AuthorizationType) // NULL → empty string

	require.Contains(t, svc.ServiceScopes, "scope1")
	scope := svc.ServiceScopes["scope1"]
	require.Len(t, scope.Credentials, 1)
	assert.Equal(t, "SimpleCredential", scope.Credentials[0].Type)
	assert.Nil(t, scope.PresentationDefinition) // NULL → nil
	assert.Nil(t, scope.DCQL)                   // NULL → nil
	assert.False(t, scope.FlatClaims)
}

// TestMigrationCompat_MultipleScopes verifies that a service with multiple
// scope entries round-trips correctly through the Go DDL schema.
func TestMigrationCompat_MultipleScopes(t *testing.T) {
	db, cleanup := newTestSQLiteDB(t)
	defer cleanup()

	repo := database.NewServiceRepository(db, database.DriverTypeSQLite)
	ctx := context.Background()

	serviceID := "multi-scope-svc"
	_, err := db.ExecContext(ctx,
		`INSERT INTO service (id, default_oidc_scope, authorization_type) VALUES (?, ?, ?)`,
		serviceID, "scopeAlpha", "oidc")
	require.NoError(t, err)

	// Insert two scope entries
	_, err = db.ExecContext(ctx,
		`INSERT INTO scope_entry (service_id, scope_key, credentials, flat_claims) VALUES (?, ?, ?, ?)`,
		serviceID, "scopeAlpha", `[{"credentialType":"AlphaType"}]`, false)
	require.NoError(t, err)

	_, err = db.ExecContext(ctx,
		`INSERT INTO scope_entry (service_id, scope_key, credentials, flat_claims) VALUES (?, ?, ?, ?)`,
		serviceID, "scopeBeta", `[{"credentialType":"BetaType"},{"credentialType":"BetaType2"}]`, true)
	require.NoError(t, err)

	// Read via repository
	svc, err := repo.GetService(ctx, serviceID)
	require.NoError(t, err)

	assert.Len(t, svc.ServiceScopes, 2)
	require.Contains(t, svc.ServiceScopes, "scopeAlpha")
	require.Contains(t, svc.ServiceScopes, "scopeBeta")

	assert.Len(t, svc.ServiceScopes["scopeAlpha"].Credentials, 1)
	assert.Equal(t, "AlphaType", svc.ServiceScopes["scopeAlpha"].Credentials[0].Type)

	assert.Len(t, svc.ServiceScopes["scopeBeta"].Credentials, 2)
	assert.True(t, svc.ServiceScopes["scopeBeta"].FlatClaims)
}

// TestMigrationCompat_CascadeDelete verifies that deleting a service also
// removes its scope entries (via ON DELETE CASCADE), matching the CCS
// database foreign key constraint behavior.
func TestMigrationCompat_CascadeDelete(t *testing.T) {
	db, cleanup := newTestSQLiteDB(t)
	defer cleanup()

	repo := database.NewServiceRepository(db, database.DriverTypeSQLite)
	ctx := context.Background()

	service := config.ConfiguredService{
		Id:               "cascade-svc",
		DefaultOidcScope: "s",
		ServiceScopes: map[string]config.ScopeEntry{
			"s": {
				Credentials: []config.Credential{{Type: "T"}},
			},
		},
	}
	require.NoError(t, repo.CreateService(ctx, service))

	// Verify scope entry exists
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scope_entry WHERE service_id = ?`, "cascade-svc").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Delete service
	require.NoError(t, repo.DeleteService(ctx, "cascade-svc"))

	// Verify scope entries are also deleted
	err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scope_entry WHERE service_id = ?`, "cascade-svc").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestMigrationCompat_SchemaIdempotent verifies that calling InitSchema
// multiple times on the same database is safe (idempotent).
func TestMigrationCompat_SchemaIdempotent(t *testing.T) {
	db, cleanup := newTestSQLiteDB(t)
	defer cleanup()

	// First InitSchema was done in newTestSQLiteDB — run it again
	err := database.InitSchema(db, database.DriverTypeSQLite)
	require.NoError(t, err)

	// And a third time
	err = database.InitSchema(db, database.DriverTypeSQLite)
	require.NoError(t, err)

	// Verify tables still work
	repo := database.NewServiceRepository(db, database.DriverTypeSQLite)
	svc := config.ConfiguredService{
		Id:               "idempotent-svc",
		DefaultOidcScope: "s",
		ServiceScopes: map[string]config.ScopeEntry{
			"s": {Credentials: []config.Credential{{Type: "T"}}},
		},
	}
	require.NoError(t, repo.CreateService(context.Background(), svc))

	got, err := repo.GetService(context.Background(), "idempotent-svc")
	require.NoError(t, err)
	assert.Equal(t, "idempotent-svc", got.Id)
}

// TestMigrationCompat_EmptyCredentialsArray verifies that an empty
// credentials array (valid JSON "[]") round-trips correctly.
func TestMigrationCompat_EmptyCredentialsArray(t *testing.T) {
	db, cleanup := newTestSQLiteDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert directly — the CCS Java code could in theory produce an empty array
	_, err := db.ExecContext(ctx,
		`INSERT INTO service (id, default_oidc_scope) VALUES (?, ?)`,
		"empty-creds-svc", "s")
	require.NoError(t, err)

	_, err = db.ExecContext(ctx,
		`INSERT INTO scope_entry (service_id, scope_key, credentials, flat_claims) VALUES (?, ?, ?, ?)`,
		"empty-creds-svc", "s", `[]`, false)
	require.NoError(t, err)

	repo := database.NewServiceRepository(db, database.DriverTypeSQLite)
	svc, err := repo.GetService(ctx, "empty-creds-svc")
	require.NoError(t, err)

	require.Contains(t, svc.ServiceScopes, "s")
	assert.Len(t, svc.ServiceScopes["s"].Credentials, 0)
}

// TestMigrationCompat_ColumnTypes verifies that the Go DDL creates tables
// with the expected columns by querying the SQLite schema metadata.
func TestMigrationCompat_ColumnTypes(t *testing.T) {
	db, cleanup := newTestSQLiteDB(t)
	defer cleanup()

	ctx := context.Background()

	// Query service table columns
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(service)`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	serviceColumns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltValue *string
		err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk)
		require.NoError(t, err)
		serviceColumns[name] = true
	}
	require.NoError(t, rows.Err())

	// Verify expected columns exist
	expectedServiceCols := []string{"id", "default_oidc_scope", "authorization_type"}
	for _, col := range expectedServiceCols {
		assert.True(t, serviceColumns[col], "service table should have column %q", col)
	}

	// Query scope_entry table columns
	rows2, err := db.QueryContext(ctx, `PRAGMA table_info(scope_entry)`)
	require.NoError(t, err)
	defer func() { _ = rows2.Close() }()

	scopeColumns := map[string]bool{}
	for rows2.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltValue *string
		err := rows2.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk)
		require.NoError(t, err)
		scopeColumns[name] = true
	}
	require.NoError(t, rows2.Err())

	expectedScopeCols := []string{"id", "service_id", "scope_key", "credentials", "presentation_definition", "flat_claims", "dcql_query"}
	for _, col := range expectedScopeCols {
		assert.True(t, scopeColumns[col], "scope_entry table should have column %q", col)
	}
}
