package database

import (
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/fiware/VCVerifier/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertScopeEntryRaw inserts a scope_entry row with raw credentials JSON
// for migration testing.
func insertScopeEntryRaw(t *testing.T, db *sql.DB, serviceID, scopeKey, credJSON string) int64 {
	t.Helper()
	// Ensure the parent service exists.
	_, _ = db.Exec(`INSERT OR IGNORE INTO service (id) VALUES (?)`, serviceID)

	res, err := db.Exec(
		`INSERT INTO scope_entry (service_id, scope_key, credentials, flat_claims) VALUES (?, ?, ?, 0)`,
		serviceID, scopeKey, credJSON,
	)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// readCredentials reads and unmarshals the credentials JSON for a given
// scope_entry row.
func readCredentials(t *testing.T, db *sql.DB, rowID int64) []CredentialDB {
	t.Helper()
	var raw string
	err := db.QueryRow(`SELECT credentials FROM scope_entry WHERE id = ?`, rowID).Scan(&raw)
	require.NoError(t, err)

	var creds []CredentialDB
	require.NoError(t, json.Unmarshal([]byte(raw), &creds))
	return creds
}

func TestMigrateCredentialsTrustedListType(t *testing.T) {
	type testCase struct {
		name           string
		credJSON       string
		expectModified bool
		// expectedListType checks the listType of the first TrustedIssuersLists
		// entry in the first credential after migration.
		expectedListType string
	}

	tests := []testCase{
		{
			name: "backfills empty listType with default",
			credJSON: mustJSON(t, []CredentialDB{
				{
					Type: "VerifiableCredential",
					TrustedIssuersLists: []config.EndpointEntry{
						{Type: config.TrustedIssuers, ListType: "", Endpoint: "https://tir.example.com"},
					},
				},
			}),
			expectModified:   true,
			expectedListType: config.DEFAULT_LIST_TYPE,
		},
		{
			name: "leaves existing listType untouched",
			credJSON: mustJSON(t, []CredentialDB{
				{
					Type: "VerifiableCredential",
					TrustedIssuersLists: []config.EndpointEntry{
						{Type: config.TrustedIssuers, ListType: "ebsi-v5", Endpoint: "https://v5.example.com"},
					},
				},
			}),
			expectModified:   false,
			expectedListType: "ebsi-v5",
		},
		{
			name: "skips rows with no trusted issuers entries",
			credJSON: mustJSON(t, []CredentialDB{
				{
					Type:                "VerifiableCredential",
					TrustedIssuersLists: []config.EndpointEntry{},
				},
			}),
			expectModified:   false,
			expectedListType: "", // no entry to check
		},
		{
			name: "backfills only empty entries in mixed list",
			credJSON: mustJSON(t, []CredentialDB{
				{
					Type: "VerifiableCredential",
					TrustedIssuersLists: []config.EndpointEntry{
						{Type: config.TrustedIssuers, ListType: "ebsi-v5", Endpoint: "https://v5.example.com"},
						{Type: config.TrustedIssuers, ListType: "", Endpoint: "https://legacy.example.com"},
					},
				},
			}),
			expectModified:   true,
			expectedListType: "ebsi-v5", // first entry stays unchanged
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestDB(t)
			err := InitSchema(db, DriverTypeSQLite)
			require.NoError(t, err)

			// Disable the migration that InitSchema calls so we can test it
			// explicitly. Re-run with a fresh DB where InitSchema already ran,
			// then insert test data and run the migration manually.
			// Actually, since InitSchema already called the migration on an
			// empty DB, we just insert our test data and call the migration
			// again (it's idempotent).
			rowID := insertScopeEntryRaw(t, db, "svc-"+tc.name, "scope", tc.credJSON)

			err = MigrateCredentialsTrustedListType(db, DriverTypeSQLite)
			require.NoError(t, err)

			creds := readCredentials(t, db, rowID)
			require.Len(t, creds, 1)

			if tc.expectedListType == "" {
				// No entries to check.
				return
			}

			require.NotEmpty(t, creds[0].TrustedIssuersLists)
			assert.Equal(t, tc.expectedListType, creds[0].TrustedIssuersLists[0].ListType)

			if tc.name == "backfills only empty entries in mixed list" {
				require.Len(t, creds[0].TrustedIssuersLists, 2)
				assert.Equal(t, config.DEFAULT_LIST_TYPE, creds[0].TrustedIssuersLists[1].ListType,
					"second entry should have been backfilled")
			}
		})
	}
}

func TestMigrateCredentialsTrustedListType_Idempotent(t *testing.T) {
	db := openTestDB(t)
	err := InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)

	credJSON := mustJSON(t, []CredentialDB{
		{
			Type: "VerifiableCredential",
			TrustedIssuersLists: []config.EndpointEntry{
				{Type: config.TrustedIssuers, ListType: "", Endpoint: "https://tir.example.com"},
			},
		},
	})
	rowID := insertScopeEntryRaw(t, db, "svc-idem", "scope", credJSON)

	// Run migration twice.
	require.NoError(t, MigrateCredentialsTrustedListType(db, DriverTypeSQLite))
	require.NoError(t, MigrateCredentialsTrustedListType(db, DriverTypeSQLite))

	creds := readCredentials(t, db, rowID)
	require.Len(t, creds, 1)
	require.Len(t, creds[0].TrustedIssuersLists, 1)
	assert.Equal(t, config.DEFAULT_LIST_TYPE, creds[0].TrustedIssuersLists[0].ListType)
}

func TestMigrateCredentialsTrustedListType_EmptyDB(t *testing.T) {
	db := openTestDB(t)
	// InitSchema already calls the migration, which should succeed on an
	// empty database with no scope_entry rows.
	err := InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)
}

func TestAdaptPlaceholders(t *testing.T) {
	type testCase struct {
		name     string
		query    string
		dbType   string
		expected string
	}

	tests := []testCase{
		{
			name:     "postgres replaces placeholders",
			query:    "UPDATE t SET a = ? WHERE b = ?",
			dbType:   DriverTypePostgres,
			expected: "UPDATE t SET a = $1 WHERE b = $2",
		},
		{
			name:     "sqlite keeps placeholders",
			query:    "UPDATE t SET a = ? WHERE b = ?",
			dbType:   DriverTypeSQLite,
			expected: "UPDATE t SET a = ? WHERE b = ?",
		},
		{
			name:     "mysql keeps placeholders",
			query:    "UPDATE t SET a = ? WHERE b = ?",
			dbType:   DriverTypeMySQL,
			expected: "UPDATE t SET a = ? WHERE b = ?",
		},
		{
			name:     "no placeholders",
			query:    "SELECT * FROM t",
			dbType:   DriverTypePostgres,
			expected: "SELECT * FROM t",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := adaptPlaceholders(tc.query, tc.dbType)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// mustJSON marshals v and returns the JSON string, failing the test on error.
func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return string(data)
}
