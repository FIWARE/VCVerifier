package database

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openTestDB opens a fresh in-memory SQLite database for testing.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1) // required for SQLite in-memory
	t.Cleanup(func() { db.Close() })
	return db
}

func TestInitSchema_CreatesTables(t *testing.T) {
	db := openTestDB(t)

	err := InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)

	// Verify service table exists by querying it.
	_, err = db.Exec("SELECT id, default_oidc_scope, authorization_type FROM service LIMIT 1")
	assert.NoError(t, err, "service table should exist")

	// Verify scope_entry table exists by querying it.
	_, err = db.Exec("SELECT id, service_id, scope_key, credentials, presentation_definition, flat_claims, dcql_query FROM scope_entry LIMIT 1")
	assert.NoError(t, err, "scope_entry table should exist")
}

func TestInitSchema_Idempotent(t *testing.T) {
	db := openTestDB(t)

	// First call creates the tables.
	err := InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)

	// Insert some data so we can verify it survives the second call.
	_, err = db.Exec(`INSERT INTO service (id) VALUES ('test-svc')`)
	require.NoError(t, err)

	// Second call should succeed without error (CREATE TABLE IF NOT EXISTS).
	err = InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)

	// Data should still be present.
	var id string
	err = db.QueryRow(`SELECT id FROM service WHERE id = 'test-svc'`).Scan(&id)
	require.NoError(t, err)
	assert.Equal(t, "test-svc", id)
}

func TestInitSchema_UnsupportedType(t *testing.T) {
	db := openTestDB(t)

	err := InitSchema(db, "unsupported")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported database type")
}

func TestInitSchema_ForeignKeyEnforced(t *testing.T) {
	db := openTestDB(t)

	err := InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)

	// Inserting a scope_entry with a non-existent service_id should fail
	// because foreign keys are enforced.
	_, err = db.Exec(`INSERT INTO scope_entry (service_id, scope_key, credentials, flat_claims) VALUES ('no-such-service', 'scope1', '[]', 0)`)
	assert.Error(t, err, "foreign key constraint should be enforced")
}

func TestInitSchema_CascadeDelete(t *testing.T) {
	db := openTestDB(t)

	err := InitSchema(db, DriverTypeSQLite)
	require.NoError(t, err)

	// Insert a service and a scope entry.
	_, err = db.Exec(`INSERT INTO service (id) VALUES ('svc1')`)
	require.NoError(t, err)

	_, err = db.Exec(`INSERT INTO scope_entry (service_id, scope_key, credentials, flat_claims) VALUES ('svc1', 'default', '[]', 0)`)
	require.NoError(t, err)

	// Delete the service — scope entry should be cascade-deleted.
	_, err = db.Exec(`DELETE FROM service WHERE id = 'svc1'`)
	require.NoError(t, err)

	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM scope_entry WHERE service_id = 'svc1'`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "scope entries should be cascade-deleted")
}
