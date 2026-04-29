package database

import (
	"database/sql"
	"fmt"

	"github.com/fiware/VCVerifier/logging"
)

// DDL for the service table. The schema is identical across all supported
// database types.
const createServiceTable = `CREATE TABLE IF NOT EXISTS service (
	id VARCHAR(255) NOT NULL PRIMARY KEY,
	default_oidc_scope VARCHAR(255),
	authorization_type VARCHAR(255)
)`

// DDL for the scope_entry table — PostgreSQL variant.
// Uses BIGSERIAL for the auto-incrementing primary key.
const createScopeEntryTablePostgres = `CREATE TABLE IF NOT EXISTS scope_entry (
	id BIGSERIAL NOT NULL PRIMARY KEY,
	service_id VARCHAR(255) REFERENCES service(id) ON DELETE CASCADE,
	scope_key VARCHAR(255),
	credentials TEXT NOT NULL,
	presentation_definition TEXT,
	flat_claims BOOLEAN NOT NULL DEFAULT false,
	dcql_query TEXT
)`

// DDL for the scope_entry table — SQLite variant.
// Uses INTEGER PRIMARY KEY AUTOINCREMENT instead of BIGSERIAL.
const createScopeEntryTableSQLite = `CREATE TABLE IF NOT EXISTS scope_entry (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	service_id VARCHAR(255) REFERENCES service(id) ON DELETE CASCADE,
	scope_key VARCHAR(255),
	credentials TEXT NOT NULL,
	presentation_definition TEXT,
	flat_claims BOOLEAN NOT NULL DEFAULT 0,
	dcql_query TEXT
)`

// DDL for the scope_entry table — MySQL variant.
// Uses BIGINT AUTO_INCREMENT and an explicit FOREIGN KEY clause.
const createScopeEntryTableMySQL = `CREATE TABLE IF NOT EXISTS scope_entry (
	id BIGINT AUTO_INCREMENT NOT NULL PRIMARY KEY,
	service_id VARCHAR(255),
	scope_key VARCHAR(255),
	credentials TEXT NOT NULL,
	presentation_definition TEXT,
	flat_claims BOOLEAN NOT NULL DEFAULT false,
	dcql_query TEXT,
	FOREIGN KEY (service_id) REFERENCES service(id) ON DELETE CASCADE
)`

// SQLite pragma to enable foreign-key enforcement. SQLite disables foreign
// keys by default; this must be executed on every connection.
const sqliteForeignKeysPragma = `PRAGMA foreign_keys = ON`

// scopeEntryDDL returns the CREATE TABLE statement for scope_entry that
// matches the given database type.
func scopeEntryDDL(dbType string) (string, error) {
	switch dbType {
	case DriverTypePostgres:
		return createScopeEntryTablePostgres, nil
	case DriverTypeSQLite:
		return createScopeEntryTableSQLite, nil
	case DriverTypeMySQL:
		return createScopeEntryTableMySQL, nil
	default:
		return "", fmt.Errorf("unsupported database type for schema init: %q", dbType)
	}
}

// InitSchema creates the service and scope_entry tables if they do not
// already exist. The DDL is database-type-aware: PostgreSQL uses BIGSERIAL,
// SQLite uses INTEGER PRIMARY KEY AUTOINCREMENT, and MySQL uses BIGINT
// AUTO_INCREMENT. The function is idempotent — calling it multiple times
// is safe.
func InitSchema(db *sql.DB, dbType string) error {
	// Enable foreign-key enforcement for SQLite (disabled by default).
	if dbType == DriverTypeSQLite {
		if _, err := db.Exec(sqliteForeignKeysPragma); err != nil {
			return fmt.Errorf("failed to enable SQLite foreign keys: %w", err)
		}
	}

	logging.Log().Info("Initializing database schema")

	if _, err := db.Exec(createServiceTable); err != nil {
		return fmt.Errorf("failed to create service table: %w", err)
	}

	scopeSQL, err := scopeEntryDDL(dbType)
	if err != nil {
		return err
	}

	if _, err := db.Exec(scopeSQL); err != nil {
		return fmt.Errorf("failed to create scope_entry table: %w", err)
	}

	logging.Log().Info("Database schema initialized successfully")
	return nil
}
