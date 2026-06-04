package database

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
)

// adaptPlaceholders rewrites `?` placeholders to `$N` when dbType is
// PostgreSQL. MySQL and SQLite use `?` natively.
func adaptPlaceholders(query, dbType string) string {
	if dbType != DriverTypePostgres {
		return query
	}
	var out []byte
	n := 1
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			out = append(out, []byte(fmt.Sprintf("$%d", n))...)
			n++
		} else {
			out = append(out, query[i])
		}
	}
	return string(out)
}

// SQL statements used by the migration. Written with `?` placeholders so
// they can be adapted per driver.
const (
	sqlMigSelectScopeCredentials = `SELECT id, credentials FROM scope_entry`
	sqlMigUpdateScopeCredentials = `UPDATE scope_entry SET credentials = ? WHERE id = ?`
)

// MigrateCredentialsTrustedListType scans all scope_entry rows and ensures
// that every EndpointEntry in the credentials JSON column has a non-empty
// listType field. Entries with an empty listType are backfilled with the
// default value ("ebsi"). This handles data written by older code versions
// that may not have populated the listType for TRUSTED_ISSUERS entries.
//
// The migration is idempotent — calling it multiple times is safe because
// rows that already have a populated listType are left untouched.
func MigrateCredentialsTrustedListType(db *sql.DB, dbType string) error {
	logging.Log().Info("Running migration: backfill empty listType in credentials JSON")

	rows, err := db.Query(sqlMigSelectScopeCredentials)
	if err != nil {
		return fmt.Errorf("migration: failed to query scope_entry: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type pendingUpdate struct {
		id       int64
		credJSON string
	}

	var updates []pendingUpdate

	for rows.Next() {
		var id int64
		var credJSON string
		if err := rows.Scan(&id, &credJSON); err != nil {
			return fmt.Errorf("migration: failed to scan scope_entry row: %w", err)
		}

		var creds []CredentialDB
		if err := json.Unmarshal([]byte(credJSON), &creds); err != nil {
			logging.Log().Warnf("Migration: skipping scope_entry id=%d with invalid credentials JSON: %v", id, err)
			continue
		}

		modified := false
		for i, cred := range creds {
			for j, entry := range cred.TrustedIssuersLists {
				if entry.ListType == "" {
					creds[i].TrustedIssuersLists[j].ListType = config.DEFAULT_LIST_TYPE
					modified = true
				}
			}
		}

		if modified {
			newJSON, err := json.Marshal(creds)
			if err != nil {
				return fmt.Errorf("migration: failed to marshal updated credentials for scope_entry id=%d: %w", id, err)
			}
			updates = append(updates, pendingUpdate{id: id, credJSON: string(newJSON)})
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migration: error iterating scope_entry rows: %w", err)
	}

	updateSQL := adaptPlaceholders(sqlMigUpdateScopeCredentials, dbType)
	for _, u := range updates {
		if _, err := db.Exec(updateSQL, u.credJSON, u.id); err != nil {
			return fmt.Errorf("migration: failed to update scope_entry id=%d: %w", u.id, err)
		}
		logging.Log().Infof("Migration: backfilled listType for scope_entry id=%d", u.id)
	}

	if len(updates) > 0 {
		logging.Log().Infof("Migration: updated %d scope_entry row(s) with missing listType", len(updates))
	} else {
		logging.Log().Info("Migration: no scope_entry rows required listType backfill")
	}

	return nil
}
