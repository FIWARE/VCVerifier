// Package database provides connection management for the integrated
// Credentials Config Service database. It supports PostgreSQL, MySQL, and
// SQLite backends, selected via the config.Database.Type field.
package database

import (
	"database/sql"
	"fmt"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"

	// PostgreSQL driver registration
	_ "github.com/jackc/pgx/v5/stdlib"
	// MySQL driver registration
	_ "github.com/go-sql-driver/mysql"
	// Pure-Go SQLite driver registration (no CGO required)
	_ "modernc.org/sqlite"
)

// Supported database driver type constants.
const (
	// DriverTypePostgres selects the PostgreSQL driver.
	DriverTypePostgres = "postgres"
	// DriverTypeMySQL selects the MySQL/MariaDB driver.
	DriverTypeMySQL = "mysql"
	// DriverTypeSQLite selects the pure-Go SQLite driver.
	DriverTypeSQLite = "sqlite"
)

// driverName maps a config database type to the Go sql.Open driver name.
func driverName(dbType string) (string, error) {
	switch dbType {
	case DriverTypePostgres:
		return "pgx", nil
	case DriverTypeMySQL:
		return "mysql", nil
	case DriverTypeSQLite:
		return "sqlite", nil
	default:
		return "", fmt.Errorf("unsupported database type: %q (must be %q, %q, or %q)",
			dbType, DriverTypePostgres, DriverTypeMySQL, DriverTypeSQLite)
	}
}

// buildDSN constructs a data-source name from the provided configuration.
// For PostgreSQL it returns a libpq-style connection string; for MySQL it
// returns a DSN in go-sql-driver/mysql format; for SQLite it returns the
// database file path (use ":memory:" for an in-memory database).
func buildDSN(cfg config.Database) (string, error) {
	switch cfg.Type {
	case DriverTypePostgres:
		return fmt.Sprintf(
			"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
			cfg.Host, cfg.Port, cfg.Name, cfg.User, cfg.Password, cfg.SSLMode,
		), nil
	case DriverTypeMySQL:
		// Format: user:password@tcp(host:port)/dbname?parseTime=true&tls=<sslMode>
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
			cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name,
		)
		if cfg.SSLMode != "" {
			dsn += fmt.Sprintf("&tls=%s", cfg.SSLMode)
		}
		return dsn, nil
	case DriverTypeSQLite:
		// For SQLite, Name is the file path or ":memory:" for in-memory.
		if cfg.Name == "" {
			return ":memory:", nil
		}
		return cfg.Name, nil
	default:
		return "", fmt.Errorf("unsupported database type: %q", cfg.Type)
	}
}

// NewConnection opens a database connection pool based on the provided
// configuration. The returned *sql.DB is ready to use and has been verified
// with a ping. Callers are responsible for closing it when done.
func NewConnection(cfg config.Database) (*sql.DB, error) {
	driver, err := driverName(cfg.Type)
	if err != nil {
		return nil, err
	}

	dsn, err := buildDSN(cfg)
	if err != nil {
		return nil, err
	}

	logging.Log().Infof("Opening %s database connection", cfg.Type)

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s connection: %w", cfg.Type, err)
	}

	// SQLite does not support concurrent writers and in-memory databases are
	// per-connection, so restrict the pool to a single connection.
	if cfg.Type == DriverTypeSQLite {
		db.SetMaxOpenConns(1)
	}

	if err := db.Ping(); err != nil {
		// Close the handle so we don't leak a half-opened pool.
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping %s database: %w", cfg.Type, err)
	}

	logging.Log().Infof("Database connection established (%s)", cfg.Type)
	return db, nil
}

// Close gracefully closes the database connection pool. It logs any error
// but does not return it, making it convenient for deferred calls.
func Close(db *sql.DB) {
	if db == nil {
		return
	}
	if err := db.Close(); err != nil {
		logging.Log().Warnf("Error closing database connection: %v", err)
	} else {
		logging.Log().Info("Database connection closed")
	}
}
