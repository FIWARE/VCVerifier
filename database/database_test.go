package database

import (
	"testing"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// LOGGING_CONFIG initializes the logger for test output.
var LOGGING_CONFIG = logging.LoggingConfig{
	Level:       "DEBUG",
	JsonLogging: false,
	LogRequests: false,
}

func init() {
	logging.Configure(LOGGING_CONFIG)
}

func TestNewConnection_SQLiteInMemory(t *testing.T) {
	cfg := config.Database{
		Type: DriverTypeSQLite,
		Name: ":memory:",
	}

	db, err := NewConnection(cfg)
	require.NoError(t, err, "should open in-memory SQLite without error")
	require.NotNil(t, db, "returned *sql.DB must not be nil")

	// Verify the connection is usable.
	err = db.Ping()
	assert.NoError(t, err, "ping should succeed on open connection")

	Close(db)

	// After close, ping should fail.
	err = db.Ping()
	assert.Error(t, err, "ping should fail after close")
}

func TestNewConnection_SQLiteEmptyName(t *testing.T) {
	cfg := config.Database{
		Type: DriverTypeSQLite,
		Name: "",
	}

	db, err := NewConnection(cfg)
	require.NoError(t, err, "empty name should default to :memory:")
	require.NotNil(t, db)
	defer Close(db)

	err = db.Ping()
	assert.NoError(t, err)
}

func TestNewConnection_UnsupportedType(t *testing.T) {
	cfg := config.Database{
		Type: "mysql",
	}

	db, err := NewConnection(cfg)
	assert.Nil(t, db, "should not return a connection for unsupported type")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported database type")
}

func TestNewConnection_EmptyType(t *testing.T) {
	cfg := config.Database{
		Type: "",
	}

	db, err := NewConnection(cfg)
	assert.Nil(t, db)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported database type")
}

func TestBuildDSN(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Database
		want    string
		wantErr bool
	}{
		{
			name: "postgres DSN",
			cfg: config.Database{
				Type:     DriverTypePostgres,
				Host:     "db.example.com",
				Port:     5433,
				Name:     "mydb",
				User:     "admin",
				Password: "secret",
				SSLMode:  "require",
			},
			want:    "host=db.example.com port=5433 dbname=mydb user=admin password=secret sslmode=require",
			wantErr: false,
		},
		{
			name: "sqlite with file path",
			cfg: config.Database{
				Type: DriverTypeSQLite,
				Name: "/tmp/test.db",
			},
			want:    "/tmp/test.db",
			wantErr: false,
		},
		{
			name: "sqlite with empty name defaults to memory",
			cfg: config.Database{
				Type: DriverTypeSQLite,
				Name: "",
			},
			want:    ":memory:",
			wantErr: false,
		},
		{
			name: "unsupported type returns error",
			cfg: config.Database{
				Type: "oracle",
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildDSN(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDriverName(t *testing.T) {
	tests := []struct {
		name    string
		dbType  string
		want    string
		wantErr bool
	}{
		{
			name:    "postgres maps to pgx",
			dbType:  DriverTypePostgres,
			want:    "pgx",
			wantErr: false,
		},
		{
			name:    "sqlite maps to sqlite",
			dbType:  DriverTypeSQLite,
			want:    "sqlite",
			wantErr: false,
		},
		{
			name:    "unknown type errors",
			dbType:  "mongodb",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := driverName(tt.dbType)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClose_NilDB(t *testing.T) {
	// Close on nil should not panic.
	assert.NotPanics(t, func() {
		Close(nil)
	})
}

func TestNewConnection_SQLiteExecuteQuery(t *testing.T) {
	cfg := config.Database{
		Type: DriverTypeSQLite,
		Name: ":memory:",
	}

	db, err := NewConnection(cfg)
	require.NoError(t, err)
	defer Close(db)

	// Verify the connection works for real SQL operations.
	_, err = db.Exec("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
	require.NoError(t, err, "should be able to create a table")

	_, err = db.Exec("INSERT INTO test_table (id, name) VALUES (1, 'hello')")
	require.NoError(t, err, "should be able to insert a row")

	var name string
	err = db.QueryRow("SELECT name FROM test_table WHERE id = 1").Scan(&name)
	require.NoError(t, err)
	assert.Equal(t, "hello", name)
}
