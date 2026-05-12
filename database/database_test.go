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

func TestNewConnection_UnsupportedType(t *testing.T) {
	cfg := config.Database{
		Type: "oracle",
	}

	db, err := NewConnection(cfg)
	assert.Nil(t, db, "should not return a connection for unsupported type")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported database type")
}

func TestNewConnection_SQLiteInMemory(t *testing.T) {
	cfg := config.Database{
		Type: DriverTypeSQLite,
		Name: ":memory:",
	}

	db, err := NewConnection(cfg)
	require.NoError(t, err)
	require.NotNil(t, db)
	defer func() { _ = db.Close() }()

	// Verify the connection works.
	var result int
	err = db.QueryRow("SELECT 1").Scan(&result)
	require.NoError(t, err)
	assert.Equal(t, 1, result)
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
			name: "mysql DSN with TLS",
			cfg: config.Database{
				Type:     DriverTypeMySQL,
				Host:     "mysql.example.com",
				Port:     3306,
				Name:     "credentials",
				User:     "root",
				Password: "secret",
				SSLMode:  "true",
			},
			want:    "root:secret@tcp(mysql.example.com:3306)/credentials?parseTime=true&tls=true",
			wantErr: false,
		},
		{
			name: "mysql DSN without TLS",
			cfg: config.Database{
				Type:     DriverTypeMySQL,
				Host:     "localhost",
				Port:     3306,
				Name:     "testdb",
				User:     "user",
				Password: "pass",
				SSLMode:  "",
			},
			want:    "user:pass@tcp(localhost:3306)/testdb?parseTime=true",
			wantErr: false,
		},
		{
			name: "sqlite DSN with file path",
			cfg: config.Database{
				Type: DriverTypeSQLite,
				Name: "/tmp/test.db",
			},
			want:    "/tmp/test.db",
			wantErr: false,
		},
		{
			name: "sqlite DSN defaults to memory",
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
			name:    "mysql maps to mysql",
			dbType:  DriverTypeMySQL,
			want:    "mysql",
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
