package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCamelToUpperSnake(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"password", "PASSWORD"},
		{"readTimeout", "READ_TIMEOUT"},
		{"sslMode", "SSL_MODE"},
		{"host", "HOST"},
		{"jsonLogging", "JSON_LOGGING"},
		{"authEnabled", "AUTH_ENABLED"},
		{"configEndpoint", "CONFIG_ENDPOINT"},
		{"clientId", "CLIENT_ID"},
		{"did", "DID"},
		{"port", "PORT"},
		{"validationMode", "VALIDATION_MODE"},
		{"keyPath", "KEY_PATH"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, CamelToUpperSnake(tt.input))
		})
	}
}

func TestApplyEnvOverrides_StringField(t *testing.T) {
	t.Setenv("VCVERIFIER_DATABASE_PASSWORD", "secret123")

	cfg := Configuration{}
	require.NoError(t, ApplyEnvOverrides(&cfg))
	assert.Equal(t, "secret123", cfg.Database.Password)
}

func TestApplyEnvOverrides_IntField(t *testing.T) {
	t.Setenv("VCVERIFIER_SERVER_PORT", "9090")

	cfg := Configuration{}
	require.NoError(t, ApplyEnvOverrides(&cfg))
	assert.Equal(t, 9090, cfg.Server.Port)
}

func TestApplyEnvOverrides_Int64Field(t *testing.T) {
	t.Setenv("VCVERIFIER_CONFIG_REPO_UPDATE_INTERVAL", "60")

	cfg := Configuration{}
	require.NoError(t, ApplyEnvOverrides(&cfg))
	assert.Equal(t, int64(60), cfg.ConfigRepo.UpdateInterval)
}

func TestApplyEnvOverrides_BoolField(t *testing.T) {
	t.Setenv("VCVERIFIER_M2M_AUTH_ENABLED", "true")

	cfg := Configuration{}
	require.NoError(t, ApplyEnvOverrides(&cfg))
	assert.True(t, cfg.M2M.AuthEnabled)
}

func TestApplyEnvOverrides_MultipleFields(t *testing.T) {
	t.Setenv("VCVERIFIER_DATABASE_HOST", "db.prod.example.com")
	t.Setenv("VCVERIFIER_DATABASE_PORT", "5433")
	t.Setenv("VCVERIFIER_DATABASE_PASSWORD", "prod-secret")
	t.Setenv("VCVERIFIER_SERVER_PORT", "443")

	cfg := Configuration{}
	require.NoError(t, ApplyEnvOverrides(&cfg))
	assert.Equal(t, "db.prod.example.com", cfg.Database.Host)
	assert.Equal(t, 5433, cfg.Database.Port)
	assert.Equal(t, "prod-secret", cfg.Database.Password)
	assert.Equal(t, 443, cfg.Server.Port)
}

func TestApplyEnvOverrides_OverridesExistingValue(t *testing.T) {
	t.Setenv("VCVERIFIER_DATABASE_PASSWORD", "from_env")

	cfg := Configuration{
		Database: Database{Password: "from_yaml"},
	}
	require.NoError(t, ApplyEnvOverrides(&cfg))
	assert.Equal(t, "from_env", cfg.Database.Password)
}

func TestApplyEnvOverrides_DoesNotOverrideWhenUnset(t *testing.T) {
	cfg := Configuration{
		Database: Database{Password: "original"},
	}
	require.NoError(t, ApplyEnvOverrides(&cfg))
	assert.Equal(t, "original", cfg.Database.Password)
}

func TestApplyEnvOverrides_InvalidIntReturnsError(t *testing.T) {
	t.Setenv("VCVERIFIER_SERVER_PORT", "notanumber")

	cfg := Configuration{}
	err := ApplyEnvOverrides(&cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VCVERIFIER_SERVER_PORT")
}

func TestApplyEnvOverrides_InvalidBoolReturnsError(t *testing.T) {
	t.Setenv("VCVERIFIER_M2M_AUTH_ENABLED", "notabool")

	cfg := Configuration{}
	err := ApplyEnvOverrides(&cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VCVERIFIER_M2M_AUTH_ENABLED")
}

func TestApplyEnvOverrides_NestedPointerStructAllocated(t *testing.T) {
	t.Setenv("VCVERIFIER_ELSI_VALIDATION_ENDPOINT_HOST", "https://validator.example.com")

	cfg := Configuration{}
	require.NoError(t, ApplyEnvOverrides(&cfg))
	require.NotNil(t, cfg.Elsi.ValidationEndpoint)
	assert.Equal(t, "https://validator.example.com", cfg.Elsi.ValidationEndpoint.Host)
}

func TestApplyEnvOverrides_PointerStructNotAllocatedWithoutEnv(t *testing.T) {
	cfg := Configuration{}
	require.NoError(t, ApplyEnvOverrides(&cfg))
	assert.Nil(t, cfg.Elsi.ValidationEndpoint)
}

func TestApplyEnvOverrides_NestedStructField(t *testing.T) {
	t.Setenv("VCVERIFIER_VERIFIER_CLIENT_IDENTIFICATION_KEY_PATH", "/keys/client.pem")

	cfg := Configuration{}
	require.NoError(t, ApplyEnvOverrides(&cfg))
	assert.Equal(t, "/keys/client.pem", cfg.Verifier.ClientIdentification.KeyPath)
}
