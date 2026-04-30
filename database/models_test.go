package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MarshalScopes / UnmarshalScopes
// ---------------------------------------------------------------------------

func TestMarshalScopes_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
	}{
		{"empty slice", []string{}},
		{"single scope", []string{"openid"}},
		{"multiple scopes", []string{"openid", "profile", "email"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := MarshalScopes(tc.scopes)
			require.NoError(t, err)

			decoded, err := UnmarshalScopes(encoded)
			require.NoError(t, err)
			assert.Equal(t, tc.scopes, decoded)
		})
	}
}

func TestUnmarshalScopes_InvalidJSON(t *testing.T) {
	_, err := UnmarshalScopes("not json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal scopes")
}

// ---------------------------------------------------------------------------
// MarshalCredentials / UnmarshalCredentials
// ---------------------------------------------------------------------------

func TestMarshalCredentials_RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		creds []map[string]interface{}
	}{
		{"empty slice", []map[string]interface{}{}},
		{"single credential", []map[string]interface{}{{"role": "admin"}}},
		{"multiple credentials", []map[string]interface{}{
			{"role": "admin", "org": "acme"},
			{"role": "user"},
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := MarshalCredentials(tc.creds)
			require.NoError(t, err)

			decoded, err := UnmarshalCredentials(encoded)
			require.NoError(t, err)
			assert.Equal(t, tc.creds, decoded)
		})
	}
}

func TestUnmarshalCredentials_InvalidJSON(t *testing.T) {
	_, err := UnmarshalCredentials("{invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal credentials")
}
