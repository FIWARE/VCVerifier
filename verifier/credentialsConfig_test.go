package verifier

import (
	"testing"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
)

// Test fixtures kept as named constants to avoid magic values.
const (
	testStatusServiceID       = "status-service"
	testStatusScope           = "openid"
	testStatusCredentialType  = "VerifiableCredential"
	testStatusUnknownCredType = "UnknownCredential"
	testStatusUnknownService  = "unknown-service"
)

// seedServiceCache replaces the global service cache with a fresh cache that
// contains exactly the supplied service. The cached entry never expires so
// tests that share the global cache remain deterministic regardless of the
// surrounding suite's execution order.
func seedServiceCache(t *testing.T, svc config.ConfiguredService) {
	t.Helper()
	common.ResetGlobalCache()
	common.GlobalCache.ServiceCache.Set(svc.Id, svc, cache.NoExpiration)
	t.Cleanup(func() { common.ResetGlobalCache() })
}

// newServiceWithCredentials builds a `ConfiguredService` that maps the default
// scope used by the tests to the provided credentials slice.
func newServiceWithCredentials(credentials ...config.Credential) config.ConfiguredService {
	return config.ConfiguredService{
		Id: testStatusServiceID,
		ServiceScopes: map[string]config.ScopeEntry{
			testStatusScope: {Credentials: credentials},
		},
	}
}

// TestServiceBackedCredentialsConfig_GetCredentialStatusConfig exercises the
// table-driven behaviour of `GetCredentialStatusConfig` for known/unknown
// services, scopes and credential types and for credentials that do / do not
// declare a `credentialStatus` block.
func TestServiceBackedCredentialsConfig_GetCredentialStatusConfig(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	enabledStatus := config.CredentialStatus{
		Enabled:          true,
		AcceptedPurposes: []string{config.StatusPurposeRevocation, config.StatusPurposeSuspension},
		RequireStatus:    true,
	}

	type testCase struct {
		name           string
		service        config.ConfiguredService
		queryService   string
		queryScope     string
		queryType      string
		expectedConfig config.CredentialStatus
	}

	tests := []testCase{
		{
			name: "known credential type with explicit credentialStatus returns the configured block",
			service: newServiceWithCredentials(config.Credential{
				Type:             testStatusCredentialType,
				CredentialStatus: enabledStatus,
			}),
			queryService:   testStatusServiceID,
			queryScope:     testStatusScope,
			queryType:      testStatusCredentialType,
			expectedConfig: enabledStatus,
		},
		{
			name: "known credential type without credentialStatus block returns the zero value",
			service: newServiceWithCredentials(config.Credential{
				Type: testStatusCredentialType,
			}),
			queryService:   testStatusServiceID,
			queryScope:     testStatusScope,
			queryType:      testStatusCredentialType,
			expectedConfig: config.CredentialStatus{},
		},
		{
			name: "unknown credential type returns the zero value with no error",
			service: newServiceWithCredentials(config.Credential{
				Type:             testStatusCredentialType,
				CredentialStatus: enabledStatus,
			}),
			queryService:   testStatusServiceID,
			queryScope:     testStatusScope,
			queryType:      testStatusUnknownCredType,
			expectedConfig: config.CredentialStatus{},
		},
		{
			name: "unknown scope returns the zero value with no error",
			service: newServiceWithCredentials(config.Credential{
				Type:             testStatusCredentialType,
				CredentialStatus: enabledStatus,
			}),
			queryService:   testStatusServiceID,
			queryScope:     "other-scope",
			queryType:      testStatusCredentialType,
			expectedConfig: config.CredentialStatus{},
		},
		{
			name: "unknown service returns the zero value with no error",
			service: newServiceWithCredentials(config.Credential{
				Type:             testStatusCredentialType,
				CredentialStatus: enabledStatus,
			}),
			queryService:   testStatusUnknownService,
			queryScope:     testStatusScope,
			queryType:      testStatusCredentialType,
			expectedConfig: config.CredentialStatus{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seedServiceCache(t, tc.service)

			cc := ServiceBackedCredentialsConfig{}
			got, err := cc.GetCredentialStatusConfig(tc.queryService, tc.queryScope, tc.queryType)

			assert.NoError(t, err, "GetCredentialStatusConfig must never return an error for missing entries")
			assert.Equal(t, tc.expectedConfig, got)
		})
	}
}

// TestServiceBackedCredentialsConfig_GetCredentialStatusConfig_DefaultsAreOff
// pins the critical "feature is off unless explicitly enabled" contract: a
// credential with the default (zero) `CredentialStatus` must report Enabled ==
// false so that the rest of the validation chain skips the revocation check.
func TestServiceBackedCredentialsConfig_GetCredentialStatusConfig_DefaultsAreOff(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	seedServiceCache(t, newServiceWithCredentials(config.Credential{Type: testStatusCredentialType}))

	cc := ServiceBackedCredentialsConfig{}
	got, err := cc.GetCredentialStatusConfig(testStatusServiceID, testStatusScope, testStatusCredentialType)

	assert.NoError(t, err)
	assert.False(t, got.Enabled, "zero-value CredentialStatus must leave the revocation-list check disabled")
	assert.Empty(t, got.AcceptedPurposes, "zero-value CredentialStatus must have no accepted purposes")
	assert.False(t, got.RequireStatus, "zero-value CredentialStatus must not require a status entry")
}
