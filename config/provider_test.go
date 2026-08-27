package config

import (
	"testing"

	"github.com/fiware/VCVerifier/logging"
	"github.com/google/go-cmp/cmp"
	"github.com/gookit/config/v2"
	"github.com/stretchr/testify/assert"
)

func Test_ReadConfig(t *testing.T) {
	type args struct {
		configFile string
	}
	tests := []struct {
		name              string
		args              args
		wantConfiguration Configuration
		wantErr           bool
	}{
		{
			"Read config",
			args{"data/config_test.yaml"},
			Configuration{
				Server: Server{
					Port:            3000,
					TemplateDir:     "views/",
					StaticDir:       "views/static",
					ReadTimeout:     100,
					WriteTimeout:    200,
					IdleTimeout:     300,
					ShutdownTimeout: 400,
				},
				Verifier: Verifier{
					Did:            "did:key:somekey",
					TirAddress:     "https://test.dev/trusted_issuer/v3/issuers/",
					TirCacheExpiry: 30,
					TilCacheExpiry: 30,
					SessionExpiry:  30,
					PolicyConfig: Policies{
						DefaultPolicies: PolicyMap{
							"SignaturePolicy": {},
							"TrustedIssuerRegistryPolicy": {
								"registryAddress": "waltId.com",
							},
						},
						CredentialTypeSpecificPolicies: map[string]PolicyMap{
							"gx:compliance": {
								"ValidFromBeforePolicy": {},
							},
						},
					},
					AuthorizationEndpoint: "/api/v2/loginQR",
					ValidationMode:        "none",
					KeyAlgorithm:          "RS256",
					GenerateKey:           true,
					SupportedModes:        []string{"urlEncoded"},
					DefaultRequestMode:    "byReference",
					JwtExpiration:         30,
					StatusListCacheExpiry: DefaultStatusCacheExpirySeconds,
					StatusListHttpTimeout: DefaultStatusHttpTimeoutSeconds,
					LdProofMaxAge:         DefaultLdProofMaxAgeSeconds,
					RefreshToken:          RefreshToken{Expiration: DefaultRefreshTokenExpirationMinutes, CleanupInterval: 60},
				},
				Logging: logging.LoggingConfig{
					Level:         "DEBUG",
					JsonLogging:   true,
					LogRequests:   true,
					PathsToSkip:   []string{"/health"},
					DisableCaller: true,
				},
				ConfigRepo: ConfigRepo{
					ConfigEndpoint: "",
					Services: []ConfiguredService{
						{
							Id:               "testService",
							DefaultOidcScope: "someScope",
							AllowedOrigins:   []string{"https://example.com"},
							ServiceScopes: map[string]ScopeEntry{
								"someScope": {
									Credentials: []Credential{

										{
											Type:                     "VerifiableCredential",
											TrustedParticipantsLists: []TrustedParticipantsList{{Type: "ebsi", Url: "https://tir-pdc.ebsi.fiware.dev"}},
											TrustedIssuersLists:      TrustedIssuersLists{{Type: "ebsi", Url: "https://til-pdc.ebsi.fiware.dev"}},
										},
									},
									PresentationDefinition: &PresentationDefinition{
										Id: "my-pd",
										InputDescriptors: []InputDescriptor{
											{
												Id: "my-descriptor",
												Constraints: Constraints{
													Fields: []Fields{
														{
															Id:   "my-field",
															Path: []string{"$.vc.my.claim"},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
					UpdateInterval: 30,
				},
				M2M: M2M{AuthEnabled: false, SignatureType: "JsonWebSignature2020", KeyType: "RSAPS256"},
				Database: Database{
					Host:    "localhost",
					Port:    5432,
					SSLMode: "disable",
				},
				ConfigServer: ConfigServer{
					Port:            8090,
					ReadTimeout:     5,
					WriteTimeout:    10,
					IdleTimeout:     120,
					ShutdownTimeout: 5,
				},
			},
			false,
		},
		{
			"Defaults only",
			args{"data/empty_test.yaml"},
			Configuration{
				Server: Server{Port: 8080,
					TemplateDir:     "views/",
					StaticDir:       "views/static/",
					ReadTimeout:     5,
					WriteTimeout:    10,
					IdleTimeout:     120,
					ShutdownTimeout: 5,
				},
				Verifier: Verifier{Did: "",
					TirAddress:            "",
					TirCacheExpiry:        30,
					TilCacheExpiry:        30,
					SessionExpiry:         30,
					ValidationMode:        "none",
					KeyAlgorithm:          "RS256",
					GenerateKey:           true,
					SupportedModes:        []string{"urlEncoded"},
					DefaultRequestMode:    "byReference",
					JwtExpiration:         30,
					StatusListCacheExpiry: DefaultStatusCacheExpirySeconds,
					StatusListHttpTimeout: DefaultStatusHttpTimeoutSeconds,
					LdProofMaxAge:         DefaultLdProofMaxAgeSeconds,
					RefreshToken:          RefreshToken{Expiration: DefaultRefreshTokenExpirationMinutes, CleanupInterval: 60},
				},
				Logging: logging.LoggingConfig{
					Level:         "INFO",
					JsonLogging:   true,
					LogRequests:   true,
					PathsToSkip:   nil,
					DisableCaller: false,
				},
				M2M:        M2M{AuthEnabled: false, SignatureType: "JsonWebSignature2020", KeyType: "RSAPS256"},
				ConfigRepo: ConfigRepo{UpdateInterval: 30},
				Database: Database{
					Host:    "localhost",
					Port:    5432,
					SSLMode: "disable",
				},
				ConfigServer: ConfigServer{
					Port:            8090,
					ReadTimeout:     5,
					WriteTimeout:    10,
					IdleTimeout:     120,
					ShutdownTimeout: 5,
				},
			},
			false,
		},
		{
			"Read database config",
			args{"data/database_test.yaml"},
			Configuration{
				Server: Server{
					Port:            3000,
					TemplateDir:     "views/",
					StaticDir:       "views/static",
					ReadTimeout:     5,
					WriteTimeout:    10,
					IdleTimeout:     120,
					ShutdownTimeout: 5,
				},
				Verifier: Verifier{
					Did:                   "did:key:somekey",
					TirAddress:            "https://test.dev/trusted_issuer/v3/issuers/",
					TirCacheExpiry:        30,
					TilCacheExpiry:        30,
					SessionExpiry:         30,
					ValidationMode:        "none",
					KeyAlgorithm:          "RS256",
					GenerateKey:           true,
					SupportedModes:        []string{"urlEncoded"},
					DefaultRequestMode:    "byReference",
					JwtExpiration:         30,
					StatusListCacheExpiry: DefaultStatusCacheExpirySeconds,
					StatusListHttpTimeout: DefaultStatusHttpTimeoutSeconds,
					LdProofMaxAge:         DefaultLdProofMaxAgeSeconds,
					RefreshToken:          RefreshToken{Expiration: DefaultRefreshTokenExpirationMinutes, CleanupInterval: 60},
				},
				Logging: logging.LoggingConfig{
					Level:       "DEBUG",
					JsonLogging: true,
					LogRequests: true,
				},
				M2M: M2M{AuthEnabled: false, SignatureType: "JsonWebSignature2020", KeyType: "RSAPS256"},
				ConfigRepo: ConfigRepo{
					UpdateInterval: 30,
				},
				Database: Database{
					Type:     "postgres",
					Host:     "db.example.com",
					Port:     5433,
					Name:     "ccs_db",
					User:     "ccs_user",
					Password: "ccs_pass",
					SSLMode:  "require",
				},
				ConfigServer: ConfigServer{
					Enabled:         true,
					Port:            9090,
					ReadTimeout:     15,
					WriteTimeout:    30,
					IdleTimeout:     240,
					ShutdownTimeout: 10,
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.Reset()
			gotConfiguration, err := ReadConfig(tt.args.configFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("readConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(gotConfiguration, tt.wantConfiguration); diff != "" {
				t.Errorf("Unexpected configuration: %s", diff)
			}
		})
	}
}

// TestReadConfigV5 verifies that a YAML config with "ebsi-v5" structured
// TrustedIssuersLists and TrustedParticipantsLists is correctly parsed.
func TestReadConfigV5(t *testing.T) {
	config.Reset()
	gotConfig, err := ReadConfig("data/config_test_v5.yaml")
	assert.NoError(t, err, "ReadConfig should not return an error for v5 config")

	services := gotConfig.ConfigRepo.Services
	assert.Len(t, services, 1)
	assert.Equal(t, "testServiceV5", services[0].Id)

	credentials := services[0].ServiceScopes["v5Scope"].Credentials
	assert.Len(t, credentials, 1)
	cred := credentials[0]
	assert.Equal(t, "VerifiableCredential", cred.Type)

	// Verify structured TrustedIssuersLists with type "ebsi-v5"
	assert.Len(t, cred.TrustedIssuersLists, 1)
	assert.Equal(t, "ebsi-v5", cred.TrustedIssuersLists[0].Type)
	assert.Equal(t, "https://til-v5.ebsi.fiware.dev", cred.TrustedIssuersLists[0].Url)

	// Verify TrustedParticipantsLists with type "ebsi-v5"
	assert.Len(t, cred.TrustedParticipantsLists, 1)
	assert.Equal(t, "ebsi-v5", cred.TrustedParticipantsLists[0].Type)
	assert.Equal(t, "https://tir-v5.ebsi.fiware.dev", cred.TrustedParticipantsLists[0].Url)
}

// TestReadConfigMixed verifies backward-compatible parsing of a YAML config
// that uses legacy string-array TrustedIssuersLists alongside structured
// TrustedParticipantsLists with mixed ebsi and ebsi-v5 types.
func TestReadConfigMixed(t *testing.T) {
	config.Reset()
	gotConfig, err := ReadConfig("data/config_test_mixed.yaml")
	assert.NoError(t, err, "ReadConfig should not return an error for mixed config")

	services := gotConfig.ConfigRepo.Services
	assert.Len(t, services, 1)
	assert.Equal(t, "testServiceMixed", services[0].Id)

	credentials := services[0].ServiceScopes["mixedScope"].Credentials
	assert.Len(t, credentials, 1)
	cred := credentials[0]

	// Legacy string array format should default to type "ebsi"
	assert.Len(t, cred.TrustedIssuersLists, 1)
	assert.Equal(t, DEFAULT_LIST_TYPE, cred.TrustedIssuersLists[0].Type)
	assert.Equal(t, "https://til-pdc.ebsi.fiware.dev", cred.TrustedIssuersLists[0].Url)

	// Mixed participants: ebsi and ebsi-v5
	assert.Len(t, cred.TrustedParticipantsLists, 2)
	assert.Equal(t, "ebsi", cred.TrustedParticipantsLists[0].Type)
	assert.Equal(t, "https://tir-pdc.ebsi.fiware.dev", cred.TrustedParticipantsLists[0].Url)
	assert.Equal(t, "ebsi-v5", cred.TrustedParticipantsLists[1].Type)
	assert.Equal(t, "https://tir-v5.ebsi.fiware.dev", cred.TrustedParticipantsLists[1].Url)
}

// TestRefreshTokenConfigDefaults verifies that the refresh token configuration
// fields receive correct default values when absent from the YAML input and
// are correctly parsed when explicitly set.
func TestRefreshTokenConfigDefaults(t *testing.T) {
	tests := []struct {
		name        string
		configFile  string
		wantEnabled bool
		wantExpiry  int
	}{
		{
			name:        "Defaults applied when refreshToken block is absent",
			configFile:  "data/empty_test.yaml",
			wantEnabled: false,
			wantExpiry:  DefaultRefreshTokenExpirationMinutes,
		},
		{
			name:        "Explicit values parsed from YAML",
			configFile:  "data/refresh_token_test.yaml",
			wantEnabled: true,
			wantExpiry:  1440,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.Reset()
			gotConfig, err := ReadConfig(tt.configFile)
			assert.NoError(t, err, "ReadConfig should not return an error")
			assert.Equal(t, tt.wantEnabled, gotConfig.Verifier.RefreshToken.Enabled,
				"RefreshToken.Enabled mismatch")
			assert.Equal(t, tt.wantExpiry, gotConfig.Verifier.RefreshToken.Expiration,
				"RefreshToken.Expiration mismatch")
		})
	}
}
