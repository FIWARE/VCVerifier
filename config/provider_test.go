package config

import (
	"reflect"
	"testing"

	"github.com/fiware/VCVerifier/logging"
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
					AuthorizationEndpoint:  "/api/v2/loginQR",
					ValidationMode:         "none",
					KeyAlgorithm:           "RS256",
					GenerateKey:            true,
					SupportedModes:         []string{"urlEncoded"},
					JwtExpiration:          30,
					StatusListCacheExpiry:  DefaultStatusCacheExpirySeconds,
					StatusListHttpTimeout:  DefaultStatusHttpTimeoutSeconds,
					RefreshTokenExpiration: DefaultRefreshTokenExpirationMinutes,
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
											TrustedIssuersLists:      []string{"https://til-pdc.ebsi.fiware.dev"},
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
				M2M: M2M{AuthEnabled: false, VerificationMethod: "JsonWebKey2020", SignatureType: "JsonWebSignature2020", KeyType: "RSAPS256"},
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
					JwtExpiration:         30,
					StatusListCacheExpiry: DefaultStatusCacheExpirySeconds,
					StatusListHttpTimeout: DefaultStatusHttpTimeoutSeconds,
					RefreshTokenExpiration: DefaultRefreshTokenExpirationMinutes,
				},
				Logging: logging.LoggingConfig{
					Level:         "INFO",
					JsonLogging:   true,
					LogRequests:   true,
					PathsToSkip:   nil,
					DisableCaller: false,
				},
				M2M:        M2M{AuthEnabled: false, VerificationMethod: "JsonWebKey2020", SignatureType: "JsonWebSignature2020", KeyType: "RSAPS256"},
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
					Did:                    "did:key:somekey",
					TirAddress:             "https://test.dev/trusted_issuer/v3/issuers/",
					TirCacheExpiry:         30,
					TilCacheExpiry:         30,
					SessionExpiry:          30,
					ValidationMode:         "none",
					KeyAlgorithm:           "RS256",
					GenerateKey:            true,
					SupportedModes:         []string{"urlEncoded"},
					JwtExpiration:          30,
					StatusListCacheExpiry:  DefaultStatusCacheExpirySeconds,
					StatusListHttpTimeout:  DefaultStatusHttpTimeoutSeconds,
					RefreshTokenExpiration: DefaultRefreshTokenExpirationMinutes,
				},
				Logging: logging.LoggingConfig{
					Level:       "DEBUG",
					JsonLogging: true,
					LogRequests: true,
				},
				M2M: M2M{AuthEnabled: false, VerificationMethod: "JsonWebKey2020", SignatureType: "JsonWebSignature2020", KeyType: "RSAPS256"},
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
			if !reflect.DeepEqual(gotConfiguration, tt.wantConfiguration) {
				t.Errorf("readConfig() = %v, want %v", logging.PrettyPrintObject(gotConfiguration), logging.PrettyPrintObject(tt.wantConfiguration))
			}
		})
	}
}

// TestRefreshTokenConfigDefaults verifies that the refresh token configuration
// fields receive correct default values when absent from the YAML input and
// are correctly parsed when explicitly set.
func TestRefreshTokenConfigDefaults(t *testing.T) {
	tests := []struct {
		name                       string
		configFile                 string
		wantRefreshTokenEnabled    bool
		wantRefreshTokenExpiration int
	}{
		{
			name:                       "Defaults applied when fields are absent",
			configFile:                 "data/empty_test.yaml",
			wantRefreshTokenEnabled:    false,
			wantRefreshTokenExpiration: DefaultRefreshTokenExpirationMinutes,
		},
		{
			name:                       "Explicit values parsed from YAML",
			configFile:                 "data/refresh_token_test.yaml",
			wantRefreshTokenEnabled:    true,
			wantRefreshTokenExpiration: 1440,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.Reset()
			gotConfig, err := ReadConfig(tt.configFile)
			assert.NoError(t, err, "ReadConfig should not return an error")
			assert.Equal(t, tt.wantRefreshTokenEnabled, gotConfig.Verifier.RefreshTokenEnabled,
				"RefreshTokenEnabled mismatch")
			assert.Equal(t, tt.wantRefreshTokenExpiration, gotConfig.Verifier.RefreshTokenExpiration,
				"RefreshTokenExpiration mismatch")
		})
	}
}
