package config

import (
	"reflect"
	"testing"

	"github.com/fiware/VCVerifier/logging"
	"github.com/gookit/config/v2"
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
					Port:        3000,
					TemplateDir: "views/",
					StaticDir:   "views/static",
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
					JwtExpiration:		 30,
				},
				Logging: Logging{
					Level:       "DEBUG",
					JsonLogging: true,
					LogRequests: true,
					PathsToSkip: []string{"/health"},
				},
				ConfigRepo: ConfigRepo{
					ConfigEndpoint: "",
					Services: []ConfiguredService{
						{
							Id:               "testService",
							DefaultOidcScope: "someScope",
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
			},
			false,
		},
		{
			"Defaults only",
			args{"data/empty_test.yaml"},
			Configuration{
				Server: Server{Port: 8080,
					TemplateDir: "views/",
					StaticDir:   "views/static/",
				},
				Verifier: Verifier{Did: "",
					TirAddress:     "",
					TirCacheExpiry: 30,
					TilCacheExpiry: 30,
					SessionExpiry:  30,
					ValidationMode: "none",
					KeyAlgorithm:   "RS256",
					GenerateKey:    true,
					SupportedModes: []string{"urlEncoded"},
					JwtExpiration:  30,
				},
				Logging: Logging{
					Level:       "INFO",
					JsonLogging: true,
					LogRequests: true,
					PathsToSkip: nil,
				},
				M2M:        M2M{AuthEnabled: false, VerificationMethod: "JsonWebKey2020", SignatureType: "JsonWebSignature2020", KeyType: "RSAPS256"},
				ConfigRepo: ConfigRepo{UpdateInterval: 30},
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
