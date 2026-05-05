package config

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"net/http"
	"reflect"

	"github.com/fiware/VCVerifier/logging"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
)

type MockHttpClient struct {
	Answer string
}

var LOGGING_CONFIG = logging.LoggingConfig{
	Level:         "DEBUG",
	JsonLogging:   true,
	LogRequests:   true,
	PathsToSkip:   []string{},
	DisableCaller: false,
}

func (mhc MockHttpClient) Get(url string) (resp *http.Response, err error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(mhc.Answer))}, nil
}

func readFile(filename string, t *testing.T) string {
	data, err := os.ReadFile("data/" + filename)
	if err != nil {
		t.Error("could not read file", err)
	}
	return string(data)
}

func Test_getScope(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)
	type test struct {
		testName          string
		testScope         string
		expectedEntry     ScopeEntry
		expectedError     error
		mockServiceScopes map[string]ScopeEntry
	}

	tests := []test{
		{testName: "For an existing scope, the correct entry should be returned.", testScope: "exists", mockServiceScopes: map[string]ScopeEntry{"exists": {Credentials: []Credential{{Type: "Test"}}}, "other": {Credentials: []Credential{{Type: "Other"}}}}, expectedEntry: ScopeEntry{Credentials: []Credential{{Type: "Test"}}}},
		{testName: "For an non-existing scope, an error should be returned.", testScope: "non-existing", mockServiceScopes: map[string]ScopeEntry{"exists": {Credentials: []Credential{{Type: "Test"}}}, "other": {Credentials: []Credential{{Type: "Other"}}}}, expectedError: ErrorNoSuchScope},
	}
	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {
			testService := ConfiguredService{ServiceScopes: tc.mockServiceScopes}
			scopeEntry, err := testService.GetScope(tc.testScope)
			if tc.expectedError != err {
				t.Errorf("%s - expected error %s but was %s.", tc.testName, tc.expectedError, err)
				return
			}
			if !reflect.DeepEqual(tc.expectedEntry, scopeEntry) {
				t.Errorf("%s - expected entry %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedEntry), logging.PrettyPrintObject(scopeEntry))
				return
			}
		})
	}

}

func Test_CredentialStatusDeserialisation(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName                 string
		rawJSON                  string
		expectedEnabled          bool
		expectedAcceptedPurposes []string
		expectedRequireStatus    bool
	}

	tests := []test{
		{
			testName:                 "A credential without a credentialStatus block deserialises to a zero-value CredentialStatus with Enabled false.",
			rawJSON:                  `{"type":"VerifiableCredential"}`,
			expectedEnabled:          false,
			expectedAcceptedPurposes: nil,
			expectedRequireStatus:    false,
		},
		{
			testName:                 "A credential with credentialStatus.enabled true deserialises with Enabled true and AcceptedPurposes empty.",
			rawJSON:                  `{"type":"VerifiableCredential","credentialStatus":{"enabled":true}}`,
			expectedEnabled:          true,
			expectedAcceptedPurposes: nil,
			expectedRequireStatus:    false,
		},
		{
			testName:                 "A credential with an explicit AcceptedPurposes list preserves it verbatim.",
			rawJSON:                  `{"type":"VerifiableCredential","credentialStatus":{"enabled":true,"acceptedPurposes":["revocation","suspension"],"requireStatus":true}}`,
			expectedEnabled:          true,
			expectedAcceptedPurposes: []string{"revocation", "suspension"},
			expectedRequireStatus:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			var credential Credential
			if err := json.Unmarshal([]byte(tc.rawJSON), &credential); err != nil {
				t.Fatalf("%s - failed to unmarshal JSON: %v", tc.testName, err)
			}
			assert.Equal(t, tc.expectedEnabled, credential.CredentialStatus.Enabled)
			assert.Equal(t, tc.expectedAcceptedPurposes, credential.CredentialStatus.AcceptedPurposes)
			assert.Equal(t, tc.expectedRequireStatus, credential.CredentialStatus.RequireStatus)
		})
	}
}

func Test_CredentialStatusMapstructureDecoding(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName                 string
		input                    map[string]interface{}
		expectedEnabled          bool
		expectedAcceptedPurposes []string
		expectedRequireStatus    bool
	}

	tests := []test{
		{
			testName:                 "Missing credentialStatus key leaves zero-value CredentialStatus on the Credential.",
			input:                    map[string]interface{}{"type": "VerifiableCredential"},
			expectedEnabled:          false,
			expectedAcceptedPurposes: nil,
			expectedRequireStatus:    false,
		},
		{
			testName: "credentialStatus.enabled true is honoured via mapstructure.",
			input: map[string]interface{}{
				"type": "VerifiableCredential",
				"credentialStatus": map[string]interface{}{
					"enabled": true,
				},
			},
			expectedEnabled:          true,
			expectedAcceptedPurposes: nil,
			expectedRequireStatus:    false,
		},
		{
			testName: "Explicit empty acceptedPurposes list is preserved (not auto-defaulted).",
			input: map[string]interface{}{
				"type": "VerifiableCredential",
				"credentialStatus": map[string]interface{}{
					"enabled":          true,
					"acceptedPurposes": []interface{}{},
					"requireStatus":    true,
				},
			},
			expectedEnabled:          true,
			expectedAcceptedPurposes: []string{},
			expectedRequireStatus:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			var credential Credential
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				TagName: "mapstructure",
				Result:  &credential,
			})
			if err != nil {
				t.Fatalf("%s - failed to create decoder: %v", tc.testName, err)
			}
			if err := decoder.Decode(tc.input); err != nil {
				t.Fatalf("%s - failed to decode: %v", tc.testName, err)
			}
			assert.Equal(t, tc.expectedEnabled, credential.CredentialStatus.Enabled)
			assert.Equal(t, tc.expectedAcceptedPurposes, credential.CredentialStatus.AcceptedPurposes)
			assert.Equal(t, tc.expectedRequireStatus, credential.CredentialStatus.RequireStatus)
		})
	}
}

func Test_DefaultAcceptedStatusPurposes(t *testing.T) {
	purposes := DefaultAcceptedStatusPurposes()
	assert.Equal(t, []string{StatusPurposeRevocation}, purposes)

	// Must return a fresh slice: mutating the result should not leak back to
	// subsequent callers.
	purposes[0] = "mutated"
	assert.Equal(t, []string{StatusPurposeRevocation}, DefaultAcceptedStatusPurposes())
}

func Test_getServices(t *testing.T) {
	mockedHttpClient := MockHttpClient{readFile("ccs_full.json", t)}
	ccsClient := HttpConfigClient{mockedHttpClient, "test.com"}
	services, err := ccsClient.GetServices()
	if err != nil {
		t.Error("should not return error", err)
	}
	assert.NotEmpty(t, services)
	assert.Len(t, services, 1)

	svc := services[0]
	assert.Equal(t, "service_all", svc.Id)
	assert.Equal(t, "did_write", svc.DefaultOidcScope)

	scopesVO := make(map[string]ScopeEntryVO, len(svc.ServiceScopes))
	for k, v := range svc.ServiceScopes {
		scopesVO[k] = v.VO()
	}

	expectedScopesVO := map[string]ScopeEntryVO{
		"did_write": {
			Credentials: []CredentialVo{
				{
					Type:                     "VerifiableCredential",
					TrustedParticipantsLists: []TrustedParticipantsList{{Type: "ebsi", Url: "https://tir-pdc.ebsi.fiware.dev"}},
					TrustedIssuersLists:      []string{"https://til-pdc.ebsi.fiware.dev"},
					HolderVerification:       HolderVerification{Enabled: false, Claim: "subject"},
				},
			},
			PresentationDefinition: &PresentationDefinitionVO{
				Id: "my-pd",
				InputDescriptors: []InputDescriptorVO{
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
						Format: map[string]FormatObjectVO{},
					},
				},
				Format: map[string]FormatObjectVO{},
			},
			DCQL: &DCQLVO{
				Credentials: []CredentialQueryVO{
					{
						Id:                 "my-credential-query-id",
						Format:             "jwt_vc_json",
						Claims:             []ClaimsQuery{{Path: []interface{}{"$.vc.credentialSubject.familyName"}, IntentToRetain: true}},
						TrustedAuthorities: []TrustedAuthorityQuery{},
					},
				},
				CredentialSets: []CredentialSetQuery{
					{
						Options: [][]string{{"my-credential-query-id"}},
						Purpose: "Please provide your family name.",
					},
				},
			},
		},
	}
	assert.Equal(t, expectedScopesVO, scopesVO)
}
