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

var TRUE_VALUE bool = true

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

	scopesVO := svc.ServiceScopes
	expectedOptionalField := true
	expectedScopesVO := map[string]ScopeEntry{
		"did_write": {
			Credentials: []Credential{
				{
					Type:                     "VerifiableCredential",
					TrustedParticipantsLists: []TrustedParticipantsList{{Type: "ebsi", Url: "https://tir-pdc.ebsi.fiware.dev"}},
					TrustedIssuersLists:      TrustedIssuersLists{{Type: "ebsi", Url: "https://til-pdc.ebsi.fiware.dev"}},
					HolderVerification:       HolderVerification{Enabled: false, Claim: "subject"},
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
									Id:       "my-field",
									Path:     []string{"$.vc.my.claim"},
									Optional: &expectedOptionalField,
								},
							},
						},
					},
				},
			},
			DCQL: &DCQL{
				Credentials: []CredentialQuery{
					{
						Id:                                "my-credential-query-id",
						Format:                            "jwt_vc_json",
						RequireCryptographicHolderBinding: &TRUE_VALUE,
						Claims:                            []ClaimsQuery{{Path: []interface{}{"$.vc.credentialSubject.familyName"}, IntentToRetain: true}},
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

func TestTrustedIssuersLists_UnmarshalJSON(t *testing.T) {
	type testCase struct {
		name     string
		input    string
		expected TrustedIssuersLists
		wantErr  bool
	}

	tests := []testCase{
		{
			name:  "structured format with explicit types",
			input: `[{"type":"ebsi-v5","url":"https://v5.example.com"},{"type":"ebsi","url":"https://v3.example.com"}]`,
			expected: TrustedIssuersLists{
				{Type: "ebsi-v5", Url: "https://v5.example.com"},
				{Type: "ebsi", Url: "https://v3.example.com"},
			},
		},
		{
			name:  "legacy plain string array",
			input: `["https://tir-a.example.com","https://tir-b.example.com"]`,
			expected: TrustedIssuersLists{
				{Type: DEFAULT_LIST_TYPE, Url: "https://tir-a.example.com"},
				{Type: DEFAULT_LIST_TYPE, Url: "https://tir-b.example.com"},
			},
		},
		{
			name:     "empty array",
			input:    `[]`,
			expected: TrustedIssuersLists{},
		},
		{
			name:  "single legacy string",
			input: `["https://only.example.com"]`,
			expected: TrustedIssuersLists{
				{Type: DEFAULT_LIST_TYPE, Url: "https://only.example.com"},
			},
		},
		{
			name:  "single structured entry",
			input: `[{"type":"ebsi-v5","url":"https://only-v5.example.com"}]`,
			expected: TrustedIssuersLists{
				{Type: "ebsi-v5", Url: "https://only-v5.example.com"},
			},
		},
		{
			name:    "invalid JSON",
			input:   `not-json`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got TrustedIssuersLists
			err := json.Unmarshal([]byte(tc.input), &got)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestTrustedIssuersListsDecodeHook(t *testing.T) {
	hook := TrustedIssuersListsDecodeHook()

	type testCase struct {
		name     string
		input    interface{}
		expected interface{}
	}

	tests := []testCase{
		{
			name: "legacy plain string slice",
			input: []interface{}{
				"https://tir-a.example.com",
				"https://tir-b.example.com",
			},
			expected: TrustedIssuersLists{
				{Type: DEFAULT_LIST_TYPE, Url: "https://tir-a.example.com"},
				{Type: DEFAULT_LIST_TYPE, Url: "https://tir-b.example.com"},
			},
		},
		{
			name: "structured map entries",
			input: []interface{}{
				map[string]interface{}{"type": "ebsi-v5", "url": "https://v5.example.com"},
				map[string]interface{}{"type": "ebsi", "url": "https://v3.example.com"},
			},
			expected: TrustedIssuersLists{
				{Type: "ebsi-v5", Url: "https://v5.example.com"},
				{Type: "ebsi", Url: "https://v3.example.com"},
			},
		},
		{
			name: "mixed strings and maps",
			input: []interface{}{
				"https://legacy.example.com",
				map[string]interface{}{"type": "ebsi-v5", "url": "https://v5.example.com"},
			},
			expected: TrustedIssuersLists{
				{Type: DEFAULT_LIST_TYPE, Url: "https://legacy.example.com"},
				{Type: "ebsi-v5", Url: "https://v5.example.com"},
			},
		},
		{
			name:     "empty slice",
			input:    []interface{}{},
			expected: TrustedIssuersLists{},
		},
	}

	targetType := reflect.TypeOf(TrustedIssuersLists{})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := hook(reflect.TypeOf(tc.input), targetType, tc.input)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}

	t.Run("passthrough for non-target type", func(t *testing.T) {
		input := []interface{}{"https://example.com"}
		result, err := hook(reflect.TypeOf(input), reflect.TypeOf(""), input)
		assert.NoError(t, err)
		// Should return the input unchanged since target type doesn't match.
		assert.Equal(t, input, result)
	})
}
