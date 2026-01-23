package config

import (
	"io"
	"os"
	"strings"
	"testing"

	"net/http"
	"reflect"

	"github.com/fiware/VCVerifier/logging"
	"github.com/stretchr/testify/assert"
)

type MockHttpClient struct {
	Answer string
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

	logging.Configure(true, "DEBUG", true, []string{})
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

func Test_getServices(t *testing.T) {
	mockedHttpClient := MockHttpClient{readFile("ccs_full.json", t)}
	ccsClient := HttpConfigClient{mockedHttpClient, "test.com"}
	services, err := ccsClient.GetServices()
	if err != nil {
		t.Error("should not return error", err)
	}
	assert.NotEmpty(t, services)
	expectedData := []ConfiguredService{
		{
			Id:               "service_all",
			DefaultOidcScope: "did_write",
			ServiceScopes: map[string]ScopeEntry{
				"did_write": {
					Credentials: []Credential{
						{
							Type:                     "VerifiableCredential",
							TrustedParticipantsLists: []TrustedParticipantsList{{Type: "ebsi", Url: "https://tir-pdc.ebsi.fiware.dev"}},
							TrustedIssuersLists:      []string{"https://til-pdc.ebsi.fiware.dev"},
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
											Id:   "my-field",
											Path: []string{"$.vc.my.claim"},
										},
									},
								},
							},
						},
					},
					DCQL: &DCQL{
						Credentials: []CredentialQuery{
							{
								Id:     "my-credential-query-id",
								Format: "jwt_vc_json",
								Claims: []ClaimsQuery{
									{
										Path:           []interface{}{"$.vc.credentialSubject.familyName"},
										IntentToRetain: true,
									},
								},
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
			},
		},
	}
	assert.Equal(t, 1, len(services))
	assert.Equal(t, expectedData, services)

}
