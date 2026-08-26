package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	common "github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
)

func TestVerifyWithJsonPath(t *testing.T) {

	type test struct {
		testName            string
		path                string
		allowedValues       []interface{}
		credentialToVerifiy common.Credential
		expectedResult      bool
	}

	tests := []test{
		{testName: "When the string claim matches, it should be valid.", path: "$.test", allowedValues: []interface{}{"value"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": "value"}), expectedResult: true},
		{testName: "When the string claim is contained in the allowed values, it should be valid.", path: "$.test", allowedValues: []interface{}{"value", "otherValue"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": "value"}), expectedResult: true},
		{testName: "When the claim does not exist, it should be valid.", path: "$.test", allowedValues: []interface{}{"value"}, credentialToVerifiy: getTestCredential(map[string]interface{}{}), expectedResult: true},
		{testName: "When the string claim does not match, it should be invalid.", path: "$.test", allowedValues: []interface{}{"value"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": "otherValue"}), expectedResult: false},
		{testName: "When the claim contains another type, it should be invalid.", path: "$.test", allowedValues: []interface{}{"value"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": 1}), expectedResult: false},
		{testName: "When the int claim matches, it should be valid.", path: "$.test", allowedValues: []interface{}{1.0}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": 1}), expectedResult: true},
		{testName: "When the int claim is contained in the allowed values, it should be valid.", path: "$.test", allowedValues: []interface{}{1.0, 2.0}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": 1}), expectedResult: true},
		{testName: "When the int claim does not match, it should be invalid.", path: "$.test", allowedValues: []interface{}{1.0}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": 2}), expectedResult: false},
		{testName: "When the bool claim matches, it should be valid.", path: "$.test", allowedValues: []interface{}{true}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": true}), expectedResult: true},
		{testName: "When the bool claim does not match, it should be invalid.", path: "$.test", allowedValues: []interface{}{true}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": false}), expectedResult: false},
		{testName: "When the object claim matches, it should be valid.", path: "$.test", allowedValues: []interface{}{map[string]interface{}{"a": "b"}}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": map[string]interface{}{"a": "b"}}), expectedResult: true},
		{testName: "When the object claim is contained, it should be valid.", path: "$.test", allowedValues: []interface{}{map[string]interface{}{"a": "b"}, map[string]interface{}{"a": "c"}}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": map[string]interface{}{"a": "b"}}), expectedResult: true},
		{testName: "When the object claim does not match, it should be invalid.", path: "$.test", allowedValues: []interface{}{map[string]interface{}{"a": "b"}}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": map[string]interface{}{"a": "c"}}), expectedResult: false},
		{testName: "When the string inside the claim matches, it should be valid.", path: "$.test.sub", allowedValues: []interface{}{"value"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": map[string]interface{}{"sub": "value"}}), expectedResult: true},
		{testName: "When the sub claim does not exist, it should be valid.", path: "$.test.sub", allowedValues: []interface{}{"value"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": "t"}), expectedResult: true},
		{testName: "When the string inside the claim matches, it should be valid.", path: "$.test.sub", allowedValues: []interface{}{"value"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": map[string]interface{}{"sub": "otherValue"}}), expectedResult: false},
		{testName: "When the string inside the claim does not match, it should be invalid.", path: "$.test.sub", allowedValues: []interface{}{"value"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": map[string]interface{}{"sub": map[string]interface{}{"sub": "value"}}}), expectedResult: false},
		{testName: "When the string inside the array matches, it should be valid.", path: "$.test", allowedValues: []interface{}{"a", "b", "c"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{"a"}}), expectedResult: true},
		{testName: "When the string array is contained, it should be valid.", path: "$.test", allowedValues: []interface{}{"a", "b", "c"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{}}), expectedResult: true},
		{testName: "When the string array is empty, it should be valid.", path: "$.test", allowedValues: []interface{}{"a", "b", "c"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{"a", "b"}}), expectedResult: true},
		{testName: "When the string array is equal, it should be valid.", path: "$.test", allowedValues: []interface{}{"a", "b", "c"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{"a", "b", "c"}}), expectedResult: true},
		{testName: "When the strings are contained that are not allowed, it should be invalid.", path: "$.test", allowedValues: []interface{}{"a", "b", "c"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{"a", "b", "c", "d"}}), expectedResult: false},
		{testName: "When the strings are contained that are not allowed, it should be invalid.", path: "$.test", allowedValues: []interface{}{"a", "b", "c"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{"d"}}), expectedResult: false},
		{testName: "When an array element is selected and the sub claim matches, it should be valid.", path: `$.test[?(@.a=="b")].role[*]`, allowedValues: []interface{}{"OPERATOR", "READER"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{map[string]interface{}{"a": "b", "role": []string{"OPERATOR"}}}}), expectedResult: true},
		{testName: "When the selected element is not contained, it should be valid.", path: `$.test[?(@.a=="b")].role[*]`, allowedValues: []interface{}{"OPERATOR", "READER"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{map[string]interface{}{"a": "c", "role": []string{"ADMIN"}}}}), expectedResult: true},
		{testName: "When the selected element does not have any such claims, it should be valid.", path: `$.test[?(@.a=="b")].role[*]`, allowedValues: []interface{}{"OPERATOR", "READER"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{map[string]interface{}{"a": "b"}}}), expectedResult: true},
		{testName: "When an array element is selected and the sub claim does not match, it should be invalid.", path: `$.test[?(@.a=="b")].role[*]`, allowedValues: []interface{}{"OPERATOR", "READER"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{map[string]interface{}{"a": "b", "role": []string{"ADMIN"}}}}), expectedResult: false},
		{testName: "When an array element is selected and the sub claim contains not allowed values, it should be invalid.", path: `$.test[?(@.a=="b")].role[*]`, allowedValues: []interface{}{"OPERATOR", "READER"}, credentialToVerifiy: getTestCredential(map[string]interface{}{"test": []interface{}{map[string]interface{}{"a": "b", "role": []string{"ADMIN", "OPERATOR", "READER"}}}}), expectedResult: false},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {

			logging.Log().Info("TestVerifyWithJsonPath +++++++++++++++++ Running test: ", tc.testName)

			result := verifyWithJsonPath(tc.credentialToVerifiy.Contents().Subject[0], tir.Claim{Path: tc.path, AllowedValues: tc.allowedValues})
			if result != tc.expectedResult {
				t.Errorf("%s - Expected result %v but was %v.", tc.testName, tc.expectedResult, result)
				return
			}
		})
	}
}

func TestVerifyVC_Issuers(t *testing.T) {

	type test struct {
		testName            string
		credentialToVerifiy common.Credential
		verificationContext ValidationContext
		participantsList    []string
		participantsV5List  []string
		tirResponse         tir.TrustedIssuer
		tirResponseV5       tir.TrustedIssuer
		tirError            error
		tirErrorV5          error
		expectedResult      bool
	}

	tests := []test{
		{testName: "If no trusted issuer is configured in the list, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("test", "claim"), verificationContext: getVerificationContext(),
			participantsList: []string{}, tirResponse: tir.TrustedIssuer{}, tirError: nil, expectedResult: false},
		{testName: "If the trusted issuer is invalid, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("test", "claim"), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: tir.TrustedIssuer{Attributes: []tir.IssuerAttribute{{Body: "invalidBody"}}}, tirError: nil, expectedResult: false},
		{testName: "If the type is not included, the vc should be rejected.",
			credentialToVerifiy: getTypedCredential("AnotherType", "testClaim", "testValue"), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "AnotherType", map[string][]interface{}{})}), tirError: nil, expectedResult: false},
		{testName: "If one of the types is not allowed, the vc should be rejected.",
			credentialToVerifiy: getMultiTypeCredential([]string{"VerifiableCredential", "SecondType"}, "testClaim", "testValue"), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}), tirError: nil, expectedResult: false},
		{testName: "If no restriction is configured, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}), tirError: nil, expectedResult: true},
		{testName: "If no restricted claim is included, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"another": {"claim"}})}), tirError: nil, expectedResult: true},
		{testName: "If the (string)claim is allowed, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {"testValue"}})}), tirError: nil, expectedResult: true},
		{testName: "If the (string)claim is one of the allowed values, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {"testValue", "anotherAllowedValue"}})}), tirError: nil, expectedResult: true},
		{testName: "If the (string)claim is not allowed, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "anotherValue"), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {"testValue"}})}), tirError: nil, expectedResult: false},
		{testName: "If the (number)claim is allowed, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", 1), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {1}})}), tirError: nil, expectedResult: true},
		{testName: "If the (number)claim is not allowed, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", 2), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {1}})}), tirError: nil, expectedResult: false},
		{testName: "If the (object)claim is allowed, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", map[string]interface{}{"some": "object"}), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {map[string]interface{}{"some": "object"}}})}), tirError: nil, expectedResult: true},
		{testName: "If the all claim allowed, the vc should be allowed.",
			credentialToVerifiy: getMultiClaimCredential(map[string]interface{}{"claimA": map[string]interface{}{"some": "object"}, "claimB": "b"}), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"claimA": {map[string]interface{}{"some": "object"}}, "claimB": {"b"}})}), tirError: nil, expectedResult: true},
		{testName: "If a wildcard til is configured for the type, the vc should be allowed.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getWildcardVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirError: nil, expectedResult: true},
		{testName: "If all types are allowed, the vc should be allowed.",
			credentialToVerifiy: getMultiTypeCredential([]string{"VerifiableCredential", "SecondType"}, "testClaim", "testValue"), verificationContext: getWildcardAndNormalVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "SecondType", map[string][]interface{}{}), getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}), tirError: nil, expectedResult: true},
		{testName: "If not all claims are allowed, the vc should be rejected.",
			credentialToVerifiy: getMultiClaimCredential(map[string]interface{}{"claimA": map[string]interface{}{"some": "object"}, "claimB": "b"}), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"claimA": {map[string]interface{}{"some": "object"}}, "claimB": {"c"}})}), tirError: nil, expectedResult: false},
		{testName: "If the trusted-issuers-registry responds with an error, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}), tirError: errors.New("some-error"), expectedResult: false},
		{testName: "If an invalid verification context is provided, the credential should be rejected.",
			credentialToVerifiy: getVerifiableCredential("test", "claim"), verificationContext: "No-context", participantsList: []string{}, tirResponse: tir.TrustedIssuer{}, tirError: nil, expectedResult: false},
		{testName: "If a wildcard til and another til is configured for the type, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getInvalidMixedVerificationContext(),
			participantsList: []string{"did:test:issuer"}, tirError: nil, expectedResult: false},
		// ebsi-v5 test cases
		{testName: "If the issuer is found via ebsi-v5, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"),
			verificationContext: getV5VerificationContext(),
			participantsV5List:  []string{"did:test:issuer"},
			tirResponseV5:       getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}),
			expectedResult:      true},
		{testName: "If the issuer is not found via ebsi-v5, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"),
			verificationContext: getV5VerificationContext(),
			participantsV5List:  []string{},
			tirResponseV5:       tir.TrustedIssuer{},
			expectedResult:      false},
		{testName: "If the ebsi-v5 registry returns an error, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"),
			verificationContext: getV5VerificationContext(),
			participantsV5List:  []string{"did:test:issuer"},
			tirResponseV5:       tir.TrustedIssuer{},
			tirErrorV5:          errors.New("v5-error"),
			expectedResult:      false},
		// Mixed ebsi + ebsi-v5 test cases
		{testName: "Mixed types: issuer found via ebsi (v3/v4) takes precedence.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"),
			verificationContext: getMixedEbsiVerificationContext(),
			participantsList:    []string{"did:test:issuer"},
			tirResponse:         getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}),
			participantsV5List:  []string{},
			tirResponseV5:       tir.TrustedIssuer{},
			expectedResult:      true},
		{testName: "Mixed types: issuer not in ebsi but found via ebsi-v5.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"),
			verificationContext: getMixedEbsiVerificationContext(),
			participantsList:    []string{},
			tirResponse:         tir.TrustedIssuer{},
			participantsV5List:  []string{"did:test:issuer"},
			tirResponseV5:       getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}),
			expectedResult:      true},
		{testName: "Mixed types: issuer not found in either registry should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"),
			verificationContext: getMixedEbsiVerificationContext(),
			participantsList:    []string{},
			tirResponse:         tir.TrustedIssuer{},
			participantsV5List:  []string{},
			tirResponseV5:       tir.TrustedIssuer{},
			expectedResult:      false},
		// HTTPS URI issuer test cases
		{testName: "HTTPS issuer matching a configured trusted issuer URL should be accepted.",
			credentialToVerifiy: getHttpsIssuerCredential("https://issuer.example.com", "testClaim", "testValue"),
			verificationContext: getHttpsIssuerVerificationContext("https://issuer.example.com"),
			expectedResult:      true},
		{testName: "HTTPS issuer not matching any configured trusted issuer URL should be rejected.",
			credentialToVerifiy: getHttpsIssuerCredential("https://untrusted.example.com", "testClaim", "testValue"),
			verificationContext: getHttpsIssuerVerificationContext("https://issuer.example.com"),
			expectedResult:      false},
		{testName: "HTTPS issuer with wildcard TIL should be accepted.",
			credentialToVerifiy: getHttpsIssuerCredential("https://any-issuer.example.com", "testClaim", "testValue"),
			verificationContext: getHttpsIssuerVerificationContext("*"),
			expectedResult:      true},
		{testName: "HTTPS issuer should match regardless of trust list type field.",
			credentialToVerifiy: getHttpsIssuerCredential("https://issuer.example.com", "testClaim", "testValue"),
			verificationContext: TrustRegistriesValidationContext{
				trustedIssuersLists: map[string][]config.TrustedIssuersList{
					"VerifiableCredential": {{Type: "ebsi-v5", Url: "https://issuer.example.com"}},
				},
			},
			expectedResult: true},
		{testName: "HTTPS issuer matching one of multiple TIL entries should be accepted.",
			credentialToVerifiy: getHttpsIssuerCredential("https://issuer-b.example.com", "testClaim", "testValue"),
			verificationContext: TrustRegistriesValidationContext{
				trustedIssuersLists: map[string][]config.TrustedIssuersList{
					"VerifiableCredential": {
						{Type: "ebsi", Url: "https://issuer-a.example.com"},
						{Type: "ebsi", Url: "https://issuer-b.example.com"},
					},
				},
			},
			expectedResult: true},
		{testName: "DID issuer should still use EBSI dispatch when HTTPS TIL entries are also present.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"),
			verificationContext: TrustRegistriesValidationContext{
				trustedIssuersLists: map[string][]config.TrustedIssuersList{
					"VerifiableCredential": {
						{Type: "ebsi", Url: "http://my-til.org"},
						{Type: "ebsi", Url: "https://issuer.example.com"},
					},
				},
			},
			participantsList: []string{"did:test:issuer"},
			tirResponse:      getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}),
			expectedResult:   true},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {

			logging.Log().Info("TestVerifyVC +++++++++++++++++ Running test: ", tc.testName)

			tirClient := mockTirClient{
				participantsList:   tc.participantsList,
				participantsV5List: tc.participantsV5List,
				expectedIssuer:     tc.tirResponse,
				expectedIssuerV5:   tc.tirResponseV5,
				expectedError:      tc.tirError,
				expectedErrorV5:    tc.tirErrorV5,
			}
			trustedIssuerVerificationService := TrustedIssuerValidationService{tirClient}
			result, _ := trustedIssuerVerificationService.ValidateVC(&tc.credentialToVerifiy, tc.verificationContext)
			if result != tc.expectedResult {
				t.Errorf("%s - Expected result %v but was %v.", tc.testName, tc.expectedResult, result)
				return
			}
		})
	}
}

func TestVerifyForType(t *testing.T) {

	type test struct {
		testName         string
		subject          common.Subject
		credentialConfig []tir.Credential
		expectedResult   bool
	}

	tests := []test{
		{testName: "When there are no credential configs, it should be invalid.",
			subject:          common.Subject{CustomFields: map[string]any{"role": "ADMIN"}},
			credentialConfig: []tir.Credential{},
			expectedResult:   false},
		{testName: "When the config has no claims, it should be valid.",
			subject:          common.Subject{CustomFields: map[string]any{"role": "ADMIN"}},
			credentialConfig: []tir.Credential{{CredentialsType: "VerifiableCredential", Claims: []tir.Claim{}}},
			expectedResult:   true},
		{testName: "When the single config has all claims matching, it should be valid.",
			subject:          common.Subject{CustomFields: map[string]any{"role": "ADMIN"}},
			credentialConfig: []tir.Credential{{CredentialsType: "VerifiableCredential", Claims: []tir.Claim{{Name: "role", AllowedValues: []any{"ADMIN"}}}}},
			expectedResult:   true},
		{testName: "When there are multiple configs and the first is invalid but the second matches, it should be valid (OR logic).",
			subject: common.Subject{CustomFields: map[string]any{"role": "READER"}},
			credentialConfig: []tir.Credential{
				{CredentialsType: "VerifiableCredential", Claims: []tir.Claim{{Name: "role", AllowedValues: []any{"ADMIN"}}}},
				{CredentialsType: "VerifiableCredential", Claims: []tir.Claim{{Name: "role", AllowedValues: []any{"READER"}}}},
			},
			expectedResult: true},
		{testName: "When there are multiple configs and the first matches, it should be valid without checking the rest (OR short-circuit).",
			subject: common.Subject{CustomFields: map[string]any{"role": "ADMIN"}},
			credentialConfig: []tir.Credential{
				{CredentialsType: "VerifiableCredential", Claims: []tir.Claim{{Name: "role", AllowedValues: []any{"ADMIN"}}}},
				{CredentialsType: "VerifiableCredential", Claims: []tir.Claim{{Name: "role", AllowedValues: []any{"READER"}}}},
			},
			expectedResult: true},
		{testName: "When there are multiple configs and one of them has all claims matching, it should be valid.",
			subject: common.Subject{CustomFields: map[string]any{"role": "ADMIN", "extra": "value"}},
			credentialConfig: []tir.Credential{
				{CredentialsType: "VerifiableCredential", Claims: []tir.Claim{
					{Name: "role", AllowedValues: []any{"ADMIN"}},
					{Name: "extra", AllowedValues: []any{"other"}},
				}},
				{CredentialsType: "VerifiableCredential", Claims: []tir.Claim{
					{Name: "role", AllowedValues: []any{"ADMIN"}},
					{Name: "extra", AllowedValues: []any{"value"}},
				}},
			},
			expectedResult: true},
		{testName: "When there are multiple configs and a claim in the middle of one fails, the next config should still be evaluated.",
			subject: common.Subject{CustomFields: map[string]any{"role": "OPERATOR", "level": "2"}},
			credentialConfig: []tir.Credential{
				{CredentialsType: "VerifiableCredential", Claims: []tir.Claim{
					{Name: "role", AllowedValues: []any{"ADMIN"}},
					{Name: "level", AllowedValues: []any{"1"}},
				}},
				{CredentialsType: "VerifiableCredential", Claims: []tir.Claim{
					{Name: "role", AllowedValues: []any{"OPERATOR"}},
					{Name: "level", AllowedValues: []any{"2"}},
				}},
			},
			expectedResult: true},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {

			logging.Log().Info("TestVerifyForType +++++++++++++++++ Running test: ", tc.testName)

			result := verifyForType(tc.subject, tc.credentialConfig)
			if result != tc.expectedResult {
				t.Errorf("%s - Expected result %v but was %v.", tc.testName, tc.expectedResult, result)
				return
			}
		})
	}
}

func getAttribute(validFor tir.TimeRange, vcType string, claimsMap map[string][]interface{}) tir.IssuerAttribute {
	claims := []tir.Claim{}

	for key, element := range claimsMap {

		claims = append(claims, tir.Claim{Name: key, AllowedValues: element})
	}

	credential := tir.Credential{ValidFor: validFor, CredentialsType: vcType, Claims: claims}
	marshaledCredential, _ := json.Marshal(credential)
	return tir.IssuerAttribute{Body: base64.StdEncoding.EncodeToString(marshaledCredential)}
}

func getTrustedIssuer(attributes []tir.IssuerAttribute) tir.TrustedIssuer {
	return tir.TrustedIssuer{Attributes: attributes}
}

func getVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{
		trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{
			"VerifiableCredential": {{Type: "ebsi", Url: "http://my-trust-registry.org"}},
		},
		trustedIssuersLists: map[string][]config.TrustedIssuersList{
			"VerifiableCredential": {{Type: "ebsi", Url: "http://my-til.org"}},
		},
	}
}

func getWildcardVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{
		trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{
			"VerifiableCredential": {{Type: "ebsi", Url: "http://my-trust-registry.org"}},
		},
		trustedIssuersLists: map[string][]config.TrustedIssuersList{
			"VerifiableCredential": {{Type: "ebsi", Url: "*"}},
		},
	}
}

func getInvalidMixedVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{
		trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{
			"VerifiableCredential": {{Type: "ebsi", Url: "http://my-trust-registry.org"}},
		},
		trustedIssuersLists: map[string][]config.TrustedIssuersList{
			"VerifiableCredential": {{Type: "ebsi", Url: "*"}, {Type: "ebsi", Url: "http://my-til.org"}},
		},
	}
}

func getWildcardAndNormalVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{
		trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{
			"VerifiableCredential": {{Type: "ebsi", Url: "http://my-trust-registry.org"}},
			"SecondType":           {{Type: "ebsi", Url: "http://my-trust-registry.org"}},
		},
		trustedIssuersLists: map[string][]config.TrustedIssuersList{
			"VerifiableCredential": {{Type: "ebsi", Url: "*"}},
			"SecondType":           {{Type: "ebsi", Url: "http://my-til.org"}},
		},
	}
}

// getV5VerificationContext returns a context with only ebsi-v5 typed TIL entries.
func getV5VerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{
		trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{
			"VerifiableCredential": {{Type: "ebsi", Url: "http://my-trust-registry.org"}},
		},
		trustedIssuersLists: map[string][]config.TrustedIssuersList{
			"VerifiableCredential": {{Type: "ebsi-v5", Url: "http://my-v5-til.org"}},
		},
	}
}

// getHttpsIssuerVerificationContext returns a validation context configured with
// an HTTPS issuer URL (or wildcard) in the trusted issuers list.
func getHttpsIssuerVerificationContext(issuerURL string) ValidationContext {
	return TrustRegistriesValidationContext{
		trustedIssuersLists: map[string][]config.TrustedIssuersList{
			"VerifiableCredential": {{Type: "ebsi", Url: issuerURL}},
		},
	}
}

// getHttpsIssuerCredential creates a credential with an HTTPS-URL-based issuer.
func getHttpsIssuerCredential(issuerURL, claimName string, value interface{}) common.Credential {
	vc, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: issuerURL},
		Types:  []string{"VerifiableCredential"},
		Subject: []common.Subject{
			{
				CustomFields: map[string]interface{}{claimName: value},
			},
		}}, common.CustomFields{})
	return *vc
}

// getMixedEbsiVerificationContext returns a context with both ebsi and ebsi-v5
// typed TIL entries for the same credential type.
func getMixedEbsiVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{
		trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{
			"VerifiableCredential": {{Type: "ebsi", Url: "http://my-trust-registry.org"}},
		},
		trustedIssuersLists: map[string][]config.TrustedIssuersList{
			"VerifiableCredential": {
				{Type: "ebsi", Url: "http://my-til.org"},
				{Type: "ebsi-v5", Url: "http://my-v5-til.org"},
			},
		},
	}
}

func getMultiTypeCredential(types []string, claimName string, value interface{}) common.Credential {
	vc, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: "did:test:issuer"},
		Types:  types,
		Subject: []common.Subject{
			{
				CustomFields: map[string]interface{}{claimName: value},
			},
		}}, common.CustomFields{})
	return *vc
}

func getMultiClaimCredential(claims map[string]interface{}) common.Credential {

	vc, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: "did:test:issuer"},
		Types:  []string{"VerifiableCredential"},
		Subject: []common.Subject{
			{
				CustomFields: claims,
			},
		}}, common.CustomFields{})

	return *vc

}

func getTypedCredential(credentialType, claimName string, value interface{}) common.Credential {
	vc, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: "did:test:issuer"},
		Types:  []string{credentialType},
		Subject: []common.Subject{
			{
				CustomFields: map[string]interface{}{claimName: value},
			},
		}}, common.CustomFields{})
	return *vc
}

func getVerifiableCredential(claimName string, value interface{}) common.Credential {
	return getTypedCredential("VerifiableCredential", claimName, value)
}

func getTestCredential(subject map[string]interface{}) common.Credential {
	vc, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: "did:test:issuer"},
		Types:  []string{"OperatorCredential"},
		Subject: []common.Subject{
			{
				CustomFields: subject,
			},
		}}, common.CustomFields{})
	return *vc
}

type Roles struct {
	Target string   `json:"target"`
	Names  []string `json:"names"`
}

// --- Tests for parseAttribute ---

func TestParseAttribute_ValidBase64(t *testing.T) {
	credJSON := `{"credentialsType":"VerifiableCredential","claims":[]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(credJSON))
	attr := tir.IssuerAttribute{Body: encoded}

	cred, err := parseAttribute(attr)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if cred.CredentialsType != "VerifiableCredential" {
		t.Errorf("Expected VerifiableCredential, got %s", cred.CredentialsType)
	}
}

func TestParseAttribute_InvalidBase64(t *testing.T) {
	attr := tir.IssuerAttribute{Body: "!!!not-base64!!!"}

	_, err := parseAttribute(attr)
	if err == nil {
		t.Error("Expected error for invalid base64, got nil")
	}
}

func TestParseAttribute_InvalidJSON(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("not json"))
	attr := tir.IssuerAttribute{Body: encoded}

	_, err := parseAttribute(attr)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestParseAttributes_Empty(t *testing.T) {
	issuer := tir.TrustedIssuer{Attributes: []tir.IssuerAttribute{}}

	creds, err := parseAttributes(issuer)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("Expected empty credentials, got %d", len(creds))
	}
}

func TestParseAttributes_MultipleWithOneInvalid(t *testing.T) {
	validJSON := `{"credentialsType":"VC","claims":[]}`
	validEncoded := base64.StdEncoding.EncodeToString([]byte(validJSON))

	issuer := tir.TrustedIssuer{
		Attributes: []tir.IssuerAttribute{
			{Body: validEncoded},
			{Body: "!!!invalid!!!"},
		},
	}

	creds, err := parseAttributes(issuer)
	if err == nil {
		t.Error("Expected error for invalid attribute, got nil")
	}
	// Should have parsed the first one before failing
	if len(creds) != 1 {
		t.Errorf("Expected 1 credential before failure, got %d", len(creds))
	}
}
