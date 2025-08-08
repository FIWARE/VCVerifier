package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
	"github.com/trustbloc/vc-go/verifiable"
)

func TestVerifyWithJsonPath(t *testing.T) {

	type test struct {
		testName            string
		path                string
		allowedValues       []interface{}
		credentialToVerifiy verifiable.Credential
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
		credentialToVerifiy verifiable.Credential
		verificationContext ValidationContext
		participantsList    []string
		tirResponse         tir.TrustedIssuer
		tirError            error
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
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {

			logging.Log().Info("TestVerifyVC +++++++++++++++++ Running test: ", tc.testName)

			trustedIssuerVerficationService := TrustedIssuerValidationService{mockTirClient{tc.participantsList, tc.tirResponse, tc.tirError}}
			result, _ := trustedIssuerVerficationService.ValidateVC(&tc.credentialToVerifiy, tc.verificationContext)
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
	return TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"VerifiableCredential": {{Type: "ebsi", Url: "http://my-trust-registry.org"}}}, trustedIssuersLists: map[string][]string{"VerifiableCredential": {"http://my-til.org"}}}
}

func getWildcardVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"VerifiableCredential": {{Type: "ebsi", Url: "http://my-trust-registry.org"}}}, trustedIssuersLists: map[string][]string{"VerifiableCredential": {"*"}}}
}

func getInvalidMixedVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"VerifiableCredential": {{Type: "ebsi", Url: "http://my-trust-registry.org"}}}, trustedIssuersLists: map[string][]string{"VerifiableCredential": {"*", "http://my-til.org"}}}
}

func getWildcardAndNormalVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"VerifiableCredential": {{Type: "ebsi", Url: "http://my-trust-registry.org"}}, "SecondType": {{Type: "ebsi", Url: "http://my-trust-registry.org"}}}, trustedIssuersLists: map[string][]string{"VerifiableCredential": {"*"}, "SecondType": {"http://my-til.org"}}}
}

func getMultiTypeCredential(types []string, claimName string, value interface{}) verifiable.Credential {
	vc, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		Issuer: &verifiable.Issuer{ID: "did:test:issuer"},
		Types:  types,
		Subject: []verifiable.Subject{
			{
				CustomFields: map[string]interface{}{claimName: value},
			},
		}}, verifiable.CustomFields{})
	return *vc
}

func getMultiClaimCredential(claims map[string]interface{}) verifiable.Credential {

	vc, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		Issuer: &verifiable.Issuer{ID: "did:test:issuer"},
		Types:  []string{"VerifiableCredential"},
		Subject: []verifiable.Subject{
			{
				CustomFields: claims,
			},
		}}, verifiable.CustomFields{})

	return *vc

}

func getTypedCredential(credentialType, claimName string, value interface{}) verifiable.Credential {
	vc, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		Issuer: &verifiable.Issuer{ID: "did:test:issuer"},
		Types:  []string{credentialType},
		Subject: []verifiable.Subject{
			{
				CustomFields: map[string]interface{}{claimName: value},
			},
		}}, verifiable.CustomFields{})
	return *vc
}

func getVerifiableCredential(claimName string, value interface{}) verifiable.Credential {
	return getTypedCredential("VerifiableCredential", claimName, value)
}

func getTestCredential(subject map[string]interface{}) verifiable.Credential {
	vc, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		Issuer: &verifiable.Issuer{ID: "did:test:issuer"},
		Types:  []string{"OperatorCredential"},
		Subject: []verifiable.Subject{
			{
				CustomFields: subject,
			},
		}}, verifiable.CustomFields{})
	return *vc
}

type Roles struct {
	Target string   `json:"target"`
	Names  []string `json:"names"`
}
