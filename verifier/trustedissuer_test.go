package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
	"github.com/trustbloc/vc-go/verifiable"
)

func TestVerifyVC_Issuers(t *testing.T) {

	type test struct {
		testName            string
		credentialToVerifiy verifiable.Credential
		verificationContext ValidationContext
		tirExists           bool
		tirResponse         tir.TrustedIssuer
		tirError            error
		expectedResult      bool
	}

	tests := []test{
		{testName: "If no trusted issuer is configured in the list, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("test", "claim"), verificationContext: getVerificationContext(),
			tirExists: false, tirResponse: tir.TrustedIssuer{}, tirError: nil, expectedResult: false},
		{testName: "If the trusted issuer is invalid, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("test", "claim"), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: tir.TrustedIssuer{Attributes: []tir.IssuerAttribute{{Body: "invalidBody"}}}, tirError: nil, expectedResult: false},
		{testName: "If the type is not included, the vc should be rejected.",
			credentialToVerifiy: getTypedCredential("AnotherType", "testClaim", "testValue"), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "AnotherType", map[string][]interface{}{})}), tirError: nil, expectedResult: false},
		{testName: "If one of the types is not allowed, the vc should be rejected.",
			credentialToVerifiy: getMultiTypeCredential([]string{"VerifiableCredential", "SecondType"}, "testClaim", "testValue"), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}), tirError: nil, expectedResult: false},
		{testName: "If no restriction is configured, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}), tirError: nil, expectedResult: true},
		{testName: "If no restricted claim is included, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"another": {"claim"}})}), tirError: nil, expectedResult: true},
		{testName: "If the (string)claim is allowed, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {"testValue"}})}), tirError: nil, expectedResult: true},
		{testName: "If the (string)claim is one of the allowed values, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {"testValue", "anotherAllowedValue"}})}), tirError: nil, expectedResult: true},
		{testName: "If the (string)claim is not allowed, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "anotherValue"), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {"testValue"}})}), tirError: nil, expectedResult: false},
		{testName: "If the (number)claim is allowed, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", 1), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {1}})}), tirError: nil, expectedResult: true},
		{testName: "If the (number)claim is not allowed, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", 2), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {1}})}), tirError: nil, expectedResult: false},
		{testName: "If the (object)claim is allowed, the vc should be accepted.",
			credentialToVerifiy: getVerifiableCredential("testClaim", map[string]interface{}{"some": "object"}), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"testClaim": {map[string]interface{}{"some": "object"}}})}), tirError: nil, expectedResult: true},
		{testName: "If the all claim allowed, the vc should be allowed.",
			credentialToVerifiy: getMultiClaimCredential(map[string]interface{}{"claimA": map[string]interface{}{"some": "object"}, "claimB": "b"}), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"claimA": {map[string]interface{}{"some": "object"}}, "claimB": {"b"}})}), tirError: nil, expectedResult: true},
		{testName: "If a wildcard til is configured for the type, the vc should be allowed.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getWildcardVerificationContext(),
			tirExists: true, tirError: nil, expectedResult: true},
		{testName: "If all types are allowed, the vc should be allowed.",
			credentialToVerifiy: getMultiTypeCredential([]string{"VerifiableCredential", "SecondType"}, "testClaim", "testValue"), verificationContext: getWildcardAndNormalVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "SecondType", map[string][]interface{}{}), getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}), tirError: nil, expectedResult: true},
		{testName: "If not all claims are allowed, the vc should be rejected.",
			credentialToVerifiy: getMultiClaimCredential(map[string]interface{}{"claimA": map[string]interface{}{"some": "object"}, "claimB": "b"}), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{"claimA": {map[string]interface{}{"some": "object"}}, "claimB": {"c"}})}), tirError: nil, expectedResult: false},
		{testName: "If the trusted-issuers-registry responds with an error, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getVerificationContext(),
			tirExists: true, tirResponse: getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "VerifiableCredential", map[string][]interface{}{})}), tirError: errors.New("some-error"), expectedResult: false},
		{testName: "If an invalid verification context is provided, the credential should be rejected.",
			credentialToVerifiy: getVerifiableCredential("test", "claim"), verificationContext: "No-context", tirExists: false, tirResponse: tir.TrustedIssuer{}, tirError: nil, expectedResult: false},
		{testName: "If a wildcard til and another til is configured for the type, the vc should be rejected.",
			credentialToVerifiy: getVerifiableCredential("testClaim", "testValue"), verificationContext: getInvalidMixedVerificationContext(),
			tirExists: true, tirError: nil, expectedResult: false},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {

			logging.Log().Info("TestVerifyVC +++++++++++++++++ Running test: ", tc.testName)

			trustedIssuerVerficationService := TrustedIssuerValidationService{mockTirClient{tc.tirExists, tc.tirResponse, tc.tirError}}
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
	return TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]string{"VerifiableCredential": {"http://my-trust-registry.org"}}, trustedIssuersLists: map[string][]string{"VerifiableCredential": {"http://my-til.org"}}}
}

func getWildcardVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]string{"VerifiableCredential": {"http://my-trust-registry.org"}}, trustedIssuersLists: map[string][]string{"VerifiableCredential": {"*"}}}
}

func getInvalidMixedVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]string{"VerifiableCredential": {"http://my-trust-registry.org"}}, trustedIssuersLists: map[string][]string{"VerifiableCredential": {"*", "http://my-til.org"}}}
}

func getWildcardAndNormalVerificationContext() ValidationContext {
	return TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]string{"VerifiableCredential": {"http://my-trust-registry.org"}, "SecondType": {"http://my-trust-registry.org"}}, trustedIssuersLists: map[string][]string{"VerifiableCredential": {"*"}, "SecondType": {"http://my-til.org"}}}
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
