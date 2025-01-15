package verifier

import (
	"testing"

	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/vc-go/verifiable"
)

func TestValidateVC(t *testing.T) {

	type test struct {
		testName            string
		credentialToVerifiy verifiable.Credential
		validationContext   ValidationContext
		expectedResult      bool
	}
	tests := []test{
		{testName: "If the holder is correct, the vc should be allowed.", credentialToVerifiy: getCredentialWithHolder("subject", "holder"), validationContext: HolderValidationContext{claim: "subject", holder: "holder"}, expectedResult: true},
		{testName: "If the holder is correct inside the sub element, the vc should be allowed.", credentialToVerifiy: getCredentialWithHolderInSubelement("holder"), validationContext: HolderValidationContext{claim: "sub.holder", holder: "holder"}, expectedResult: true},
		{testName: "If the holder is not correct, the vc should be rejected.", credentialToVerifiy: getCredentialWithHolder("subject", "holder"), validationContext: HolderValidationContext{claim: "subject", holder: "someOneElse"}, expectedResult: false},
		{testName: "If the holder is not correct inside the sub element, the vc should be rejected.", credentialToVerifiy: getCredentialWithHolderInSubelement("holder"), validationContext: HolderValidationContext{claim: "sub.holder", holder: "someOneElse"}, expectedResult: false},
	}
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {

			logging.Log().Info("TestValidateVC +++++++++++++++++ Running test: ", tc.testName)

			holderValidationService := HolderValidationService{}

			result, _ := holderValidationService.ValidateVC(&tc.credentialToVerifiy, tc.validationContext)
			if result != tc.expectedResult {
				t.Errorf("%s - Expected result %v but was %v.", tc.testName, tc.expectedResult, result)
				return
			}
		})
	}
}

func getCredentialWithHolder(holderClaim, holder string) verifiable.Credential {
	vc, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		Issuer: &verifiable.Issuer{ID: "did:test:issuer"},
		Types:  []string{"VerifiableCredential"},
		Subject: []verifiable.Subject{
			{
				CustomFields: map[string]interface{}{holderClaim: holder},
			},
		}}, verifiable.CustomFields{})
	return *vc
}

func getCredentialWithHolderInSubelement(holder string) verifiable.Credential {

	vc, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		Issuer: &verifiable.Issuer{ID: "did:test:issuer"},
		Types:  []string{"VerifiableCredential"},
		Subject: []verifiable.Subject{
			{
				CustomFields: map[string]interface{}{"sub": map[string]interface{}{"holder": holder}},
			},
		}}, verifiable.CustomFields{})
	return *vc
}
