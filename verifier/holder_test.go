package verifier

import (
	"testing"

	common "github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
)

func TestValidateVC(t *testing.T) {

	type test struct {
		testName            string
		credentialToVerifiy common.Credential
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

func getCredentialWithHolder(holderClaim, holder string) common.Credential {
	vc, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: "did:test:issuer"},
		Types:  []string{"VerifiableCredential"},
		Subject: []common.Subject{
			{
				CustomFields: map[string]interface{}{holderClaim: holder},
			},
		}}, common.CustomFields{})
	return *vc
}

func getCredentialWithHolderInSubelement(holder string) common.Credential {

	vc, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: "did:test:issuer"},
		Types:  []string{"VerifiableCredential"},
		Subject: []common.Subject{
			{
				CustomFields: map[string]interface{}{"sub": map[string]interface{}{"holder": holder}},
			},
		}}, common.CustomFields{})
	return *vc
}
