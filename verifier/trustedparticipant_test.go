package verifier

import (
	"testing"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
	"github.com/trustbloc/vc-go/verifiable"
)

type mockGaiaXClient struct {
}

func (mgc mockGaiaXClient) IsTrustedParticipant(registryEndpoint string, did string) (trusted bool) {
	return true
}

type mockTirClient struct {
	expectedExists bool
	expectedIssuer tir.TrustedIssuer
	expectedError  error
}

func (mtc mockTirClient) IsTrustedParticipant(tirEndpoint string, did string) (trusted bool) {
	return mtc.expectedExists
}

func (mtc mockTirClient) GetTrustedIssuer(tirEndpoints []string, did string) (exists bool, trustedIssuer tir.TrustedIssuer, err error) {
	return mtc.expectedExists, mtc.expectedIssuer, mtc.expectedError
}

func TestVerifyVC_Participant(t *testing.T) {

	type test struct {
		testName            string
		credentialToVerifiy verifiable.Credential
		verificationContext ValidationContext
		tirResponse         bool
		expectedResult      bool
	}

	tests := []test{
		{testName: "A credential issued by a registerd issuer should be successfully validated.", credentialToVerifiy: getCredential("did:web:trusted-issuer.org"), verificationContext: TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": []config.TrustedParticipantsList{{Type: "ebsi", Url: "http://my-trust-registry.org"}}}}, tirResponse: true, expectedResult: true},
		{testName: "A credential issued by a not-registerd issuer should be rejected.", credentialToVerifiy: getCredential("did:web:trusted-issuer.org"), verificationContext: TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": []config.TrustedParticipantsList{{Type: "ebsi", Url: "http://my-trust-registry.org"}}}}, tirResponse: false, expectedResult: false},
		{testName: "If no registry is configured, the credential should be accepted.", credentialToVerifiy: getCredential("did:web:trusted-issuer.org"), verificationContext: TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{}}, expectedResult: true},
		{testName: "If no registry is configured, the credential should be accepted.", credentialToVerifiy: getCredential("did:web:trusted-issuer.org"), verificationContext: TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"VerifiableCredential": []config.TrustedParticipantsList{}}}, expectedResult: true},
		{testName: "If an invalid context is received, the credential should be rejected.", credentialToVerifiy: getCredential("did:web:trusted-issuer.org"), verificationContext: "No-Context", tirResponse: false, expectedResult: false},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {

			logging.Log().Info("TestVerifyVC +++++++++++++++++ Running test: ", tc.testName)

			trustedParticipantVerificationService := TrustedParticipantValidationService{mockTirClient{tc.tirResponse, tir.TrustedIssuer{}, nil}, mockGaiaXClient{}}
			result, _ := trustedParticipantVerificationService.ValidateVC(&tc.credentialToVerifiy, tc.verificationContext)
			if result != tc.expectedResult {
				t.Errorf("%s - Expected result %v but was %v.", tc.testName, tc.expectedResult, result)
				return
			}
		})
	}
}

func getCredential(issuer string) verifiable.Credential {
	vc, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		Issuer: &verifiable.Issuer{ID: issuer},
	}, verifiable.CustomFields{})
	return *vc
}
