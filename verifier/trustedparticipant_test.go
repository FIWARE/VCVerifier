package verifier

import (
	"slices"
	"testing"

	common "github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
)

type mockGaiaXClient struct {
	participantsList []string
}

func (mgc mockGaiaXClient) IsTrustedParticipant(registryEndpoint string, did string) (trusted bool) {
	return slices.Contains(mgc.participantsList, did)
}

type mockTirClient struct {
	participantsList   []string
	participantsV5List []string
	expectedIssuer     tir.TrustedIssuer
	expectedIssuerV5   tir.TrustedIssuer
	expectedError      error
	expectedErrorV5    error
}

// IsTrustedParticipant checks the v3/v4 participants list.
func (mtc mockTirClient) IsTrustedParticipant(tirEndpoint string, did string) (trusted bool) {
	return slices.Contains(mtc.participantsList, did)
}

// GetTrustedIssuer returns a trusted issuer from the v3/v4 list.
func (mtc mockTirClient) GetTrustedIssuer(tirEndpoints []string, did string) (exists bool, trustedIssuer tir.TrustedIssuer, err error) {
	return slices.Contains(mtc.participantsList, did), mtc.expectedIssuer, mtc.expectedError
}

// IsTrustedParticipantV5 checks the v5 participants list.
func (mtc mockTirClient) IsTrustedParticipantV5(tirEndpoint string, did string) (trusted bool) {
	return slices.Contains(mtc.participantsV5List, did)
}

// GetTrustedIssuerV5 returns a trusted issuer from the v5 list.
func (mtc mockTirClient) GetTrustedIssuerV5(tirEndpoints []string, did string) (exists bool, trustedIssuer tir.TrustedIssuer, err error) {
	return slices.Contains(mtc.participantsV5List, did), mtc.expectedIssuerV5, mtc.expectedErrorV5
}

func TestVerifyVC_Participant(t *testing.T) {

	type test struct {
		testName               string
		credentialToVerifiy    common.Credential
		verificationContext    ValidationContext
		ebsiParticipantsList   []string
		ebsiV5ParticipantsList []string
		gaiaXParticipantsList  []string
		expectedResult         bool
	}

	tests := []test{
		{testName: "A credential issued by an ebsi registered issuer should be successfully validated.",
			credentialToVerifiy:  getCredential("did:web:trusted-issuer.org"),
			verificationContext:  TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": {{Type: "ebsi", Url: "http://my-trust-registry.org"}}}},
			ebsiParticipantsList: []string{"did:web:trusted-issuer.org"}, expectedResult: true},
		{testName: "A credential issued by a gaia-x registered issuer should be successfully validated.",
			credentialToVerifiy:   getCredential("did:web:trusted-issuer.org"),
			verificationContext:   TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": {{Type: "gaia-x", Url: "http://gaia-x-registry.org"}}}},
			gaiaXParticipantsList: []string{"did:web:trusted-issuer.org"}, expectedResult: true},
		{testName: "A credential issued by a registered issuer in mixed gaia-x/ebsi list should be validated via gaia-x.",
			credentialToVerifiy:   getCredential("did:web:trusted-issuer.org"),
			verificationContext:   TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": {{Type: "gaia-x", Url: "http://gaia-x-registry.org"}, {Type: "ebsi", Url: "http://my-trust-registry.org"}}}},
			gaiaXParticipantsList: []string{"did:web:trusted-issuer.org"}, expectedResult: true},
		{testName: "A credential issued by a registered issuer in mixed gaia-x/ebsi list should be validated via ebsi.",
			credentialToVerifiy:  getCredential("did:web:trusted-issuer.org"),
			verificationContext:  TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": {{Type: "gaia-x", Url: "http://gaia-x-registry.org"}, {Type: "ebsi", Url: "http://my-trust-registry.org"}}}},
			ebsiParticipantsList: []string{"did:web:trusted-issuer.org"}, expectedResult: true},
		{testName: "A credential issued by a not-registered issuer should be rejected.",
			credentialToVerifiy:  getCredential("did:web:trusted-issuer.org"),
			verificationContext:  TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": {{Type: "ebsi", Url: "http://my-trust-registry.org"}}}},
			ebsiParticipantsList: []string{}, expectedResult: false},
		{testName: "If no registry is configured, the credential should be accepted.",
			credentialToVerifiy: getCredential("did:web:trusted-issuer.org"),
			verificationContext: TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{}}, expectedResult: true},
		{testName: "If an empty registry list is configured, the credential should be accepted.",
			credentialToVerifiy: getCredential("did:web:trusted-issuer.org"),
			verificationContext: TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"VerifiableCredential": {}}}, expectedResult: true},
		{testName: "If an invalid context is received, the credential should be rejected.",
			credentialToVerifiy:  getCredential("did:web:trusted-issuer.org"),
			verificationContext:  "No-Context",
			ebsiParticipantsList: []string{"did:web:trusted-issuer.org"}, expectedResult: false},
		// ebsi-v5 test cases
		{testName: "A credential issued by an ebsi-v5 registered participant should be successfully validated.",
			credentialToVerifiy:    getCredential("did:web:trusted-issuer.org"),
			verificationContext:    TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": {{Type: "ebsi-v5", Url: "http://my-v5-registry.org"}}}},
			ebsiV5ParticipantsList: []string{"did:web:trusted-issuer.org"}, expectedResult: true},
		{testName: "A credential issued by a participant not in ebsi-v5 registry should be rejected.",
			credentialToVerifiy:    getCredential("did:web:trusted-issuer.org"),
			verificationContext:    TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": {{Type: "ebsi-v5", Url: "http://my-v5-registry.org"}}}},
			ebsiV5ParticipantsList: []string{}, expectedResult: false},
		{testName: "Mixed ebsi and ebsi-v5 list: found via ebsi-v5 when not in ebsi.",
			credentialToVerifiy:    getCredential("did:web:trusted-issuer.org"),
			verificationContext:    TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": {{Type: "ebsi", Url: "http://my-trust-registry.org"}, {Type: "ebsi-v5", Url: "http://my-v5-registry.org"}}}},
			ebsiParticipantsList:   []string{},
			ebsiV5ParticipantsList: []string{"did:web:trusted-issuer.org"}, expectedResult: true},
		{testName: "Mixed ebsi and ebsi-v5 list: found via ebsi, v5 not checked.",
			credentialToVerifiy:    getCredential("did:web:trusted-issuer.org"),
			verificationContext:    TrustRegistriesValidationContext{trustedParticipantsRegistries: map[string][]config.TrustedParticipantsList{"someType": {{Type: "ebsi", Url: "http://my-trust-registry.org"}, {Type: "ebsi-v5", Url: "http://my-v5-registry.org"}}}},
			ebsiParticipantsList:   []string{"did:web:trusted-issuer.org"},
			ebsiV5ParticipantsList: []string{}, expectedResult: true},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {

			logging.Log().Info("TestVerifyVC +++++++++++++++++ Running test: ", tc.testName)

			tirClient := mockTirClient{
				participantsList:   tc.ebsiParticipantsList,
				participantsV5List: tc.ebsiV5ParticipantsList,
				expectedIssuer:     tir.TrustedIssuer{},
				expectedIssuerV5:   tir.TrustedIssuer{},
			}
			trustedParticipantVerificationService := TrustedParticipantValidationService{tirClient, mockGaiaXClient{tc.gaiaXParticipantsList}}
			result, _ := trustedParticipantVerificationService.ValidateVC(&tc.credentialToVerifiy, tc.verificationContext)
			if result != tc.expectedResult {
				t.Errorf("%s - Expected result %v but was %v.", tc.testName, tc.expectedResult, result)
				return
			}
		})
	}
}

func getCredential(issuer string) common.Credential {
	vc, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: issuer},
	}, common.CustomFields{})
	return *vc
}
