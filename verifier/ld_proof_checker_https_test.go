package verifier

import (
	"errors"
	"testing"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- HTTPS-based issuer / holder identifiers in the LD-proof path ---
//
// These tests cover the JSON-LD counterpart of the HTTPS issuer support in
// JWTProofChecker: a credential or presentation whose verificationMethod is
// an https:// URL has its key resolved through the HttpsIssuerResolver
// instead of the DID registry.

// testHttpsIssuerURL is an HTTPS-based credential issuer identifier.
const testHttpsIssuerURL = "https://issuer.example.com"

// testHttpsIssuerKeyID is the verificationMethod of testHttpsIssuerURL. The
// fragment names the key inside the issuer's JWKS.
const testHttpsIssuerKeyID = testHttpsIssuerURL + "#key-1"

// testHttpsIssuerJwksKid is the JWKS `kid` the fragment of
// testHttpsIssuerKeyID resolves to.
const testHttpsIssuerJwksKid = "key-1"

// testHttpsHolderURL is an HTTPS-based presentation holder identifier.
const testHttpsHolderURL = "https://holder.example.com"

// testHttpsHolderKeyID is the verificationMethod of testHttpsHolderURL.
const testHttpsHolderKeyID = testHttpsHolderURL + "#key-1"

// errRegistryMustNotBeUsed is what the DID registry in these tests returns.
// The HTTPS path must never reach the registry, so a stray registry hit shows
// up as a failure instead of a silent fallback to DID resolution.
var errRegistryMustNotBeUsed = errors.New("did_registry_must_not_be_used_for_https_issuers")

// newHttpsOnlyRegistry returns a registry that fails on every resolve.
func newHttpsOnlyRegistry() *did.Registry {
	return createFailingRegistry(errRegistryMustNotBeUsed)
}

// TestHttpsJwksKeyId verifies how a JWKS `kid` is derived from an HTTPS
// verificationMethod URI.
func TestHttpsJwksKeyId(t *testing.T) {
	tests := []struct {
		testName           string
		verificationMethod string
		expectedKid        string
	}{
		{"fragment names the key", "https://issuer.example.com#key-1", "key-1"},
		{"fragment after a path", "https://issuer.example.com/tenant/a#sig-2024", "sig-2024"},
		{"no fragment yields empty kid", "https://issuer.example.com", ""},
		{"empty fragment yields empty kid", "https://issuer.example.com#", ""},
		{"only the first hash splits", "https://issuer.example.com#a#b", "a#b"},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			assert.Equal(t, tc.expectedKid, httpsJwksKeyId(tc.verificationMethod))
		})
	}
}

// TestLDProofChecker_VerifyCredential_HttpsIssuer covers credential LD-proof
// verification for HTTPS-based issuer identifiers.
func TestLDProofChecker_VerifyCredential_HttpsIssuer(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	// A key that is valid but belongs to somebody else.
	_, _, foreignPubJWK := generateTestECKeys(t)

	// Sign a credential whose issuer and verificationMethod are HTTPS URLs.
	vcMap := signTestCredential(t, testHttpsIssuerURL, signer, testHttpsIssuerKeyID, docLoader)
	vcJSON, proof := splitSignedCredential(t, vcMap)

	tests := []struct {
		testName       string
		resolver       HttpsIssuerResolver
		expectedIssuer string
		expectError    bool
		expectedError  error
	}{
		{
			testName:       "valid HTTPS issuer proof is accepted",
			resolver:       &mockHttpsIssuerResolver{key: pubJWK},
			expectedIssuer: testHttpsIssuerURL,
			expectError:    false,
		},
		{
			testName:       "no resolver configured fails closed",
			resolver:       nil,
			expectedIssuer: testHttpsIssuerURL,
			expectError:    true,
			expectedError:  ErrorHttpsIssuerNotSupported,
		},
		{
			testName:       "resolver error is propagated",
			resolver:       &mockHttpsIssuerResolver{err: ErrorIssuerMetadataNotFound},
			expectedIssuer: testHttpsIssuerURL,
			expectError:    true,
			expectedError:  ErrorIssuerMetadataNotFound,
		},
		{
			testName:       "key not found in the issuer JWKS is rejected",
			resolver:       &mockHttpsIssuerResolver{err: ErrorIssuerKeyNotFound},
			expectedIssuer: testHttpsIssuerURL,
			expectError:    true,
			expectedError:  ErrorIssuerKeyNotFound,
		},
		{
			testName:       "a foreign key from the resolver does not verify",
			resolver:       &mockHttpsIssuerResolver{key: foreignPubJWK},
			expectedIssuer: testHttpsIssuerURL,
			expectError:    true,
		},
		{
			testName:       "proof signer that is not the claimed issuer is rejected",
			resolver:       &mockHttpsIssuerResolver{key: pubJWK},
			expectedIssuer: "https://other-issuer.example.com",
			expectError:    true,
			expectedError:  ErrorProofIssuerMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			checker := NewLDProofChecker(newHttpsOnlyRegistry(), docLoader)
			if tc.resolver != nil {
				checker = checker.WithHttpsResolver(tc.resolver)
			}

			err := checker.VerifyCredential(vcJSON, proof, tc.expectedIssuer)

			if !tc.expectError {
				assert.NoError(t, err)
				return
			}
			assert.Error(t, err)
			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
			}
		})
	}
}

// TestLDProofChecker_VerifyCredential_HttpsIssuer_ResolverArguments asserts
// that the resolver is asked for the issuer URL and the JWKS kid taken from
// the verificationMethod fragment — not for the full verificationMethod URI,
// which would never match a JWKS entry.
func TestLDProofChecker_VerifyCredential_HttpsIssuer_ResolverArguments(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	vcMap := signTestCredential(t, testHttpsIssuerURL, signer, testHttpsIssuerKeyID, docLoader)
	vcJSON, proof := splitSignedCredential(t, vcMap)

	resolver := &mockHttpsIssuerResolver{key: pubJWK}
	checker := NewLDProofChecker(newHttpsOnlyRegistry(), docLoader).WithHttpsResolver(resolver)

	require.NoError(t, checker.VerifyCredential(vcJSON, proof, testHttpsIssuerURL))

	assert.Equal(t, testHttpsIssuerURL, resolver.calledURL, "resolver should be asked for the issuer URL")
	assert.Equal(t, testHttpsIssuerJwksKid, resolver.calledKid, "resolver should be asked for the JWKS kid, not the full URI")
}

// TestLDProofChecker_VerifyPresentation_HttpsHolder covers presentation
// LD-proof verification for HTTPS-based holder identifiers.
func TestLDProofChecker_VerifyPresentation_HttpsHolder(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	_, _, foreignPubJWK := generateTestECKeys(t)

	pres := &common.Presentation{
		Context: []string{common.ContextCredentialsV1},
		Type:    []string{common.TypeVerifiablePresentation},
		Holder:  testHttpsHolderURL,
	}
	vpJSON, proof := signPresentation(t, pres, signer, testHttpsHolderKeyID, docLoader)

	tests := []struct {
		testName       string
		resolver       HttpsIssuerResolver
		expectedHolder string
		expectError    bool
		expectedError  error
	}{
		{
			testName:       "valid HTTPS holder proof is accepted",
			resolver:       &mockHttpsIssuerResolver{key: pubJWK},
			expectedHolder: testHttpsHolderURL,
			expectError:    false,
		},
		{
			testName:       "no resolver configured fails closed",
			resolver:       nil,
			expectedHolder: testHttpsHolderURL,
			expectError:    true,
			expectedError:  ErrorHttpsIssuerNotSupported,
		},
		{
			testName:       "a foreign key from the resolver does not verify",
			resolver:       &mockHttpsIssuerResolver{key: foreignPubJWK},
			expectedHolder: testHttpsHolderURL,
			expectError:    true,
		},
		{
			testName:       "proof signer that is not the claimed holder is rejected",
			resolver:       &mockHttpsIssuerResolver{key: pubJWK},
			expectedHolder: "https://other-holder.example.com",
			expectError:    true,
			expectedError:  ErrorProofHolderMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			checker := NewLDProofChecker(newHttpsOnlyRegistry(), docLoader)
			if tc.resolver != nil {
				checker = checker.WithHttpsResolver(tc.resolver)
			}

			key, err := checker.VerifyPresentation(vpJSON, proof, tc.expectedHolder)

			if !tc.expectError {
				assert.NoError(t, err)
				assert.NotNil(t, key, "the resolved holder key should be returned for downstream binding")
				return
			}
			assert.Error(t, err)
			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
			}
		})
	}
}

// TestLDProofChecker_HttpsIssuer_ProofPurposeStillEnforced makes sure the
// HTTPS path does not bypass the proof-purpose check. A JWKS carries no
// verification relationships, so proofPurpose is the only remaining guard
// against a key being reused across purposes.
func TestLDProofChecker_HttpsIssuer_ProofPurposeStillEnforced(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	// A credential signed for the authentication purpose instead of
	// assertionMethod.
	vcMap := createTestVC(testHttpsIssuerURL)
	vcMap[common.VPKeyProof] = signDocument(t, vcMap, signer, testHttpsIssuerKeyID, docLoader,
		ldProofTestOptions{proofPurpose: common.ProofPurposeAuthentication})
	vcJSON, proof := splitSignedCredential(t, vcMap)

	checker := NewLDProofChecker(newHttpsOnlyRegistry(), docLoader).
		WithHttpsResolver(&mockHttpsIssuerResolver{key: pubJWK})

	err := checker.VerifyCredential(vcJSON, proof, testHttpsIssuerURL)
	assert.ErrorIs(t, err, ErrorProofPurposeMismatch)
}

// splitSignedCredential turns a signed credential map into the proof-less
// JSON bytes plus the parsed proof, which is the shape VerifyCredential
// expects.
func splitSignedCredential(t *testing.T, vcMap map[string]interface{}) ([]byte, *common.LDProof) {
	t.Helper()

	proofMap, ok := vcMap[common.VPKeyProof].(map[string]interface{})
	require.True(t, ok, "signed credential should carry a proof map")

	proof, err := common.ParseLDProof(proofMap)
	require.NoError(t, err)

	return marshalWithoutProof(t, vcMap), proof
}
