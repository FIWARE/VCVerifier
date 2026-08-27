package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/multiformats/go-multibase"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Logging ---

// init initializes logging for tests. The LOGGING_CONFIG var is defined in
// verifier_test.go and shared across the verifier test package.
func init() {
	logging.Configure(LOGGING_CONFIG)
}

// --- Test Signers ---

// p256KeySize is the byte-length of each coordinate for the P-256 curve.
const testP256KeySize = 32

// testES256Signer implements common.LDSigner for ECDSA P-256 SHA-256 (ES256).
type testES256Signer struct {
	key *ecdsa.PrivateKey
}

// Sign signs data using ECDSA P-256 with SHA-256 and returns the signature
// in IEEE P1363 (fixed-size r||s) format, matching the ES256 JWS algorithm.
func (s *testES256Signer) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, hash[:])
	if err != nil {
		return nil, err
	}
	rBytes := r.Bytes()
	sBytes := sv.Bytes()
	sig := make([]byte, testP256KeySize*2)
	copy(sig[testP256KeySize-len(rBytes):testP256KeySize], rBytes)
	copy(sig[2*testP256KeySize-len(sBytes):], sBytes)
	return sig, nil
}

// --- Test Document Loader ---

// newTestDocumentLoader returns a document loader that serves the real,
// vendored W3C credentials/v1 and JsonWebSignature2020 contexts from
// common/contexts. Using the genuine contexts matters: a hand-written stand-in
// that defines the proof terms at the top level would hide the fact that the
// real credentials/v1 context does not, and with it the whole class of
// "proof options are not covered by the signature" bugs.
//
// Any other URL is rejected, so a test cannot accidentally depend on the
// network.
func newTestDocumentLoader() ld.DocumentLoader {
	loader, err := common.NewEmbeddedContextLoader(nil)
	if err != nil {
		panic(fmt.Sprintf("test: failed to load embedded JSON-LD contexts: %v", err))
	}
	return loader
}

// --- Test Key Helpers ---

// generateTestECKeys generates an ECDSA P-256 key pair and returns the
// private key, private JWK, and public JWK.
func generateTestECKeys(t *testing.T) (*ecdsa.PrivateKey, jwk.Key, jwk.Key) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJWK, err := jwk.Import(privKey)
	require.NoError(t, err)

	pubJWK, err := jwk.Import(&privKey.PublicKey)
	require.NoError(t, err)

	return privKey, privJWK, pubJWK
}

// --- Mock Registry Helpers ---

// createMockRegistry creates a did.Registry with the existing mockVDR
// (from key_resolver_test.go) that resolves the DID contained in keyID to a
// document holding the given public JWK. The key is declared for both the
// authentication and the assertionMethod relationship, which is what real
// documents do for a general-purpose key.
func createMockRegistry(t *testing.T, method string, keyID string, pubJWK jwk.Key) *did.Registry {
	t.Helper()
	return createMockRegistryForRelationships(t, keyID, pubJWK,
		[]string{keyID}, []string{keyID})
}

// createMockRegistryForRelationships is createMockRegistry with explicit
// control over which verification relationships the key is listed under, so
// tests can exercise a key that is only allowed to assert or only allowed to
// authenticate.
func createMockRegistryForRelationships(t *testing.T, keyID string, pubJWK jwk.Key, authentication, assertionMethod []string) *did.Registry {
	t.Helper()
	didStr, _ := ExtractDIDAndFragment(keyID)
	vm, err := did.NewVerificationMethodFromJWK(keyID, "JsonWebKey2020", didStr, pubJWK)
	require.NoError(t, err)

	doc := &did.DocResolution{
		DIDDocument: &did.Doc{
			ID:                 didStr,
			VerificationMethod: []did.VerificationMethod{*vm},
			Authentication:     authentication,
			AssertionMethod:    assertionMethod,
		},
	}

	return did.NewRegistry(did.WithVDR(&mockVDR{
		readFunc: func(_ string) (*did.DocResolution, error) {
			return doc, nil
		},
	}))
}

// createFailingRegistry creates a did.Registry that returns an error on resolve.
func createFailingRegistry(resolveErr error) *did.Registry {
	return did.NewRegistry(did.WithVDR(&mockVDR{
		readFunc: func(_ string) (*did.DocResolution, error) {
			return nil, resolveErr
		},
	}))
}

// --- Test Helpers ---

// testHolderDID is the holder used by the shared test presentation.
const testHolderDID = "did:web:holder.example.com"

// testHolderKeyID is the verification method of testHolderDID.
const testHolderKeyID = testHolderDID + "#key-1"

// testIssuerDID is the issuer used by the shared test credential.
const testIssuerDID = "did:web:issuer.example.com"

// testIssuerKeyID is the verification method of testIssuerDID.
const testIssuerKeyID = testIssuerDID + "#key-1"

// testSubjectDID is the subject of the shared test credential.
const testSubjectDID = "did:web:subject.example.com"

// testProofAlgorithm is the JWS algorithm all test proofs are created with.
const testProofAlgorithm = "ES256"

// ldProofTestOptions carries the optional proof members a test wants bound
// into the signature.
type ldProofTestOptions struct {
	proofPurpose string
	challenge    string
	domain       string
}

// signPresentation signs a VP for the authentication purpose and returns the
// raw JSON (with proof) and the proof object.
func signPresentation(t *testing.T, pres *common.Presentation, signer common.LDSigner, verificationMethod string, docLoader ld.DocumentLoader) ([]byte, *common.LDProof) {
	t.Helper()
	return signPresentationWithOptions(t, pres, signer, verificationMethod, docLoader,
		ldProofTestOptions{proofPurpose: common.ProofPurposeAuthentication})
}

// signPresentationWithOptions signs a VP with explicit proof options so tests
// can bind (or deliberately omit) proofPurpose, challenge and domain.
func signPresentationWithOptions(t *testing.T, pres *common.Presentation, signer common.LDSigner, verificationMethod string, docLoader ld.DocumentLoader, opts ldProofTestOptions) ([]byte, *common.LDProof) {
	t.Helper()
	now := time.Now()
	err := pres.AddLinkedDataProof(&common.LinkedDataProofContext{
		Created:            &now,
		SignatureType:      common.ProofTypeJsonWebSignature2020,
		Algorithm:          testProofAlgorithm,
		VerificationMethod: verificationMethod,
		Signer:             signer,
		DocumentLoader:     docLoader,
		ProofPurpose:       opts.proofPurpose,
		Challenge:          opts.challenge,
		Domain:             opts.domain,
	})
	require.NoError(t, err, "AddLinkedDataProof should not fail")
	require.NotEmpty(t, pres.Proofs)

	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err, "MarshalJSON should not fail")

	proof := pres.Proofs[len(pres.Proofs)-1]
	return vpJSON, proof
}

// createTestVP creates a minimal Verifiable Presentation for testing.
func createTestVP() *common.Presentation {
	return &common.Presentation{
		Context: []string{common.ContextCredentialsV1},
		Type:    []string{common.TypeVerifiablePresentation},
		Holder:  testHolderDID,
	}
}

// createTestVC returns a minimal JSON-LD Verifiable Credential map without a
// proof. The suite context is included because a credential that carries a
// JsonWebSignature2020 proof has to define the proof terms.
func createTestVC(issuerDID string) map[string]interface{} {
	return map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{
			common.ContextCredentialsV1,
			common.ContextSecuritySuiteJWS2020,
		},
		common.JSONLDKeyType: []interface{}{common.TypeVerifiableCredential},
		common.VCKeyIssuer:   issuerDID,
		common.JSONLDKeyID:   "urn:uuid:11111111-2222-3333-4444-555555555555",
		"issuanceDate":       "2024-01-01T00:00:00Z",
		common.VCKeyCredentialSubject: map[string]interface{}{
			common.JSONLDKeyID: testSubjectDID,
		},
	}
}

// signDocument signs an arbitrary proof-less JSON-LD document and returns the
// proof as a JSON map, ready to be attached as the document's proof member.
// It goes through the production signing code so the tests exercise exactly
// what AddLinkedDataProof does.
func signDocument(t *testing.T, docMap map[string]interface{}, signer common.LDSigner, verificationMethod string, docLoader ld.DocumentLoader, opts ldProofTestOptions) map[string]interface{} {
	t.Helper()
	now := time.Now()
	proof, err := common.CreateLinkedDataProof(docMap, &common.LinkedDataProofContext{
		Created:            &now,
		SignatureType:      common.ProofTypeJsonWebSignature2020,
		Algorithm:          testProofAlgorithm,
		VerificationMethod: verificationMethod,
		Signer:             signer,
		DocumentLoader:     docLoader,
		ProofPurpose:       opts.proofPurpose,
		Challenge:          opts.challenge,
		Domain:             opts.domain,
	})
	require.NoError(t, err, "CreateLinkedDataProof should not fail")

	proofJSON, err := json.Marshal(proof)
	require.NoError(t, err)
	var proofMap map[string]interface{}
	require.NoError(t, json.Unmarshal(proofJSON, &proofMap))
	return proofMap
}

// signTestCredential returns a signed JSON-LD credential map (proof included)
// for the given issuer.
func signTestCredential(t *testing.T, issuerDID string, signer common.LDSigner, verificationMethod string, docLoader ld.DocumentLoader) map[string]interface{} {
	t.Helper()
	vcMap := createTestVC(issuerDID)
	vcMap[common.VPKeyProof] = signDocument(t, vcMap, signer, verificationMethod, docLoader,
		ldProofTestOptions{proofPurpose: common.ProofPurposeAssertionMethod})
	return vcMap
}

// --- LDProofChecker Tests ---

// TestLDProofChecker_VerifyPresentation tests the VerifyPresentation method
// of LDProofChecker using table-driven tests.
func TestLDProofChecker_VerifyPresentation(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	registry := createMockRegistry(t, "web", testHolderKeyID, pubJWK)

	// Sign a valid VP.
	vpJSON, proof := signPresentation(t, createTestVP(), signer, testHolderKeyID, docLoader)
	vpWithoutProof := stripProof(t, vpJSON)

	// A document whose content was changed after signing.
	tamperedDoc := withField(t, vpWithoutProof, common.VPKeyHolder, "did:web:attacker.example.com")

	// A VP signed for the wrong purpose.
	_, assertionProof := signPresentationWithOptions(t, createTestVP(), signer, testHolderKeyID, docLoader,
		ldProofTestOptions{proofPurpose: common.ProofPurposeAssertionMethod})

	// A VP whose proof declares no purpose at all.
	_, purposelessProof := signPresentationWithOptions(t, createTestVP(), signer, testHolderKeyID, docLoader,
		ldProofTestOptions{})

	type testCase struct {
		name           string
		vpJSON         []byte
		proof          *common.LDProof
		expectedHolder string
		registry       *did.Registry
		wantErr        bool
		wantErrIs      error
	}

	tests := []testCase{
		{
			name:           "valid_vp_with_did_web",
			vpJSON:         vpWithoutProof,
			proof:          proof,
			expectedHolder: testHolderDID,
			registry:       registry,
		},
		{
			name:           "tampered_vp_rejected",
			vpJSON:         tamperedDoc,
			proof:          proof,
			expectedHolder: testHolderDID,
			registry:       registry,
			wantErr:        true,
		},
		{
			name:           "unresolvable_did_rejected",
			vpJSON:         vpWithoutProof,
			proof:          proof,
			expectedHolder: testHolderDID,
			registry:       createFailingRegistry(errors.New("network error")),
			wantErr:        true,
		},
		{
			name:   "did_elsi_rejected",
			vpJSON: vpWithoutProof,
			proof: &common.LDProof{
				Type:               common.ProofTypeJsonWebSignature2020,
				Created:            "2024-01-01T00:00:00Z",
				VerificationMethod: "did:elsi:some-org#key-1",
				ProofPurpose:       common.ProofPurposeAuthentication,
				JWS:                proof.JWS,
			},
			expectedHolder: "did:elsi:some-org",
			registry:       registry,
			wantErr:        true,
			wantErrIs:      ErrorDidElsiNotSupportedForLDProof,
		},
		{
			name:   "empty_verification_method_rejected",
			vpJSON: vpWithoutProof,
			proof: &common.LDProof{
				Type:               common.ProofTypeJsonWebSignature2020,
				Created:            "2024-01-01T00:00:00Z",
				VerificationMethod: "",
				ProofPurpose:       common.ProofPurposeAuthentication,
				JWS:                proof.JWS,
			},
			expectedHolder: testHolderDID,
			registry:       registry,
			wantErr:        true,
			wantErrIs:      ErrorNoVerificationKey,
		},
		{
			name:           "signer_other_than_holder_rejected",
			vpJSON:         vpWithoutProof,
			proof:          proof,
			expectedHolder: "did:web:someone-else.example.com",
			registry:       registry,
			wantErr:        true,
			wantErrIs:      ErrorProofHolderMismatch,
		},
		{
			name:           "missing_holder_rejected",
			vpJSON:         vpWithoutProof,
			proof:          proof,
			expectedHolder: "",
			registry:       registry,
			wantErr:        true,
			wantErrIs:      ErrorMissingProofSubject,
		},
		{
			name:           "assertion_purpose_rejected_for_presentation",
			vpJSON:         vpWithoutProof,
			proof:          assertionProof,
			expectedHolder: testHolderDID,
			registry:       registry,
			wantErr:        true,
			wantErrIs:      ErrorProofPurposeMismatch,
		},
		{
			name:           "missing_purpose_rejected",
			vpJSON:         vpWithoutProof,
			proof:          purposelessProof,
			expectedHolder: testHolderDID,
			registry:       registry,
			wantErr:        true,
			wantErrIs:      ErrorProofPurposeMismatch,
		},
		{
			name:           "key_without_authentication_relationship_rejected",
			vpJSON:         vpWithoutProof,
			proof:          proof,
			expectedHolder: testHolderDID,
			registry: createMockRegistryForRelationships(t, testHolderKeyID, pubJWK,
				nil, []string{testHolderKeyID}),
			wantErr:   true,
			wantErrIs: ErrorVerificationRelationshipNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := NewLDProofChecker(tc.registry, docLoader)
			key, err := checker.VerifyPresentation(tc.vpJSON, tc.proof, tc.expectedHolder)
			if tc.wantErr {
				assert.Error(t, err)
				if tc.wantErrIs != nil {
					assert.True(t, errors.Is(err, tc.wantErrIs), "expected error %v, got %v", tc.wantErrIs, err)
				}
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, key, "expected resolved key to be returned")
		})
	}
}

// TestLDProofChecker_VerifyPresentation_ChallengeAndDomainAreSigned is the
// regression test for the replay hole: challenge and domain have to be part
// of what the signature covers, so rewriting either of them in a captured
// presentation must invalidate the proof.
func TestLDProofChecker_VerifyPresentation_ChallengeAndDomainAreSigned(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()
	registry := createMockRegistry(t, "web", testHolderKeyID, pubJWK)
	checker := NewLDProofChecker(registry, docLoader)

	const originalChallenge = "session-nonce-AAA"
	const originalDomain = "https://verifier.example.com"

	vpJSON, proof := signPresentationWithOptions(t, createTestVP(), signer, testHolderKeyID, docLoader,
		ldProofTestOptions{
			proofPurpose: common.ProofPurposeAuthentication,
			challenge:    originalChallenge,
			domain:       originalDomain,
		})
	vpWithoutProof := stripProof(t, vpJSON)

	_, err := checker.VerifyPresentation(vpWithoutProof, proof, testHolderDID)
	require.NoError(t, err, "the untouched proof must verify")

	tests := []struct {
		name    string
		tamper  func(p *common.LDProof)
		wantErr error
	}{
		{
			name:    "rewritten_challenge",
			tamper:  func(p *common.LDProof) { p.Challenge = "session-nonce-ZZZ-attacker-replay" },
			wantErr: common.ErrorLDProofVerifySignature,
		},
		{
			name:    "rewritten_domain",
			tamper:  func(p *common.LDProof) { p.Domain = "https://attacker.example.com" },
			wantErr: common.ErrorLDProofVerifySignature,
		},
		{
			name:    "rewritten_created",
			tamper:  func(p *common.LDProof) { p.Created = "1999-01-01T00:00:00Z" },
			wantErr: common.ErrorLDProofVerifySignature,
		},
		{
			name:    "dropped_challenge",
			tamper:  func(p *common.LDProof) { p.Challenge = "" },
			wantErr: common.ErrorLDProofVerifySignature,
		},
		{
			name:    "dropped_domain",
			tamper:  func(p *common.LDProof) { p.Domain = "" },
			wantErr: common.ErrorLDProofVerifySignature,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *proof
			tc.tamper(&tampered)

			_, err := checker.VerifyPresentation(vpWithoutProof, &tampered, testHolderDID)
			require.Error(t, err, "tampered proof metadata must not verify")
			assert.True(t, errors.Is(err, tc.wantErr), "expected %v, got %v", tc.wantErr, err)
		})
	}
}

// TestVerifyLinkedDataProof_ContextWithoutSuiteTermsRejected asserts the
// fail-closed guard: when the document context does not define the proof
// terms, verification must refuse rather than accept a signature that covers
// nothing but the proof type.
func TestVerifyLinkedDataProof_ContextWithoutSuiteTermsRejected(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	// Sign normally, then hand verification a proof whose verificationMethod
	// is a relative IRI. A relative IRI is dropped during expansion, so the
	// canonical proof options no longer carry it.
	vpJSON, proof := signPresentation(t, createTestVP(), signer, testHolderKeyID, docLoader)
	vpWithoutProof := stripProof(t, vpJSON)

	unresolvable := *proof
	unresolvable.VerificationMethod = "not-an-absolute-iri"

	err := common.VerifyLinkedDataProof(vpWithoutProof, &unresolvable, pubJWK, docLoader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, common.ErrorLDProofOptionsNotCovered),
		"expected ErrorLDProofOptionsNotCovered, got %v", err)
}

// TestLDProofChecker_VerifyCredential tests the VerifyCredential method
// of LDProofChecker using table-driven tests.
func TestLDProofChecker_VerifyCredential(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	registry := createMockRegistry(t, "web", testIssuerKeyID, pubJWK)

	signedVC := signTestCredential(t, testIssuerDID, signer, testIssuerKeyID, docLoader)
	proof, err := common.ParseLDProof(signedVC[common.VPKeyProof].(map[string]interface{}))
	require.NoError(t, err)

	vcWithoutProof := marshalWithoutProof(t, signedVC)
	tamperedVC := withField(t, vcWithoutProof, common.VCKeyIssuer, "did:web:attacker.example.com")

	// Wrong key behind the same verification method.
	_, _, wrongPubJWK := generateTestECKeys(t)
	wrongKeyRegistry := createMockRegistry(t, "web", testIssuerKeyID, wrongPubJWK)

	// The forgery the binding check exists for: a valid signature by an
	// attacker key over a credential that claims a trusted issuer.
	attackerVC := signTestCredential(t, testIssuerDID, signer, "did:web:attacker.example.com#key-1", docLoader)
	attackerProof, err := common.ParseLDProof(attackerVC[common.VPKeyProof].(map[string]interface{}))
	require.NoError(t, err)
	attackerVCWithoutProof := marshalWithoutProof(t, attackerVC)

	type testCase struct {
		name           string
		vcJSON         []byte
		proof          *common.LDProof
		expectedIssuer string
		registry       *did.Registry
		wantErr        bool
		wantErrIs      error
	}

	tests := []testCase{
		{
			name:           "valid_vc",
			vcJSON:         vcWithoutProof,
			proof:          proof,
			expectedIssuer: testIssuerDID,
			registry:       registry,
		},
		{
			name:           "tampered_vc_rejected",
			vcJSON:         tamperedVC,
			proof:          proof,
			expectedIssuer: testIssuerDID,
			registry:       registry,
			wantErr:        true,
		},
		{
			name:           "wrong_key_rejected",
			vcJSON:         vcWithoutProof,
			proof:          proof,
			expectedIssuer: testIssuerDID,
			registry:       wrongKeyRegistry,
			wantErr:        true,
		},
		{
			name:           "signer_other_than_issuer_rejected",
			vcJSON:         attackerVCWithoutProof,
			proof:          attackerProof,
			expectedIssuer: testIssuerDID,
			registry:       createMockRegistry(t, "web", "did:web:attacker.example.com#key-1", pubJWK),
			wantErr:        true,
			wantErrIs:      ErrorProofIssuerMismatch,
		},
		{
			name:           "missing_issuer_rejected",
			vcJSON:         vcWithoutProof,
			proof:          proof,
			expectedIssuer: "",
			registry:       registry,
			wantErr:        true,
			wantErrIs:      ErrorMissingProofSubject,
		},
		{
			name:           "key_without_assertion_relationship_rejected",
			vcJSON:         vcWithoutProof,
			proof:          proof,
			expectedIssuer: testIssuerDID,
			registry: createMockRegistryForRelationships(t, testIssuerKeyID, pubJWK,
				[]string{testIssuerKeyID}, nil),
			wantErr:   true,
			wantErrIs: ErrorVerificationRelationshipNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := NewLDProofChecker(tc.registry, docLoader)
			err := checker.VerifyCredential(tc.vcJSON, tc.proof, tc.expectedIssuer)
			if tc.wantErr {
				assert.Error(t, err)
				if tc.wantErrIs != nil {
					assert.True(t, errors.Is(err, tc.wantErrIs), "expected error %v, got %v", tc.wantErrIs, err)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

// stripProof removes the proof member from a signed JSON-LD document and
// returns the remaining document — the input the verification functions take.
func stripProof(t *testing.T, documentJSON []byte) []byte {
	t.Helper()
	var docMap map[string]interface{}
	require.NoError(t, json.Unmarshal(documentJSON, &docMap))
	delete(docMap, common.VPKeyProof)
	return marshal(t, docMap)
}

// marshalWithoutProof marshals a document map with its proof member removed.
func marshalWithoutProof(t *testing.T, docMap map[string]interface{}) []byte {
	t.Helper()
	withoutProof := make(map[string]interface{}, len(docMap))
	for k, v := range docMap {
		if k != common.VPKeyProof {
			withoutProof[k] = v
		}
	}
	return marshal(t, withoutProof)
}

// withField returns documentJSON with a single top-level field replaced,
// simulating content tampering after signing.
func withField(t *testing.T, documentJSON []byte, key string, value interface{}) []byte {
	t.Helper()
	var docMap map[string]interface{}
	require.NoError(t, json.Unmarshal(documentJSON, &docMap))
	docMap[key] = value
	return marshal(t, docMap)
}

// marshal is json.Marshal with the error folded into the test.
func marshal(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return raw
}

// TestResolveKeyFromDID_SharedResolver verifies that the shared
// ResolveKeyFromDID function returns the correct key for a given DID
// and key ID fragment.
func TestResolveKeyFromDID_SharedResolver(t *testing.T) {
	_, _, pubJWK := generateTestECKeys(t)
	keyID := "did:web:example.com#key-1"
	registry := createMockRegistry(t, "web", keyID, pubJWK)

	key, err := ResolveKeyFromDID(registry, "did:web:example.com", keyID)
	require.NoError(t, err)
	assert.True(t, jwk.Equal(key, pubJWK), "resolved key should match the expected public key")
}

// TestExtractDIDAndFragment verifies the helper function for splitting
// verification method URIs.
func TestExtractDIDAndFragment(t *testing.T) {
	type testCase struct {
		name    string
		input   string
		wantDID string
		wantKid string
	}

	tests := []testCase{
		{
			name:    "with_fragment",
			input:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			wantDID: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			wantKid: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
		{
			name:    "without_fragment",
			input:   "did:web:example.com",
			wantDID: "did:web:example.com",
			wantKid: "did:web:example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotDID, gotKid := ExtractDIDAndFragment(tc.input)
			assert.Equal(t, tc.wantDID, gotDID)
			assert.Equal(t, tc.wantKid, gotKid)
		})
	}
}

// TestIsDidElsi verifies the did:elsi detection helper.
func TestIsDidElsi(t *testing.T) {
	type testCase struct {
		name string
		did  string
		want bool
	}

	tests := []testCase{
		{name: "elsi", did: "did:elsi:some-org", want: true},
		{name: "web", did: "did:web:example.com", want: false},
		{name: "key", did: "did:key:z6Mk...", want: false},
		{name: "empty", did: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsDidElsi(tc.did))
		})
	}
}

// --- Integration: VerifyPresentation with did:key ---

// TestLDProofChecker_VerifyPresentation_DidKey tests round-trip signing and
// verification with a real did:key resolver: the DID is derived from the
// generated public key, so resolution genuinely exercises the did:key VDR
// rather than a mock.
func TestLDProofChecker_VerifyPresentation_DidKey(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	holderDID := didKeyFromP256(t, &privKey.PublicKey)
	verificationMethodID := holderDID + "#" + strings.TrimPrefix(holderDID, "did:key:")

	registry := did.NewRegistry(did.WithVDR(did.NewKeyVDR()))

	pres := createTestVP()
	pres.Holder = holderDID
	vpJSON, proof := signPresentation(t, pres, signer, verificationMethodID, docLoader)
	vpWithoutProof := stripProof(t, vpJSON)

	checker := NewLDProofChecker(registry, docLoader)
	key, err := checker.VerifyPresentation(vpWithoutProof, proof, holderDID)
	require.NoError(t, err)
	require.NotNil(t, key, "expected resolved key")
	assert.True(t, jwk.Equal(key, pubJWK), "resolved key should match")
}

// multicodecP256Pub is the multicodec prefix for a compressed P-256 public
// key, as used by the did:key method.
const multicodecP256Pub = 0x1200

// didKeyFromP256 derives the did:key DID for a P-256 public key by
// multicodec-prefixing the compressed point and multibase-encoding it.
func didKeyFromP256(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	compressed := elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)

	prefix := make([]byte, binary.MaxVarintLen64)
	prefixLen := binary.PutUvarint(prefix, multicodecP256Pub)

	encoded, err := multibase.Encode(multibase.Base58BTC, append(prefix[:prefixLen], compressed...))
	require.NoError(t, err)
	return "did:key:" + encoded
}

// --- Detached JWS helper (local to this test file) ---

// buildDetachedJWS constructs a detached JWS string from an algorithm and signature.
func buildDetachedJWS(alg string, sig []byte) string {
	header := map[string]interface{}{
		"alg":  alg,
		"b64":  false,
		"crit": []string{"b64"},
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return headerB64 + ".." + sigB64
}
