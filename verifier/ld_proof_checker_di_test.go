package verifier

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
)

// --- Data Integrity test constants ---

// diP256CoordSize is the byte length of each P-256 coordinate in IEEE P1363 format.
const diP256CoordSize = 32

// --- Data Integrity signing helpers ---
//
// These replicate the signing logic from common/data_integrity_test.go for use
// in the verifier integration tests. They produce real, verifiable
// DataIntegrityProof proofs without importing unexported test helpers from the
// common package.

// signDICredential signs a JSON-LD VC map with a DataIntegrityProof
// (ecdsa-rdfc-2019, P-256) and returns the full document JSON (with proof
// embedded) and the parsed LDProof.
func signDICredential(t *testing.T, vcMap map[string]interface{}, privKey *ecdsa.PrivateKey, verificationMethod string) ([]byte, *common.LDProof) {
	t.Helper()
	return signDIDocumentECDSA(t, vcMap, privKey, verificationMethod,
		common.ProofPurposeAssertionMethod, "", "")
}

// signDIPresentation signs a JSON-LD VP map with a DataIntegrityProof
// (ecdsa-rdfc-2019, P-256) for authentication purpose.
func signDIPresentation(t *testing.T, vpMap map[string]interface{}, privKey *ecdsa.PrivateKey, verificationMethod string) ([]byte, *common.LDProof) {
	t.Helper()
	return signDIDocumentECDSA(t, vpMap, privKey, verificationMethod,
		common.ProofPurposeAuthentication, "", "")
}

// signDICredentialEd25519 signs a JSON-LD VC map with a DataIntegrityProof
// (eddsa-rdfc-2022, Ed25519) and returns the full document JSON (with proof
// embedded) and the parsed LDProof.
func signDICredentialEd25519(t *testing.T, vcMap map[string]interface{}, privKey ed25519.PrivateKey, verificationMethod string) ([]byte, *common.LDProof) {
	t.Helper()
	return signDIDocumentEd25519(t, vcMap, privKey, verificationMethod,
		common.ProofPurposeAssertionMethod, "", "")
}

// signDIPresentationEd25519 signs a JSON-LD VP map with a DataIntegrityProof
// (eddsa-rdfc-2022, Ed25519) for authentication purpose.
func signDIPresentationEd25519(t *testing.T, vpMap map[string]interface{}, privKey ed25519.PrivateKey, verificationMethod string) ([]byte, *common.LDProof) {
	t.Helper()
	return signDIDocumentEd25519(t, vpMap, privKey, verificationMethod,
		common.ProofPurposeAuthentication, "", "")
}

// signDIDocumentECDSA creates a DataIntegrityProof with ecdsa-rdfc-2019 (P-256)
// over the given document. It performs URDNA2015 canonicalization, SHA-256
// hashing, and ECDSA signing in IEEE P1363 format, matching the W3C
// VC-DI-ECDSA specification.
func signDIDocumentECDSA(t *testing.T, doc map[string]interface{}, privKey *ecdsa.PrivateKey, verificationMethod, proofPurpose, challenge, domain string) ([]byte, *common.LDProof) {
	t.Helper()

	proof := &common.LDProof{
		Type:               common.ProofTypeDataIntegrityProof,
		Cryptosuite:        common.CryptosuiteEcdsaRdfc2019,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurpose,
		Challenge:          challenge,
		Domain:             domain,
	}

	hashData := computeDITestHashData(t, doc, proof)

	// Per W3C VC-DI-ECDSA, ECDSA internally hashes the hashData. Go's
	// ecdsa.Sign expects the pre-computed digest.
	digest := sha256.Sum256(hashData)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	require.NoError(t, err)

	// Encode as IEEE P1363 (r || s).
	sigBytes := make([]byte, diP256CoordSize*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[diP256CoordSize-len(rBytes):diP256CoordSize], rBytes)
	copy(sigBytes[2*diP256CoordSize-len(sBytes):], sBytes)

	proof.ProofValue, err = multibase.Encode(multibase.Base58BTC, sigBytes)
	require.NoError(t, err)

	return marshalDocWithDIProof(t, doc, proof), proof
}

// signDIDocumentEd25519 creates a DataIntegrityProof with eddsa-rdfc-2022
// (Ed25519) over the given document.
func signDIDocumentEd25519(t *testing.T, doc map[string]interface{}, privKey ed25519.PrivateKey, verificationMethod, proofPurpose, challenge, domain string) ([]byte, *common.LDProof) {
	t.Helper()

	proof := &common.LDProof{
		Type:               common.ProofTypeDataIntegrityProof,
		Cryptosuite:        common.CryptosuiteEddsaRdfc2022,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       proofPurpose,
		Challenge:          challenge,
		Domain:             domain,
	}

	hashData := computeDITestHashData(t, doc, proof)
	sig := ed25519.Sign(privKey, hashData)

	var err error
	proof.ProofValue, err = multibase.Encode(multibase.Base58BTC, sig)
	require.NoError(t, err)

	return marshalDocWithDIProof(t, doc, proof), proof
}

// computeDITestHashData builds proof options, canonicalizes both the document
// and proof options, and computes the hashData for signing. It replicates the
// logic of common.buildProofOptions and common.computeDataIntegrityHashData.
func computeDITestHashData(t *testing.T, doc map[string]interface{}, proof *common.LDProof) []byte {
	t.Helper()

	loader := newTestDocumentLoader()

	// Build proof options matching common.buildProofOptions.
	proofOptions := map[string]interface{}{
		common.JSONLDKeyContext:             common.EnsureDataIntegrityContext(doc[common.JSONLDKeyContext]),
		common.JSONLDKeyType:               proof.Type,
		common.LDProofKeyCreated:           proof.Created,
		common.LDProofKeyVerificationMethod: proof.VerificationMethod,
	}
	if proof.ProofPurpose != "" {
		proofOptions[common.LDProofKeyProofPurpose] = proof.ProofPurpose
	}
	if proof.Challenge != "" {
		proofOptions[common.LDProofKeyChallenge] = proof.Challenge
	}
	if proof.Domain != "" {
		proofOptions[common.LDProofKeyDomain] = proof.Domain
	}
	if proof.Cryptosuite != "" {
		proofOptions[common.LDProofKeyCryptosuite] = proof.Cryptosuite
	}

	// Canonicalize both.
	proc := ld.NewJsonLdProcessor()
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Format = common.LDNormFormatNQuads
	ldOpts.Algorithm = common.LDNormAlgorithmURDNA
	ldOpts.DocumentLoader = loader

	canonDoc, err := proc.Normalize(doc, ldOpts)
	require.NoError(t, err)

	canonProof, err := proc.Normalize(proofOptions, ldOpts)
	require.NoError(t, err)

	// Compute hash data: SHA-256(canonProof) || SHA-256(canonDoc) for P-256/Ed25519.
	proofHash := sha256.Sum256([]byte(canonProof.(string)))
	docHash := sha256.Sum256([]byte(canonDoc.(string)))
	return append(proofHash[:], docHash[:]...)
}

// marshalDocWithDIProof attaches a Data Integrity proof to a document map and
// returns the marshalled JSON.
func marshalDocWithDIProof(t *testing.T, doc map[string]interface{}, proof *common.LDProof) []byte {
	t.Helper()

	docWithProof := shallowCopyMap(doc)
	proofMap := map[string]interface{}{
		common.LDProofKeyType:               proof.Type,
		common.LDProofKeyCryptosuite:        proof.Cryptosuite,
		common.LDProofKeyCreated:            proof.Created,
		common.LDProofKeyVerificationMethod: proof.VerificationMethod,
		common.LDProofKeyProofPurpose:       proof.ProofPurpose,
		common.LDProofKeyProofValue:         proof.ProofValue,
	}
	if proof.Challenge != "" {
		proofMap[common.LDProofKeyChallenge] = proof.Challenge
	}
	if proof.Domain != "" {
		proofMap[common.LDProofKeyDomain] = proof.Domain
	}
	docWithProof[common.VPKeyProof] = proofMap

	docJSON, err := json.Marshal(docWithProof)
	require.NoError(t, err)
	return docJSON
}

// shallowCopyMap returns a shallow copy of a map.
func shallowCopyMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// --- Data Integrity key generation helpers ---

// generateTestEd25519Keys generates an Ed25519 key pair and returns the
// raw private key, the private JWK, and the public JWK.
func generateTestEd25519Keys(t *testing.T) (ed25519.PrivateKey, jwk.Key, jwk.Key) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privJWK, err := jwk.Import(privKey)
	require.NoError(t, err)

	pubJWK, err := jwk.Import(pubKey)
	require.NoError(t, err)

	return privKey, privJWK, pubJWK
}

// --- Data Integrity document helpers ---

// createDITestVC creates a minimal JSON-LD Verifiable Credential map using the
// VCDM 2.0 context (required for Data Integrity proofs).
func createDITestVC(issuerDID string, subjectDID string) map[string]interface{} {
	return map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{
			common.ContextCredentialsV2,
		},
		common.JSONLDKeyType:          []interface{}{common.TypeVerifiableCredential},
		common.VCKeyIssuer:            map[string]interface{}{common.JSONLDKeyID: issuerDID},
		common.JSONLDKeyID:            "urn:uuid:11111111-2222-3333-4444-555555555555",
		"issuanceDate":                "2024-01-01T00:00:00Z",
		common.VCKeyCredentialSubject: map[string]interface{}{common.JSONLDKeyID: subjectDID},
	}
}

// createDITestVP creates a minimal JSON-LD Verifiable Presentation map using
// the VCDM 2.0 context (required for Data Integrity proofs).
func createDITestVP(holderDID string) map[string]interface{} {
	return map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{
			common.ContextCredentialsV2,
		},
		common.JSONLDKeyType:   []interface{}{common.TypeVerifiablePresentation},
		common.VPKeyHolder:     holderDID,
	}
}

// --- Integration Tests: Data Integrity proof dispatch ---

// TestLDProofChecker_VerifyCredential_DataIntegrity tests end-to-end
// verification of credentials with DataIntegrityProof proofs through the
// LDProofChecker, exercising the full dispatch chain from VerifyCredential
// through verifyLDProofWithCandidateKeys to common.VerifyDataIntegrityProof.
func TestLDProofChecker_VerifyCredential_DataIntegrity(t *testing.T) {
	docLoader := newTestDocumentLoader()

	tests := []struct {
		name            string
		setupFunc       func(t *testing.T) (vcJSON []byte, proof *common.LDProof, registry *did.Registry, expectedIssuer string)
		wantErr         bool
		wantErrSentinel error
	}{
		{
			name: "valid_vc_ecdsa_rdfc_2019_p256",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				issuerDID := testIssuerDID
				keyID := testIssuerKeyID

				vcMap := createDITestVC(issuerDID, testSubjectDID)
				vcJSON, proof := signDICredential(t, vcMap, privKey, keyID)
				vcJSONNoProof := stripProof(t, vcJSON)

				registry := createMockRegistry(t, "web", keyID, pubJWK)
				return vcJSONNoProof, proof, registry, issuerDID
			},
		},
		{
			name: "valid_vc_eddsa_rdfc_2022_ed25519",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestEd25519Keys(t)
				issuerDID := testIssuerDID
				keyID := testIssuerKeyID

				vcMap := createDITestVC(issuerDID, testSubjectDID)
				vcJSON, proof := signDICredentialEd25519(t, vcMap, privKey, keyID)
				vcJSONNoProof := stripProof(t, vcJSON)

				registry := createMockRegistry(t, "web", keyID, pubJWK)
				return vcJSONNoProof, proof, registry, issuerDID
			},
		},
		{
			name: "valid_vc_with_multikey_verification_method",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				issuerDID := testIssuerDID
				keyID := testIssuerKeyID

				vcMap := createDITestVC(issuerDID, testSubjectDID)
				vcJSON, proof := signDICredential(t, vcMap, privKey, keyID)
				vcJSONNoProof := stripProof(t, vcJSON)

				// Create a registry with a Multikey VM type (tests Step 1+2 integration).
				registry := createMockRegistryWithVMType(t, keyID, pubJWK, did.TypeMultikey,
					[]string{keyID}, []string{keyID})
				return vcJSONNoProof, proof, registry, issuerDID
			},
		},
		{
			name: "tampered_vc_rejected",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				issuerDID := testIssuerDID
				keyID := testIssuerKeyID

				vcMap := createDITestVC(issuerDID, testSubjectDID)
				vcJSON, proof := signDICredential(t, vcMap, privKey, keyID)
				vcJSONNoProof := stripProof(t, vcJSON)

				// Tamper with the credentialSubject (a term defined in the
				// VCDM 2.0 context, so it survives canonicalization).
				tamperedJSON := withField(t, vcJSONNoProof, common.VCKeyCredentialSubject,
					map[string]interface{}{common.JSONLDKeyID: "did:web:tampered.example.com"})

				registry := createMockRegistry(t, "web", keyID, pubJWK)
				return tamperedJSON, proof, registry, issuerDID
			},
			wantErr:         true,
			wantErrSentinel: common.ErrorLDProofVerifyDataIntegrity,
		},
		{
			name: "signer_other_than_issuer_rejected",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				attackerDID := "did:web:attacker.example.com"
				attackerKeyID := attackerDID + "#key-1"

				vcMap := createDITestVC(testIssuerDID, testSubjectDID)
				// Sign with the attacker's key
				vcJSON, proof := signDICredential(t, vcMap, privKey, attackerKeyID)
				vcJSONNoProof := stripProof(t, vcJSON)

				registry := createMockRegistry(t, "web", attackerKeyID, pubJWK)
				// Expect to verify against the credential's claimed issuer, not the signer
				return vcJSONNoProof, proof, registry, testIssuerDID
			},
			wantErr:         true,
			wantErrSentinel: ErrorProofIssuerMismatch,
		},
		{
			name: "wrong_proof_purpose_rejected",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				issuerDID := testIssuerDID
				keyID := testIssuerKeyID

				vcMap := createDITestVC(issuerDID, testSubjectDID)
				// Sign with authentication purpose instead of assertionMethod
				vcJSON, proof := signDIDocumentECDSA(t, vcMap, privKey, keyID,
					common.ProofPurposeAuthentication, "", "")
				vcJSONNoProof := stripProof(t, vcJSON)

				registry := createMockRegistry(t, "web", keyID, pubJWK)
				return vcJSONNoProof, proof, registry, issuerDID
			},
			wantErr:         true,
			wantErrSentinel: ErrorProofPurposeMismatch,
		},
		{
			name: "unsupported_cryptosuite_rejected",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				issuerDID := testIssuerDID
				keyID := testIssuerKeyID

				vcMap := createDITestVC(issuerDID, testSubjectDID)
				vcJSON, proof := signDICredential(t, vcMap, privKey, keyID)
				vcJSONNoProof := stripProof(t, vcJSON)

				// Tamper with the cryptosuite after signing.
				proof.Cryptosuite = "unknown-suite-2099"

				registry := createMockRegistry(t, "web", keyID, pubJWK)
				return vcJSONNoProof, proof, registry, issuerDID
			},
			wantErr:         true,
			wantErrSentinel: common.ErrorLDProofUnsupportedCryptosuite,
		},
		{
			name: "unsupported_proof_type_rejected",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				issuerDID := testIssuerDID
				keyID := testIssuerKeyID

				vcMap := createDITestVC(issuerDID, testSubjectDID)
				_, proof := signDICredential(t, vcMap, privKey, keyID)

				// Set an unrecognized proof type.
				proof.Type = "UnknownProofType2099"

				registry := createMockRegistry(t, "web", keyID, pubJWK)
				return marshal(t, vcMap), proof, registry, issuerDID
			},
			wantErr:         true,
			wantErrSentinel: common.ErrorLDProofUnsupportedType,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vcJSON, proof, registry, expectedIssuer := tc.setupFunc(t)
			checker := NewLDProofChecker(registry, docLoader)

			err := checker.VerifyCredential(vcJSON, proof, expectedIssuer)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.wantErrSentinel != nil {
					assert.True(t, errors.Is(err, tc.wantErrSentinel),
						"expected %v, got: %v", tc.wantErrSentinel, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestLDProofChecker_VerifyPresentation_DataIntegrity tests end-to-end
// verification of presentations with DataIntegrityProof proofs, exercising
// holder binding and the authentication proof purpose.
func TestLDProofChecker_VerifyPresentation_DataIntegrity(t *testing.T) {
	docLoader := newTestDocumentLoader()

	tests := []struct {
		name            string
		setupFunc       func(t *testing.T) (vpJSON []byte, proof *common.LDProof, registry *did.Registry, expectedHolder string)
		wantErr         bool
		wantErrSentinel error
	}{
		{
			name: "valid_vp_ecdsa_rdfc_2019_p256",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				holderDID := testHolderDID
				keyID := testHolderKeyID

				vpMap := createDITestVP(holderDID)
				vpJSON, proof := signDIPresentation(t, vpMap, privKey, keyID)
				vpJSONNoProof := stripProof(t, vpJSON)

				registry := createMockRegistry(t, "web", keyID, pubJWK)
				return vpJSONNoProof, proof, registry, holderDID
			},
		},
		{
			name: "valid_vp_eddsa_rdfc_2022_ed25519",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestEd25519Keys(t)
				holderDID := testHolderDID
				keyID := testHolderKeyID

				vpMap := createDITestVP(holderDID)
				vpJSON, proof := signDIPresentationEd25519(t, vpMap, privKey, keyID)
				vpJSONNoProof := stripProof(t, vpJSON)

				registry := createMockRegistry(t, "web", keyID, pubJWK)
				return vpJSONNoProof, proof, registry, holderDID
			},
		},
		{
			name: "valid_vp_with_multikey_verification_method",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestEd25519Keys(t)
				holderDID := testHolderDID
				keyID := testHolderKeyID

				vpMap := createDITestVP(holderDID)
				vpJSON, proof := signDIPresentationEd25519(t, vpMap, privKey, keyID)
				vpJSONNoProof := stripProof(t, vpJSON)

				// Create a registry with a Multikey VM type.
				registry := createMockRegistryWithVMType(t, keyID, pubJWK, did.TypeMultikey,
					[]string{keyID}, []string{keyID})
				return vpJSONNoProof, proof, registry, holderDID
			},
		},
		{
			name: "holder_mismatch_rejected",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				attackerDID := "did:web:attacker.example.com"
				attackerKeyID := attackerDID + "#key-1"

				vpMap := createDITestVP(testHolderDID)
				// Sign with the attacker's key
				vpJSON, proof := signDIDocumentECDSA(t, vpMap, privKey, attackerKeyID,
					common.ProofPurposeAuthentication, "", "")
				vpJSONNoProof := stripProof(t, vpJSON)

				registry := createMockRegistry(t, "web", attackerKeyID, pubJWK)
				return vpJSONNoProof, proof, registry, testHolderDID
			},
			wantErr:         true,
			wantErrSentinel: ErrorProofHolderMismatch,
		},
		{
			name: "wrong_purpose_rejected_for_presentation",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				holderDID := testHolderDID
				keyID := testHolderKeyID

				vpMap := createDITestVP(holderDID)
				// Sign with assertionMethod instead of authentication
				vpJSON, proof := signDIDocumentECDSA(t, vpMap, privKey, keyID,
					common.ProofPurposeAssertionMethod, "", "")
				vpJSONNoProof := stripProof(t, vpJSON)

				registry := createMockRegistry(t, "web", keyID, pubJWK)
				return vpJSONNoProof, proof, registry, holderDID
			},
			wantErr:         true,
			wantErrSentinel: ErrorProofPurposeMismatch,
		},
		{
			name: "key_without_authentication_relationship_rejected",
			setupFunc: func(t *testing.T) ([]byte, *common.LDProof, *did.Registry, string) {
				privKey, _, pubJWK := generateTestECKeys(t)
				holderDID := testHolderDID
				keyID := testHolderKeyID

				vpMap := createDITestVP(holderDID)
				vpJSON, proof := signDIPresentation(t, vpMap, privKey, keyID)
				vpJSONNoProof := stripProof(t, vpJSON)

				// Key is only in assertionMethod, not authentication.
				registry := createMockRegistryForRelationships(t, keyID, pubJWK,
					[]string{}, []string{keyID})
				return vpJSONNoProof, proof, registry, holderDID
			},
			wantErr:         true,
			wantErrSentinel: ErrorVerificationRelationshipNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vpJSON, proof, registry, expectedHolder := tc.setupFunc(t)
			checker := NewLDProofChecker(registry, docLoader)

			key, err := checker.VerifyPresentation(vpJSON, proof, expectedHolder)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
				if tc.wantErrSentinel != nil {
					assert.True(t, errors.Is(err, tc.wantErrSentinel),
						"expected %v, got: %v", tc.wantErrSentinel, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key, "verified VP should return the signing key")
			}
		})
	}
}

// TestSelectProofVerifier tests the proof type dispatch function directly.
func TestSelectProofVerifier(t *testing.T) {
	tests := []struct {
		name      string
		proofType string
		wantErr   bool
	}{
		{
			name:      "JsonWebSignature2020_dispatches",
			proofType: common.ProofTypeJsonWebSignature2020,
		},
		{
			name:      "DataIntegrityProof_dispatches",
			proofType: common.ProofTypeDataIntegrityProof,
		},
		{
			name:      "unknown_type_rejected",
			proofType: "UnknownProofType",
			wantErr:   true,
		},
		{
			name:      "empty_type_rejected",
			proofType: "",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proof := &common.LDProof{Type: tc.proofType}
			fn, err := selectProofVerifier(proof)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, fn)
				assert.True(t, errors.Is(err, common.ErrorLDProofUnsupportedType),
					"expected ErrorLDProofUnsupportedType, got: %v", err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, fn)
			}
		})
	}
}

// TestLDProofChecker_JWSAndDICoexist verifies that both proof types still work
// correctly through the same LDProofChecker — a JWS credential and a DI
// credential can be verified by the same checker instance.
func TestLDProofChecker_JWSAndDICoexist(t *testing.T) {
	docLoader := newTestDocumentLoader()

	// Generate keys shared by both proof types.
	ecPrivKey, _, ecPubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: ecPrivKey}
	issuerDID := testIssuerDID
	keyID := testIssuerKeyID

	registry := createMockRegistry(t, "web", keyID, ecPubJWK)
	checker := NewLDProofChecker(registry, docLoader)

	// 1. Verify a JWS-signed credential.
	jwsVC := signTestCredential(t, issuerDID, signer, keyID, docLoader)
	jwsVCJSONNoProof := marshalWithoutProof(t, jwsVC)
	// Extract the proof from the signed VC map.
	jwsProofRaw, ok := jwsVC[common.VPKeyProof].(map[string]interface{})
	require.True(t, ok, "signed VC should have a proof map")
	jwsProof, err := common.ParseLDProof(jwsProofRaw)
	require.NoError(t, err)

	err = checker.VerifyCredential(jwsVCJSONNoProof, jwsProof, issuerDID)
	assert.NoError(t, err, "JWS credential should verify")

	// 2. Verify a DI-signed credential.
	diVCMap := createDITestVC(issuerDID, testSubjectDID)
	diVCJSON, diProof := signDICredential(t, diVCMap, ecPrivKey, keyID)
	diVCJSONNoProof := stripProof(t, diVCJSON)

	err = checker.VerifyCredential(diVCJSONNoProof, diProof, issuerDID)
	assert.NoError(t, err, "DI credential should verify")
}

// --- Helper: createMockRegistryWithVMType ---

// createMockRegistryWithVMType is like createMockRegistryForRelationships but
// allows specifying the verification method type (e.g. did.TypeMultikey).
func createMockRegistryWithVMType(t *testing.T, keyID string, pubJWK jwk.Key, vmType string, authentication, assertionMethod []string) *did.Registry {
	t.Helper()
	didStr, _ := ExtractDIDAndFragment(keyID)
	vm, err := did.NewVerificationMethodFromJWK(keyID, vmType, didStr, pubJWK)
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
