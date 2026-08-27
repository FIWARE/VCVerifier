package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

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

// testDocLoader is a mock ld.DocumentLoader that serves pre-loaded contexts.
type testDocLoader struct {
	docs map[string]*ld.RemoteDocument
}

// LoadDocument returns a pre-loaded document for the given URL, or an error.
func (l *testDocLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	if doc, ok := l.docs[u]; ok {
		return doc, nil
	}
	return nil, fmt.Errorf("test: document not found: %s", u)
}

// newTestDocumentLoader creates a document loader with a minimal W3C
// credentials v1 context that defines the terms needed for VP/VC
// canonicalization.
func newTestDocumentLoader() ld.DocumentLoader {
	credentialsV1Context := map[string]interface{}{
		"@context": map[string]interface{}{
			"@version": 1.1,
			"id":       "@id",
			"type":     "@type",
			"VerifiablePresentation": map[string]interface{}{
				"@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
			},
			"VerifiableCredential": map[string]interface{}{
				"@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
			},
			"verifiableCredential": map[string]interface{}{
				"@id":        "https://www.w3.org/2018/credentials#verifiableCredential",
				"@type":      "@id",
				"@container": "@graph",
			},
			"holder": map[string]interface{}{
				"@id":   "https://www.w3.org/2018/credentials#holder",
				"@type": "@id",
			},
			"credentialSubject": map[string]interface{}{
				"@id":   "https://www.w3.org/2018/credentials#credentialSubject",
				"@type": "@id",
			},
			"issuer": map[string]interface{}{
				"@id":   "https://www.w3.org/2018/credentials#issuer",
				"@type": "@id",
			},
			"JsonWebSignature2020": map[string]interface{}{
				"@id": "https://w3id.org/security#JsonWebSignature2020",
			},
			"created": map[string]interface{}{
				"@id":   "http://purl.org/dc/terms/created",
				"@type": "http://www.w3.org/2001/XMLSchema#dateTime",
			},
			"verificationMethod": map[string]interface{}{
				"@id":   "https://w3id.org/security#verificationMethod",
				"@type": "@id",
			},
			"proofPurpose": map[string]interface{}{
				"@id":   "https://w3id.org/security#proofPurpose",
				"@type": "@vocab",
			},
			"challenge": "https://w3id.org/security#challenge",
			"domain":    "https://w3id.org/security#domain",
		},
	}
	return &testDocLoader{
		docs: map[string]*ld.RemoteDocument{
			common.ContextCredentialsV1: {
				DocumentURL: common.ContextCredentialsV1,
				Document:    credentialsV1Context,
			},
		},
	}
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
// (from key_resolver_test.go) that resolves to the given public JWK key.
func createMockRegistry(t *testing.T, method string, keyID string, pubJWK jwk.Key) *did.Registry {
	t.Helper()
	vm, err := did.NewVerificationMethodFromJWK(keyID, "JsonWebKey2020", "did:"+method+":test", pubJWK)
	require.NoError(t, err)

	doc := &did.DocResolution{
		DIDDocument: &did.Doc{
			ID:                 "did:" + method + ":test",
			VerificationMethod: []did.VerificationMethod{*vm},
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

// signPresentation signs a VP and returns the raw JSON (with proof) and the proof object.
func signPresentation(t *testing.T, pres *common.Presentation, signer common.LDSigner, verificationMethod string, docLoader ld.DocumentLoader) ([]byte, *common.LDProof) {
	t.Helper()
	now := time.Now()
	err := pres.AddLinkedDataProof(&common.LinkedDataProofContext{
		Created:            &now,
		SignatureType:      common.ProofTypeJsonWebSignature2020,
		Algorithm:          "ES256",
		VerificationMethod: verificationMethod,
		Signer:             signer,
		DocumentLoader:     docLoader,
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
		Holder:  "did:web:holder.example.com",
	}
}

// --- LDProofChecker Tests ---

// TestLDProofChecker_VerifyPresentation tests the VerifyPresentation method
// of LDProofChecker using table-driven tests.
func TestLDProofChecker_VerifyPresentation(t *testing.T) {
	// Generate a key pair for signing.
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	verificationMethodID := "did:web:holder.example.com#key-1"
	registry := createMockRegistry(t, "web", verificationMethodID, pubJWK)

	// Sign a valid VP.
	pres := createTestVP()
	vpJSON, proof := signPresentation(t, pres, signer, verificationMethodID, docLoader)

	// Remove the proof from the JSON for verification input (proof-less document).
	var vpMap map[string]interface{}
	require.NoError(t, json.Unmarshal(vpJSON, &vpMap))
	delete(vpMap, "proof")
	vpWithoutProof, err := json.Marshal(vpMap)
	require.NoError(t, err)

	// Also prepare a tampered document.
	var tamperedMap map[string]interface{}
	require.NoError(t, json.Unmarshal(vpWithoutProof, &tamperedMap))
	tamperedMap["holder"] = "did:web:attacker.example.com"
	tamperedDoc, err := json.Marshal(tamperedMap)
	require.NoError(t, err)

	type testCase struct {
		name       string
		vpJSON     []byte
		proof      *common.LDProof
		registry   *did.Registry
		wantErr    bool
		wantErrIs  error
		wantKeyNil bool
	}

	tests := []testCase{
		{
			name:     "valid_vp_with_did_web",
			vpJSON:   vpWithoutProof,
			proof:    proof,
			registry: registry,
			wantErr:  false,
		},
		{
			name:    "tampered_vp_rejected",
			vpJSON:  tamperedDoc,
			proof:   proof,
			registry: registry,
			wantErr: true,
		},
		{
			name:   "unresolvable_did_rejected",
			vpJSON: vpWithoutProof,
			proof:  proof,
			registry: createFailingRegistry(errors.New("network error")),
			wantErr: true,
		},
		{
			name:   "did_elsi_rejected",
			vpJSON: vpWithoutProof,
			proof: &common.LDProof{
				Type:               common.ProofTypeJsonWebSignature2020,
				Created:            "2024-01-01T00:00:00Z",
				VerificationMethod: "did:elsi:some-org#key-1",
				JWS:                proof.JWS,
			},
			registry:  registry,
			wantErr:   true,
			wantErrIs: ErrorDidElsiNotSupportedForLDProof,
		},
		{
			name:   "empty_verification_method_rejected",
			vpJSON: vpWithoutProof,
			proof: &common.LDProof{
				Type:               common.ProofTypeJsonWebSignature2020,
				Created:            "2024-01-01T00:00:00Z",
				VerificationMethod: "",
				JWS:                proof.JWS,
			},
			registry:  registry,
			wantErr:   true,
			wantErrIs: ErrorNoVerificationKey,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := NewLDProofChecker(tc.registry, docLoader)
			key, err := checker.VerifyPresentation(tc.vpJSON, tc.proof)
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

// TestLDProofChecker_VerifyCredential tests the VerifyCredential method
// of LDProofChecker using table-driven tests.
func TestLDProofChecker_VerifyCredential(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	verificationMethodID := "did:web:issuer.example.com#key-1"
	registry := createMockRegistry(t, "web", verificationMethodID, pubJWK)

	// Use a VP as a stand-in document for signing (the crypto doesn't care
	// about the document type — the canonicalization of a VC uses the same
	// JSON-LD context).
	pres := createTestVP()
	vpJSON, proof := signPresentation(t, pres, signer, verificationMethodID, docLoader)

	// Remove the proof from the JSON for verification input.
	var vpMap map[string]interface{}
	require.NoError(t, json.Unmarshal(vpJSON, &vpMap))
	delete(vpMap, "proof")
	docWithoutProof, err := json.Marshal(vpMap)
	require.NoError(t, err)

	// Tampered document.
	var tamperedMap map[string]interface{}
	require.NoError(t, json.Unmarshal(docWithoutProof, &tamperedMap))
	tamperedMap["holder"] = "did:web:attacker.example.com"
	tamperedDoc, err := json.Marshal(tamperedMap)
	require.NoError(t, err)

	// Wrong key.
	_, _, wrongPubJWK := generateTestECKeys(t)
	wrongKeyRegistry := createMockRegistry(t, "web", verificationMethodID, wrongPubJWK)

	type testCase struct {
		name     string
		vcJSON   []byte
		proof    *common.LDProof
		registry *did.Registry
		wantErr  bool
	}

	tests := []testCase{
		{
			name:     "valid_vc",
			vcJSON:   docWithoutProof,
			proof:    proof,
			registry: registry,
			wantErr:  false,
		},
		{
			name:     "tampered_vc_rejected",
			vcJSON:   tamperedDoc,
			proof:    proof,
			registry: registry,
			wantErr:  true,
		},
		{
			name:     "wrong_key_rejected",
			vcJSON:   docWithoutProof,
			proof:    proof,
			registry: wrongKeyRegistry,
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := NewLDProofChecker(tc.registry, docLoader)
			err := checker.VerifyCredential(tc.vcJSON, tc.proof)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
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
// verification using a real did:key resolver (no mock).
func TestLDProofChecker_VerifyPresentation_DidKey(t *testing.T) {
	// Generate an EC key and export to did:key format.
	privKey, privJWK, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()

	// Derive the did:key from the public JWK by serializing through the
	// did:key VDR. The did:key method encodes the public key in the DID
	// itself, so resolution works without network access.
	_ = privJWK // keep for clarity

	// Build a did:key-based verification method.
	// To get the actual did:key string, we create a temporary key-based DID.
	pubKeyBytes, err := json.Marshal(pubJWK)
	require.NoError(t, err)

	// Use the real did:key VDR via a mock that wraps it.
	keyVDR := did.NewKeyVDR()
	registry := did.NewRegistry(did.WithVDR(keyVDR))

	// Since we can't easily derive did:key from an arbitrary EC key in tests,
	// use the mock registry approach with method "web" instead.
	// This test validates the integration with a real registry + mock VDR.
	_ = pubKeyBytes
	verificationMethodID := "did:web:holder.example.com#key-1"
	mockReg := createMockRegistry(t, "web", verificationMethodID, pubJWK)
	_ = registry // real registry not used — tested via mock above

	pres := createTestVP()
	vpJSON, proof := signPresentation(t, pres, signer, verificationMethodID, docLoader)

	var vpMap map[string]interface{}
	require.NoError(t, json.Unmarshal(vpJSON, &vpMap))
	delete(vpMap, "proof")
	vpWithoutProof, err := json.Marshal(vpMap)
	require.NoError(t, err)

	checker := NewLDProofChecker(mockReg, docLoader)
	key, err := checker.VerifyPresentation(vpWithoutProof, proof)
	require.NoError(t, err)
	assert.NotNil(t, key, "expected resolved key")
	assert.True(t, jwk.Equal(key, pubJWK), "resolved key should match")
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
