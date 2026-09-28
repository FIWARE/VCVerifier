package common

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test key generators ---

// generateP384TestKeys generates an ECDSA P-384 key pair and returns the
// private key, the private JWK key, and the public JWK key.
func generateP384TestKeys(t *testing.T) (*ecdsa.PrivateKey, jwk.Key, jwk.Key) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	privJWK, err := jwk.Import(privKey)
	require.NoError(t, err)

	pubJWK, err := jwk.Import(&privKey.PublicKey)
	require.NoError(t, err)

	return privKey, privJWK, pubJWK
}

// generateEd25519TestKeys generates an Ed25519 key pair and returns the
// private key, the private JWK key, and the public JWK key.
func generateEd25519TestKeys(t *testing.T) (ed25519.PrivateKey, jwk.Key, jwk.Key) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privJWK, err := jwk.Import(privKey)
	require.NoError(t, err)

	pubJWK, err := jwk.Import(pubKey)
	require.NoError(t, err)

	return privKey, privJWK, pubJWK
}

// --- Test document and proof creation helpers ---

// dataIntegrityTestDocument creates a minimal JSON-LD Verifiable Credential
// document suitable for Data Integrity proof verification testing.
func dataIntegrityTestDocument() map[string]interface{} {
	return map[string]interface{}{
		JSONLDKeyContext: []interface{}{
			ContextCredentialsV2,
		},
		"type": []interface{}{"VerifiableCredential"},
		"issuer": map[string]interface{}{
			"id": "did:web:example.com",
		},
		"issuanceDate": "2024-01-01T00:00:00Z",
		"credentialSubject": map[string]interface{}{
			"id":   "did:web:holder.example.com",
			"name": "Test Subject",
		},
	}
}

// p256CoordSize is the byte length of each P-256 coordinate, matching
// p1363CoordinateSize[elliptic.P256()].
const p256CoordSize = 32

// p384CoordSize is the byte length of each P-384 coordinate, matching
// p1363CoordinateSize[elliptic.P384()].
const p384CoordSize = 48

// signDataIntegrityP256 creates an ecdsa-rdfc-2019 P-256 proof over the given
// document using URDNA2015 canonicalization, SHA-256 hashing, and IEEE P1363
// signature encoding.
func signDataIntegrityP256(t *testing.T, doc map[string]interface{}, privKey *ecdsa.PrivateKey, verificationMethod string) ([]byte, *LDProof) {
	t.Helper()
	return signDataIntegrityECDSA(t, doc, privKey, verificationMethod, CryptosuiteEcdsaRdfc2019, p256CoordSize, false)
}

// signDataIntegrityP384 creates an ecdsa-rdfc-2019 P-384 proof over the given
// document using URDNA2015 canonicalization, SHA-384 hashing, and IEEE P1363
// signature encoding.
func signDataIntegrityP384(t *testing.T, doc map[string]interface{}, privKey *ecdsa.PrivateKey, verificationMethod string) ([]byte, *LDProof) {
	t.Helper()
	return signDataIntegrityECDSA(t, doc, privKey, verificationMethod, CryptosuiteEcdsaRdfc2019, p384CoordSize, true)
}

// signDataIntegrityECDSA creates a DataIntegrityProof with the given ECDSA key
// and parameters. The hashData is hashed once more with the curve's hash
// algorithm before calling ecdsa.Sign, matching the W3C spec's ECDSA algorithm
// which internally hashes its input (Go's ecdsa.Sign expects the pre-computed
// digest).
func signDataIntegrityECDSA(t *testing.T, doc map[string]interface{}, privKey *ecdsa.PrivateKey, verificationMethod string, cryptosuite string, coordSize int, useSHA384 bool) ([]byte, *LDProof) {
	t.Helper()

	proof := &LDProof{
		Type:               ProofTypeDataIntegrityProof,
		Cryptosuite:        cryptosuite,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       ProofPurposeAssertionMethod,
	}

	// Build proof options, canonicalize, hash, sign.
	hashData := computeTestHashData(t, doc, proof, useSHA384)

	// Per W3C VC-DI-ECDSA, the ECDSA algorithm hashes the hashData with the
	// curve's hash function (SHA-256 for P-256, SHA-384 for P-384). Go's
	// ecdsa.Sign expects the pre-computed digest, so we hash here.
	var digest []byte
	if useSHA384 {
		h := sha512.Sum384(hashData)
		digest = h[:]
	} else {
		h := sha256.Sum256(hashData)
		digest = h[:]
	}

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
	require.NoError(t, err)

	// Encode as P1363 (r || s).
	sigBytes := make([]byte, coordSize*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[coordSize-len(rBytes):coordSize], rBytes)
	copy(sigBytes[2*coordSize-len(sBytes):], sBytes)

	// Encode proofValue as multibase (base58btc).
	proof.ProofValue, err = multibase.Encode(multibase.Base58BTC, sigBytes)
	require.NoError(t, err)

	// Marshal the full document with proof.
	docWithProof := copyMap(doc)
	proofMap := map[string]interface{}{
		LDProofKeyType:               proof.Type,
		LDProofKeyCryptosuite:        proof.Cryptosuite,
		LDProofKeyCreated:            proof.Created,
		LDProofKeyVerificationMethod: proof.VerificationMethod,
		LDProofKeyProofPurpose:       proof.ProofPurpose,
		LDProofKeyProofValue:         proof.ProofValue,
	}
	docWithProof[VPKeyProof] = proofMap

	docJSON, err := json.Marshal(docWithProof)
	require.NoError(t, err)

	return docJSON, proof
}

// signDataIntegrityEd25519 creates an eddsa-rdfc-2022 Ed25519 proof over the
// given document.
func signDataIntegrityEd25519(t *testing.T, doc map[string]interface{}, privKey ed25519.PrivateKey, verificationMethod string) ([]byte, *LDProof) {
	t.Helper()

	proof := &LDProof{
		Type:               ProofTypeDataIntegrityProof,
		Cryptosuite:        CryptosuiteEddsaRdfc2022,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       ProofPurposeAssertionMethod,
	}

	// Build proof options, canonicalize, hash, sign.
	hashData := computeTestHashData(t, doc, proof, false)

	sig := ed25519.Sign(privKey, hashData)

	var err error
	proof.ProofValue, err = multibase.Encode(multibase.Base58BTC, sig)
	require.NoError(t, err)

	// Marshal the full document with proof.
	docWithProof := copyMap(doc)
	proofMap := map[string]interface{}{
		LDProofKeyType:               proof.Type,
		LDProofKeyCryptosuite:        proof.Cryptosuite,
		LDProofKeyCreated:            proof.Created,
		LDProofKeyVerificationMethod: proof.VerificationMethod,
		LDProofKeyProofPurpose:       proof.ProofPurpose,
		LDProofKeyProofValue:         proof.ProofValue,
	}
	docWithProof[VPKeyProof] = proofMap

	docJSON, err := json.Marshal(docWithProof)
	require.NoError(t, err)

	return docJSON, proof
}

// computeTestHashData builds proof options, canonicalizes both the document and
// proof options, and computes hashData for signing.
func computeTestHashData(t *testing.T, doc map[string]interface{}, proof *LDProof, useSHA384 bool) []byte {
	t.Helper()

	loader := newTestDocumentLoader()

	// Build proof options.
	proofOptions := buildProofOptions(doc[JSONLDKeyContext], proof)

	// Canonicalize both.
	proc := ld.NewJsonLdProcessor()
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Format = LDNormFormatNQuads
	ldOpts.Algorithm = LDNormAlgorithmURDNA
	ldOpts.DocumentLoader = loader

	canonDoc, err := proc.Normalize(doc, ldOpts)
	require.NoError(t, err)

	canonProof, err := proc.Normalize(proofOptions, ldOpts)
	require.NoError(t, err)

	// Compute hash data.
	if useSHA384 {
		proofHash := sha512.Sum384([]byte(canonProof.(string)))
		docHash := sha512.Sum384([]byte(canonDoc.(string)))
		return append(proofHash[:], docHash[:]...)
	}

	proofHash := sha256.Sum256([]byte(canonProof.(string)))
	docHash := sha256.Sum256([]byte(canonDoc.(string)))
	return append(proofHash[:], docHash[:]...)
}

// copyMap returns a shallow copy of a map. Nested maps (e.g. credentialSubject,
// issuer) are shared between the original and the copy — callers that need to
// mutate nested values should re-unmarshal from JSON instead.
func copyMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// --- Tests for VerifyDataIntegrityProof ---

// TestVerifyDataIntegrityProof_ValidProofs tests successful verification of
// valid Data Integrity proofs across all supported cryptosuites and curves.
func TestVerifyDataIntegrityProof_ValidProofs(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(t *testing.T) (docJSON []byte, proof *LDProof, pubKey jwk.Key)
	}{
		{
			name: "ecdsa-rdfc-2019_P-256",
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				privKey, _, pubJWK := generateECTestKeys(t) // P-256
				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityP256(t, doc, privKey, "did:web:example.com#key-1")
				return docJSON, proof, pubJWK
			},
		},
		{
			name: "ecdsa-rdfc-2019_P-384",
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				privKey, _, pubJWK := generateP384TestKeys(t)
				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityP384(t, doc, privKey, "did:web:example.com#key-1")
				return docJSON, proof, pubJWK
			},
		},
		{
			name: "eddsa-rdfc-2022_Ed25519",
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				privKey, _, pubJWK := generateEd25519TestKeys(t)
				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityEd25519(t, doc, privKey, "did:web:example.com#key-1")
				return docJSON, proof, pubJWK
			},
		},
	}

	loader := newTestDocumentLoader()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docJSON, proof, pubKey := tc.setupFunc(t)
			err := VerifyDataIntegrityProof(docJSON, proof, pubKey, loader)
			assert.NoError(t, err)
		})
	}
}

// TestVerifyDataIntegrityProof_TamperedDocument verifies that modifying the
// document after signing causes verification to fail.
func TestVerifyDataIntegrityProof_TamperedDocument(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(t *testing.T) (docJSON []byte, proof *LDProof, pubKey jwk.Key)
	}{
		{
			name: "ecdsa-rdfc-2019_P-256_tampered",
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				privKey, _, pubJWK := generateECTestKeys(t)
				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityP256(t, doc, privKey, "did:web:example.com#key-1")

				// Tamper with a field defined in the VC context so it
				// survives JSON-LD expansion and changes the canonical form.
				var docMap map[string]interface{}
				require.NoError(t, json.Unmarshal(docJSON, &docMap))
				subject := docMap["credentialSubject"].(map[string]interface{})
				subject["id"] = "did:web:attacker.example.com"
				tampered, err := json.Marshal(docMap)
				require.NoError(t, err)

				return tampered, proof, pubJWK
			},
		},
		{
			name: "ecdsa-rdfc-2019_P-384_tampered",
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				privKey, _, pubJWK := generateP384TestKeys(t)
				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityP384(t, doc, privKey, "did:web:example.com#key-1")

				// Tamper with a field defined in the VC context so it
				// survives JSON-LD expansion and changes the canonical form.
				var docMap map[string]interface{}
				require.NoError(t, json.Unmarshal(docJSON, &docMap))
				subject := docMap["credentialSubject"].(map[string]interface{})
				subject["id"] = "did:web:attacker.example.com"
				tampered, err := json.Marshal(docMap)
				require.NoError(t, err)

				return tampered, proof, pubJWK
			},
		},
		{
			name: "eddsa-rdfc-2022_Ed25519_tampered",
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				privKey, _, pubJWK := generateEd25519TestKeys(t)
				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityEd25519(t, doc, privKey, "did:web:example.com#key-1")

				// Tamper with a field defined in the VC context.
				var docMap map[string]interface{}
				require.NoError(t, json.Unmarshal(docJSON, &docMap))
				subject := docMap["credentialSubject"].(map[string]interface{})
				subject["id"] = "did:web:attacker.example.com"
				tampered, err := json.Marshal(docMap)
				require.NoError(t, err)

				return tampered, proof, pubJWK
			},
		},
	}

	loader := newTestDocumentLoader()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docJSON, proof, pubKey := tc.setupFunc(t)
			err := VerifyDataIntegrityProof(docJSON, proof, pubKey, loader)
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrorLDProofVerifyDataIntegrity),
				"expected ErrorLDProofVerifyDataIntegrity, got: %v", err)
		})
	}
}

// TestVerifyDataIntegrityProof_TamperedProofValue verifies that a modified
// proofValue causes verification to fail.
func TestVerifyDataIntegrityProof_TamperedProofValue(t *testing.T) {
	privKey, _, pubJWK := generateECTestKeys(t) // P-256
	doc := dataIntegrityTestDocument()
	docJSON, proof := signDataIntegrityP256(t, doc, privKey, "did:web:example.com#key-1")

	// Decode the proof value, flip a byte, re-encode.
	_, sigBytes, err := multibase.Decode(proof.ProofValue)
	require.NoError(t, err)
	sigBytes[0] ^= 0xFF
	proof.ProofValue, err = multibase.Encode(multibase.Base58BTC, sigBytes)
	require.NoError(t, err)

	loader := newTestDocumentLoader()
	err = VerifyDataIntegrityProof(docJSON, proof, pubJWK, loader)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofVerifyDataIntegrity),
		"expected ErrorLDProofVerifyDataIntegrity, got: %v", err)
}

// TestVerifyDataIntegrityProof_WrongKeyType tests that using a key of the
// wrong type for the declared cryptosuite is rejected.
func TestVerifyDataIntegrityProof_WrongKeyType(t *testing.T) {
	tests := []struct {
		name        string
		cryptosuite string
		setupFunc   func(t *testing.T) (docJSON []byte, proof *LDProof, wrongKey jwk.Key)
	}{
		{
			name:        "ecdsa-rdfc-2019_with_Ed25519_key",
			cryptosuite: CryptosuiteEcdsaRdfc2019,
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				privKey, _, _ := generateECTestKeys(t)
				_, _, wrongPubJWK := generateEd25519TestKeys(t) // wrong key type

				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityP256(t, doc, privKey, "did:web:example.com#key-1")
				return docJSON, proof, wrongPubJWK
			},
		},
		{
			name:        "eddsa-rdfc-2022_with_EC_key",
			cryptosuite: CryptosuiteEddsaRdfc2022,
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				privKey, _, _ := generateEd25519TestKeys(t)
				_, _, wrongPubJWK := generateECTestKeys(t) // wrong key type

				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityEd25519(t, doc, privKey, "did:web:example.com#key-1")
				return docJSON, proof, wrongPubJWK
			},
		},
		{
			name:        "ecdsa-rdfc-2019_with_RSA_key",
			cryptosuite: CryptosuiteEcdsaRdfc2019,
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				privKey, _, _ := generateECTestKeys(t)
				_, _, wrongPubJWK := generateRSATestKeys(t) // wrong key type

				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityP256(t, doc, privKey, "did:web:example.com#key-1")
				return docJSON, proof, wrongPubJWK
			},
		},
	}

	loader := newTestDocumentLoader()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docJSON, proof, wrongKey := tc.setupFunc(t)
			err := VerifyDataIntegrityProof(docJSON, proof, wrongKey, loader)
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrorLDProofCryptosuiteKeyMismatch),
				"expected ErrorLDProofCryptosuiteKeyMismatch, got: %v", err)
		})
	}
}

// TestVerifyDataIntegrityProof_UnsupportedCryptosuite verifies that an
// unrecognized cryptosuite is rejected.
func TestVerifyDataIntegrityProof_UnsupportedCryptosuite(t *testing.T) {
	_, _, pubJWK := generateECTestKeys(t)
	loader := newTestDocumentLoader()

	proof := &LDProof{
		Type:               ProofTypeDataIntegrityProof,
		Cryptosuite:        "unknown-suite-2099",
		Created:            "2024-01-01T00:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		ProofPurpose:       ProofPurposeAssertionMethod,
		ProofValue:         "z3FXQ",
	}

	docJSON, err := json.Marshal(dataIntegrityTestDocument())
	require.NoError(t, err)

	err = VerifyDataIntegrityProof(docJSON, proof, pubJWK, loader)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofUnsupportedCryptosuite),
		"expected ErrorLDProofUnsupportedCryptosuite, got: %v", err)
}

// TestVerifyDataIntegrityProof_MissingProofValue verifies that a proof
// without proofValue is rejected.
func TestVerifyDataIntegrityProof_MissingProofValue(t *testing.T) {
	_, _, pubJWK := generateECTestKeys(t)
	loader := newTestDocumentLoader()

	proof := &LDProof{
		Type:               ProofTypeDataIntegrityProof,
		Cryptosuite:        CryptosuiteEcdsaRdfc2019,
		Created:            "2024-01-01T00:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		ProofPurpose:       ProofPurposeAssertionMethod,
		ProofValue:         "", // missing
	}

	docJSON, err := json.Marshal(dataIntegrityTestDocument())
	require.NoError(t, err)

	err = VerifyDataIntegrityProof(docJSON, proof, pubJWK, loader)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofMissingProofValue),
		"expected ErrorLDProofMissingProofValue, got: %v", err)
}

// TestVerifyDataIntegrityProof_MissingCreated verifies that a proof without
// a created timestamp is rejected.
func TestVerifyDataIntegrityProof_MissingCreated(t *testing.T) {
	_, _, pubJWK := generateECTestKeys(t)
	loader := newTestDocumentLoader()

	proof := &LDProof{
		Type:               ProofTypeDataIntegrityProof,
		Cryptosuite:        CryptosuiteEcdsaRdfc2019,
		Created:            "", // missing
		VerificationMethod: "did:web:example.com#key-1",
		ProofPurpose:       ProofPurposeAssertionMethod,
		ProofValue:         "z3FXQ",
	}

	docJSON, err := json.Marshal(dataIntegrityTestDocument())
	require.NoError(t, err)

	err = VerifyDataIntegrityProof(docJSON, proof, pubJWK, loader)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofMissingCreated),
		"expected ErrorLDProofMissingCreated, got: %v", err)
}

// TestVerifyDataIntegrityProof_InvalidMultibase verifies that an invalid
// multibase-encoded proofValue is rejected.
func TestVerifyDataIntegrityProof_InvalidMultibase(t *testing.T) {
	_, _, pubJWK := generateECTestKeys(t)
	loader := newTestDocumentLoader()

	proof := &LDProof{
		Type:               ProofTypeDataIntegrityProof,
		Cryptosuite:        CryptosuiteEcdsaRdfc2019,
		Created:            "2024-01-01T00:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		ProofPurpose:       ProofPurposeAssertionMethod,
		ProofValue:         "not-valid-multibase", // invalid
	}

	docJSON, err := json.Marshal(dataIntegrityTestDocument())
	require.NoError(t, err)

	err = VerifyDataIntegrityProof(docJSON, proof, pubJWK, loader)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofMalformedProofValue),
		"expected ErrorLDProofMalformedProofValue, got: %v", err)
}

// TestVerifyDataIntegrityProof_WrongProofType verifies that a proof with a
// non-DataIntegrityProof type is rejected.
func TestVerifyDataIntegrityProof_WrongProofType(t *testing.T) {
	_, _, pubJWK := generateECTestKeys(t)
	loader := newTestDocumentLoader()

	proof := &LDProof{
		Type:               "JsonWebSignature2020", // wrong type for DI verification
		Cryptosuite:        CryptosuiteEcdsaRdfc2019,
		Created:            "2024-01-01T00:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		ProofPurpose:       ProofPurposeAssertionMethod,
		ProofValue:         "z3FXQ",
	}

	docJSON, err := json.Marshal(dataIntegrityTestDocument())
	require.NoError(t, err)

	err = VerifyDataIntegrityProof(docJSON, proof, pubJWK, loader)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofUnsupportedType),
		"expected ErrorLDProofUnsupportedType, got: %v", err)
}

// TestVerifyDataIntegrityProof_WrongSigningKey verifies that a proof signed
// with one key cannot be verified with a different key.
func TestVerifyDataIntegrityProof_WrongSigningKey(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(t *testing.T) (docJSON []byte, proof *LDProof, wrongPubKey jwk.Key)
	}{
		{
			name: "ecdsa-rdfc-2019_P-256_wrong_key",
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				signerKey, _, _ := generateECTestKeys(t)
				_, _, otherPubJWK := generateECTestKeys(t)

				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityP256(t, doc, signerKey, "did:web:example.com#key-1")
				return docJSON, proof, otherPubJWK
			},
		},
		{
			name: "eddsa-rdfc-2022_wrong_key",
			setupFunc: func(t *testing.T) ([]byte, *LDProof, jwk.Key) {
				signerKey, _, _ := generateEd25519TestKeys(t)
				_, _, otherPubJWK := generateEd25519TestKeys(t)

				doc := dataIntegrityTestDocument()
				docJSON, proof := signDataIntegrityEd25519(t, doc, signerKey, "did:web:example.com#key-1")
				return docJSON, proof, otherPubJWK
			},
		},
	}

	loader := newTestDocumentLoader()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docJSON, proof, wrongKey := tc.setupFunc(t)
			err := VerifyDataIntegrityProof(docJSON, proof, wrongKey, loader)
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrorLDProofVerifyDataIntegrity),
				"expected ErrorLDProofVerifyDataIntegrity, got: %v", err)
		})
	}
}

// TestVerifyDataIntegrityProof_P256SignatureLengthMismatch verifies that a
// proofValue with incorrect length for the curve is rejected.
func TestVerifyDataIntegrityProof_SignatureLengthMismatch(t *testing.T) {
	privKey, _, pubJWK := generateECTestKeys(t) // P-256
	doc := dataIntegrityTestDocument()
	docJSON, proof := signDataIntegrityP256(t, doc, privKey, "did:web:example.com#key-1")

	// Replace the proofValue with a multibase-encoded value of the wrong length.
	wrongLenSig := make([]byte, 10) // too short for P-256 (expects 64)
	var err error
	proof.ProofValue, err = multibase.Encode(multibase.Base58BTC, wrongLenSig)
	require.NoError(t, err)

	loader := newTestDocumentLoader()
	err = VerifyDataIntegrityProof(docJSON, proof, pubJWK, loader)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofMalformedProofValue),
		"expected ErrorLDProofMalformedProofValue, got: %v", err)
}

// TestVerifyDataIntegrityProof_Ed25519SignatureLengthMismatch verifies that an
// Ed25519 proofValue with incorrect length is rejected.
func TestVerifyDataIntegrityProof_Ed25519SignatureLengthMismatch(t *testing.T) {
	privKey, _, pubJWK := generateEd25519TestKeys(t)
	doc := dataIntegrityTestDocument()
	docJSON, proof := signDataIntegrityEd25519(t, doc, privKey, "did:web:example.com#key-1")

	// Replace the proofValue with a multibase-encoded value of the wrong length.
	wrongLenSig := make([]byte, 32) // too short for Ed25519 (expects 64)
	var err error
	proof.ProofValue, err = multibase.Encode(multibase.Base58BTC, wrongLenSig)
	require.NoError(t, err)

	loader := newTestDocumentLoader()
	err = VerifyDataIntegrityProof(docJSON, proof, pubJWK, loader)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofMalformedProofValue),
		"expected ErrorLDProofMalformedProofValue, got: %v", err)
}

// TestVerifyDataIntegrityProof_ECDSAUnsupportedCurve verifies that an EC key
// on an unsupported curve (P-521) is rejected.
func TestVerifyDataIntegrityProof_ECDSAUnsupportedCurve(t *testing.T) {
	// Generate a P-521 key, which is not supported by ecdsa-rdfc-2019.
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	pubJWK, err := jwk.Import(&p521Key.PublicKey)
	require.NoError(t, err)

	// Sign with P-256 (which works) but try to verify with P-521 key.
	signerKey, _, _ := generateECTestKeys(t) // P-256
	doc := dataIntegrityTestDocument()
	docJSON, proof := signDataIntegrityP256(t, doc, signerKey, "did:web:example.com#key-1")

	loader := newTestDocumentLoader()
	err = VerifyDataIntegrityProof(docJSON, proof, pubJWK, loader)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofCryptosuiteKeyMismatch),
		"expected ErrorLDProofCryptosuiteKeyMismatch, got: %v", err)
}

// --- Tests for proofOptionsContext ---

// TestProofOptionsContext verifies that the proof options are canonicalized
// under the context each suite requires: the document's own context verbatim
// for DataIntegrityProof, the document's context plus the suite context for
// JsonWebSignature2020.
func TestProofOptionsContext(t *testing.T) {
	tests := []struct {
		name            string
		documentContext interface{}
		proofType       string
		want            interface{}
	}{
		{
			name:            "data_integrity_keeps_v2_context_verbatim",
			documentContext: []interface{}{ContextCredentialsV2},
			proofType:       ProofTypeDataIntegrityProof,
			want:            []interface{}{ContextCredentialsV2},
		},
		{
			name:            "data_integrity_adds_nothing_to_a_foreign_context",
			documentContext: []interface{}{ContextCredentialsV1},
			proofType:       ProofTypeDataIntegrityProof,
			want:            []interface{}{ContextCredentialsV1},
		},
		{
			name:            "data_integrity_passes_a_nil_context_through",
			documentContext: nil,
			proofType:       ProofTypeDataIntegrityProof,
			want:            nil,
		},
		{
			name:            "jws_2020_adds_the_suite_context",
			documentContext: []interface{}{ContextCredentialsV1},
			proofType:       ProofTypeJsonWebSignature2020,
			want:            []interface{}{ContextCredentialsV1, ContextSecuritySuiteJWS2020},
		},
		{
			name:            "jws_2020_keeps_an_existing_suite_context",
			documentContext: []interface{}{ContextCredentialsV1, ContextSecuritySuiteJWS2020},
			proofType:       ProofTypeJsonWebSignature2020,
			want:            []interface{}{ContextCredentialsV1, ContextSecuritySuiteJWS2020},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, proofOptionsContext(tc.documentContext, tc.proofType))
		})
	}
}

// --- Tests for assertProofOptionsCovered with cryptosuite ---

// TestAssertProofOptionsCovered_Cryptosuite verifies that the cryptosuite
// field is required in the canonicalized proof options when it is set.
func TestAssertProofOptionsCovered_Cryptosuite(t *testing.T) {
	loader := newTestDocumentLoader()

	doc := dataIntegrityTestDocument()
	proof := &LDProof{
		Type:               ProofTypeDataIntegrityProof,
		Cryptosuite:        CryptosuiteEcdsaRdfc2019,
		Created:            "2024-01-01T00:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		ProofPurpose:       ProofPurposeAssertionMethod,
	}

	proofOptions := buildProofOptions(doc[JSONLDKeyContext], proof)

	proc := ld.NewJsonLdProcessor()
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Format = LDNormFormatNQuads
	ldOpts.Algorithm = LDNormAlgorithmURDNA
	ldOpts.DocumentLoader = loader

	canonProof, err := proc.Normalize(proofOptions, ldOpts)
	require.NoError(t, err)

	// Should pass since the VCDM 2.0 context defines cryptosuite.
	err = assertProofOptionsCovered(canonProof.(string), proof)
	assert.NoError(t, err, "cryptosuite should be covered by the canonical proof options")
}

// TestAssertProofOptionsCovered_CryptosuiteEmpty verifies that an empty
// cryptosuite is not required in the proof options.
func TestAssertProofOptionsCovered_CryptosuiteEmpty(t *testing.T) {
	loader := newTestDocumentLoader()

	doc := dataIntegrityTestDocument()
	proof := &LDProof{
		Type:               ProofTypeJsonWebSignature2020,
		Created:            "2024-01-01T00:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		ProofPurpose:       ProofPurposeAssertionMethod,
		Cryptosuite:        "", // empty — should not be checked
	}

	proofOptions := buildProofOptions(doc[JSONLDKeyContext], proof)

	proc := ld.NewJsonLdProcessor()
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Format = LDNormFormatNQuads
	ldOpts.Algorithm = LDNormAlgorithmURDNA
	ldOpts.DocumentLoader = loader

	canonProof, err := proc.Normalize(proofOptions, ldOpts)
	require.NoError(t, err)

	// Should pass since empty cryptosuite is skipped.
	err = assertProofOptionsCovered(canonProof.(string), proof)
	assert.NoError(t, err, "empty cryptosuite should not trigger a coverage check")
}
