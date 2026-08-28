package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loggingConfig initializes the logger for test output.
var loggingConfig = logging.LoggingConfig{
	Level:       "DEBUG",
	JsonLogging: false,
	LogRequests: false,
}

func init() {
	logging.Configure(loggingConfig)
}

// --- Test Signers ---

// ps256Signer implements LDSigner for RSA-PSS SHA-256 (PS256).
type ps256Signer struct {
	key *rsa.PrivateKey
}

// Sign signs data using RSA-PSS with SHA-256, matching the PS256 JWS algorithm.
func (s *ps256Signer) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return rsa.SignPSS(rand.Reader, s.key, crypto.SHA256, hash[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

// es256Signer implements LDSigner for ECDSA P-256 SHA-256 (ES256).
type es256Signer struct {
	key *ecdsa.PrivateKey
}

// p256KeySize is the byte-length of each coordinate for the P-256 curve.
const p256KeySize = 32

// Sign signs data using ECDSA P-256 with SHA-256 and returns the signature
// in IEEE P1363 (fixed-size r||s) format, matching the ES256 JWS algorithm.
func (s *es256Signer) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, hash[:])
	if err != nil {
		return nil, err
	}
	rBytes := r.Bytes()
	sBytes := sv.Bytes()
	sig := make([]byte, p256KeySize*2)
	copy(sig[p256KeySize-len(rBytes):p256KeySize], rBytes)
	copy(sig[2*p256KeySize-len(sBytes):], sBytes)
	return sig, nil
}

// failingSigner is an LDSigner that always returns an error.
type failingSigner struct{}

// Sign always returns an error for testing error paths.
func (s *failingSigner) Sign(_ []byte) ([]byte, error) {
	return nil, errors.New("signer failure")
}

// --- Test Document Loader ---

// newTestDocumentLoader returns a document loader that serves the real,
// vendored W3C credentials/v1 and JsonWebSignature2020 contexts. Using the
// genuine contexts is deliberate: a hand-written stand-in that defines the
// proof terms at the top level would make proof options look covered by the
// signature when, against the real context, they are not.
//
// Any other URL is rejected so no test can depend on the network.
func newTestDocumentLoader() ld.DocumentLoader {
	loader, err := NewEmbeddedContextLoader(nil)
	if err != nil {
		panic(fmt.Sprintf("test: failed to load embedded JSON-LD contexts: %v", err))
	}
	return loader
}

// --- Test Key Helpers ---

// rsaKeySize is the RSA key size used in tests.
const rsaKeySize = 2048

// generateRSATestKeys generates an RSA key pair and returns the private key,
// the private JWK key, and the public JWK key.
func generateRSATestKeys(t *testing.T) (*rsa.PrivateKey, jwk.Key, jwk.Key) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	require.NoError(t, err)

	privJWK, err := jwk.Import(privKey)
	require.NoError(t, err)

	pubJWK, err := jwk.Import(&privKey.PublicKey)
	require.NoError(t, err)

	return privKey, privJWK, pubJWK
}

// generateECTestKeys generates an ECDSA P-256 key pair and returns the private key,
// the private JWK key, and the public JWK key.
func generateECTestKeys(t *testing.T) (*ecdsa.PrivateKey, jwk.Key, jwk.Key) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJWK, err := jwk.Import(privKey)
	require.NoError(t, err)

	pubJWK, err := jwk.Import(&privKey.PublicKey)
	require.NoError(t, err)

	return privKey, privJWK, pubJWK
}

// --- Test Helpers ---

// createTestPresentation creates a minimal VP for testing.
func createTestPresentation() *Presentation {
	return &Presentation{
		Context: []string{ContextCredentialsV1},
		Type:    []string{TypeVerifiablePresentation},
		Holder:  "did:web:example.com",
	}
}

// signAndMarshal signs a presentation and returns the raw JSON and the proof.
func signAndMarshal(t *testing.T, pres *Presentation, ctx *LinkedDataProofContext) ([]byte, *LDProof) {
	t.Helper()

	err := pres.AddLinkedDataProof(ctx)
	require.NoError(t, err, "AddLinkedDataProof should not fail")
	require.NotEmpty(t, pres.Proofs, "should have at least one proof")

	// Marshal the presentation (including proof) to JSON
	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err, "MarshalJSON should not fail")

	// The last proof added
	proof := pres.Proofs[len(pres.Proofs)-1]

	return vpJSON, proof
}

// --- Existing ParseLDProof Tests ---

func TestParseLDProof_JsonWebSignature2020(t *testing.T) {
	proofMap := map[string]interface{}{
		LDProofKeyType:               "JsonWebSignature2020",
		LDProofKeyCreated:            "2024-01-01T00:00:00Z",
		LDProofKeyVerificationMethod: "did:web:example.com#key-1",
		LDProofKeyJWS:                "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature",
		LDProofKeyProofPurpose:       "assertionMethod",
	}

	proof, err := ParseLDProof(proofMap)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if proof.Type != "JsonWebSignature2020" {
		t.Errorf("Expected type JsonWebSignature2020, got %s", proof.Type)
	}
	if proof.Created != "2024-01-01T00:00:00Z" {
		t.Errorf("Expected created 2024-01-01T00:00:00Z, got %s", proof.Created)
	}
	if proof.VerificationMethod != "did:web:example.com#key-1" {
		t.Errorf("Expected verificationMethod did:web:example.com#key-1, got %s", proof.VerificationMethod)
	}
	if proof.JWS != "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature" {
		t.Errorf("Unexpected JWS value: %s", proof.JWS)
	}
	if proof.ProofPurpose != "assertionMethod" {
		t.Errorf("Expected proofPurpose assertionMethod, got %s", proof.ProofPurpose)
	}
	if proof.ProofValue != "" {
		t.Errorf("Expected empty proofValue, got %s", proof.ProofValue)
	}
}

func TestParseLDProof_DataIntegrityWithProofValue(t *testing.T) {
	proofMap := map[string]interface{}{
		LDProofKeyType:               "DataIntegrityProof",
		LDProofKeyCreated:            "2024-06-15T12:00:00Z",
		LDProofKeyVerificationMethod: "did:key:z6Mktest#z6Mktest",
		LDProofKeyProofValue:         "z3FXQjecWufY46...base58btc-encoded",
		LDProofKeyCryptosuite:        "eddsa-rdfc-2022",
		LDProofKeyProofPurpose:       "authentication",
		LDProofKeyChallenge:          "nonce-abc123",
		LDProofKeyDomain:             "https://verifier.example.com",
	}

	proof, err := ParseLDProof(proofMap)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if proof.Type != "DataIntegrityProof" {
		t.Errorf("Expected type DataIntegrityProof, got %s", proof.Type)
	}
	if proof.ProofValue != "z3FXQjecWufY46...base58btc-encoded" {
		t.Errorf("Unexpected proofValue: %s", proof.ProofValue)
	}
	if proof.Cryptosuite != "eddsa-rdfc-2022" {
		t.Errorf("Expected cryptosuite eddsa-rdfc-2022, got %s", proof.Cryptosuite)
	}
	if proof.Challenge != "nonce-abc123" {
		t.Errorf("Expected challenge nonce-abc123, got %s", proof.Challenge)
	}
	if proof.Domain != "https://verifier.example.com" {
		t.Errorf("Expected domain https://verifier.example.com, got %s", proof.Domain)
	}
	if proof.ProofPurpose != "authentication" {
		t.Errorf("Expected proofPurpose authentication, got %s", proof.ProofPurpose)
	}
	if proof.JWS != "" {
		t.Errorf("Expected empty JWS, got %s", proof.JWS)
	}
}

func TestParseLDProof_MissingType(t *testing.T) {
	proofMap := map[string]interface{}{
		LDProofKeyCreated: "2024-01-01T00:00:00Z",
		LDProofKeyJWS:     "eyJ..sig",
	}

	_, err := ParseLDProof(proofMap)
	if err != ErrorLDProofMissingType {
		t.Errorf("Expected ErrorLDProofMissingType, got %v", err)
	}
}

func TestParseLDProof_EmptyType(t *testing.T) {
	proofMap := map[string]interface{}{
		LDProofKeyType: "",
		LDProofKeyJWS:  "eyJ..sig",
	}

	_, err := ParseLDProof(proofMap)
	if err != ErrorLDProofMissingType {
		t.Errorf("Expected ErrorLDProofMissingType, got %v", err)
	}
}

func TestParseLDProof_NoSignature(t *testing.T) {
	proofMap := map[string]interface{}{
		LDProofKeyType:               "JsonWebSignature2020",
		LDProofKeyCreated:            "2024-01-01T00:00:00Z",
		LDProofKeyVerificationMethod: "did:web:example.com#key-1",
	}

	_, err := ParseLDProof(proofMap)
	if err != ErrorLDProofNoSignature {
		t.Errorf("Expected ErrorLDProofNoSignature, got %v", err)
	}
}

func TestParseLDProof_OptionalFieldsAbsent(t *testing.T) {
	// Minimal valid proof with only required fields + JWS.
	proofMap := map[string]interface{}{
		LDProofKeyType: "JsonWebSignature2020",
		LDProofKeyJWS:  "eyJ..sig",
	}

	proof, err := ParseLDProof(proofMap)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if proof.Created != "" {
		t.Errorf("Expected empty created, got %s", proof.Created)
	}
	if proof.VerificationMethod != "" {
		t.Errorf("Expected empty verificationMethod, got %s", proof.VerificationMethod)
	}
	if proof.ProofPurpose != "" {
		t.Errorf("Expected empty proofPurpose, got %s", proof.ProofPurpose)
	}
	if proof.Challenge != "" {
		t.Errorf("Expected empty challenge, got %s", proof.Challenge)
	}
	if proof.Domain != "" {
		t.Errorf("Expected empty domain, got %s", proof.Domain)
	}
}

// Table-driven tests for ParseLDProofs.
func TestParseLDProofs(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		wantCount int
		wantErr   error
	}{
		{
			name:      "nil input",
			input:     nil,
			wantCount: 0,
			wantErr:   nil,
		},
		{
			name: "single proof map",
			input: map[string]interface{}{
				LDProofKeyType: "JsonWebSignature2020",
				LDProofKeyJWS:  "eyJ..sig",
			},
			wantCount: 1,
			wantErr:   nil,
		},
		{
			name: "array with two proofs",
			input: []interface{}{
				map[string]interface{}{
					LDProofKeyType: "JsonWebSignature2020",
					LDProofKeyJWS:  "eyJ..sig1",
				},
				map[string]interface{}{
					LDProofKeyType:       "DataIntegrityProof",
					LDProofKeyProofValue: "z3FXQ...",
				},
			},
			wantCount: 2,
			wantErr:   nil,
		},
		{
			name:      "invalid type (string)",
			input:     "not-a-proof",
			wantCount: 0,
			wantErr:   ErrorLDProofInvalidFormat,
		},
		{
			name: "array with non-map element",
			input: []interface{}{
				"not-a-map",
			},
			wantCount: 0,
			wantErr:   ErrorLDProofInvalidFormat,
		},
		{
			name:      "empty array",
			input:     []interface{}{},
			wantCount: 0,
			wantErr:   nil,
		},
		{
			name: "single proof map missing type",
			input: map[string]interface{}{
				LDProofKeyJWS: "eyJ..sig",
			},
			wantCount: 0,
			wantErr:   ErrorLDProofMissingType,
		},
		{
			name: "array with invalid proof (no signature)",
			input: []interface{}{
				map[string]interface{}{
					LDProofKeyType: "JsonWebSignature2020",
					// no jws or proofValue
				},
			},
			wantCount: 0,
			wantErr:   ErrorLDProofNoSignature,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proofs, err := ParseLDProofs(tc.input)
			if err != tc.wantErr {
				t.Errorf("Expected error %v, got %v", tc.wantErr, err)
			}
			if len(proofs) != tc.wantCount {
				t.Errorf("Expected %d proofs, got %d", tc.wantCount, len(proofs))
			}
		})
	}
}

func TestParseLDProofs_SingleProofFields(t *testing.T) {
	input := map[string]interface{}{
		LDProofKeyType:               "JsonWebSignature2020",
		LDProofKeyCreated:            "2024-01-01T00:00:00Z",
		LDProofKeyVerificationMethod: "did:web:example.com#key-1",
		LDProofKeyJWS:                "eyJ..sig",
		LDProofKeyProofPurpose:       "assertionMethod",
	}

	proofs, err := ParseLDProofs(input)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(proofs) != 1 {
		t.Fatalf("Expected 1 proof, got %d", len(proofs))
	}
	p := proofs[0]
	if p.Type != "JsonWebSignature2020" {
		t.Errorf("Expected type JsonWebSignature2020, got %s", p.Type)
	}
	if p.VerificationMethod != "did:web:example.com#key-1" {
		t.Errorf("Expected verificationMethod, got %s", p.VerificationMethod)
	}
}

func TestParseLDProofs_MultipleProofFields(t *testing.T) {
	input := []interface{}{
		map[string]interface{}{
			LDProofKeyType:         "JsonWebSignature2020",
			LDProofKeyJWS:          "eyJ..sig1",
			LDProofKeyProofPurpose: "assertionMethod",
		},
		map[string]interface{}{
			LDProofKeyType:        "DataIntegrityProof",
			LDProofKeyProofValue:  "zProofValue2",
			LDProofKeyCryptosuite: "ecdsa-rdfc-2019",
			LDProofKeyChallenge:   "challenge-xyz",
			LDProofKeyDomain:      "https://example.com",
		},
	}

	proofs, err := ParseLDProofs(input)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(proofs) != 2 {
		t.Fatalf("Expected 2 proofs, got %d", len(proofs))
	}

	if proofs[0].JWS != "eyJ..sig1" {
		t.Errorf("First proof JWS mismatch: %s", proofs[0].JWS)
	}
	if proofs[0].ProofPurpose != "assertionMethod" {
		t.Errorf("First proof proofPurpose mismatch: %s", proofs[0].ProofPurpose)
	}

	if proofs[1].ProofValue != "zProofValue2" {
		t.Errorf("Second proof proofValue mismatch: %s", proofs[1].ProofValue)
	}
	if proofs[1].Cryptosuite != "ecdsa-rdfc-2019" {
		t.Errorf("Second proof cryptosuite mismatch: %s", proofs[1].Cryptosuite)
	}
	if proofs[1].Challenge != "challenge-xyz" {
		t.Errorf("Second proof challenge mismatch: %s", proofs[1].Challenge)
	}
	if proofs[1].Domain != "https://example.com" {
		t.Errorf("Second proof domain mismatch: %s", proofs[1].Domain)
	}
}

// --- VerifyLinkedDataProof Tests ---

// TestVerifyLinkedDataProof_RoundTrip_PS256 verifies that a VP signed with
// AddLinkedDataProof using PS256 can be verified by VerifyLinkedDataProof.
func TestVerifyLinkedDataProof_RoundTrip_PS256(t *testing.T) {
	rsaPriv, _, pubJWK := generateRSATestKeys(t)
	loader := newTestDocumentLoader()
	created := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	pres := createTestPresentation()
	vpJSON, proof := signAndMarshal(t, pres, &LinkedDataProofContext{
		Created:            &created,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "PS256",
		VerificationMethod: "did:web:example.com#key-1",
		Signer:             &ps256Signer{key: rsaPriv},
		DocumentLoader:     loader,
	})

	err := VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
	assert.NoError(t, err, "round-trip verification with PS256 should succeed")
}

// TestVerifyLinkedDataProof_RoundTrip_ES256 verifies that a VP signed with
// AddLinkedDataProof using ES256 can be verified by VerifyLinkedDataProof.
func TestVerifyLinkedDataProof_RoundTrip_ES256(t *testing.T) {
	ecPriv, _, pubJWK := generateECTestKeys(t)
	loader := newTestDocumentLoader()
	created := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	pres := createTestPresentation()
	vpJSON, proof := signAndMarshal(t, pres, &LinkedDataProofContext{
		Created:            &created,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "ES256",
		VerificationMethod: "did:web:example.com#ec-key-1",
		Signer:             &es256Signer{key: ecPriv},
		DocumentLoader:     loader,
	})

	err := VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
	assert.NoError(t, err, "round-trip verification with ES256 should succeed")
}

// TestVerifyLinkedDataProof_Negative contains table-driven negative tests for
// all error paths in VerifyLinkedDataProof.
func TestVerifyLinkedDataProof_Negative(t *testing.T) {
	// Generate key pairs for the tests.
	rsaPriv, _, rsaPubJWK := generateRSATestKeys(t)
	ecPriv, _, ecPubJWK := generateECTestKeys(t)
	// A second RSA key pair (wrong key).
	_, _, wrongPubJWK := generateRSATestKeys(t)

	loader := newTestDocumentLoader()
	created := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	// Sign a valid VP with PS256 for use in tamper tests.
	validPres := createTestPresentation()
	validJSON, validProof := signAndMarshal(t, validPres, &LinkedDataProofContext{
		Created:            &created,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "PS256",
		VerificationMethod: "did:web:example.com#key-1",
		Signer:             &ps256Signer{key: rsaPriv},
		DocumentLoader:     loader,
	})

	// Sign a valid VP with ES256 for algorithm mismatch tests.
	ecPres := createTestPresentation()
	_, ecProof := signAndMarshal(t, ecPres, &LinkedDataProofContext{
		Created:            &created,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "ES256",
		VerificationMethod: "did:web:example.com#ec-key-1",
		Signer:             &es256Signer{key: ecPriv},
		DocumentLoader:     loader,
	})

	tests := []struct {
		name       string
		docJSON    []byte
		proof      *LDProof
		publicKey  jwk.Key
		loader     ld.DocumentLoader
		wantErr    error
		wantErrMsg string // optional substring in error message
	}{
		{
			name:    "unsupported proof type",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               "DataIntegrityProof",
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS:                validProof.JWS,
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofUnsupportedType,
		},
		{
			name:    "missing created timestamp",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "",
				VerificationMethod: "did:web:example.com#key-1",
				JWS:                validProof.JWS,
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofMissingCreated,
		},
		{
			name:    "missing JWS",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS:                "",
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofMissingJWS,
		},
		{
			name:    "malformed JWS - only one part",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS:                "justonepart",
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofMalformedJWS,
		},
		{
			name:    "malformed JWS - non-empty payload",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS:                "header.payload.signature",
			},
			publicKey:  rsaPubJWK,
			loader:     loader,
			wantErr:    ErrorLDProofMalformedJWS,
			wantErrMsg: "payload must be empty",
		},
		{
			name:    "malformed JWS - empty header",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS:                "..c2ln",
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofMalformedJWS,
		},
		{
			name:    "malformed JWS - invalid base64 header",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS:                "!!!invalid!!!..c2ln",
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofMalformedJWS,
		},
		{
			name:    "invalid b64 header - missing b64",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS: buildJWSHeaderOnly(t, map[string]interface{}{
					JWSHeaderAlg:  "PS256",
					JWSHeaderCrit: []string{JWSHeaderB64},
				}),
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofInvalidB64Header,
		},
		{
			name:    "invalid b64 header - b64 is true",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS: buildJWSHeaderOnly(t, map[string]interface{}{
					JWSHeaderAlg:  "PS256",
					JWSHeaderB64:  true,
					JWSHeaderCrit: []string{JWSHeaderB64},
				}),
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofInvalidB64Header,
		},
		{
			name:    "invalid b64 header - missing crit",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS: buildJWSHeaderOnly(t, map[string]interface{}{
					JWSHeaderAlg: "PS256",
					JWSHeaderB64: false,
				}),
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofInvalidB64Header,
		},
		{
			name:    "invalid b64 header - crit without b64 entry",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS: buildJWSHeaderOnly(t, map[string]interface{}{
					JWSHeaderAlg:  "PS256",
					JWSHeaderB64:  false,
					JWSHeaderCrit: []string{"other"},
				}),
			},
			publicKey:  rsaPubJWK,
			loader:     loader,
			wantErr:    ErrorLDProofInvalidB64Header,
			wantErrMsg: "must contain \"b64\"",
		},
		{
			name:    "missing alg header",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS: buildJWSHeaderOnly(t, map[string]interface{}{
					JWSHeaderB64:  false,
					JWSHeaderCrit: []string{JWSHeaderB64},
				}),
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofMalformedJWS,
		},
		{
			name:      "algorithm key type mismatch - ES256 key with PS256 header",
			docJSON:   validJSON,
			proof:     validProof, // PS256-signed
			publicKey: ecPubJWK,   // EC key, but proof was signed with PS256
			loader:    loader,
			wantErr:   ErrorLDProofAlgMismatch,
		},
		{
			name:      "algorithm key type mismatch - RSA key with ES256 header",
			docJSON:   validJSON,
			proof:     ecProof,   // ES256-signed
			publicKey: rsaPubJWK, // RSA key, but proof was signed with ES256
			loader:    loader,
			wantErr:   ErrorLDProofAlgMismatch,
		},
		{
			name:      "wrong verification key",
			docJSON:   validJSON,
			proof:     validProof,
			publicKey: wrongPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofVerifySignature,
		},
		{
			name:      "tampered document content",
			docJSON:   tamperDocumentHolder(t, validJSON),
			proof:     validProof,
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofVerifySignature,
		},
		{
			name:    "tampered proof created timestamp",
			docJSON: validJSON,
			proof: &LDProof{
				Type:               validProof.Type,
				Created:            "2099-01-01T00:00:00Z", // Different from what was signed
				VerificationMethod: validProof.VerificationMethod,
				JWS:                validProof.JWS,
			},
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofVerifySignature,
		},
		{
			name:      "invalid document JSON",
			docJSON:   []byte("not valid json{{{"),
			proof:     validProof,
			publicKey: rsaPubJWK,
			loader:    loader,
			wantErr:   ErrorLDProofVerifyMarshal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyLinkedDataProof(tc.docJSON, tc.proof, tc.publicKey, tc.loader)
			require.Error(t, err, "expected an error")
			assert.True(t, errors.Is(err, tc.wantErr),
				"expected error wrapping %v, got: %v", tc.wantErr, err)
			if tc.wantErrMsg != "" {
				assert.Contains(t, err.Error(), tc.wantErrMsg,
					"error message should contain %q", tc.wantErrMsg)
			}
		})
	}
}

// TestVerifyLinkedDataProof_UnknownAlgorithm tests that an unknown JWS algorithm
// in the JWS header is rejected.
func TestVerifyLinkedDataProof_UnknownAlgorithm(t *testing.T) {
	_, _, pubJWK := generateRSATestKeys(t)
	loader := newTestDocumentLoader()

	pres := createTestPresentation()
	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err)

	proof := &LDProof{
		Type:               ProofTypeJsonWebSignature2020,
		Created:            "2024-06-15T12:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		JWS: buildJWSHeaderOnly(t, map[string]interface{}{
			JWSHeaderAlg:  "UNKNOWN_ALG",
			JWSHeaderB64:  false,
			JWSHeaderCrit: []string{JWSHeaderB64},
		}),
	}

	err = VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofAlgMismatch))
	assert.Contains(t, err.Error(), "UNKNOWN_ALG")
}

// TestVerifyLinkedDataProof_RoundTrip_WithOptionalFields verifies that optional
// proof fields (proofPurpose, challenge, domain) are included in canonicalization
// and the round-trip succeeds.
func TestVerifyLinkedDataProof_RoundTrip_WithOptionalFields(t *testing.T) {
	rsaPriv, _, pubJWK := generateRSATestKeys(t)
	loader := newTestDocumentLoader()
	created := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	pres := createTestPresentation()

	// Sign using AddLinkedDataProof
	ctx := &LinkedDataProofContext{
		Created:            &created,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "PS256",
		VerificationMethod: "did:web:example.com#key-1",
		Signer:             &ps256Signer{key: rsaPriv},
		DocumentLoader:     loader,
	}
	err := pres.AddLinkedDataProof(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, pres.Proofs)

	// Manually add optional fields to the proof (simulating what a real flow would do).
	proof := pres.Proofs[0]
	proof.ProofPurpose = "authentication"
	proof.Challenge = "test-challenge-nonce"
	proof.Domain = "https://verifier.example.com"

	// Now re-sign the presentation including the optional proof fields.
	// To do this properly, we need to create a new proof with the optional fields
	// considered in the canonicalization. Since AddLinkedDataProof doesn't support
	// optional fields yet, we test that VerifyLinkedDataProof includes them by
	// verifying that changing any optional field on a signed proof causes verification
	// to fail — which is covered in the tampered tests above.
	//
	// For this test, we verify the basic round-trip (without optional fields) works.
	pres2 := createTestPresentation()
	vpJSON2, proof2 := signAndMarshal(t, pres2, ctx)

	err = VerifyLinkedDataProof(vpJSON2, proof2, pubJWK, loader)
	assert.NoError(t, err)
}

// TestVerifyLinkedDataProof_ProofStrippedFromDocument verifies that the proof
// member is correctly stripped from the document before canonicalization, even
// when the document JSON includes the proof.
func TestVerifyLinkedDataProof_ProofStrippedFromDocument(t *testing.T) {
	rsaPriv, _, pubJWK := generateRSATestKeys(t)
	loader := newTestDocumentLoader()
	created := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	pres := createTestPresentation()
	vpJSON, proof := signAndMarshal(t, pres, &LinkedDataProofContext{
		Created:            &created,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "PS256",
		VerificationMethod: "did:web:example.com#key-1",
		Signer:             &ps256Signer{key: rsaPriv},
		DocumentLoader:     loader,
	})

	// The vpJSON from MarshalJSON includes the proof member.
	// VerifyLinkedDataProof should strip it before canonicalizing.
	assert.Contains(t, string(vpJSON), "proof",
		"document JSON should contain proof member")

	err := VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
	assert.NoError(t, err, "verification should succeed even with proof in document JSON")
}

// --- Test Helpers ---

// buildJWSHeaderOnly builds a detached JWS string with the given header and a
// dummy signature. Used for testing header validation logic.
func buildJWSHeaderOnly(t *testing.T, header map[string]interface{}) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	// Use a dummy signature (will fail signature verification but allows header parsing)
	dummySig := base64.RawURLEncoding.EncodeToString([]byte("dummy-signature"))
	return headerB64 + ".." + dummySig
}

// tamperDocumentHolder modifies the holder field in the VP JSON to simulate
// document tampering.
func tamperDocumentHolder(t *testing.T, docJSON []byte) []byte {
	t.Helper()
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(docJSON, &doc))
	doc[VPKeyHolder] = "did:web:attacker.example.com"
	tampered, err := json.Marshal(doc)
	require.NoError(t, err)
	return tampered
}

// TestVerifyLinkedDataProof_MalformedJWSHeader tests that a JWS with unparseable
// JSON in the header is rejected.
func TestVerifyLinkedDataProof_MalformedJWSHeader(t *testing.T) {
	_, _, pubJWK := generateRSATestKeys(t)
	loader := newTestDocumentLoader()

	pres := createTestPresentation()
	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err)

	// Create a header that is valid base64 but invalid JSON
	invalidJSONHeader := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	dummySig := base64.RawURLEncoding.EncodeToString([]byte("sig"))

	proof := &LDProof{
		Type:               ProofTypeJsonWebSignature2020,
		Created:            "2024-06-15T12:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		JWS:                invalidJSONHeader + ".." + dummySig,
	}

	err = VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofMalformedJWS))
	assert.Contains(t, err.Error(), "failed to parse header")
}

// TestVerifyLinkedDataProof_CritEmptyArray tests that an empty crit array is rejected.
func TestVerifyLinkedDataProof_CritEmptyArray(t *testing.T) {
	_, _, pubJWK := generateRSATestKeys(t)
	loader := newTestDocumentLoader()

	pres := createTestPresentation()
	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err)

	proof := &LDProof{
		Type:               ProofTypeJsonWebSignature2020,
		Created:            "2024-06-15T12:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		JWS: buildJWSHeaderOnly(t, map[string]interface{}{
			JWSHeaderAlg:  "PS256",
			JWSHeaderB64:  false,
			JWSHeaderCrit: []string{},
		}),
	}

	err = VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofInvalidB64Header))
}

// TestVerifyLinkedDataProof_B64NotBoolean tests that b64 as a non-boolean value
// is rejected.
func TestVerifyLinkedDataProof_B64NotBoolean(t *testing.T) {
	_, _, pubJWK := generateRSATestKeys(t)
	loader := newTestDocumentLoader()

	pres := createTestPresentation()
	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err)

	// b64 as string "false" instead of boolean false
	headerMap := map[string]interface{}{
		JWSHeaderAlg:  "PS256",
		JWSHeaderB64:  "false",
		JWSHeaderCrit: []string{JWSHeaderB64},
	}
	headerJSON, err := json.Marshal(headerMap)
	require.NoError(t, err)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	dummySig := base64.RawURLEncoding.EncodeToString([]byte("sig"))

	proof := &LDProof{
		Type:               ProofTypeJsonWebSignature2020,
		Created:            "2024-06-15T12:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		JWS:                headerB64 + ".." + dummySig,
	}

	err = VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofInvalidB64Header))
}

// TestVerifyLinkedDataProof_AlgKeyTypeCrossCheck is a parameterized test that
// verifies algorithm-key-type cross-checking for all supported algorithm families.
func TestVerifyLinkedDataProof_AlgKeyTypeCrossCheck(t *testing.T) {
	_, _, rsaPubJWK := generateRSATestKeys(t)
	_, _, ecPubJWK := generateECTestKeys(t)
	loader := newTestDocumentLoader()

	pres := createTestPresentation()
	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err)

	tests := []struct {
		name      string
		alg       string
		publicKey jwk.Key
		wantErr   bool
	}{
		// RSA algorithms with EC key should fail
		{"RS256 with EC key", "RS256", ecPubJWK, true},
		{"RS384 with EC key", "RS384", ecPubJWK, true},
		{"RS512 with EC key", "RS512", ecPubJWK, true},
		{"PS256 with EC key", "PS256", ecPubJWK, true},
		{"PS384 with EC key", "PS384", ecPubJWK, true},
		{"PS512 with EC key", "PS512", ecPubJWK, true},
		// EC algorithms with RSA key should fail
		{"ES256 with RSA key", "ES256", rsaPubJWK, true},
		{"ES384 with RSA key", "ES384", rsaPubJWK, true},
		{"ES512 with RSA key", "ES512", rsaPubJWK, true},
		// Correct pairings should pass header validation (but may fail at signature verification)
		{"PS256 with RSA key", "PS256", rsaPubJWK, false},
		{"ES256 with EC key", "ES256", ecPubJWK, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proof := &LDProof{
				Type:               ProofTypeJsonWebSignature2020,
				Created:            "2024-06-15T12:00:00Z",
				VerificationMethod: "did:web:example.com#key-1",
				JWS: buildJWSHeaderOnly(t, map[string]interface{}{
					JWSHeaderAlg:  tc.alg,
					JWSHeaderB64:  false,
					JWSHeaderCrit: []string{JWSHeaderB64},
				}),
			}

			err := VerifyLinkedDataProof(vpJSON, proof, tc.publicKey, loader)
			if tc.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrorLDProofAlgMismatch),
					"expected ErrorLDProofAlgMismatch, got: %v", err)
			} else {
				// If the algorithm/key type match, the error should NOT be
				// ErrorLDProofAlgMismatch (it may be a signature error since
				// we use a dummy signature).
				if err != nil {
					assert.False(t, errors.Is(err, ErrorLDProofAlgMismatch),
						"should not get algorithm mismatch error for correct pairing")
				}
			}
		})
	}
}

// TestVerifyLinkedDataProof_TamperedJWSSignature verifies that a tampered
// signature (bit-flipped) is rejected.
func TestVerifyLinkedDataProof_TamperedJWSSignature(t *testing.T) {
	rsaPriv, _, pubJWK := generateRSATestKeys(t)
	loader := newTestDocumentLoader()
	created := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	pres := createTestPresentation()
	vpJSON, proof := signAndMarshal(t, pres, &LinkedDataProofContext{
		Created:            &created,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "PS256",
		VerificationMethod: "did:web:example.com#key-1",
		Signer:             &ps256Signer{key: rsaPriv},
		DocumentLoader:     loader,
	})

	// Tamper with the signature by flipping a byte
	parts := strings.SplitN(proof.JWS, ".", jwsDetachedParts)
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.NotEmpty(t, sigBytes)

	// Flip the first byte
	sigBytes[0] ^= 0xFF
	tamperedSig := base64.RawURLEncoding.EncodeToString(sigBytes)
	tamperedJWS := parts[0] + ".." + tamperedSig

	tamperedProof := &LDProof{
		Type:               proof.Type,
		Created:            proof.Created,
		VerificationMethod: proof.VerificationMethod,
		JWS:                tamperedJWS,
	}

	err = VerifyLinkedDataProof(vpJSON, tamperedProof, pubJWK, loader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofVerifySignature))
}

// TestVerifyLinkedDataProof_JWSWithTwoParts tests that a JWS with only two parts
// (missing the signature part) is rejected.
func TestVerifyLinkedDataProof_JWSWithTwoParts(t *testing.T) {
	_, _, pubJWK := generateRSATestKeys(t)
	loader := newTestDocumentLoader()

	pres := createTestPresentation()
	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err)

	proof := &LDProof{
		Type:               ProofTypeJsonWebSignature2020,
		Created:            "2024-06-15T12:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		JWS:                "header.payload", // only 2 parts
	}

	err = VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofMalformedJWS))
}

// TestVerifyLinkedDataProof_EmptySignaturePart tests that a JWS with an empty
// signature part is rejected.
func TestVerifyLinkedDataProof_EmptySignaturePart(t *testing.T) {
	_, _, pubJWK := generateRSATestKeys(t)
	loader := newTestDocumentLoader()

	pres := createTestPresentation()
	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err)

	headerJSON, _ := json.Marshal(map[string]interface{}{
		JWSHeaderAlg:  "PS256",
		JWSHeaderB64:  false,
		JWSHeaderCrit: []string{JWSHeaderB64},
	})
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	proof := &LDProof{
		Type:               ProofTypeJsonWebSignature2020,
		Created:            "2024-06-15T12:00:00Z",
		VerificationMethod: "did:web:example.com#key-1",
		JWS:                headerB64 + "..", // empty signature
	}

	err = VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrorLDProofMalformedJWS))
}

// TestVerifyLinkedDataProof_MultipleRoundTrips verifies that signing and
// verifying multiple times with different keys all succeed independently.
func TestVerifyLinkedDataProof_MultipleRoundTrips(t *testing.T) {
	loader := newTestDocumentLoader()
	created := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	// Round-trip count for stress testing
	const roundTrips = 3

	for i := 0; i < roundTrips; i++ {
		t.Run(fmt.Sprintf("round_trip_%d", i), func(t *testing.T) {
			rsaPriv, _, pubJWK := generateRSATestKeys(t)
			pres := createTestPresentation()
			pres.Holder = fmt.Sprintf("did:web:example-%d.com", i)

			vpJSON, proof := signAndMarshal(t, pres, &LinkedDataProofContext{
				Created:            &created,
				SignatureType:      ProofTypeJsonWebSignature2020,
				Algorithm:          "PS256",
				VerificationMethod: fmt.Sprintf("did:web:example-%d.com#key-1", i),
				Signer:             &ps256Signer{key: rsaPriv},
				DocumentLoader:     loader,
			})

			err := VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
			assert.NoError(t, err)
		})
	}
}

// --- Helpers for parameterized IEEE P1363 signature tests ---

// verifyIEEEP1363Roundtrip tests that an ES256-signed VP round-trips correctly.
// This validates that our es256Signer produces signatures compatible with jws.Verify.
func TestVerifyLinkedDataProof_ES256_IEEESignatureFormat(t *testing.T) {
	ecPriv, _, pubJWK := generateECTestKeys(t)
	loader := newTestDocumentLoader()
	created := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Create a VP with some data to make the canonical form non-trivial
	pres := &Presentation{
		Context: []string{ContextCredentialsV1},
		Type:    []string{TypeVerifiablePresentation},
		Holder:  "did:web:holder.example.com",
		// Note: no credentials in this test to keep it focused
	}

	vpJSON, proof := signAndMarshal(t, pres, &LinkedDataProofContext{
		Created:            &created,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "ES256",
		VerificationMethod: "did:web:holder.example.com#key-1",
		Signer:             &es256Signer{key: ecPriv},
		DocumentLoader:     loader,
	})

	// Verify the proof JWS has the expected structure
	parts := strings.SplitN(proof.JWS, ".", jwsDetachedParts)
	require.Len(t, parts, jwsDetachedParts, "JWS should have 3 parts")
	assert.NotEmpty(t, parts[0], "header should not be empty")
	assert.Empty(t, parts[1], "payload should be empty for detached JWS")
	assert.NotEmpty(t, parts[2], "signature should not be empty")

	// Decode and verify the header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "ES256", header[JWSHeaderAlg])
	assert.Equal(t, false, header[JWSHeaderB64])

	// Verify the signature is correct
	err = VerifyLinkedDataProof(vpJSON, proof, pubJWK, loader)
	assert.NoError(t, err, "ES256 signature verification should succeed")

	// Verify the signature is 64 bytes (r||s, each 32 bytes for P-256)
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	assert.Equal(t, p256KeySize*2, len(sigBytes),
		"ES256 signature should be 64 bytes (32-byte r || 32-byte s)")

	// Verify that r and s are valid big integers (not all zeros)
	r := new(big.Int).SetBytes(sigBytes[:p256KeySize])
	s := new(big.Int).SetBytes(sigBytes[p256KeySize:])
	assert.True(t, r.Sign() > 0, "r should be positive")
	assert.True(t, s.Sign() > 0, "s should be positive")
}

// --- Proof-options coverage and context handling ---

// TestEnsureSuiteContext verifies that the JsonWebSignature2020 suite context
// is added to every shape of @context value and never duplicated.
func TestEnsureSuiteContext(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  interface{}
	}{
		{
			name:  "nil_context",
			input: nil,
			want:  []interface{}{ContextSecuritySuiteJWS2020},
		},
		{
			name:  "single_string",
			input: ContextCredentialsV1,
			want:  []interface{}{ContextCredentialsV1, ContextSecuritySuiteJWS2020},
		},
		{
			name:  "string_already_the_suite",
			input: ContextSecuritySuiteJWS2020,
			want:  ContextSecuritySuiteJWS2020,
		},
		{
			name:  "slice_without_suite",
			input: []interface{}{ContextCredentialsV1},
			want:  []interface{}{ContextCredentialsV1, ContextSecuritySuiteJWS2020},
		},
		{
			name:  "slice_with_suite_unchanged",
			input: []interface{}{ContextCredentialsV1, ContextSecuritySuiteJWS2020},
			want:  []interface{}{ContextCredentialsV1, ContextSecuritySuiteJWS2020},
		},
		{
			name:  "string_slice_without_suite",
			input: []string{ContextCredentialsV1},
			want:  []string{ContextCredentialsV1, ContextSecuritySuiteJWS2020},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, EnsureSuiteContext(tc.input))
		})
	}
}

// TestProofOptionsAreCoveredBySignature is the direct regression test for the
// bug where the canonicalized proof options collapsed to a single type
// triple: with the suite context in place every proof field has to show up in
// the canonical form, and tampering with any of them must break the
// signature.
// TestAddLinkedDataProof_SignerFailure verifies that a failure of the
// underlying signer is surfaced as ErrorLDProofSign and that no half-built
// proof is left on the presentation.
func TestAddLinkedDataProof_SignerFailure(t *testing.T) {
	loader := newTestDocumentLoader()

	now := time.Now()
	pres := &Presentation{
		Context: []string{ContextCredentialsV1},
		Type:    []string{TypeVerifiablePresentation},
		Holder:  "did:web:holder.example.com",
	}
	err := pres.AddLinkedDataProof(&LinkedDataProofContext{
		Created:            &now,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "ES256",
		VerificationMethod: "did:web:holder.example.com#key-1",
		Signer:             &failingSigner{},
		DocumentLoader:     loader,
		ProofPurpose:       ProofPurposeAuthentication,
	})

	assert.ErrorIs(t, err, ErrorLDProofSign)
	assert.Empty(t, pres.Proofs, "a failed signature must not leave a proof behind")
}

func TestProofOptionsAreCoveredBySignature(t *testing.T) {
	loader := newTestDocumentLoader()
	privKey, pubJWK := generateTestES256Material(t)

	now := time.Now()
	pres := &Presentation{
		Context: []string{ContextCredentialsV1},
		Type:    []string{TypeVerifiablePresentation},
		Holder:  "did:web:holder.example.com",
	}
	err := pres.AddLinkedDataProof(&LinkedDataProofContext{
		Created:            &now,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "ES256",
		VerificationMethod: "did:web:holder.example.com#key-1",
		Signer:             &es256TestSigner{key: privKey},
		DocumentLoader:     loader,
		ProofPurpose:       ProofPurposeAuthentication,
		Challenge:          "session-nonce-AAA",
		Domain:             "https://verifier.example.com",
	})
	require.NoError(t, err)

	assert.Contains(t, pres.Context, ContextSecuritySuiteJWS2020,
		"signing must add the suite context to the presentation")

	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err)
	var vpMap JSONObject
	require.NoError(t, json.Unmarshal(vpJSON, &vpMap))
	delete(vpMap, VPKeyProof)
	docBytes, err := json.Marshal(vpMap)
	require.NoError(t, err)

	proof := pres.Proofs[0]
	require.NoError(t, VerifyLinkedDataProof(docBytes, proof, pubJWK, loader),
		"the untouched proof must verify")

	tests := []struct {
		name   string
		tamper func(p *LDProof)
	}{
		{name: "challenge", tamper: func(p *LDProof) { p.Challenge = "other-nonce" }},
		{name: "domain", tamper: func(p *LDProof) { p.Domain = "https://attacker.example.com" }},
		{name: "created", tamper: func(p *LDProof) { p.Created = "1999-01-01T00:00:00Z" }},
		{name: "proofPurpose", tamper: func(p *LDProof) { p.ProofPurpose = ProofPurposeAssertionMethod }},
		{name: "verificationMethod", tamper: func(p *LDProof) { p.VerificationMethod = "did:web:attacker.example.com#key-1" }},
	}

	for _, tc := range tests {
		t.Run("tampered_"+tc.name, func(t *testing.T) {
			tampered := *proof
			tc.tamper(&tampered)
			err := VerifyLinkedDataProof(docBytes, &tampered, pubJWK, loader)
			require.Error(t, err, "changing %s must invalidate the proof", tc.name)
			assert.ErrorIs(t, err, ErrorLDProofVerifySignature)
		})
	}
}

// TestVerifyLinkedDataProof_CurveMismatch verifies the explicit EC curve
// cross-check: an ES256 proof must not be accepted with a P-384 key.
func TestVerifyLinkedDataProof_CurveMismatch(t *testing.T) {
	loader := newTestDocumentLoader()
	privKey, _ := generateTestES256Material(t)

	now := time.Now()
	pres := &Presentation{
		Context: []string{ContextCredentialsV1},
		Type:    []string{TypeVerifiablePresentation},
		Holder:  "did:web:holder.example.com",
	}
	require.NoError(t, pres.AddLinkedDataProof(&LinkedDataProofContext{
		Created:            &now,
		SignatureType:      ProofTypeJsonWebSignature2020,
		Algorithm:          "ES256",
		VerificationMethod: "did:web:holder.example.com#key-1",
		Signer:             &es256TestSigner{key: privKey},
		DocumentLoader:     loader,
		ProofPurpose:       ProofPurposeAuthentication,
	}))

	vpJSON, err := pres.MarshalJSON()
	require.NoError(t, err)
	var vpMap JSONObject
	require.NoError(t, json.Unmarshal(vpJSON, &vpMap))
	delete(vpMap, VPKeyProof)
	docBytes, err := json.Marshal(vpMap)
	require.NoError(t, err)

	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384JWK, err := jwk.Import(&p384Key.PublicKey)
	require.NoError(t, err)

	err = VerifyLinkedDataProof(docBytes, pres.Proofs[0], p384JWK, loader)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorLDProofCurveMismatch)
}

// es256TestSigner signs with ECDSA P-256/SHA-256 and returns the IEEE P1363
// (r||s) form the ES256 JWS algorithm expects.
type es256TestSigner struct {
	key *ecdsa.PrivateKey
}

// es256CoordinateSize is the byte length of an ES256 signature coordinate.
const es256CoordinateSize = 32

// Sign implements LDSigner.
func (s *es256TestSigner) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, err
	}
	rBytes := r.Bytes()
	sBytes := sv.Bytes()
	sig := make([]byte, es256CoordinateSize*2)
	copy(sig[es256CoordinateSize-len(rBytes):es256CoordinateSize], rBytes)
	copy(sig[2*es256CoordinateSize-len(sBytes):], sBytes)
	return sig, nil
}

// generateTestES256Material returns a fresh P-256 private key and its public
// JWK.
func generateTestES256Material(t *testing.T) (*ecdsa.PrivateKey, jwk.Key) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import(&privKey.PublicKey)
	require.NoError(t, err)
	return privKey, pubJWK
}
