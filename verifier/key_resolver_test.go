package verifier

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ = logging.Log()

// mockVDR implements did.VDR for testing
type mockVDR struct {
	readFunc func(didStr string) (*did.DocResolution, error)
}

func (m *mockVDR) Read(didStr string) (*did.DocResolution, error) {
	return m.readFunc(didStr)
}
func (m *mockVDR) Accept(method string) bool { return true }

// helper: create a DID document with an EC key verification method
func createTestDocResolution(didID, vmID string) (*did.DocResolution, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwkKey, err := jwk.Import(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	vm, err := did.NewVerificationMethodFromJWK(vmID, "JsonWebKey2020", didID, jwkKey)
	if err != nil {
		return nil, err
	}

	doc := &did.Doc{
		ID:                 didID,
		VerificationMethod: []did.VerificationMethod{*vm},
	}

	return &did.DocResolution{DIDDocument: doc}, nil
}

func TestResolvePublicKeyFromDID_WithFragment(t *testing.T) {
	docRes, err := createTestDocResolution("did:web:example.com", "did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("Failed to create test doc: %v", err)
	}

	vdr := &mockVDR{
		readFunc: func(d string) (*did.DocResolution, error) {
			if d == "did:web:example.com" {
				return docRes, nil
			}
			return nil, errors.New("not found")
		},
	}

	resolver := &VdrKeyResolver{Vdr: []did.VDR{vdr}}
	key, err := resolver.ResolvePublicKeyFromDID("did:web:example.com#key-1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if key == nil {
		t.Error("Expected a key, got nil")
	}
}

func TestResolvePublicKeyFromDID_WithoutFragment(t *testing.T) {
	docRes, err := createTestDocResolution("did:web:example.com", "did:web:example.com")
	if err != nil {
		t.Fatalf("Failed to create test doc: %v", err)
	}

	vdr := &mockVDR{
		readFunc: func(d string) (*did.DocResolution, error) {
			return docRes, nil
		},
	}

	resolver := &VdrKeyResolver{Vdr: []did.VDR{vdr}}
	key, err := resolver.ResolvePublicKeyFromDID("did:web:example.com")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if key == nil {
		t.Error("Expected a key, got nil")
	}
}

func TestResolvePublicKeyFromDID_AllVDRsFail(t *testing.T) {
	failVdr := &mockVDR{
		readFunc: func(d string) (*did.DocResolution, error) {
			return nil, errors.New("resolution failed")
		},
	}

	resolver := &VdrKeyResolver{Vdr: []did.VDR{failVdr}}
	key, err := resolver.ResolvePublicKeyFromDID("did:web:example.com#key-1")
	if err == nil {
		t.Error("Expected an error, got nil")
	}
	if key != nil {
		t.Error("Expected nil key on failure")
	}
}

func TestResolvePublicKeyFromDID_KeyIDNotFound(t *testing.T) {
	docRes, err := createTestDocResolution("did:web:example.com", "did:web:example.com#other-key")
	if err != nil {
		t.Fatalf("Failed to create test doc: %v", err)
	}

	vdr := &mockVDR{
		readFunc: func(d string) (*did.DocResolution, error) {
			return docRes, nil
		},
	}

	resolver := &VdrKeyResolver{Vdr: []did.VDR{vdr}}
	key, err := resolver.ResolvePublicKeyFromDID("did:web:example.com#key-1")
	if err != ErrorInvalidJWT {
		t.Errorf("Expected ErrorInvalidJWT, got %v", err)
	}
	if key != nil {
		t.Error("Expected nil key when key ID not found")
	}
}

func TestResolvePublicKeyFromDID_NilJWK(t *testing.T) {
	// Create a verification method with no JWK (Value-only)
	vm := did.NewVerificationMethodFromBytes("did:web:example.com#key-1", "Ed25519VerificationKey2018", "did:web:example.com", []byte("rawbytes"))
	doc := &did.Doc{
		ID:                 "did:web:example.com",
		VerificationMethod: []did.VerificationMethod{*vm},
	}
	docRes := &did.DocResolution{DIDDocument: doc}

	vdr := &mockVDR{
		readFunc: func(d string) (*did.DocResolution, error) {
			return docRes, nil
		},
	}

	resolver := &VdrKeyResolver{Vdr: []did.VDR{vdr}}
	key, err := resolver.ResolvePublicKeyFromDID("did:web:example.com#key-1")
	if err == nil {
		t.Error("Expected error for nil JWK, got nil")
	}
	if key != nil {
		t.Error("Expected nil key for nil JWK")
	}
}

func TestResolvePublicKeyFromDID_FirstVDRFailsSecondSucceeds(t *testing.T) {
	docRes, err := createTestDocResolution("did:web:example.com", "did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("Failed to create test doc: %v", err)
	}

	failVdr := &mockVDR{
		readFunc: func(d string) (*did.DocResolution, error) {
			return nil, errors.New("not supported")
		},
	}
	successVdr := &mockVDR{
		readFunc: func(d string) (*did.DocResolution, error) {
			return docRes, nil
		},
	}

	resolver := &VdrKeyResolver{Vdr: []did.VDR{failVdr, successVdr}}
	key, err := resolver.ResolvePublicKeyFromDID("did:web:example.com#key-1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if key == nil {
		t.Error("Expected a key from second VDR")
	}
}

func TestVdrKeyResolver_ExtractKIDFromJWT(t *testing.T) {
	type test struct {
		testName      string
		tokenString   string
		expectedKid   string
		expectedError error
	}

	headerWithKid, _ := json.Marshal(map[string]interface{}{"kid": "test_kid"})
	headerWithoutKid, _ := json.Marshal(map[string]interface{}{"alg": "ES256"})

	tests := []test{
		{
			testName:      "Valid JWT with kid",
			tokenString:   base64.RawURLEncoding.EncodeToString(headerWithKid) + ".payload.signature",
			expectedKid:   "test_kid",
			expectedError: nil,
		},
		{
			testName:      "JWT with no kid",
			tokenString:   base64.RawURLEncoding.EncodeToString(headerWithoutKid) + ".payload.signature",
			expectedKid:   "",
			expectedError: ErrorInvalidJWT,
		},
		{
			testName:      "Invalid JWT string",
			tokenString:   "invalid_jwt",
			expectedKid:   "",
			expectedError: ErrorInvalidJWT,
		},
		{
			testName:      "Malformed header",
			tokenString:   base64.RawURLEncoding.EncodeToString([]byte("not_json")) + ".payload.signature",
			expectedKid:   "",
			expectedError: ErrorInvalidJWT,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			resolver := &VdrKeyResolver{}
			kid, err := resolver.ExtractKIDFromJWT(tc.tokenString)

			if kid != tc.expectedKid {
				t.Errorf("Expected kid %v, but got %v", tc.expectedKid, kid)
			}

			if err != tc.expectedError {
				t.Errorf("Expected error %v, but got %v", tc.expectedError, err)
			}
		})
	}
}

// TestResolveCandidateKeysFromDID covers the kid-optional resolution the VC-JOSE-COSE
// paths depend on: a token whose issuer is named by the document rather than the
// envelope often carries no kid, and the DID document's keys are then all candidates.
func TestResolveCandidateKeysFromDID(t *testing.T) {
	_, signerDID := generateTestKeyAndDIDJWK(t)
	registry := did.NewRegistry(did.WithVDR(did.NewJWKVDR()))

	tests := []struct {
		name      string
		didStr    string
		kid       string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "kid selects a single verification method",
			didStr:    signerDID,
			kid:       signerDID + "#0",
			wantCount: 1,
		},
		{
			name:      "no kid offers every verification method",
			didStr:    signerDID,
			kid:       "",
			wantCount: 1, // a did:jwk document declares exactly one
		},
		{
			name:    "kid names a method the document does not declare",
			didStr:  signerDID,
			kid:     signerDID + "#does-not-exist",
			wantErr: true,
		},
		{
			name:    "unresolvable DID",
			didStr:  "did:jwk:not-valid-base64url",
			kid:     "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := ResolveCandidateKeysFromDID(registry, tc.didStr, tc.kid)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Len(t, keys, tc.wantCount)
		})
	}
}

// testMultibaseKey encodes a raw public key as a multibase string with the
// given multicodec prefix, using base58btc ('z') encoding.
func testMultibaseKey(codec uint64, rawKey []byte) string {
	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], codec)
	multicodecKey := append(prefix[:n], rawKey...)
	encoded, _ := multibase.Encode(multibase.Base58BTC, multicodecKey)
	return encoded
}

// createMultikeyDocResolution builds a DocResolution containing a single
// Multikey verification method with the given publicKeyMultibase value.
// Optional authentication and assertionMethod string slices add the VM to
// the corresponding verification relationships.
func createMultikeyDocResolution(
	didID, vmID, multibaseKey string,
	authentication, assertionMethod []string,
) *did.DocResolution {
	// DecodeMultibaseKey produces the same JWK that the did:web parser would.
	key, err := did.DecodeMultibaseKey(multibaseKey)
	if err != nil || key == nil {
		// Callers that test invalid input pass a nil-JWK VM.
		vm := did.NewVerificationMethodFromBytes(vmID, did.TypeMultikey, didID, []byte(multibaseKey))
		doc := &did.Doc{
			ID:                 didID,
			VerificationMethod: []did.VerificationMethod{*vm},
			Authentication:     authentication,
			AssertionMethod:    assertionMethod,
		}
		return &did.DocResolution{DIDDocument: doc}
	}

	vm, _ := did.NewVerificationMethodFromJWK(vmID, did.TypeMultikey, didID, key)
	doc := &did.Doc{
		ID:                 didID,
		VerificationMethod: []did.VerificationMethod{*vm},
		Authentication:     authentication,
		AssertionMethod:    assertionMethod,
	}
	return &did.DocResolution{DIDDocument: doc}
}

// TestResolveKeyFromDID_MultikeyVM is the real integration test for Multikey
// verification methods through the actual ResolveKeyFromDID function from
// key_resolver.go. It constructs DID documents with Multikey VMs (decoded
// via did.DecodeMultibaseKey) and resolves keys through a mock VDR, proving
// that the full resolution pipeline works end-to-end.
func TestResolveKeyFromDID_MultikeyVM(t *testing.T) {
	tests := []struct {
		name        string
		description string
		setup       func(t *testing.T) (docRes *did.DocResolution, vmID string, wantKeyType jwa.KeyType, wantCurve jwa.EllipticCurveAlgorithm)
	}{
		{
			name:        "Ed25519 Multikey resolved via ResolveKeyFromDID",
			description: "A Multikey VM with an Ed25519 publicKeyMultibase is resolved to a usable OKP/Ed25519 JWK",
			setup: func(t *testing.T) (*did.DocResolution, string, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				mb := testMultibaseKey(did.MulticodecEd25519Pub, pub)
				docRes := createMultikeyDocResolution(
					"did:web:example.com", "did:web:example.com#key-1", mb, nil, nil,
				)
				return docRes, "did:web:example.com#key-1", jwa.OKP(), jwa.Ed25519()
			},
		},
		{
			name:        "P-256 Multikey resolved via ResolveKeyFromDID",
			description: "A Multikey VM with a P-256 publicKeyMultibase is resolved to a usable EC/P-256 JWK",
			setup: func(t *testing.T) (*did.DocResolution, string, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				compressed := elliptic.MarshalCompressed(elliptic.P256(), privKey.X, privKey.Y)
				mb := testMultibaseKey(did.MulticodecP256Pub, compressed)
				docRes := createMultikeyDocResolution(
					"did:web:example.com", "did:web:example.com#key-2", mb, nil, nil,
				)
				return docRes, "did:web:example.com#key-2", jwa.EC(), jwa.P256()
			},
		},
		{
			name:        "P-384 Multikey resolved via ResolveKeyFromDID",
			description: "A Multikey VM with a P-384 publicKeyMultibase is resolved to a usable EC/P-384 JWK",
			setup: func(t *testing.T) (*did.DocResolution, string, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				compressed := elliptic.MarshalCompressed(elliptic.P384(), privKey.X, privKey.Y)
				mb := testMultibaseKey(did.MulticodecP384Pub, compressed)
				docRes := createMultikeyDocResolution(
					"did:web:example.com", "did:web:example.com#key-3", mb, nil, nil,
				)
				return docRes, "did:web:example.com#key-3", jwa.EC(), jwa.P384()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docRes, vmID, wantKeyType, wantCurve := tc.setup(t)

			registry := did.NewRegistry(did.WithVDR(&mockVDR{
				readFunc: func(_ string) (*did.DocResolution, error) {
					return docRes, nil
				},
			}))

			key, err := ResolveKeyFromDID(registry, "did:web:example.com", vmID)
			require.NoError(t, err)
			require.NotNil(t, key, "ResolveKeyFromDID should return a non-nil key")
			assert.Equal(t, wantKeyType, key.KeyType())

			var crv jwa.EllipticCurveAlgorithm
			if err := key.Get(jwk.ECDSACrvKey, &crv); err != nil {
				err = key.Get(jwk.OKPCrvKey, &crv)
				require.NoError(t, err, "key should have a curve parameter")
			}
			assert.Equal(t, wantCurve, crv)
		})
	}
}

// TestResolveKeyForRelationship_MultikeyVM verifies that the real
// ResolveKeyForRelationship function enforces verification relationships
// correctly for Multikey verification methods.
func TestResolveKeyForRelationship_MultikeyVM(t *testing.T) {
	// Generate a P-256 Multikey VM
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), privKey.X, privKey.Y)
	mb := testMultibaseKey(did.MulticodecP256Pub, compressed)

	const (
		didID = "did:web:example.com"
		vmID  = "did:web:example.com#key-assert"
	)

	tests := []struct {
		name         string
		description  string
		relationship string
		auth         []string
		assertion    []string
		wantErr      error
	}{
		{
			name:         "allowed for assertionMethod",
			description:  "A Multikey VM listed under assertionMethod is accepted when assertionMethod is required",
			relationship: did.RelationshipAssertionMethod,
			assertion:    []string{vmID},
			wantErr:      nil,
		},
		{
			name:         "rejected for authentication when only assertionMethod",
			description:  "A Multikey VM listed only under assertionMethod is rejected when authentication is required",
			relationship: did.RelationshipAuthentication,
			assertion:    []string{vmID},
			wantErr:      ErrorVerificationRelationshipNotAllowed,
		},
		{
			name:         "allowed for authentication",
			description:  "A Multikey VM listed under authentication is accepted when authentication is required",
			relationship: did.RelationshipAuthentication,
			auth:         []string{vmID},
			wantErr:      nil,
		},
		{
			name:         "no relationship enforcement when document declares none",
			description:  "When the document declares no relationships, the key is accepted regardless",
			relationship: did.RelationshipAuthentication,
			wantErr:      nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docRes := createMultikeyDocResolution(didID, vmID, mb, tc.auth, tc.assertion)
			registry := did.NewRegistry(did.WithVDR(&mockVDR{
				readFunc: func(_ string) (*did.DocResolution, error) {
					return docRes, nil
				},
			}))

			key, err := ResolveKeyForRelationship(registry, didID, vmID, tc.relationship)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				require.NotNil(t, key)
				assert.Equal(t, jwa.EC(), key.KeyType())
			}
		})
	}
}
