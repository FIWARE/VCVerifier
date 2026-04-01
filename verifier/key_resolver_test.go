package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
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
