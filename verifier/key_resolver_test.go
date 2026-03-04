package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/did-go/doc/did"
	diddoc "github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/vdr/api"
	kmsjwk "github.com/trustbloc/kms-go/doc/jose/jwk"

	gojose "github.com/go-jose/go-jose/v3"
)

var _ = logging.Log()

// mockVDR implements api.VDR for testing
type mockVDR struct {
	readFunc func(did string, opts ...api.DIDMethodOption) (*diddoc.DocResolution, error)
}

func (m *mockVDR) Read(did string, opts ...api.DIDMethodOption) (*diddoc.DocResolution, error) {
	return m.readFunc(did, opts...)
}
func (m *mockVDR) Create(did *diddoc.Doc, opts ...api.DIDMethodOption) (*diddoc.DocResolution, error) {
	return nil, nil
}
func (m *mockVDR) Accept(method string, opts ...api.DIDMethodOption) bool { return true }
func (m *mockVDR) Update(did *diddoc.Doc, opts ...api.DIDMethodOption) error {
	return nil
}
func (m *mockVDR) Deactivate(did string, opts ...api.DIDMethodOption) error { return nil }
func (m *mockVDR) Close() error                                             { return nil }

// helper: create a DID document with an EC key verification method
func createTestDocResolution(didID, vmID string) (*diddoc.DocResolution, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwkObj := &kmsjwk.JWK{
		JSONWebKey: gojose.JSONWebKey{
			Key:       &privKey.PublicKey,
			KeyID:     vmID,
			Algorithm: "ES256",
		},
		Kty: "EC",
		Crv: "P-256",
	}

	vm, err := diddoc.NewVerificationMethodFromJWK(vmID, "JsonWebKey2020", didID, jwkObj)
	if err != nil {
		return nil, err
	}

	doc := &diddoc.Doc{
		ID:                 didID,
		VerificationMethod: []did.VerificationMethod{*vm},
	}

	return &diddoc.DocResolution{DIDDocument: doc}, nil
}

func TestResolvePublicKeyFromDID_WithFragment(t *testing.T) {
	docRes, err := createTestDocResolution("did:web:example.com", "did:web:example.com#key-1")
	if err != nil {
		t.Fatalf("Failed to create test doc: %v", err)
	}

	vdr := &mockVDR{
		readFunc: func(d string, opts ...api.DIDMethodOption) (*diddoc.DocResolution, error) {
			if d == "did:web:example.com" {
				return docRes, nil
			}
			return nil, errors.New("not found")
		},
	}

	resolver := &VdrKeyResolver{Vdr: []api.VDR{vdr}}
	key, err := resolver.ResolvePublicKeyFromDID("did:web:example.com#key-1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if key == nil {
		t.Error("Expected a key, got nil")
	}
}

func TestResolvePublicKeyFromDID_WithoutFragment(t *testing.T) {
	// For a DID without fragment, the code builds combinedKeyId = kid + "#" + last part of did
	// VM ID must match either keyID (the full DID) or combinedKeyId
	docRes, err := createTestDocResolution("did:web:example.com", "did:web:example.com")
	if err != nil {
		t.Fatalf("Failed to create test doc: %v", err)
	}

	vdr := &mockVDR{
		readFunc: func(d string, opts ...api.DIDMethodOption) (*diddoc.DocResolution, error) {
			return docRes, nil
		},
	}

	resolver := &VdrKeyResolver{Vdr: []api.VDR{vdr}}
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
		readFunc: func(d string, opts ...api.DIDMethodOption) (*diddoc.DocResolution, error) {
			return nil, errors.New("resolution failed")
		},
	}

	resolver := &VdrKeyResolver{Vdr: []api.VDR{failVdr}}
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
		readFunc: func(d string, opts ...api.DIDMethodOption) (*diddoc.DocResolution, error) {
			return docRes, nil
		},
	}

	resolver := &VdrKeyResolver{Vdr: []api.VDR{vdr}}
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
	vm := diddoc.NewVerificationMethodFromBytes("did:web:example.com#key-1", "Ed25519VerificationKey2018", "did:web:example.com", []byte("rawbytes"))
	doc := &diddoc.Doc{
		ID:                 "did:web:example.com",
		VerificationMethod: []did.VerificationMethod{*vm},
	}
	docRes := &diddoc.DocResolution{DIDDocument: doc}

	vdr := &mockVDR{
		readFunc: func(d string, opts ...api.DIDMethodOption) (*diddoc.DocResolution, error) {
			return docRes, nil
		},
	}

	resolver := &VdrKeyResolver{Vdr: []api.VDR{vdr}}
	// JSONWebKey() returns nil when created from bytes without JWK, json.Marshal(nil) = "null"
	// jwk.ParseKey("null") will fail
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
		readFunc: func(d string, opts ...api.DIDMethodOption) (*diddoc.DocResolution, error) {
			return nil, errors.New("not supported")
		},
	}
	successVdr := &mockVDR{
		readFunc: func(d string, opts ...api.DIDMethodOption) (*diddoc.DocResolution, error) {
			return docRes, nil
		},
	}

	resolver := &VdrKeyResolver{Vdr: []api.VDR{failVdr, successVdr}}
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
