package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fiware/VCVerifier/did"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractDIDFromKid(t *testing.T) {
	tests := []struct {
		kid      string
		expected string
	}{
		{"did:web:example.com#key-1", "did:web:example.com"},
		{"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"},
		{"key-1", ""},
		{"", ""},
	}

	for _, tc := range tests {
		result := extractDIDFromKid(tc.kid)
		assert.Equal(t, tc.expected, result, "kid=%s", tc.kid)
	}
}

// mockHttpsIssuerResolver is a test double for HttpsIssuerResolver that returns
// a preconfigured key or error.
type mockHttpsIssuerResolver struct {
	key       jwk.Key
	keys      []jwk.Key
	err       error
	calledURL string
	calledKid string
}

// ResolveIssuerKeys returns the preconfigured key or error, recording the call arguments.
func (m *mockHttpsIssuerResolver) ResolveIssuerKeys(_ context.Context, issuerURL string, kid string) ([]jwk.Key, error) {
	m.calledURL = issuerURL
	m.calledKid = kid
	if m.err != nil {
		return nil, m.err
	}
	if len(m.keys) > 0 {
		return m.keys, nil
	}
	if m.key == nil {
		return nil, ErrorIssuerKeyNotFound
	}
	return []jwk.Key{m.key}, nil
}

// generateTestECKeyPair creates an ECDSA P-256 key pair and returns the private jwk.Key,
// public jwk.Key, and the raw private key. The optional kid is set on both keys.
func generateTestECKeyPair(t *testing.T, kid string) (jwk.Key, jwk.Key) {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privKey, err := jwk.Import(raw)
	require.NoError(t, err)
	pubKey, err := jwk.Import(&raw.PublicKey)
	require.NoError(t, err)

	if kid != "" {
		require.NoError(t, privKey.Set(jwk.KeyIDKey, kid))
		require.NoError(t, pubKey.Set(jwk.KeyIDKey, kid))
	}

	return privKey, pubKey
}

// signTestJWT creates a JWS-signed JWT with the given header claims and payload claims.
func signTestJWT(t *testing.T, privKey jwk.Key, kid string, payload map[string]interface{}) []byte {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	headers := jws.NewHeaders()
	if kid != "" {
		require.NoError(t, headers.Set(jws.KeyIDKey, kid))
	}

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), privKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

func TestIsHttpsIssuer(t *testing.T) {
	tests := []struct {
		name     string
		issuer   string
		expected bool
	}{
		{"HTTPS URL", "https://issuer.example.com", true},
		{"HTTPS URL with path", "https://issuer.example.com/path", true},
		{"HTTP URL (not HTTPS)", "http://issuer.example.com", false},
		{"DID web", "did:web:example.com", false},
		{"DID key", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", false},
		{"Empty string", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isHttpsIssuer(tc.issuer))
		})
	}
}

func TestWithHttpsResolver(t *testing.T) {
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry)

	// Initially no resolver
	assert.Nil(t, checker.httpsResolver)

	// Set resolver
	mockResolver := &mockHttpsIssuerResolver{}
	result := checker.WithHttpsResolver(mockResolver)

	// Verify fluent chaining
	assert.Same(t, checker, result)
	assert.Same(t, mockResolver, checker.httpsResolver)
}

func TestVerifyJWT_HttpsIssuer_Success(t *testing.T) {
	privKey, pubKey := generateTestECKeyPair(t, "key-1")
	issuerURL := "https://issuer.example.com"

	token := signTestJWT(t, privKey, "key-1", map[string]interface{}{
		"iss": issuerURL,
		"vc":  map[string]interface{}{"type": []string{"VerifiableCredential"}},
	})

	mockResolver := &mockHttpsIssuerResolver{key: pubKey}
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).WithHttpsResolver(mockResolver)

	payload, key, err := checker.VerifyJWTAndReturnKey(token)
	assert.NoError(t, err)
	assert.NotNil(t, payload)
	assert.NotNil(t, key)

	// Verify the resolver was called with correct arguments
	assert.Equal(t, issuerURL, mockResolver.calledURL)
	assert.Equal(t, "key-1", mockResolver.calledKid)

	// Verify payload contents
	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	assert.NoError(t, err)
	assert.Equal(t, issuerURL, claims["iss"])
}

func TestVerifyJWT_HttpsIssuer_NoResolver(t *testing.T) {
	privKey, _ := generateTestECKeyPair(t, "key-1")
	issuerURL := "https://issuer.example.com"

	token := signTestJWT(t, privKey, "key-1", map[string]interface{}{
		"iss": issuerURL,
	})

	// No HTTPS resolver configured
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry)

	_, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.Error(t, err)
	assert.Equal(t, ErrorHttpsIssuerNotSupported, err)
}

func TestVerifyJWT_HttpsIssuer_ResolverError(t *testing.T) {
	privKey, _ := generateTestECKeyPair(t, "key-1")
	issuerURL := "https://issuer.example.com"

	token := signTestJWT(t, privKey, "key-1", map[string]interface{}{
		"iss": issuerURL,
	})

	resolverErr := errors.New("metadata_fetch_failed")
	mockResolver := &mockHttpsIssuerResolver{err: resolverErr}
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).WithHttpsResolver(mockResolver)

	_, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.Error(t, err)
	assert.Equal(t, resolverErr, err)
}

func TestVerifyJWT_HttpsIssuer_WrongKey(t *testing.T) {
	privKey, _ := generateTestECKeyPair(t, "key-1")
	_, wrongPubKey := generateTestECKeyPair(t, "key-1")
	issuerURL := "https://issuer.example.com"

	token := signTestJWT(t, privKey, "key-1", map[string]interface{}{
		"iss": issuerURL,
	})

	// Return wrong public key — signature verification should fail
	mockResolver := &mockHttpsIssuerResolver{key: wrongPubKey}
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).WithHttpsResolver(mockResolver)

	_, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.Error(t, err)
}

func TestVerifyJWT_HttpsIssuer_KidFromHeader(t *testing.T) {
	privKey, pubKey := generateTestECKeyPair(t, "my-key-id")
	issuerURL := "https://issuer.example.com"

	// Sign with a specific kid in the header
	token := signTestJWT(t, privKey, "my-key-id", map[string]interface{}{
		"iss": issuerURL,
	})

	mockResolver := &mockHttpsIssuerResolver{key: pubKey}
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).WithHttpsResolver(mockResolver)

	payload, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.NoError(t, err)
	assert.NotNil(t, payload)

	// Verify kid was forwarded to the resolver
	assert.Equal(t, "my-key-id", mockResolver.calledKid)
}

func TestVerifyJWT_HttpsIssuer_NoKid(t *testing.T) {
	privKey, pubKey := generateTestECKeyPair(t, "")
	issuerURL := "https://issuer.example.com"

	// Sign without a kid
	token := signTestJWT(t, privKey, "", map[string]interface{}{
		"iss": issuerURL,
	})

	mockResolver := &mockHttpsIssuerResolver{key: pubKey}
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).WithHttpsResolver(mockResolver)

	payload, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.NoError(t, err)
	assert.NotNil(t, payload)

	// Verify empty kid was forwarded
	assert.Equal(t, "", mockResolver.calledKid)
}

func TestVerifyJWT_DIDIssuer_BypassesHttpsResolver(t *testing.T) {
	// Verify that DID-based issuers don't go through the HTTPS resolver.
	// The DID resolution will fail (no real DID), but the HTTPS resolver should not be called.
	privKey, _ := generateTestECKeyPair(t, "key-1")
	didIssuer := "did:web:example.com"

	token := signTestJWT(t, privKey, "did:web:example.com#key-1", map[string]interface{}{
		"iss": didIssuer,
	})

	mockResolver := &mockHttpsIssuerResolver{key: nil, err: errors.New("should_not_be_called")}
	registry := did.NewRegistry(did.WithVDR(did.NewWebVDR()))
	checker := NewJWTProofChecker(registry).WithHttpsResolver(mockResolver)

	// This will fail because did:web:example.com can't be resolved in tests,
	// but that's fine — we just verify the HTTPS resolver was NOT called
	_, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.Error(t, err)
	assert.Equal(t, "", mockResolver.calledURL, "HTTPS resolver should not be called for DID issuers")
}

func TestVerifyJWT_HttpsIssuerURL_InKid(t *testing.T) {
	// When kid contains an HTTPS URL (not a DID), extractDIDFromKid returns "".
	// The iss claim should then be used, and if iss is HTTPS, the HTTPS path is taken.
	privKey, pubKey := generateTestECKeyPair(t, "https://issuer.example.com/keys/1")
	issuerURL := "https://issuer.example.com"

	token := signTestJWT(t, privKey, "https://issuer.example.com/keys/1", map[string]interface{}{
		"iss": issuerURL,
	})

	mockResolver := &mockHttpsIssuerResolver{key: pubKey}
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).WithHttpsResolver(mockResolver)

	payload, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.NoError(t, err)
	assert.NotNil(t, payload)

	// The resolver should have been called with the iss URL (not the kid URL)
	assert.Equal(t, issuerURL, mockResolver.calledURL)
	// kid should be the full kid from the header
	assert.Equal(t, "https://issuer.example.com/keys/1", mockResolver.calledKid)
}
