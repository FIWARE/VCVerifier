package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/eidas"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/cert"
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

// --- did:elsi test helpers ---

// oidOrganizationIdentifierTest is OID 2.5.4.97 for the organizationIdentifier
// attribute, used in test certificate generation.
var oidOrganizationIdentifierTest = asn1.ObjectIdentifier{2, 5, 4, 97}

// generateTestCACert creates a self-signed CA certificate with a corresponding
// ECDSA P-256 private key, suitable for use as a trust anchor in tests.
func generateTestCACert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			Country:      []string{"EU"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	return caCert, caKey
}

// generateTestLeafCert creates a leaf certificate signed by the given CA,
// with the specified organizationIdentifier (OID 2.5.4.97) in the Subject.
func generateTestLeafCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, orgIdentifier string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			Country:      []string{"ES"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  oidOrganizationIdentifierTest,
					Value: orgIdentifier,
				},
			},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(leafCertDER)
	require.NoError(t, err)

	return leafCert, leafKey
}

// signElsiJWT creates a JWS-signed JWT with the given leaf certificate and
// optional intermediates in the x5c header, simulating a did:elsi token.
func signElsiJWT(t *testing.T, leafKey *ecdsa.PrivateKey, certs []*x509.Certificate, payload map[string]interface{}) []byte {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	// Build x5c chain using cert.Chain (required by jwx v3)
	x5cChain := cert.Chain{}
	for _, c := range certs {
		require.NoError(t, x5cChain.AddString(base64.StdEncoding.EncodeToString(c.Raw)))
	}

	privJWK, err := jwk.Import(leafKey)
	require.NoError(t, err)

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set("x5c", &x5cChain))

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), privJWK, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

// createTestTrustStore creates a TrustStore populated with the given CA
// certificate as a trusted service, suitable for did:elsi tests.
func createTestTrustStore(t *testing.T, caCert *x509.Certificate) *eidas.TrustStore {
	t.Helper()
	store := eidas.NewTrustStore()
	store.Update("ES", []eidas.TrustedService{
		{
			CountryCode:   "ES",
			TSPName:       "Test TSP",
			ServiceName:   "Test CA Service",
			ServiceType:   eidas.ServiceTypeCAQC,
			ServiceStatus: eidas.ServiceStatusGranted,
			Certificates:  []*x509.Certificate{caCert},
		},
	})
	return store
}

// --- did:elsi tests ---

func TestIsDidElsi(t *testing.T) {
	tests := []struct {
		name     string
		did      string
		expected bool
	}{
		{"valid did:elsi with VATES identifier", "did:elsi:VATES-B12345678", true},
		{"valid did:elsi with short identifier", "did:elsi:X", true},
		{"valid did:elsi with complex identifier", "did:elsi:VATEU-DE123456789", true},
		{"empty method-specific identifier", "did:elsi:", false},
		{"did:key method", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", false},
		{"did:web method", "did:web:example.com", false},
		{"HTTPS URL", "https://issuer.example.com", false},
		{"empty string", "", false},
		{"just did:elsi prefix no trailing", "did:elsi", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsDidElsi(tc.did))
		})
	}
}

func TestValidateElsiIssuer(t *testing.T) {
	caCert, caKey := generateTestCACert(t)

	tests := []struct {
		name          string
		orgIdentifier string
		issuerDID     string
		expectErr     error
	}{
		{
			name:          "matching organization identifier",
			orgIdentifier: "VATES-B12345678",
			issuerDID:     "did:elsi:VATES-B12345678",
			expectErr:     nil,
		},
		{
			name:          "mismatched organization identifier",
			orgIdentifier: "VATES-B12345678",
			issuerDID:     "did:elsi:VATES-B99999999",
			expectErr:     ErrorIssuerValidationFailed,
		},
		{
			name:          "empty DID method-specific identifier",
			orgIdentifier: "VATES-B12345678",
			issuerDID:     "did:elsi:",
			expectErr:     ErrorIssuerValidationFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leafCert, _ := generateTestLeafCert(t, caCert, caKey, tc.orgIdentifier)
			err := validateElsiIssuer(leafCert, tc.issuerDID)
			if tc.expectErr != nil {
				assert.ErrorIs(t, err, tc.expectErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateElsiIssuer_NoCertOrgId(t *testing.T) {
	// Certificate without OID 2.5.4.97
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = validateElsiIssuer(cert, "did:elsi:VATES-B12345678")
	assert.ErrorIs(t, err, ErrorIssuerValidationFailed)
	assert.Contains(t, err.Error(), "organizationIdentifier")
}

func TestWithTrustStore(t *testing.T) {
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry)

	// Initially no trust store
	assert.Nil(t, checker.trustStore)

	// Set trust store
	store := eidas.NewTrustStore()
	result := checker.WithTrustStore(store)

	// Verify fluent chaining
	assert.Same(t, checker, result)
	assert.Same(t, store, checker.trustStore)
}

func TestVerifyElsiJWT_Success(t *testing.T) {
	caCert, caKey := generateTestCACert(t)
	orgId := "VATES-B12345678"
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey, orgId)

	token := signElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
		"iss": "did:elsi:" + orgId,
		"sub": "test-subject",
	})

	store := createTestTrustStore(t, caCert)
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).WithTrustStore(store)

	payload, key, err := checker.VerifyJWTAndReturnKey(token)
	assert.NoError(t, err)
	assert.NotNil(t, payload)
	assert.NotNil(t, key)

	// Verify payload contents
	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	assert.NoError(t, err)
	assert.Equal(t, "did:elsi:"+orgId, claims["iss"])
}

func TestVerifyElsiJWT_NoTrustStore(t *testing.T) {
	caCert, caKey := generateTestCACert(t)
	orgId := "VATES-B12345678"
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey, orgId)

	token := signElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
		"iss": "did:elsi:" + orgId,
	})

	// No trust store configured
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry)

	_, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.ErrorIs(t, err, ErrorEidasRequiredForElsi)
}

func TestVerifyElsiJWT_IssuerMismatch(t *testing.T) {
	caCert, caKey := generateTestCACert(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey, "VATES-B12345678")

	// DID has different org identifier than the certificate
	token := signElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
		"iss": "did:elsi:VATES-B99999999",
	})

	store := createTestTrustStore(t, caCert)
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).WithTrustStore(store)

	_, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.ErrorIs(t, err, ErrorIssuerValidationFailed)
}

func TestVerifyElsiJWT_UntrustedCertificate(t *testing.T) {
	// Create two different CAs — token signed by one, trust store has the other
	caCert, caKey := generateTestCACert(t)
	otherCACert, _ := generateTestCACert(t)

	orgId := "VATES-B12345678"
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey, orgId)

	token := signElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
		"iss": "did:elsi:" + orgId,
	})

	// Trust store has a different CA
	store := createTestTrustStore(t, otherCACert)
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).WithTrustStore(store)

	_, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.ErrorIs(t, err, ErrorElsiUntrustedCertificate)
}

func TestVerifyElsiJWT_NoX5CHeader(t *testing.T) {
	// Create a JWT without x5c header but with did:elsi issuer
	privKey, _ := generateTestECKeyPair(t, "")
	token := signTestJWT(t, privKey, "", map[string]interface{}{
		"iss": "did:elsi:VATES-B12345678",
	})

	store := eidas.NewTrustStore()
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).WithTrustStore(store)

	_, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.ErrorIs(t, err, ErrorNoCertInHeader)
}

func TestVerifyJWT_DidElsi_DispatchesToElsiPath(t *testing.T) {
	// Verify that did:elsi issuers are dispatched to the elsi path,
	// not the HTTPS resolver or DID resolution path.
	caCert, caKey := generateTestCACert(t)
	orgId := "VATES-B12345678"
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey, orgId)

	token := signElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
		"iss": "did:elsi:" + orgId,
	})

	store := createTestTrustStore(t, caCert)
	mockResolver := &mockHttpsIssuerResolver{err: errors.New("should_not_be_called")}
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry).
		WithHttpsResolver(mockResolver).
		WithTrustStore(store)

	payload, _, err := checker.VerifyJWTAndReturnKey(token)
	assert.NoError(t, err)
	assert.NotNil(t, payload)

	// HTTPS resolver should NOT have been called
	assert.Empty(t, mockResolver.calledURL, "HTTPS resolver should not be called for did:elsi issuers")
}

func TestVerifyJWT_DidElsi_KidElsiButIssMismatch(t *testing.T) {
	// When the kid header carries a did:elsi DID but the iss claim does not
	// start with "did:elsi:", the guard rejects the token with ErrorNoDIDInJWT.
	// This prevents a malformed JWT where kid: "did:elsi:A#k" and iss: "did:web:B"
	// from entering the elsi path with a non-elsi issuer.
	privKey, _ := generateTestECKeyPair(t, "")

	tests := []struct {
		name string
		kid  string
		iss  string
	}{
		{
			name: "kid is did:elsi but iss is did:web",
			kid:  "did:elsi:VATES-B12345678#key-1",
			iss:  "did:web:example.com",
		},
		{
			name: "kid is did:elsi but iss is HTTPS URL",
			kid:  "did:elsi:VATES-B12345678#key-1",
			iss:  "https://issuer.example.com",
		},
		{
			name: "kid is did:elsi but iss is empty",
			kid:  "did:elsi:VATES-B12345678#key-1",
			iss:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := signTestJWT(t, privKey, tc.kid, map[string]interface{}{
				"iss": tc.iss,
			})

			store := eidas.NewTrustStore()
			registry := did.NewRegistry()
			checker := NewJWTProofChecker(registry).WithTrustStore(store)

			_, _, err := checker.VerifyJWTAndReturnKey(token)
			assert.ErrorIs(t, err, ErrorNoDIDInJWT)
		})
	}
}

// TestVerifyElsiJWT_Guarantees pins the security properties that did:elsi
// verification upholds now that it is built on a plain JWS signature plus a
// PKIX chain to an eIDAS trust list, rather than on JAdES envelope validation.
//
// The set of guarantees is deliberately different from the JAdES one — the
// AdES signed properties (signing time, signing certificate reference, signature
// policy) are no longer evaluated — so these are the properties a deployment can
// still rely on:
//
//  1. the payload is covered by the signature,
//  2. the signature is made with the key of the certificate in x5c,
//  3. that certificate is bound to the claimed did:elsi identity through its
//     organizationIdentifier, and
//  4. that certificate chains to a CA listed as a granted service in the trust
//     list, and is itself valid at verification time.
//
// Anything not on this list is not checked; see docs/eidas-verification.md.
func TestVerifyElsiJWT_Guarantees(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	const orgIdentifier = "VATES-B12345678"
	const issuerDID = "did:elsi:" + orgIdentifier

	tests := []struct {
		name string
		// tamper mutates the signed token, the certificate chain presented in
		// x5c, or the signing key, to break exactly one guarantee.
		buildToken  func(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []byte
		expectError bool
	}{
		{
			name: "intact token verifies",
			buildToken: func(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
				leafCert, leafKey := generateTestLeafCert(t, caCert, caKey, orgIdentifier)
				return signElsiJWT(t, leafKey, []*x509.Certificate{leafCert}, map[string]interface{}{"iss": issuerDID})
			},
		},
		{
			name: "payload tampering breaks the signature",
			buildToken: func(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
				leafCert, leafKey := generateTestLeafCert(t, caCert, caKey, orgIdentifier)
				token := signElsiJWT(t, leafKey, []*x509.Certificate{leafCert}, map[string]interface{}{"iss": issuerDID, "role": "user"})

				// Replace the payload segment with one claiming a different role.
				parts := strings.Split(string(token), ".")
				require.Len(t, parts, 3)
				tamperedPayload, err := json.Marshal(map[string]interface{}{"iss": issuerDID, "role": "admin"})
				require.NoError(t, err)
				parts[1] = base64.RawURLEncoding.EncodeToString(tamperedPayload)
				return []byte(strings.Join(parts, "."))
			},
			expectError: true,
		},
		{
			name: "signature by a key other than the one in x5c is rejected",
			buildToken: func(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
				leafCert, _ := generateTestLeafCert(t, caCert, caKey, orgIdentifier)
				// A second certificate for the same organisation, whose key
				// signs the token while the first one is presented in x5c.
				_, otherKey := generateTestLeafCert(t, caCert, caKey, orgIdentifier)
				return signElsiJWT(t, otherKey, []*x509.Certificate{leafCert}, map[string]interface{}{"iss": issuerDID})
			},
			expectError: true,
		},
		{
			name: "certificate for a different organisation is rejected",
			buildToken: func(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
				leafCert, leafKey := generateTestLeafCert(t, caCert, caKey, "VATES-B99999999")
				return signElsiJWT(t, leafKey, []*x509.Certificate{leafCert}, map[string]interface{}{"iss": issuerDID})
			},
			expectError: true,
		},
		{
			name: "certificate from an unlisted CA is rejected",
			buildToken: func(t *testing.T, _ *x509.Certificate, _ *ecdsa.PrivateKey) []byte {
				foreignCA, foreignCAKey := generateTestCACert(t)
				leafCert, leafKey := generateTestLeafCert(t, foreignCA, foreignCAKey, orgIdentifier)
				return signElsiJWT(t, leafKey, []*x509.Certificate{leafCert}, map[string]interface{}{"iss": issuerDID})
			},
			expectError: true,
		},
		{
			name: "expired signing certificate is rejected",
			buildToken: func(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
				leafCert, leafKey := generateExpiredLeafCert(t, caCert, caKey, orgIdentifier)
				return signElsiJWT(t, leafKey, []*x509.Certificate{leafCert}, map[string]interface{}{"iss": issuerDID})
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caCert, caKey := generateTestCACert(t)
			store := createTestTrustStore(t, caCert)
			checker := NewJWTProofChecker(did.NewRegistry()).WithTrustStore(store)

			token := tc.buildToken(t, caCert, caKey)

			payload, err := checker.VerifyJWT(token)
			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, payload)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, payload)
		})
	}
}

// generateExpiredLeafCert creates a leaf certificate that expired before the
// current time, signed by the given CA.
func generateExpiredLeafCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, orgIdentifier string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			Country:      []string{"ES"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: oidOrganizationIdentifierTest, Value: orgIdentifier},
			},
		},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(leafCertDER)
	require.NoError(t, err)

	return leafCert, leafKey
}
