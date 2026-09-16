package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
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

// --- Test helpers for integration tests ---

// generateIntegrationCA creates a self-signed CA certificate with a
// corresponding ECDSA P-256 private key for use as a trust anchor
// in integration tests.
func generateIntegrationCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Integration Test CA"},
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

// generateIntegrationLeafCert creates a leaf certificate signed by the given
// CA, with the specified organizationIdentifier (OID 2.5.4.97) in the Subject.
func generateIntegrationLeafCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, orgIdentifier string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Integration Test Org"},
			Country:      []string{"ES"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  oidOrganizationIdentifier,
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

// buildElsiJWT creates a JWS-signed JWT with the given leaf certificate
// and optional intermediates in the x5c header, simulating a did:elsi
// token for integration tests.
func buildElsiJWT(t *testing.T, leafKey *ecdsa.PrivateKey, certs []*x509.Certificate, payload map[string]interface{}) []byte {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	// Build x5c chain using cert.Chain (required by jwx v3).
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

// populateTrustStore creates a TrustStore and registers the given CA
// certificate as a granted trusted service under the specified country.
func populateTrustStore(t *testing.T, caCert *x509.Certificate, countryCode string) *eidas.TrustStore {
	t.Helper()
	store := eidas.NewTrustStore()
	store.Update(countryCode, []eidas.TrustedService{
		{
			CountryCode:   countryCode,
			TSPName:       "Integration Test TSP",
			ServiceName:   "Integration Test CA Service",
			ServiceType:   eidas.ServiceTypeCAQC,
			ServiceStatus: eidas.ServiceStatusGranted,
			Certificates:  []*x509.Certificate{caCert},
		},
	})
	return store
}

// --- Integration tests ---

// TestElsiIntegration_FullFlow exercises the full did:elsi JWT verification
// end-to-end using the JWTProofChecker wired with a mock eIDAS TrustStore.
// It covers the happy path, untrusted issuers, DID-cert mismatches, eIDAS
// disabled, LD proof rejection, and non-did:elsi pass-through.
func TestElsiIntegration_FullFlow(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	// Generate test PKI: CA + leaf certificate with organizationIdentifier.
	const orgID = "VATES-ORG123"
	caCert, caKey := generateIntegrationCA(t)
	leafCert, leafKey := generateIntegrationLeafCert(t, caCert, caKey, orgID)

	// A separate, unrelated CA (for the "untrusted" test case).
	untrustedCACert, _ := generateIntegrationCA(t)

	type testCase struct {
		name    string
		setupFn func(t *testing.T) (*JWTProofChecker, []byte) // returns checker + token
		wantErr error
	}

	tests := []testCase{
		{
			name: "happy path: valid did:elsi JWT verified against trusted CA",
			setupFn: func(t *testing.T) (*JWTProofChecker, []byte) {
				store := populateTrustStore(t, caCert, "ES")
				checker := NewJWTProofChecker(did.NewRegistry()).WithTrustStore(store)

				token := buildElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
					"iss": "did:elsi:" + orgID,
					"sub": "test-subject",
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				return checker, token
			},
			wantErr: nil,
		},
		{
			name: "untrusted issuer: certificate does not chain to any trusted service",
			setupFn: func(t *testing.T) (*JWTProofChecker, []byte) {
				// Populate trust store with a different CA — the leaf cert
				// was signed by caCert, which is NOT in this store.
				store := populateTrustStore(t, untrustedCACert, "ES")
				checker := NewJWTProofChecker(did.NewRegistry()).WithTrustStore(store)

				token := buildElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
					"iss": "did:elsi:" + orgID,
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				return checker, token
			},
			wantErr: ErrorElsiUntrustedCertificate,
		},
		{
			name: "issuer DID mismatch: org identifier does not match certificate",
			setupFn: func(t *testing.T) (*JWTProofChecker, []byte) {
				store := populateTrustStore(t, caCert, "ES")
				checker := NewJWTProofChecker(did.NewRegistry()).WithTrustStore(store)

				// The cert has orgID="VATES-ORG123" but the JWT claims
				// a different organization.
				token := buildElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
					"iss": "did:elsi:VATES-MISMATCH999",
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				return checker, token
			},
			wantErr: ErrorIssuerValidationFailed,
		},
		{
			name: "eIDAS disabled: no trust store configured",
			setupFn: func(t *testing.T) (*JWTProofChecker, []byte) {
				// No trust store — simulates eIDAS being disabled.
				checker := NewJWTProofChecker(did.NewRegistry())

				token := buildElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
					"iss": "did:elsi:" + orgID,
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				return checker, token
			},
			wantErr: ErrorEidasRequiredForElsi,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker, token := tc.setupFn(t)

			payload, key, err := checker.VerifyJWTAndReturnKey(token)

			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, payload)
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, payload)
				assert.NotNil(t, key)

				// Parse the payload to verify claims round-trip.
				var claims map[string]interface{}
				require.NoError(t, json.Unmarshal(payload, &claims))
				assert.Equal(t, "did:elsi:"+orgID, claims["iss"])
			}
		})
	}
}

// TestElsiIntegration_HappyPathPayload verifies that the decoded JWT payload
// from a successful did:elsi verification contains all expected claims.
func TestElsiIntegration_HappyPathPayload(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	const orgID = "VATES-B12345678"
	caCert, caKey := generateIntegrationCA(t)
	leafCert, leafKey := generateIntegrationLeafCert(t, caCert, caKey, orgID)

	store := populateTrustStore(t, caCert, "ES")
	checker := NewJWTProofChecker(did.NewRegistry()).WithTrustStore(store)

	now := time.Now().Unix()
	token := buildElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
		"iss":              "did:elsi:" + orgID,
		"sub":              "holder-did:key:z6Mk...",
		"iat":              now,
		"exp":              now + 3600,
		"verifiableCredential": "credential-data-here",
	})

	payload, key, err := checker.VerifyJWTAndReturnKey(token)
	require.NoError(t, err)
	require.NotNil(t, payload)
	require.NotNil(t, key)

	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.Equal(t, "did:elsi:"+orgID, claims["iss"])
	assert.Equal(t, "holder-did:key:z6Mk...", claims["sub"])
	assert.Equal(t, "credential-data-here", claims["verifiableCredential"])
	assert.InDelta(t, float64(now), claims["iat"], 1)
	assert.InDelta(t, float64(now+3600), claims["exp"], 1)
}

// TestElsiIntegration_LDProofRejection verifies that attempting to verify
// an LD proof with a did:elsi signer is rejected with
// ErrorDidElsiNotSupportedForLDProof.
func TestElsiIntegration_LDProofRejection(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	registry := did.NewRegistry()
	docLoader, err := common.NewEmbeddedContextLoader(nil)
	require.NoError(t, err)
	checker := NewLDProofChecker(registry, docLoader)

	const elsiDID = "did:elsi:VATES-ORG123"

	tests := []struct {
		name         string
		proofPurpose string
	}{
		{
			name:         "VP authentication proof with did:elsi is rejected",
			proofPurpose: common.ProofPurposeAuthentication,
		},
		{
			name:         "VC assertionMethod proof with did:elsi is rejected",
			proofPurpose: common.ProofPurposeAssertionMethod,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proof := &common.LDProof{
				VerificationMethod: elsiDID + "#key-1",
				ProofPurpose:       tc.proofPurpose,
			}

			if tc.proofPurpose == common.ProofPurposeAuthentication {
				_, verifyErr := checker.VerifyPresentation([]byte("{}"), proof, elsiDID)
				assert.ErrorIs(t, verifyErr, ErrorDidElsiNotSupportedForLDProof)
			} else {
				verifyErr := checker.VerifyCredential([]byte("{}"), proof, elsiDID)
				assert.ErrorIs(t, verifyErr, ErrorDidElsiNotSupportedForLDProof)
			}
		})
	}
}

// TestElsiIntegration_NonElsiJWTUnchanged verifies that standard DID method
// JWTs (did:key) continue to work correctly when a trust store is configured
// on the proof checker — the trust store must not interfere with non-did:elsi
// verification paths.
func TestElsiIntegration_NonElsiJWTUnchanged(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	// Generate a did:key-style ECDSA key pair.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJWK, err := jwk.Import(privKey)
	require.NoError(t, err)

	pubJWK, err := privJWK.PublicKey()
	require.NoError(t, err)

	// Create a mock DID registry that returns our public key.
	mockResolver := &mockHttpsIssuerResolver{keys: []jwk.Key{pubJWK}}

	// Create a trust store (simulates eIDAS being enabled).
	caCert, _ := generateIntegrationCA(t)
	store := populateTrustStore(t, caCert, "ES")

	// Wire the checker with both an HTTPS resolver and a trust store.
	checker := NewJWTProofChecker(did.NewRegistry(
		did.WithVDR(did.NewKeyVDR()),
	)).WithHttpsResolver(mockResolver).WithTrustStore(store)

	// Build a JWT signed with our private key, using an HTTPS issuer.
	payload := map[string]interface{}{
		"iss": "https://example.com",
		"sub": "test-subject",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), privJWK))
	require.NoError(t, err)

	// Verify — this should go through the HTTPS resolver path, not the did:elsi path.
	decodedPayload, key, err := checker.VerifyJWTAndReturnKey(signed)
	require.NoError(t, err)
	assert.NotNil(t, decodedPayload)
	assert.NotNil(t, key)

	// Confirm the HTTPS resolver was invoked (not the trust store).
	assert.Equal(t, "https://example.com", mockResolver.calledURL)
}

// TestElsiIntegration_MultipleTrustStoreCountries verifies that did:elsi
// JWT verification works when the trust store contains CAs from multiple
// EU countries — the verifier should search all countries.
func TestElsiIntegration_MultipleTrustStoreCountries(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	const orgID = "VATES-DE999888"
	// The "real" CA that signed our leaf.
	caCert, caKey := generateIntegrationCA(t)
	leafCert, leafKey := generateIntegrationLeafCert(t, caCert, caKey, orgID)

	// A different CA in a different country.
	otherCACert, _ := generateIntegrationCA(t)

	store := eidas.NewTrustStore()
	// Register the other CA under FR.
	store.Update("FR", []eidas.TrustedService{
		{
			CountryCode:   "FR",
			TSPName:       "French TSP",
			ServiceName:   "French CA",
			ServiceType:   eidas.ServiceTypeCAQC,
			ServiceStatus: eidas.ServiceStatusGranted,
			Certificates:  []*x509.Certificate{otherCACert},
		},
	})
	// Register the real CA under DE.
	store.Update("DE", []eidas.TrustedService{
		{
			CountryCode:   "DE",
			TSPName:       "German TSP",
			ServiceName:   "German CA",
			ServiceType:   eidas.ServiceTypeCAQC,
			ServiceStatus: eidas.ServiceStatusGranted,
			Certificates:  []*x509.Certificate{caCert},
		},
	})

	checker := NewJWTProofChecker(did.NewRegistry()).WithTrustStore(store)

	token := buildElsiJWT(t, leafKey, []*x509.Certificate{leafCert, caCert}, map[string]interface{}{
		"iss": "did:elsi:" + orgID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	payload, key, err := checker.VerifyJWTAndReturnKey(token)
	require.NoError(t, err)
	assert.NotNil(t, payload)
	assert.NotNil(t, key)

	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.Equal(t, "did:elsi:"+orgID, claims["iss"])
}
