package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/fiware/VCVerifier/did"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- HTTPS-based issuers for status list JWTs ---
//
// A status list JWT is signed by the issuer of the credentials it covers, so
// once credential issuers may be identified by an https:// URL the status
// list path has to resolve those identifiers too. Otherwise revocation
// checking fails for exactly the credentials the HTTPS support enables.

// testStatusListHttpsIssuer is the HTTPS-based issuer of the test status list.
const testStatusListHttpsIssuer = "https://issuer.example.com"

// testStatusListSubject is the `sub` claim of the test status list.
const testStatusListSubject = "https://example.org/statuslists/1"

// newStatusListPayload returns a minimal, valid status list JWT payload.
func newStatusListPayload() map[string]interface{} {
	return map[string]interface{}{
		"status_list": map[string]interface{}{
			"bits": 1,
			"lst":  "eNpjAAAAAQAB",
		},
		"sub": testStatusListSubject,
	}
}

// newStatusListHttpsVerifier builds a StatusListJWTVerifierImpl whose DID
// registry has no VDRs at all, so a test proves the HTTPS issuer path never
// depends on DID resolution.
func newStatusListHttpsVerifier(resolver HttpsIssuerResolver) *StatusListJWTVerifierImpl {
	v := NewStatusListJWTVerifier(did.NewRegistry())
	if resolver != nil {
		v = v.WithHttpsResolver(resolver)
	}
	return v
}

// generateStatusListKeyPair returns a signing key and its public JWK.
func generateStatusListKeyPair(t *testing.T) (*ecdsa.PrivateKey, jwk.Key) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubJWK, err := jwk.Import(&privateKey.PublicKey)
	require.NoError(t, err)
	return privateKey, pubJWK
}

// TestStatusListJWTVerifier_HttpsIssuer covers signature verification of a
// status list JWT whose `iss` claim is an HTTPS URL.
func TestStatusListJWTVerifier_HttpsIssuer(t *testing.T) {
	privateKey, pubJWK := generateStatusListKeyPair(t)
	_, foreignPubJWK := generateStatusListKeyPair(t)

	jwtBytes := buildStatusListJWTWithISS(t, newStatusListPayload(), privateKey, testStatusListHttpsIssuer)

	tests := []struct {
		testName        string
		resolver        HttpsIssuerResolver
		expectError     bool
		expectedError   error
		expectedMessage string
	}{
		{
			testName:    "valid signature from the resolved issuer JWKS is accepted",
			resolver:    &mockHttpsIssuerResolver{key: pubJWK},
			expectError: false,
		},
		{
			testName:        "no resolver configured fails closed",
			resolver:        nil,
			expectError:     true,
			expectedError:   ErrorStatusListUnparseable,
			expectedMessage: ErrorHttpsIssuerNotSupported.Error(),
		},
		{
			testName:      "metadata discovery failure is reported as unparseable",
			resolver:      &mockHttpsIssuerResolver{err: ErrorIssuerMetadataNotFound},
			expectError:   true,
			expectedError: ErrorStatusListUnparseable,
		},
		{
			testName:      "a foreign key from the resolver does not verify",
			resolver:      &mockHttpsIssuerResolver{key: foreignPubJWK},
			expectError:   true,
			expectedError: ErrorStatusListUnparseable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			verifier := newStatusListHttpsVerifier(tc.resolver)

			verified, err := verifier.VerifyStatusListJWT(jwtBytes)

			if !tc.expectError {
				require.NoError(t, err)
				var claims map[string]interface{}
				require.NoError(t, json.Unmarshal(verified, &claims))
				assert.Equal(t, testStatusListSubject, claims["sub"])
				return
			}
			assert.Error(t, err)
			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
			}
			if tc.expectedMessage != "" {
				assert.Contains(t, err.Error(), tc.expectedMessage,
					"the underlying cause should stay visible in the message")
			}
		})
	}
}

// TestStatusListJWTVerifier_HttpsIssuer_TamperedPayload makes sure the HTTPS
// path verifies the signature rather than merely resolving a key.
func TestStatusListJWTVerifier_HttpsIssuer_TamperedPayload(t *testing.T) {
	privateKey, pubJWK := generateStatusListKeyPair(t)

	jwtBytes := buildStatusListJWTWithISS(t, newStatusListPayload(), privateKey, testStatusListHttpsIssuer)

	// Flip a byte in the signature segment. The header and payload stay
	// intact, so the iss claim is still read and the HTTPS key still
	// resolves — the only thing that can fail is the signature check.
	tampered := append([]byte{}, jwtBytes...)
	lastDot := bytes.LastIndexByte(tampered, '.')
	require.Positive(t, lastDot, "JWS should have a signature separator")
	require.Less(t, lastDot+1, len(tampered), "JWS should have a signature segment")
	tampered[lastDot+1] = flipBase64Char(tampered[lastDot+1])

	resolver := &mockHttpsIssuerResolver{key: pubJWK}
	verifier := newStatusListHttpsVerifier(resolver)
	_, err := verifier.VerifyStatusListJWT(tampered)

	assert.ErrorIs(t, err, ErrorStatusListUnparseable, "a tampered status list JWT must not verify")
	assert.Equal(t, testStatusListHttpsIssuer, resolver.calledURL,
		"the failure should come from the signature check, not from key resolution")
}

// TestStatusListJWTVerifier_HttpsIssuer_ResolverArguments asserts the issuer
// URL and the JWS `kid` header are what the resolver is asked for.
func TestStatusListJWTVerifier_HttpsIssuer_ResolverArguments(t *testing.T) {
	privateKey, pubJWK := generateStatusListKeyPair(t)
	jwtBytes := buildStatusListJWTWithISS(t, newStatusListPayload(), privateKey, testStatusListHttpsIssuer)

	resolver := &mockHttpsIssuerResolver{key: pubJWK}
	verifier := newStatusListHttpsVerifier(resolver)

	_, err := verifier.VerifyStatusListJWT(jwtBytes)
	require.NoError(t, err)

	assert.Equal(t, testStatusListHttpsIssuer, resolver.calledURL,
		"the resolver should be asked for the iss URL")
}

// TestStatusListJWTVerifier_DidIssuerUnaffectedByHttpsResolver checks that
// configuring an HTTPS resolver does not divert DID-based issuers away from
// DID resolution.
func TestStatusListJWTVerifier_DidIssuerUnaffectedByHttpsResolver(t *testing.T) {
	privateKey, issuerDID := generateTestKeyAndDID(t)
	jwtBytes := buildStatusListJWTWithISS(t, newStatusListPayload(), privateKey, issuerDID)

	// The resolver would fail if it were consulted.
	resolver := &mockHttpsIssuerResolver{err: ErrorIssuerMetadataNotFound}
	verifier := NewStatusListJWTVerifier(did.NewRegistry(did.WithVDR(did.NewJWKVDR()))).
		WithHttpsResolver(resolver)

	verified, err := verifier.VerifyStatusListJWT(jwtBytes)
	require.NoError(t, err, "a did:jwk issuer should still resolve via the DID registry")

	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(verified, &claims))
	assert.Equal(t, testStatusListSubject, claims["sub"])
	assert.Empty(t, resolver.calledURL, "the HTTPS resolver must not be consulted for a DID issuer")
}

// flipBase64Char returns a different base64url character, so flipping it
// changes the signed content.
func flipBase64Char(c byte) byte {
	if c == 'A' {
		return 'B'
	}
	return 'A'
}
