package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signWithAlgorithm signs a payload with the given key and algorithm and
// returns the JWS together with its protected headers.
func signWithAlgorithm(t *testing.T, privKey jwk.Key, alg jwa.SignatureAlgorithm) ([]byte, jws.Headers) {
	t.Helper()

	payload, err := json.Marshal(map[string]interface{}{"iss": "https://issuer.example.com"})
	require.NoError(t, err)

	signed, err := jws.Sign(payload, jws.WithKey(alg, privKey))
	require.NoError(t, err)

	msg, err := jws.Parse(signed)
	require.NoError(t, err)

	return signed, msg.Signatures()[0].ProtectedHeaders()
}

// TestVerifyJWSWithCandidateKeys_TriesEveryCandidate verifies that a signature
// is accepted when any candidate key verifies it, regardless of the position of
// that key — a kid-less JWS must not depend on JWKS ordering.
func TestVerifyJWSWithCandidateKeys_TriesEveryCandidate(t *testing.T) {
	logging.Configure(testLoggingConfig)

	signingPriv, signingPub := generateTestECKeyPair(t, "")
	_, otherPub := generateTestECKeyPair(t, "")
	_, thirdPub := generateTestECKeyPair(t, "")

	token, headers := signWithAlgorithm(t, signingPriv, jwa.ES256())

	tests := []struct {
		testName    string
		keys        []jwk.Key
		expectValid bool
	}{
		{"the signing key is the only candidate", []jwk.Key{signingPub}, true},
		{"the signing key comes first", []jwk.Key{signingPub, otherPub}, true},
		{"the signing key comes last", []jwk.Key{otherPub, thirdPub, signingPub}, true},
		{"no candidate signed the token", []jwk.Key{otherPub, thirdPub}, false},
		{"no candidates at all", []jwk.Key{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			payload, key, err := verifyJWSWithCandidateKeys(token, headers, tc.keys)

			if !tc.expectValid {
				assert.ErrorIs(t, err, ErrorNoUsableVerificationKey)
				assert.Nil(t, payload)
				assert.Nil(t, key)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, payload)
			assert.Same(t, signingPub, key)
		})
	}
}

// TestVerifyJWSWithCandidateKeys_AlgorithmPinning verifies that the algorithm
// named in the JWS header is checked against the allowlist and against the
// algorithm the key itself declares.
func TestVerifyJWSWithCandidateKeys_AlgorithmPinning(t *testing.T) {
	logging.Configure(testLoggingConfig)

	signingPriv, signingPub := generateTestECKeyPair(t, "key-1")
	token, headers := signWithAlgorithm(t, signingPriv, jwa.ES256())

	tests := []struct {
		testName      string
		keyAlgorithm  string
		keyUsage      string
		expectedError error
	}{
		{testName: "key without alg is used as is"},
		{testName: "key declaring the same alg is used", keyAlgorithm: jwa.ES256().String()},
		{
			testName:      "key declaring another alg is refused",
			keyAlgorithm:  jwa.ES384().String(),
			expectedError: ErrorAlgorithmKeyMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			candidate, err := signingPub.Clone()
			require.NoError(t, err)
			if tc.keyAlgorithm != "" {
				require.NoError(t, candidate.Set(jwk.AlgorithmKey, tc.keyAlgorithm))
			}

			payload, _, err := verifyJWSWithCandidateKeys(token, headers, []jwk.Key{candidate})

			if tc.expectedError != nil {
				assert.ErrorIs(t, err, ErrorNoUsableVerificationKey)
				assert.Contains(t, err.Error(), tc.expectedError.Error())
				assert.Nil(t, payload)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, payload)
		})
	}
}

// TestVerifyJWSWithCandidateKeys_UnsupportedAlgorithms verifies that `none` and
// the symmetric family are rejected before any key is consulted.
func TestVerifyJWSWithCandidateKeys_UnsupportedAlgorithms(t *testing.T) {
	logging.Configure(testLoggingConfig)

	_, pubKey := generateTestECKeyPair(t, "key-1")

	tests := []struct {
		testName string
		alg      jwa.SignatureAlgorithm
		allowed  bool
	}{
		{"ES256 is allowed", jwa.ES256(), true},
		{"RS256 is allowed", jwa.RS256(), true},
		{"PS256 is allowed", jwa.PS256(), true},
		{"EdDSA is allowed", jwa.EdDSA(), true},
		{"HS256 is refused", jwa.HS256(), false},
		{"none is refused", jwa.NoSignature(), false},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			err := assertAllowedAlgorithm(tc.alg)
			if tc.allowed {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, ErrorUnsupportedSignatureAlgorithm)
		})
	}

	// A header without an alg is refused too.
	_, _, err := verifyJWSWithCandidateKeys([]byte("irrelevant"), jws.NewHeaders(), []jwk.Key{pubKey})
	assert.ErrorIs(t, err, ErrorUnsupportedSignatureAlgorithm)
}

// TestVerifyJWSWithCandidateKeys_HmacKeyIsNeverAccepted verifies that a token
// signed with HS256 — using the public key material as the shared secret — is
// rejected rather than verified against a resolved public key.
func TestVerifyJWSWithCandidateKeys_HmacKeyIsNeverAccepted(t *testing.T) {
	logging.Configure(testLoggingConfig)

	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKey, err := jwk.Import(&raw.PublicKey)
	require.NoError(t, err)

	pubKeyJSON, err := json.Marshal(pubKey)
	require.NoError(t, err)
	hmacKey, err := jwk.Import(pubKeyJSON)
	require.NoError(t, err)

	payload, err := json.Marshal(map[string]interface{}{"iss": "https://issuer.example.com"})
	require.NoError(t, err)
	token, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), hmacKey))
	require.NoError(t, err)

	msg, err := jws.Parse(token)
	require.NoError(t, err)

	verified, key, err := verifyJWSWithCandidateKeys(token, msg.Signatures()[0].ProtectedHeaders(), []jwk.Key{pubKey})
	assert.ErrorIs(t, err, ErrorUnsupportedSignatureAlgorithm)
	assert.Nil(t, verified)
	assert.Nil(t, key)
}
