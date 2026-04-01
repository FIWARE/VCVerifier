package verifier

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	"github.com/stretchr/testify/assert"
)

type mockJAdESValidator struct {
	signatureValid bool
}

func (c *mockJAdESValidator) ValidateSignature(_ string) (bool, error) {
	return c.signatureValid, nil
}

const ElsiSameIssuer = "did:elsi:VATDE_1234567"
const ElsiOtherIssuer = "did:elsi:VATDE_999"

var ElsiCertChain = []string{
	"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",
}

// buildElsiJWT creates a JWT token with ELSI-specific headers for testing.
func buildElsiJWT(kid string, x5c []string, payload map[string]interface{}) string {
	header := map[string]interface{}{
		"alg": "RS256",
		"kid": kid,
		"x5c": x5c,
	}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
}

func TestVerifyElsiJWT(t *testing.T) {
	type testCase struct {
		testName       string
		kid            string
		iss            string
		signatureValid bool
		expectError    bool
	}

	testCases := []testCase{
		{
			testName:       "Valid ELSI JWT with matching issuer and cert",
			kid:            ElsiSameIssuer,
			iss:            ElsiSameIssuer,
			signatureValid: true,
			expectError:    false,
		},
		{
			testName:       "Invalid JAdES signature should be rejected",
			kid:            ElsiSameIssuer,
			iss:            ElsiSameIssuer,
			signatureValid: false,
			expectError:    true,
		},
		{
			testName:       "Different kid but matching iss should succeed (iss is authoritative for did:elsi)",
			kid:            ElsiOtherIssuer,
			iss:            ElsiSameIssuer,
			signatureValid: true,
			expectError:    false,
		},
		{
			testName:       "Mismatching iss and cert should be rejected",
			kid:            ElsiOtherIssuer,
			iss:            ElsiOtherIssuer,
			signatureValid: true,
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("Running ELSI test: ", tc.testName)

			validator := &mockJAdESValidator{signatureValid: tc.signatureValid}
			registry := did.NewRegistry()
			checker := NewJWTProofChecker(registry, validator)

			token := buildElsiJWT(tc.kid, ElsiCertChain, map[string]interface{}{
				"iss": tc.iss,
				"vc":  map[string]interface{}{"type": []string{"VerifiableCredential"}},
			})

			_, err := checker.VerifyJWT([]byte(token))

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyElsiJWT_NoCertInHeader(t *testing.T) {
	validator := &mockJAdESValidator{signatureValid: true}
	registry := did.NewRegistry()
	checker := NewJWTProofChecker(registry, validator)

	// JWT without x5c header
	header := map[string]interface{}{"alg": "RS256", "kid": ElsiSameIssuer}
	payload := map[string]interface{}{"iss": ElsiSameIssuer}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)
	token := base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("sig"))

	_, err := checker.VerifyJWT([]byte(token))
	assert.Error(t, err)
	assert.Equal(t, ErrorNoCertInHeader, err)
}

func TestExtractDIDFromKid(t *testing.T) {
	tests := []struct {
		kid      string
		expected string
	}{
		{"did:web:example.com#key-1", "did:web:example.com"},
		{"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"},
		{"did:elsi:VATDE_1234567", "did:elsi:VATDE_1234567"},
		{"key-1", ""},
		{"", ""},
	}

	for _, tc := range tests {
		result := extractDIDFromKid(tc.kid)
		assert.Equal(t, tc.expected, result, "kid=%s", tc.kid)
	}
}

func TestIsDidElsiMethod(t *testing.T) {
	assert.True(t, isDidElsiMethod("did:elsi:VATDE_1234567"))
	assert.False(t, isDidElsiMethod("did:web:example.com"))
	assert.True(t, isDidElsiMethod("did:elsi:"))
	assert.False(t, isDidElsiMethod("not-a-did"))
}
