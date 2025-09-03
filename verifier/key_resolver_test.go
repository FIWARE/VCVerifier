package verifier

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

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
