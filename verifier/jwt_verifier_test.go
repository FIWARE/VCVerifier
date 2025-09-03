package verifier

import (
	"testing"
)

func TestGetKeyFromMethod(t *testing.T) {
	type test struct {
		testName             string
		verificationMethod   string
		expectedKeyId        string
		expectedAbsolutePath string
		expectedFullAbsolutePath string
		expectedError        error
	}

	tests := []test{
		{
			testName:             "Full absolute path",
			verificationMethod:   "did:key:123#abc",
			expectedKeyId:        "abc",
			expectedAbsolutePath: "did:key:123",
			expectedFullAbsolutePath: "did:key:123#abc",
			expectedError:        nil,
		},
		{
			testName:             "Absolute path",
			verificationMethod:   "did:key:123",
			expectedKeyId:        "123",
			expectedAbsolutePath: "did:key:123",
			expectedFullAbsolutePath: "",
			expectedError:        nil,
		},
		{
			testName:             "Key only",
			verificationMethod:   "123",
			expectedKeyId:        "123",
			expectedAbsolutePath: "",
			expectedFullAbsolutePath: "",
			expectedError:        nil,
		},
		{
			testName:             "Invalid method",
			verificationMethod:   "",
			expectedKeyId:        "",
			expectedAbsolutePath: "",
			expectedFullAbsolutePath: "",
			expectedError:        ErrorNotAValidVerficationMethod,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			keyId, absolutePath, fullAbsolutePath, err := getKeyFromMethod(tc.verificationMethod)

			if keyId != tc.expectedKeyId {
				t.Errorf("Expected keyId %v, but got %v", tc.expectedKeyId, keyId)
			}

			if absolutePath != tc.expectedAbsolutePath {
				t.Errorf("Expected absolutePath %v, but got %v", tc.expectedAbsolutePath, absolutePath)
			}

			if fullAbsolutePath != tc.expectedFullAbsolutePath {
				t.Errorf("Expected fullAbsolutePath %v, but got %v", tc.expectedFullAbsolutePath, fullAbsolutePath)
			}

			if err != tc.expectedError {
				t.Errorf("Expected error %v, but got %v", tc.expectedError, err)
			}
		})
	}
}

func TestCompareVerificationMethod(t *testing.T) {
	type test struct {
		testName          string
		presentedMethod   string
		didDocumentMethod string
		expectedResult    bool
	}

	tests := []test{
		{
			testName:          "Match full absolute path",
			presentedMethod:   "did:key:123#abc",
			didDocumentMethod: "did:key:123#abc",
			expectedResult:    true,
		},
		{
			testName:          "Match absolute path",
			presentedMethod:   "did:key:123",
			didDocumentMethod: "did:key:123#abc",
			expectedResult:    true,
		},
		{
			testName:          "Match key id",
			presentedMethod:   "abc",
			didDocumentMethod: "did:key:123#abc",
			expectedResult:    true,
		},
		{
			testName:          "No match",
			presentedMethod:   "xyz",
			didDocumentMethod: "did:key:123#abc",
			expectedResult:    false,
		},
		{
			testName:          "Empty presented method",
			presentedMethod:   "",
			didDocumentMethod: "did:key:123#abc",
			expectedResult:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			result := compareVerificationMethod(tc.presentedMethod, tc.didDocumentMethod)

			if result != tc.expectedResult {
				t.Errorf("Expected result %v, but got %v", tc.expectedResult, result)
			}
		})
	}
}
