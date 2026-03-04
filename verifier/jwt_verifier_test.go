package verifier

import (
	"testing"

	"github.com/trustbloc/vc-go/verifiable"
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

func TestValidationService_NoneMode(t *testing.T) {
	// Test that a ValidationService with mode "none" always passes, regardless of credential content.
	var validator ValidationService = TrustBlocValidator{validationMode: "none"}

	credential, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		Issuer: &verifiable.Issuer{ID: "did:web:example.com"},
		Types:  []string{"VerifiableCredential"},
		Subject: []verifiable.Subject{
			{CustomFields: map[string]interface{}{"name": "test"}},
		},
	}, verifiable.CustomFields{})

	result, err := validator.ValidateVC(credential, nil)
	if !result {
		t.Error("Expected true for none mode")
	}
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestValidationService_NonNoneModeRejectsInvalid(t *testing.T) {
	// Test that non-"none" validation modes reject credentials that lack required VC fields.
	// This verifies the validator actually performs content checks in combined/jsonLd modes.

	credential, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		Issuer: &verifiable.Issuer{ID: "did:web:example.com"},
		Types:  []string{"VerifiableCredential"},
		Subject: []verifiable.Subject{
			{CustomFields: map[string]interface{}{"name": "test"}},
		},
	}, verifiable.CustomFields{})

	for _, mode := range []string{"combined", "jsonLd"} {
		t.Run(mode, func(t *testing.T) {
			var validator ValidationService = TrustBlocValidator{validationMode: mode}
			result, err := validator.ValidateVC(credential, nil)
			if result {
				t.Errorf("Expected false for %s mode with incomplete credential", mode)
			}
			if err == nil {
				t.Errorf("Expected error for %s mode with incomplete credential", mode)
			}
		})
	}
}

func TestSupportedModes(t *testing.T) {
	// Verify that all documented modes are present in SupportedModes.
	expected := map[string]bool{"none": false, "combined": false, "jsonLd": false, "baseContext": false}
	for _, m := range SupportedModes {
		if _, ok := expected[m]; ok {
			expected[m] = true
		}
	}
	for mode, found := range expected {
		if !found {
			t.Errorf("Expected mode %q in SupportedModes", mode)
		}
	}
}
