package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/trustbloc/vc-go/verifiable"
)

func TestCheckSignature(t *testing.T) {
	type test struct {
		testName       string
		rawCredential  []byte
		signature      string
		expectedResult bool
		expectedError  bool
	}

	credential := map[string]interface{}{"test": "value"}
	rawCredential, _ := json.Marshal(credential)
	canonicalized, _ := jsoncanonicalizer.Transform(rawCredential)
	hash := sha256.Sum256(canonicalized)
	hashHex := "sha256-" + hex.EncodeToString(hash[:])

	tests := []test{
		{
			testName:       "Valid signature",
			rawCredential:  rawCredential,
			signature:      hashHex,
			expectedResult: true,
			expectedError:  false,
		},
		{
			testName:       "Invalid signature",
			rawCredential:  rawCredential,
			signature:      "invalid_signature",
			expectedResult: false,
			expectedError:  false,
		},
		{
			testName:       "Invalid JSON",
			rawCredential:  []byte("invalid_json"),
			signature:      "any_signature",
			expectedResult: false,
			expectedError:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			result, err := checkSignature(tc.rawCredential, tc.signature)

			if result != tc.expectedResult {
				t.Errorf("Expected result %v, but got %v", tc.expectedResult, result)
			}

			if (err != nil) != tc.expectedError {
				t.Errorf("Expected error %v, but got %v", tc.expectedError, err)
			}
		})
	}
}

func TestComplianceValidationService_ValidateVC(t *testing.T) {
	type test struct {
		testName             string
		verifiableCredential *verifiable.Credential
		validationContext    ValidationContext
		expectedResult       bool
		expectedError        error
	}

	vc, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		ID: "test_credential",
	}, verifiable.CustomFields{})
	rawVC, _ := vc.MarshalJSON()
	canonicalized, _ := jsoncanonicalizer.Transform(rawVC)
	hash := sha256.Sum256(canonicalized)
	hashHex := "sha256-" + hex.EncodeToString(hash[:])

	tests := []test{
		{
			testName:             "Successful validation",
			verifiableCredential: vc,
			validationContext: ComplianceValidationContext{
				complianceSubjects: []ComplianceSubject{
					{Type: GAIA_X_COMPLIANCE_SUBJECT_TYPE, Id: "test_credential", Integrity: hashHex},
				},
			},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			testName:             "No matching compliance subject",
			verifiableCredential: vc,
			validationContext: ComplianceValidationContext{
				complianceSubjects: []ComplianceSubject{
					{Type: GAIA_X_COMPLIANCE_SUBJECT_TYPE, Id: "other_credential", Integrity: hashHex},
				},
			},
			expectedResult: false,
			expectedError:  ErrorNoComplianceID,
		},
		{
			testName:             "Mismatched signature",
			verifiableCredential: vc,
			validationContext: ComplianceValidationContext{
				complianceSubjects: []ComplianceSubject{
					{Type: GAIA_X_COMPLIANCE_SUBJECT_TYPE, Id: "test_credential", Integrity: "invalid_signature"},
				},
			},
			expectedResult: false,
			expectedError:  nil,
		},
		{
			testName:             "Invalid validation context",
			verifiableCredential: vc,
			validationContext:    nil,
			expectedResult:       false,
			expectedError:        ErrorCannotConverContext,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			service := &ComplianceValidationService{}
			result, err := service.ValidateVC(tc.verifiableCredential, tc.validationContext)

			if result != tc.expectedResult {
				t.Errorf("Expected result %v, but got %v", tc.expectedResult, result)
			}

			if !errors.Is(err, tc.expectedError) {
				t.Errorf("Expected error %v, but got %v", tc.expectedError, err)
			}
		})
	}
}
