package verifier

import (
	"testing"
	"time"

	common "github.com/fiware/VCVerifier/common"
)

// fixedClock is a test double that always returns the configured instant.
type fixedClock struct{ t time.Time }

func (fc fixedClock) Now() time.Time { return fc.t }

func TestGetKeyFromMethod(t *testing.T) {
	type test struct {
		testName                 string
		verificationMethod       string
		expectedKeyId            string
		expectedAbsolutePath     string
		expectedFullAbsolutePath string
		expectedError            error
	}

	tests := []test{
		{
			testName:                 "Full absolute path",
			verificationMethod:       "did:key:123#abc",
			expectedKeyId:            "abc",
			expectedAbsolutePath:     "did:key:123",
			expectedFullAbsolutePath: "did:key:123#abc",
			expectedError:            nil,
		},
		{
			testName:                 "Absolute path",
			verificationMethod:       "did:key:123",
			expectedKeyId:            "123",
			expectedAbsolutePath:     "did:key:123",
			expectedFullAbsolutePath: "",
			expectedError:            nil,
		},
		{
			testName:                 "Key only",
			verificationMethod:       "123",
			expectedKeyId:            "123",
			expectedAbsolutePath:     "",
			expectedFullAbsolutePath: "",
			expectedError:            nil,
		},
		{
			testName:                 "Invalid method",
			verificationMethod:       "",
			expectedKeyId:            "",
			expectedAbsolutePath:     "",
			expectedFullAbsolutePath: "",
			expectedError:            ErrorNotAValidVerficationMethod,
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
	// Test that a CredentialValidator with mode "none" always passes, regardless of credential content.
	var validator ValidationService = CredentialValidator{validationMode: ValidationModeNone}

	credential, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: "did:web:example.com"},
		Types:  []string{"VerifiableCredential"},
		Subject: []common.Subject{
			{CustomFields: map[string]interface{}{"name": "test"}},
		},
	}, common.CustomFields{})

	result, err := validator.ValidateVC(credential, nil)
	if !result {
		t.Error("Expected true for none mode")
	}
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestValidationService_NonNoneModeRejectsInvalid(t *testing.T) {
	// Test that non-"none" validation modes reject credentials that lack required fields.

	// Create a credential with no issuer
	credential, _ := common.CreateCredential(common.CredentialContents{
		Types: []string{"VerifiableCredential"},
		Subject: []common.Subject{
			{CustomFields: map[string]interface{}{"name": "test"}},
		},
	}, common.CustomFields{})

	for _, mode := range []string{ValidationModeCombined, ValidationModeJsonLd} {
		t.Run(mode, func(t *testing.T) {
			var validator ValidationService = CredentialValidator{validationMode: mode}
			result, err := validator.ValidateVC(credential, nil)
			if result {
				t.Errorf("Expected false for %s mode with missing issuer", mode)
			}
			if err == nil {
				t.Errorf("Expected error for %s mode with missing issuer", mode)
			}
		})
	}
}

func TestValidationService_BaseContextRejectsCustomTypes(t *testing.T) {
	credential, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: "did:web:example.com"},
		Types:  []string{"VerifiableCredential", "CustomType"},
		Subject: []common.Subject{
			{CustomFields: map[string]interface{}{"name": "test"}},
		},
	}, common.CustomFields{})

	var validator ValidationService = CredentialValidator{validationMode: ValidationModeBaseContext}
	result, err := validator.ValidateVC(credential, nil)
	if result {
		t.Error("Expected false for baseContext mode with custom type")
	}
	if err == nil {
		t.Error("Expected error for baseContext mode with custom type")
	}
}

func TestValidationService_CombinedAcceptsValid(t *testing.T) {
	credential, _ := common.CreateCredential(common.CredentialContents{
		Issuer: &common.Issuer{ID: "did:web:example.com"},
		Types:  []string{"VerifiableCredential"},
		Subject: []common.Subject{
			{CustomFields: map[string]interface{}{"name": "test"}},
		},
	}, common.CustomFields{})

	var validator ValidationService = CredentialValidator{validationMode: ValidationModeCombined}
	result, err := validator.ValidateVC(credential, nil)
	if !result {
		t.Error("Expected true for combined mode with valid credential")
	}
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSupportedModes(t *testing.T) {
	// Verify that all documented modes are present in SupportedModes.
	expected := map[string]bool{ValidationModeNone: false, ValidationModeCombined: false, ValidationModeJsonLd: false, ValidationModeBaseContext: false}
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

// ---------------------------------------------------------------------------
// Temporal validity tests
// ---------------------------------------------------------------------------

// baseTime is a fixed "now" used across all temporal tests so results are deterministic.
var baseTime = time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

func makeCredential(validFrom, validUntil *time.Time) *common.Credential {
	c, _ := common.CreateCredential(common.CredentialContents{
		Issuer:     &common.Issuer{ID: "did:web:example.com"},
		Types:      []string{"VerifiableCredential"},
		Subject:    []common.Subject{{CustomFields: map[string]interface{}{"name": "test"}}},
		ValidFrom:  validFrom,
		ValidUntil: validUntil,
	}, common.CustomFields{})
	return c
}

func tp(t time.Time) *time.Time { return &t }

func TestValidateCredentialContent_TemporalValidity(t *testing.T) {
	past := baseTime.Add(-24 * time.Hour)
	future := baseTime.Add(24 * time.Hour)

	tests := []struct {
		name       string
		validFrom  *time.Time
		validUntil *time.Time
		wantErr    error
	}{
		{
			name:    "no_dates_always_valid",
			wantErr: nil,
		},
		{
			name:      "valid_from_past_no_expiry",
			validFrom: tp(past),
			wantErr:   nil,
		},
		{
			name:       "valid_until_future_no_issued",
			validUntil: tp(future),
			wantErr:    nil,
		},
		{
			name:       "both_in_valid_window",
			validFrom:  tp(past),
			validUntil: tp(future),
			wantErr:    nil,
		},
		{
			name:       "expired_credential",
			validFrom:  tp(past.Add(-48 * time.Hour)),
			validUntil: tp(past),
			wantErr:    ErrorCredentialExpired,
		},
		{
			name:      "not_yet_valid",
			validFrom: tp(future),
			wantErr:   ErrorCredentialNotYetValid,
		},
		{
			name:       "not_yet_valid_with_future_expiry",
			validFrom:  tp(future),
			validUntil: tp(future.Add(24 * time.Hour)),
			wantErr:    ErrorCredentialNotYetValid,
		},
	}

	for _, mode := range []string{ValidationModeCombined, ValidationModeJsonLd, ValidationModeBaseContext} {
		for _, tc := range tests {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				cred := makeCredential(tc.validFrom, tc.validUntil)
				validator := CredentialValidator{validationMode: mode, clock: fixedClock{t: baseTime}}
				_, err := validator.ValidateVC(cred, nil)
				if tc.wantErr != nil {
					if err == nil {
						t.Fatalf("expected error %v, got nil", tc.wantErr)
					}
					if !isErr(err, tc.wantErr) {
						t.Fatalf("expected error %v, got %v", tc.wantErr, err)
					}
				} else if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			})
		}
	}
}

func TestValidateCredentialContent_NoneMode_StillChecksDates(t *testing.T) {
	past := baseTime.Add(-1 * time.Hour)
	// Even in "none" mode, expired credentials must be rejected.
	cred := makeCredential(nil, tp(past))
	validator := CredentialValidator{validationMode: ValidationModeNone, clock: fixedClock{t: baseTime}}
	result, err := validator.ValidateVC(cred, nil)
	if result || !isErr(err, ErrorCredentialExpired) {
		t.Fatalf("none mode should still reject expired credential, got result=%v err=%v", result, err)
	}
}

func TestValidateCredentialContent_ExactBoundary(t *testing.T) {
	// validFrom == now is still valid (inclusive).
	fromCred := makeCredential(tp(baseTime), nil)
	fromValidator := CredentialValidator{validationMode: ValidationModeCombined, clock: fixedClock{t: baseTime}}
	if _, err := fromValidator.ValidateVC(fromCred, nil); err != nil {
		t.Fatalf("credential starting exactly at now should be valid, got %v", err)
	}

	// validUntil == now is still valid (inclusive).
	untilCred := makeCredential(nil, tp(baseTime))
	untilValidator := CredentialValidator{validationMode: ValidationModeCombined, clock: fixedClock{t: baseTime}}
	if _, err := untilValidator.ValidateVC(untilCred, nil); err != nil {
		t.Fatalf("credential expiring exactly at now should be valid, got %v", err)
	}
}

func TestValidateCredentialContent_ZeroLengthValidityPeriod(t *testing.T) {
	// validFrom == validUntil is always rejected, regardless of now.
	cred := makeCredential(tp(baseTime), tp(baseTime))
	validator := CredentialValidator{validationMode: ValidationModeCombined, clock: fixedClock{t: baseTime}}
	_, err := validator.ValidateVC(cred, nil)
	if !isErr(err, ErrorCredentialInvalidValidityPeriod) {
		t.Fatalf("credential with validFrom == validUntil should be rejected, got %v", err)
	}
}

// isErr reports whether err wraps or equals target.
func isErr(err, target error) bool {
	if err == target {
		return true
	}
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(unwrapper)
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return false
}
