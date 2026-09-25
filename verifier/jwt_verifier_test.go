package verifier

import (
	"strings"
	"testing"
	"time"

	common "github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

// ---------------------------------------------------------------------------
// DeprecatedValidationModes and WarnDeprecatedMode tests
// ---------------------------------------------------------------------------

func TestDeprecatedValidationModes(t *testing.T) {
	// Verify that the deprecated set contains exactly the expected modes.
	if !DeprecatedValidationModes[ValidationModeCombined] {
		t.Error("expected 'combined' to be in DeprecatedValidationModes")
	}
	if !DeprecatedValidationModes[ValidationModeJsonLd] {
		t.Error("expected 'jsonLd' to be in DeprecatedValidationModes")
	}
	if DeprecatedValidationModes[ValidationModeNone] {
		t.Error("'none' should not be in DeprecatedValidationModes")
	}
	if DeprecatedValidationModes[ValidationModeBaseContext] {
		t.Error("'baseContext' should not be in DeprecatedValidationModes")
	}
}

func TestWarnDeprecatedMode(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		expectWarnAt bool
	}{
		{
			name:         "combined is deprecated and logs a warning",
			mode:         ValidationModeCombined,
			expectWarnAt: true,
		},
		{
			name:         "jsonLd is deprecated and logs a warning",
			mode:         ValidationModeJsonLd,
			expectWarnAt: true,
		},
		{
			name:         "none is not deprecated — no warning",
			mode:         ValidationModeNone,
			expectWarnAt: false,
		},
		{
			name:         "baseContext is not deprecated — no warning",
			mode:         ValidationModeBaseContext,
			expectWarnAt: false,
		},
		{
			name:         "empty string — no warning",
			mode:         "",
			expectWarnAt: false,
		},
		{
			name:         "unknown mode — no warning",
			mode:         "unknownMode",
			expectWarnAt: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set up an observed logger so we can inspect log output.
			core, recorded := observer.New(zapcore.WarnLevel)
			testLogger := zap.New(core).Sugar()
			prev := logging.SetTestLogger(testLogger)
			defer logging.SetTestLogger(prev)

			WarnDeprecatedMode(tc.mode)

			warnCount := recorded.FilterLevelExact(zapcore.WarnLevel).Len()
			if tc.expectWarnAt && warnCount == 0 {
				t.Errorf("expected a Warn-level log entry for mode %q, but none was recorded", tc.mode)
			}
			if !tc.expectWarnAt && warnCount > 0 {
				t.Errorf("expected no Warn-level log entry for mode %q, but got %d", tc.mode, warnCount)
			}

			if tc.expectWarnAt {
				msg := recorded.FilterLevelExact(zapcore.WarnLevel).All()[0].Message
				if !strings.Contains(msg, tc.mode) {
					t.Errorf("expected warning message to mention mode %q, got: %s", tc.mode, msg)
				}
				if !strings.Contains(msg, "does not perform real JSON-LD validation") {
					t.Errorf("expected warning message to mention missing JSON-LD validation, got: %s", msg)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// VC Data Model version filtering tests
// ---------------------------------------------------------------------------

// makeCredentialWithContext creates a credential with the given @context array and a valid issuer/type.
func makeCredentialWithContext(contexts []string) *common.Credential {
	return makeCredentialWithContextAndFormat(contexts, common.FormatLDPVC)
}

// makeCredentialWithContextAndFormat creates a credential with the given @context array,
// a valid issuer/type and the given credential format. The format decides whether the
// version gate applies at all, so it has to be settable per test case.
func makeCredentialWithContextAndFormat(contexts []string, format string) *common.Credential {
	c, _ := common.CreateCredential(common.CredentialContents{
		Context: contexts,
		Issuer:  &common.Issuer{ID: "did:web:example.com"},
		Types:   []string{"VerifiableCredential"},
		Subject: []common.Subject{{CustomFields: map[string]interface{}{"name": "test"}}},
	}, common.CustomFields{})
	c.SetFormat(format)
	return c
}

func TestValidateVC_VCDataModelVersionFiltering(t *testing.T) {
	tests := []struct {
		name     string
		contexts []string
		// format defaults to ldp_vc when empty; only SD-JWT is exempt from the gate.
		format              string
		vcDataModelVersions []string
		validationMode      string
		wantErr             error
	}{
		{
			name:                "V1 credential accepted when config allows 1.1",
			contexts:            []string{common.ContextCredentialsV1},
			vcDataModelVersions: []string{common.VCDataModelVersion11},
			validationMode:      ValidationModeNone,
			wantErr:             nil,
		},
		{
			name:                "V2 credential accepted when config allows 2.0",
			contexts:            []string{common.ContextCredentialsV2},
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             nil,
		},
		{
			name:                "V1 credential rejected when config allows only 2.0",
			contexts:            []string{common.ContextCredentialsV1},
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "V2 credential rejected when config allows only 1.1",
			contexts:            []string{common.ContextCredentialsV2},
			vcDataModelVersions: []string{common.VCDataModelVersion11},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "V1 credential accepted when config allows both",
			contexts:            []string{common.ContextCredentialsV1},
			vcDataModelVersions: []string{common.VCDataModelVersion11, common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             nil,
		},
		{
			name:                "V2 credential accepted when config allows both",
			contexts:            []string{common.ContextCredentialsV2},
			vcDataModelVersions: []string{common.VCDataModelVersion11, common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             nil,
		},
		{
			// A document carrying both base contexts is valid under neither data model,
			// so it must not satisfy either allowlist.
			name:                "credential with both V1 and V2 contexts rejected when config allows 1.1",
			contexts:            []string{common.ContextCredentialsV1, common.ContextCredentialsV2},
			vcDataModelVersions: []string{common.VCDataModelVersion11},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "credential with both V1 and V2 contexts rejected when config allows 2.0",
			contexts:            []string{common.ContextCredentialsV1, common.ContextCredentialsV2},
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "credential with both V1 and V2 contexts rejected when config allows both",
			contexts:            []string{common.ContextCredentialsV1, common.ContextCredentialsV2},
			vcDataModelVersions: []string{common.VCDataModelVersion11, common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			// The base context must lead; a v2 context appended after a custom one
			// does not make the credential a v2 credential.
			name:                "V2 base context in second position rejected when config allows 2.0",
			contexts:            []string{"https://example.com/custom/v1", common.ContextCredentialsV2},
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "V2 base context followed by a suite context accepted when config allows 2.0",
			contexts:            []string{common.ContextCredentialsV2, "https://w3id.org/security/suites/jws-2020/v1"},
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             nil,
		},
		{
			name:                "unknown context rejected when config allows 1.1 — mode none",
			contexts:            []string{"https://example.com/unknown/v1"},
			vcDataModelVersions: []string{common.VCDataModelVersion11},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "unknown context rejected when config allows both — mode none",
			contexts:            []string{"https://example.com/unknown/v1"},
			vcDataModelVersions: []string{common.VCDataModelVersion11, common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			// A JSON-LD credential MUST declare a recognized base context. Missing one,
			// it declares no data model version and the gate rejects it - the gate must
			// not be bypassable by omitting or mangling the @context.
			name:                "context-less ldp_vc rejected when config allows both — mode none",
			contexts:            []string{},
			format:              common.FormatLDPVC,
			vcDataModelVersions: []string{common.VCDataModelVersion11, common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "context-less jwt_vc rejected when config allows only 2.0 — mode none",
			contexts:            nil,
			format:              common.FormatJWTVC,
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			// SD-JWT VCs are IETF credentials typed via `vct`; they carry no @context
			// and are the only format exempt from the version gate.
			name:                "context-less SD-JWT accepted when config allows only 2.0 — mode none",
			contexts:            nil,
			format:              common.FormatSDJWT,
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             nil,
		},
		{
			// Even an SD-JWT that somehow carries a v1.1 context stays exempt: the
			// exemption is keyed on the format, not on the absence of a context.
			name:                "SD-JWT with V1 context accepted when config allows only 2.0 — mode none",
			contexts:            []string{common.ContextCredentialsV1},
			format:              common.FormatSDJWT,
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             nil,
		},
		{
			name:                "unknown context rejected when config allows both — mode combined",
			contexts:            []string{"https://example.com/unknown/v1"},
			vcDataModelVersions: []string{common.VCDataModelVersion11, common.VCDataModelVersion20},
			validationMode:      ValidationModeCombined,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "unknown context rejected when config allows both — mode baseContext",
			contexts:            []string{"https://example.com/unknown/v1"},
			vcDataModelVersions: []string{common.VCDataModelVersion11, common.VCDataModelVersion20},
			validationMode:      ValidationModeBaseContext,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "V1 credential accepted in combined mode with config allows 1.1",
			contexts:            []string{common.ContextCredentialsV1},
			vcDataModelVersions: []string{common.VCDataModelVersion11},
			validationMode:      ValidationModeCombined,
			wantErr:             nil,
		},
		{
			name:                "V2 credential accepted in baseContext mode with config allows 2.0",
			contexts:            []string{common.ContextCredentialsV2},
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeBaseContext,
			wantErr:             nil,
		},
		// --- vc+jwt (VC-JOSE-COSE) format tests ---
		// vc+jwt credentials carry @context and participate in the version gate,
		// just like jwt_vc and ldp_vc. They are NOT exempt like SD-JWT.
		{
			name:                "vc+jwt V2 credential accepted when config allows 2.0",
			contexts:            []string{common.ContextCredentialsV2},
			format:              common.FormatVCJWT,
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             nil,
		},
		{
			name:                "vc+jwt V2 credential rejected when config allows only 1.1",
			contexts:            []string{common.ContextCredentialsV2},
			format:              common.FormatVCJWT,
			vcDataModelVersions: []string{common.VCDataModelVersion11},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "vc+jwt V1 credential rejected when config allows only 2.0",
			contexts:            []string{common.ContextCredentialsV1},
			format:              common.FormatVCJWT,
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "vc+jwt with no context rejected when config allows both",
			contexts:            nil,
			format:              common.FormatVCJWT,
			vcDataModelVersions: []string{common.VCDataModelVersion11, common.VCDataModelVersion20},
			validationMode:      ValidationModeNone,
			wantErr:             ErrorVCDataModelVersionNotAccepted,
		},
		{
			name:                "vc+jwt V2 credential accepted in baseContext mode with config allows 2.0",
			contexts:            []string{common.ContextCredentialsV2},
			format:              common.FormatVCJWT,
			vcDataModelVersions: []string{common.VCDataModelVersion20},
			validationMode:      ValidationModeBaseContext,
			wantErr:             nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			format := tc.format
			if format == "" {
				format = common.FormatLDPVC
			}
			cred := makeCredentialWithContextAndFormat(tc.contexts, format)
			validator := CredentialValidator{
				validationMode:      tc.validationMode,
				vcDataModelVersions: tc.vcDataModelVersions,
			}
			result, err := validator.ValidateVC(cred, nil)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.wantErr)
				}
				if !isErr(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				if result {
					t.Fatal("expected result=false when error is returned")
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if !result {
					t.Fatal("expected result=true")
				}
			}
		})
	}
}

func TestValidateVC_EmptyVersionConfig_SkipsVersionCheck(t *testing.T) {
	// When vcDataModelVersions is empty (nil), the version gate is skipped
	// and any context passes through to mode-specific validation.
	cred := makeCredentialWithContext([]string{"https://example.com/unknown/v1"})
	validator := CredentialValidator{
		validationMode:      ValidationModeNone,
		vcDataModelVersions: nil,
	}
	result, err := validator.ValidateVC(cred, nil)
	if err != nil {
		t.Fatalf("expected no error when vcDataModelVersions is nil, got %v", err)
	}
	if !result {
		t.Fatal("expected result=true when vcDataModelVersions is nil")
	}
}

// TestValidateVC_SdJwtCredentialSkipsVersionCheck ensures that a credential built
// from SD-JWT claims — which carries no @context, only a `vct` type — passes the
// version gate even when the allowlist is fully populated (the default).
func TestValidateVC_SdJwtCredentialSkipsVersionCheck(t *testing.T) {
	parser := ConfigurableSdJwtParser{}
	cred, err := parser.ClaimsToCredential(map[string]interface{}{
		common.JWTClaimIss: "did:key:zDnaefBaD8o4NH1CdozDSkRujXpL5hYs4CPsN12oycxBq8jLf",
		common.JWTClaimVct: "CustomerCredential",
		"familyName":       "Doe",
	})
	if err != nil {
		t.Fatalf("unexpected error building the SD-JWT credential: %v", err)
	}

	for _, mode := range []string{ValidationModeNone, ValidationModeCombined, ValidationModeJsonLd} {
		t.Run(mode, func(t *testing.T) {
			validator := CredentialValidator{
				validationMode:      mode,
				vcDataModelVersions: common.VCDataModelVersionAll(),
			}
			result, err := validator.ValidateVC(cred, nil)
			if err != nil {
				t.Fatalf("expected no error for an SD-JWT credential, got %v", err)
			}
			if !result {
				t.Fatal("expected an SD-JWT credential to be accepted")
			}
		})
	}
}

func TestValidateVC_VersionCheckBeforeDateCheck(t *testing.T) {
	// The version check should run before the date check. An expired credential
	// with a disallowed version should get the version error, not the expiry error.
	past := baseTime.Add(-24 * time.Hour)
	c, _ := common.CreateCredential(common.CredentialContents{
		Context:    []string{common.ContextCredentialsV2},
		Issuer:     &common.Issuer{ID: "did:web:example.com"},
		Types:      []string{"VerifiableCredential"},
		Subject:    []common.Subject{{CustomFields: map[string]interface{}{"name": "test"}}},
		ValidUntil: tp(past),
	}, common.CustomFields{})

	validator := CredentialValidator{
		validationMode:      ValidationModeNone,
		clock:               fixedClock{t: baseTime},
		vcDataModelVersions: []string{common.VCDataModelVersion11}, // only V1 allowed
	}
	_, err := validator.ValidateVC(c, nil)
	if !isErr(err, ErrorVCDataModelVersionNotAccepted) {
		t.Fatalf("expected ErrorVCDataModelVersionNotAccepted (version check before date check), got %v", err)
	}
}

func TestHasOverlap(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{"both empty", nil, nil, false},
		{"a empty", nil, []string{"1.1"}, false},
		{"b empty", []string{"1.1"}, nil, false},
		{"no overlap", []string{"1.1"}, []string{"2.0"}, false},
		{"exact match", []string{"1.1"}, []string{"1.1"}, true},
		{"overlap with extras", []string{"1.1", "2.0"}, []string{"2.0", "3.0"}, true},
		{"multiple overlaps", []string{"1.1", "2.0"}, []string{"1.1", "2.0"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hasOverlap(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("hasOverlap(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestIsVersionedDataModelCredential_FormatDispatch verifies that the version
// gate applies to every W3C credential format (jwt_vc, ldp_vc, vc+jwt) and
// exempts only SD-JWT. The vp+jwt format is not tested here because the gate
// acts on credentials, not presentations — but the gate helper would treat
// it as versioned too since it is not SD-JWT.
func TestIsVersionedDataModelCredential_FormatDispatch(t *testing.T) {
	tests := []struct {
		name   string
		format string
		want   bool
	}{
		{"jwt_vc is versioned", common.FormatJWTVC, true},
		{"ldp_vc is versioned", common.FormatLDPVC, true},
		{"vc+jwt is versioned", common.FormatVCJWT, true},
		{"vp+jwt is versioned", common.FormatVPJWT, true},
		{"sd-jwt is exempt", common.FormatSDJWT, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred := makeCredentialWithContextAndFormat(
				[]string{common.ContextCredentialsV2}, tc.format,
			)
			got := isVersionedDataModelCredential(cred)
			if got != tc.want {
				t.Errorf("isVersionedDataModelCredential(format=%q) = %v, want %v",
					tc.format, got, tc.want)
			}
		})
	}
}
