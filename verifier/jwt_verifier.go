package verifier

import (
	"errors"
	"strings"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
)

// Validation mode constants.
const (
	ValidationModeNone        = "none"
	ValidationModeCombined    = "combined"
	ValidationModeJsonLd      = "jsonLd"
	ValidationModeBaseContext = "baseContext"
)

// W3C base context credential types.
const (
	TypeVerifiableCredential   = "VerifiableCredential"
	TypeVerifiablePresentation = "VerifiablePresentation"
)

var (
	ErrorNoVerificationKey               = errors.New("no_verification_key")
	ErrorNotAValidVerficationMethod      = errors.New("not_a_valid_verfication_method")
	ErrorNoOriginalCredential            = errors.New("no_original_credential_for_validation")
	ErrorCredentialMissingIssuer         = errors.New("credential_missing_issuer")
	ErrorCredentialMissingType           = errors.New("credential_missing_type")
	ErrorCredentialNonBaseType           = errors.New("credential_contains_non_base_context_type")
	ErrorCredentialExpired               = errors.New("credential_expired")
	ErrorCredentialNotYetValid           = errors.New("credential_not_yet_valid")
	ErrorCredentialInvalidValidityPeriod = errors.New("credential_invalid_validity_period")
	// ErrorVCDataModelVersionNotAccepted is returned when a credential's VC Data
	// Model version (detected from its @context) is not in the configured
	// vcDataModelVersions allowlist.
	ErrorVCDataModelVersionNotAccepted = errors.New("vc_data_model_version_not_accepted")
)

var SupportedModes = []string{ValidationModeNone, ValidationModeCombined, ValidationModeJsonLd, ValidationModeBaseContext}

// DeprecatedValidationModes lists validation modes that are deprecated because
// they do not perform real JSON-LD validation — they only check field presence
// (issuer and type). Users should migrate to "none" or "baseContext".
var DeprecatedValidationModes = map[string]bool{
	ValidationModeCombined: true,
	ValidationModeJsonLd:   true,
}

// WarnDeprecatedMode logs a prominent warning if the given validation mode is
// in the deprecated set. Call this at startup so operators are aware that
// "combined" and "jsonLd" modes do NOT perform real JSON-LD validation.
func WarnDeprecatedMode(mode string) {
	if DeprecatedValidationModes[mode] {
		logging.Log().Warnf("validationMode '%s' is configured but does not perform real JSON-LD validation "+
			"— it only checks field presence. Consider using 'none' or 'baseContext' instead.", mode)
	}
}

// CredentialValidator validates credential content (not signatures — those are checked by JWTProofChecker).
type CredentialValidator struct {
	validationMode string
	clock          common.Clock
	// vcDataModelVersions is the allowlist of accepted VC Data Model versions
	// (e.g. "1.1", "2.0"). Credentials whose @context does not match any
	// version in this list are rejected before any other validation.
	vcDataModelVersions []string
}

// now returns the current time, falling back to time.Now() when no clock is injected.
func (cv CredentialValidator) now() time.Time {
	if cv.clock == nil {
		return time.Now()
	}
	return cv.clock.Now()
}

// the jwt-vc standard defines multiple options for the kid-header, while the standard implementation only allows for absolute paths.
// see https://identity.foundation/jwt-vc-presentation-profile/#kid-jose-header
// potential headers:
//   - thePublicKey(1)
//   - did:key:thePublicKey(2)
//   - did:key:thePublicKey#id(3)
func compareVerificationMethod(presentedMethod string, didDocumentMethod string) (result bool) {
	keyId, absolutePath, fullAbsolutePath, _ := getKeyFromMethod(didDocumentMethod)

	if presentedMethod != "" {
		return keyId == presentedMethod || absolutePath == presentedMethod || fullAbsolutePath == presentedMethod
	}
	logging.Log().Info("DidDocumentMethod is invalid.")
	return false

}

func getKeyFromMethod(verificationMethod string) (keyId, absolutePath, fullAbsolutePath string, err error) {
	if verificationMethod == "" {
		logging.Log().Warnf("The verification method %s is invalid.", verificationMethod)
		return "", "", "", ErrorNotAValidVerficationMethod
	}
	keyArray := strings.Split(verificationMethod, "#")
	if len(keyArray) == 2 {
		// full-absolute path - format 3
		return keyArray[1], keyArray[0], verificationMethod, nil
	} else if didParts := strings.Split(verificationMethod, ":"); len(didParts) == 1 && len(keyArray) == 1 {
		// just the key - format 1
		return verificationMethod, absolutePath, fullAbsolutePath, nil
	} else if didParts := strings.Split(verificationMethod, ":"); len(didParts) > 1 && len(keyArray) == 1 {
		// absolute path did - format 2
		return didParts[len(didParts)-1], verificationMethod, fullAbsolutePath, nil
	}

	logging.Log().Warnf("The verification method %s is invalid.", verificationMethod)
	return keyId, absolutePath, fullAbsolutePath, ErrorNotAValidVerficationMethod
}

// ValidateVC validates credential content. Signature verification is handled separately by JWTProofChecker.
//
// The VC Data Model version check runs first: if vcDataModelVersions is configured
// (non-empty), the credential's @context must match at least one allowed version.
// Credentials that declare no @context at all are not W3C Data Model credentials
// (SD-JWT VCs identify their type via `vct`) and are therefore not subject to the
// version gate — see isVersionedDataModelCredential.
// Temporal validity (validFrom/validUntil) is always enforced regardless of mode.
//
// Available modes:
//   - "none": no content validation beyond temporal checks.
//   - "combined": DEPRECATED — checks only that issuer and type fields are present.
//     Does NOT perform real JSON-LD or JSON-Schema validation despite the name.
//   - "jsonLd": DEPRECATED — identical to "combined"; checks only field presence,
//     not actual JSON-LD processing. Will be removed in a future release.
//   - "baseContext": validates that the credential uses only W3C base-context types
//     (VerifiableCredential, VerifiablePresentation) and has an issuer.
func (cv CredentialValidator) ValidateVC(verifiableCredential *common.Credential, verificationContext ValidationContext) (result bool, err error) {
	// Version gate: reject credentials whose VC Data Model version is not allowed.
	// Only credentials that declare a @context participate in the W3C data model
	// versioning; SD-JWT VCs carry none and are validated through their `vct` type.
	if len(cv.vcDataModelVersions) > 0 && isVersionedDataModelCredential(verifiableCredential) {
		detectedVersions := common.DetectVCDataModelVersion(verifiableCredential.Contents().Context)
		if !hasOverlap(detectedVersions, cv.vcDataModelVersions) {
			logging.Log().Warnf("Credential validation failed: detected VC Data Model version(s) %v not in allowed list %v",
				detectedVersions, cv.vcDataModelVersions)
			return false, ErrorVCDataModelVersionNotAccepted
		}
	}

	if ok, err := validateCredentialDates(verifiableCredential.Contents(), cv.now()); !ok {
		return false, err
	}

	switch cv.validationMode {
	case ValidationModeNone:
		return true, nil
	case ValidationModeCombined:
		// DEPRECATED: only checks issuer + type presence, not real LD/Schema validation.
		return validateCredentialContent(verifiableCredential)
	case ValidationModeJsonLd:
		// DEPRECATED: only checks issuer + type presence, not real JSON-LD validation.
		return validateCredentialContent(verifiableCredential)
	case ValidationModeBaseContext:
		return validateBaseContext(verifiableCredential)
	}
	return true, nil
}

// validateCredentialContent checks that essential credential fields are present.
func validateCredentialContent(cred *common.Credential) (bool, error) {
	contents := cred.Contents()
	if contents.Issuer == nil || contents.Issuer.ID == "" {
		logging.Log().Warn("Credential validation failed: missing issuer")
		return false, ErrorCredentialMissingIssuer
	}
	if len(contents.Types) == 0 {
		logging.Log().Warn("Credential validation failed: missing type")
		return false, ErrorCredentialMissingType
	}
	return true, nil
}

// validateBaseContext checks that the credential uses only W3C base context types and is temporally valid.
var baseContextTypes = map[string]bool{
	TypeVerifiableCredential:   true,
	TypeVerifiablePresentation: true,
}

func validateBaseContext(cred *common.Credential) (bool, error) {
	contents := cred.Contents()
	if contents.Issuer == nil || contents.Issuer.ID == "" {
		logging.Log().Warn("Credential validation failed: missing issuer")
		return false, ErrorCredentialMissingIssuer
	}
	for _, t := range contents.Types {
		if !baseContextTypes[t] {
			logging.Log().Warnf("Credential validation failed: non-base-context type %s", t)
			return false, ErrorCredentialNonBaseType
		}
	}
	return true, nil
}

// hasOverlap reports whether slices a and b share at least one common element.
func hasOverlap(a, b []string) bool {
	set := make(map[string]bool, len(b))
	for _, v := range b {
		set[v] = true
	}
	for _, v := range a {
		if set[v] {
			return true
		}
	}
	return false
}

// isVersionedDataModelCredential reports whether the credential takes part in the
// W3C VC Data Model versioning, i.e. whether it declares a @context at all.
//
// Only JSON-LD based credentials (`ldp_vc`, `jwt_vc_json`) carry a @context and
// therefore a data model version. An SD-JWT VC (`dc+sd-jwt` / `vc+sd-jwt`) is an
// IETF credential whose type is given by the `vct` claim; it has no @context and
// no data model version, so the vcDataModelVersions allowlist does not apply to
// it. A credential declaring an unknown @context still participates and is
// rejected by the version gate.
func isVersionedDataModelCredential(credential *common.Credential) bool {
	return len(credential.Contents().Context) > 0
}

// validateCredentialDates checks validFrom and validUntil against now, both bounds inclusive:
// the credential is valid for now in [validFrom, validUntil]. A zero-length validity period
// (validFrom == validUntil) is always rejected. Either field being absent is not an error.
func validateCredentialDates(contents common.CredentialContents, now time.Time) (bool, error) {
	logging.Log().Debugf("Validating credential dates: validFrom=%v, validUntil=%v, now=%v", contents.ValidFrom, contents.ValidUntil, now)
	if contents.ValidFrom != nil && contents.ValidUntil != nil && contents.ValidFrom.Equal(*contents.ValidUntil) {
		logging.Log().Warnf("Credential validation failed: zero-length validity period (validFrom == validUntil: %s)", contents.ValidFrom.Format(time.RFC3339))
		return false, ErrorCredentialInvalidValidityPeriod
	}
	if contents.ValidFrom != nil && now.Before(*contents.ValidFrom) {
		logging.Log().Warnf("Credential validation failed: not yet valid (validFrom: %s, now: %s)", contents.ValidFrom.Format(time.RFC3339), now.Format(time.RFC3339))
		return false, ErrorCredentialNotYetValid
	}
	if contents.ValidUntil != nil && now.After(*contents.ValidUntil) {
		logging.Log().Warnf("Credential validation failed: expired (validUntil: %s, now: %s)", contents.ValidUntil.Format(time.RFC3339), now.Format(time.RFC3339))
		return false, ErrorCredentialExpired
	}
	return true, nil
}
