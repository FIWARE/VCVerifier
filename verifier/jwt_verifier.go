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
)

var SupportedModes = []string{ValidationModeNone, ValidationModeCombined, ValidationModeJsonLd, ValidationModeBaseContext}

// CredentialValidator validates credential content (not signatures — those are checked by JWTProofChecker).
type CredentialValidator struct {
	validationMode string
	clock          common.Clock
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
// Temporal validity (validFrom/validUntil) is always enforced regardless of mode.
func (cv CredentialValidator) ValidateVC(verifiableCredential *common.Credential, verificationContext ValidationContext) (result bool, err error) {
	if ok, err := validateCredentialDates(verifiableCredential.Contents(), cv.now()); !ok {
		return false, err
	}

	switch cv.validationMode {
	case ValidationModeNone:
		return true, nil
	case ValidationModeCombined:
		return validateCredentialContent(verifiableCredential)
	case ValidationModeJsonLd:
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

// validateCredentialDates checks validFrom and validUntil against now, both bounds inclusive:
// the credential is valid for now in [validFrom, validUntil]. A zero-length validity period
// (validFrom == validUntil) is always rejected. Either field being absent is not an error.
func validateCredentialDates(contents common.CredentialContents, now time.Time) (bool, error) {
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
