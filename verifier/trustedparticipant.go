package verifier

import (
	"errors"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/gaiax"
	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
)

var ErrorCannotConverContext = errors.New("cannot_convert_context")
var ErrorInvalidCredential = errors.New("invalid_trusted_participant_type")

const (
	typeGaiaX  = "gaia-x"
	typeEbsi   = "ebsi"
	typeEbsiV5 = "ebsi-v5"
)

/**
*	The trusted participant validation service will validate the entry of a participant within the trusted list.
 */
type TrustedParticipantValidationService struct {
	tirClient   tir.TirClient
	gaiaXClient gaiax.GaiaXClient
}

func (tpvs *TrustedParticipantValidationService) ValidateVC(verifiableCredential *common.Credential, validationContext ValidationContext) (result bool, err error) {

	logging.Log().Debugf("Verify trusted participant for %s", logging.PrettyPrintObject(verifiableCredential))
	defer func() {
		if recErr := recover(); recErr != nil {
			logging.Log().Warnf("TrustedParticipantValidationService: Was not able to convert context. Err: %v", recErr)
			err = ErrorCannotConverContext
		}
	}()
	trustContext := validationContext.(TrustRegistriesValidationContext)

	tirSpecified := false
	for _, pl := range trustContext.GetTrustedParticipantLists() {
		if len(pl) > 0 {
			tirSpecified = true
			break
		}
	}

	if !tirSpecified {
		logging.Log().Debug("The validation context does not specify a trusted issuers registry, therefor we consider every participant as trusted.")
		return true, err
	}

	issuerID := verifiableCredential.Contents().Issuer.ID

	// HTTPS-URL-based issuers are validated by URL matching against the
	// configured trusted participant URLs. Cryptographic trust was already
	// established during JWT signature verification (via HTTPS metadata
	// discovery and JWKS). This check applies regardless of the trust list
	// Type — an HTTPS issuer is never looked up in an external registry.
	if isHttpsIssuer(issuerID) {
		for _, listEntries := range trustContext.GetTrustedParticipantLists() {
			for _, participantList := range listEntries {
				if matchesHttpsIssuerURL(issuerID, participantList.Url) {
					logging.Log().Debugf("HTTPS issuer %s matched trusted participant URL %s.", issuerID, participantList.Url)
					return true, err
				}
			}
		}
		logging.Log().Warnf("HTTPS issuer %s did not match any configured trusted participant URL.", issuerID)
		return false, ErrorInvalidCredential
	}

	// DID-based issuers continue through the existing type-based dispatch.
	for _, listEntries := range trustContext.GetTrustedParticipantLists() {
		for _, participantList := range listEntries {
			if participantList.Type == typeEbsi {
				logging.Log().Debug("Check at ebsi.")
				result = tpvs.tirClient.IsTrustedParticipant(participantList.Url, issuerID)
			}
			if participantList.Type == typeEbsiV5 {
				logging.Log().Debug("Check at ebsi-v5.")
				result = tpvs.tirClient.IsTrustedParticipantV5(participantList.Url, issuerID)
			}
			if participantList.Type == typeGaiaX {
				logging.Log().Debug("Check at gaia-x.")
				result = tpvs.gaiaXClient.IsTrustedParticipant(participantList.Url, issuerID)
			}
			if result {
				return result, err
			}
		}
	}

	return false, ErrorInvalidCredential
}

// matchesHttpsIssuerURL checks whether an HTTPS issuer URL matches a
// configured trusted URL. The wildcard value "*" matches any issuer.
// Otherwise an exact string match is performed.
func matchesHttpsIssuerURL(issuerURL, trustedURL string) bool {
	if trustedURL == WILDCARD_TIL {
		return true
	}
	return issuerURL == trustedURL
}
