package verifier

import (
	"errors"

	"github.com/fiware/VCVerifier/gaiax"
	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
	"github.com/trustbloc/vc-go/verifiable"
)

var ErrorCannotConverContext = errors.New("cannot_convert_context")
var ErrorInvalidCredential = errors.New("invalid_trusted_participant_type")

const (
	typeGaiaX = "gaia-x"
	typeEbsi  = "ebsi"
)

/**
*	The trusted participant validation service will validate the entry of a participant within the trusted list.
 */
type TrustedParticipantValidationService struct {
	tirClient   tir.TirClient
	gaiaXClient gaiax.GaiaXClient
}

func (tpvs *TrustedParticipantValidationService) ValidateVC(verifiableCredential *verifiable.Credential, validationContext ValidationContext) (result bool, err error) {

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

	for _, listEntries := range trustContext.GetTrustedParticipantLists() {
		for _, participantList := range listEntries {
			if participantList.Type == typeEbsi {
				logging.Log().Debug("Check at ebsi.")
				result = tpvs.tirClient.IsTrustedParticipant(participantList.Url, verifiableCredential.Contents().Issuer.ID)
			}
			if participantList.Type == typeGaiaX {
				logging.Log().Debug("Check at gaia-x.")
				result = tpvs.gaiaXClient.IsTrustedParticipant(participantList.Url, verifiableCredential.Contents().Issuer.ID)
			}
			if result {
				return result, err
			}
		}
	}

	return false, ErrorInvalidCredential
}
