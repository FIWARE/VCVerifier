package verifier

import (
	"errors"

	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
	"github.com/trustbloc/vc-go/verifiable"
)

var ErrorCannotConverContext = errors.New("cannot_convert_context")

/**
*	The trusted participant validation service will validate the entry of a participant within the trusted list.
 */
type TrustedParticipantValidationService struct {
	tirClient tir.TirClient
}

func (tpvs *TrustedParticipantValidationService) ValidateVC(verifiableCredential *verifiable.Credential, validationContext ValidationContext) (result bool, err error) {

	logging.Log().Debugf("Verify trusted participant for %s", logging.PrettyPrintObject(verifiableCredential))
	defer func() {
		if recErr := recover(); recErr != nil {
			logging.Log().Warnf("Was not able to convert context. Err: %v", recErr)
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
	// FIXME Can we assume that if we have a VC with multiple types, its enough to check for only one type?

	for _, listEntries := range trustContext.GetTrustedParticipantLists() {
		for _, participantList := range listEntries {
			if participantList.Type == "ebsi" {
				result = tpvs.tirClient.IsTrustedParticipant(participantList.Url, verifiableCredential.Contents().Issuer.ID)
			}
			if participantList.Type == "gaia-X" {
				// gaia-x client
			}
			if result {
				return result, err
			}
		}
	}

	return false, err
}
