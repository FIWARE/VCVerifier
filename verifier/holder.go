package verifier

import (
	"errors"
	"strings"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
)

type HolderValidationService struct{}

var ErrorNoHolderClaim = errors.New("Credential has not holder claim")

func (hvs *HolderValidationService) ValidateVC(verifiableCredential *common.Credential, validationContext ValidationContext) (result bool, err error) {
	logging.Log().Debugf("Validate holder for %s", logging.PrettyPrintObject(verifiableCredential))
	defer func() {
		if recErr := recover(); recErr != nil {
			logging.Log().Warnf("HolderValidationService: Was not able to convert context. Err: %v", recErr)
			err = ErrorCannotConverContext
		}
	}()
	holderContext := validationContext.(HolderValidationContext)

	path := strings.Split(holderContext.claim, ".")
	pathLength := len(path)

	credentialJson := verifiableCredential.ToRawJSON()
	currentClaim := credentialJson["credentialSubject"].(map[string]interface{})
	for i, p := range path {
		if i == pathLength-1 {
			valid := currentClaim[p].(string) == holderContext.holder
			if !valid {
				logging.Log().Debugf("Credential %v has not expected holder '%s' at claim path '%s'", logging.PrettyPrintObject(credentialJson), holderContext.holder, holderContext.claim)
			}
			return valid, err
		}
		currentClaim = currentClaim[p].(common.JSONObject)
	}
	logging.Log().Warnf("Credential %v has not holder claim '%s'", logging.PrettyPrintObject(verifiableCredential), holderContext.claim)
	return false, ErrorNoHolderClaim
}
