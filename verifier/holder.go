package verifier

import (
	"strings"

	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/vc-go/verifiable"
)

type HolderValidationService struct{}

func (hvs *HolderValidationService) ValidateVC(verifiableCredential *verifiable.Credential, validationContext ValidationContext) (result bool, err error) {
	logging.Log().Debugf("Validate holder for %s", logging.PrettyPrintObject(verifiableCredential))
	defer func() {
		if recErr := recover(); recErr != nil {
			logging.Log().Warnf("Was not able to convert context. Err: %v", recErr)
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
			return currentClaim[p].(string) == holderContext.holder, err
		}
		currentClaim = currentClaim[p].(verifiable.JSONObject)
	}
	return false, err
}
