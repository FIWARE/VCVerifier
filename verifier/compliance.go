package verifier

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/vc-go/verifiable"
)

const (
	GAIA_X_COMPLIANCE_SUBJECT_TYPE = "gx:compliance"
)

type ComplianceValidationContext struct {
	complianceSubjects []ComplianceSubject
}

type ComplianceValidationService struct{}

func (cvs *ComplianceValidationService) ValidateVC(verifiableCredential *verifiable.Credential, validationContext ValidationContext) (result bool, err error) {
	logging.Log().Debugf("Validate compliance for %s", logging.PrettyPrintObject(verifiableCredential))
	defer func() {
		if recErr := recover(); recErr != nil {
			logging.Log().Warnf("Was not able to convert context. Err: %v", recErr)
			err = ErrorCannotConverContext
		}
	}()
	complianceContext := validationContext.(ComplianceValidationContext)
	credentialId := verifiableCredential.Contents().ID

	for _, complianceSubject := range complianceContext.complianceSubjects {

		logging.Log().Debugf("The compliance subject ID %v - cred id %v", complianceSubject.Id, credentialId)

		if complianceSubject.Type == GAIA_X_COMPLIANCE_SUBJECT_TYPE && complianceSubject.Id == credentialId {
			json, _ := verifiableCredential.MarshalJSON()
			logging.Log().Debugf("The raw credential %v", string(json))
			return checkSignature(json, complianceSubject.Integrity)
		}

	}
	return false, err
}

func checkSignature(rawCredential []byte, signature string) (valid bool, err error) {

	canonicalized, err := jsoncanonicalizer.Transform(rawCredential)
	if err != nil {
		logging.Log().Warnf("Was not able to canonicalize credential %v. Error: %v", string(rawCredential), err)
		return false, err
	}

	hash := sha256.Sum256(canonicalized)
	hashHex := "sha256-" + hex.EncodeToString(hash[:])
	logging.Log().Debugf("The created signature is %s - the signature to test %s.", hashHex, signature)

	return hashHex == signature, err
}

type ComplianceSubject struct {
	Type                   string `json:"type"`
	Id                     string `json:"id"`
	Integrity              string `json:"gx:integrity"`
	IntegrityNormalization string `json:"gx:integrityNormalization"`
	Version                string `json:"gx:version"`
	GxType                 string `json:"gx:type"`
}
