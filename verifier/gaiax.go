package verifier

import (
	"errors"
	"fmt"

	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/gaiax"
	"github.com/trustbloc/vc-go/verifiable"
	"golang.org/x/exp/slices"

	logging "github.com/fiware/VCVerifier/logging"
)

const gaiaxCompliancePolicy = "GaiaXComplianceIssuer"
const registryUrlPropertyName = "registryAddress"

var ErrorNoTrustedIssuer = errors.New("Issuer is not in trusted issuer list")

type GaiaXRegistryValidationService struct {
	validateAll               bool
	credentialTypesToValidate []string
	// client for gaiax registry connection
	gaiaxRegistryClient gaiax.RegistryClient
}

func InitGaiaXRegistryValidationService(verifierConfig *configModel.Verifier) GaiaXRegistryValidationService {
	var url string
	verifier := GaiaXRegistryValidationService{credentialTypesToValidate: []string{}}

	for policyName, arguments := range verifierConfig.PolicyConfig.DefaultPolicies {
		if policyName == gaiaxCompliancePolicy {
			url = fmt.Sprintf("%v", arguments[registryUrlPropertyName])
			verifier.validateAll = true
		}
	}
	for credentialType, policies := range verifierConfig.PolicyConfig.CredentialTypeSpecificPolicies {
		for policyName, arguments := range policies {
			if policyName == gaiaxCompliancePolicy {
				url = fmt.Sprintf("%v", arguments[registryUrlPropertyName])
				verifier.credentialTypesToValidate = append(verifier.credentialTypesToValidate, credentialType)
			}
		}
	}
	if len(url) > 0 {
		verifier.gaiaxRegistryClient = gaiax.InitGaiaXRegistryVerificationService(url)
	}
	return verifier
}

func (v *GaiaXRegistryValidationService) ValidateVC(verifiableCredential *verifiable.Credential, validationContext ValidationContext) (result bool, err error) {
	isContained := false
	for _, t := range verifiableCredential.Contents().Types {
		isContained = slices.Contains(v.credentialTypesToValidate, t)
		if isContained {
			break
		}
	}

	if v.validateAll || isContained {
		issuerDids, err := v.gaiaxRegistryClient.GetComplianceIssuers()
		if err != nil {
			return false, err
		}
		if slices.Contains(issuerDids, verifiableCredential.Contents().Issuer.ID) {
			logging.Log().Info("Credential was issued by trusted issuer")
			return true, nil
		} else {
			logging.Log().Warnf("Failed to validate credential %s. Issuer was not in trusted issuer list", logging.PrettyPrintObject(verifiableCredential))
			return false, ErrorNoTrustedIssuer
		}
	}
	// No need to validate
	return true, nil
}
