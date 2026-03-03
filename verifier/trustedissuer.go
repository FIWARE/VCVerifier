package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/PaesslerAG/jsonpath"
	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
	"github.com/google/go-cmp/cmp"
	"github.com/trustbloc/vc-go/verifiable"
	"golang.org/x/exp/slices"
)

const WILDCARD_TIL = "*"

var ErrorInvalidTil = errors.New("invalid_til_configured")
var ErrorEmptyTilList = errors.New("empty_til_list")
var ErrorNoTilForType = errors.New("no_til_defined_for_credential_type")
var ErrorNoTilDefined = errors.New("no_til_defined_for_credential_type")
var ErrorForbiddenClaims = errors.New("forbidden_claim_or_value")

/**
*	The trusted participant verification service will validate the entry of a participant within the trusted list.
 */
type TrustedIssuerValidationService struct {
	tirClient tir.TirClient
}

func (tpvs *TrustedIssuerValidationService) ValidateVC(verifiableCredential *verifiable.Credential, validationContext ValidationContext) (result bool, err error) {

	logging.Log().Debugf("Validate trusted issuer for %s with context %v", logging.PrettyPrintObject(verifiableCredential), validationContext)
	defer func() {
		if recErr := recover(); recErr != nil {
			logging.Log().Warnf("TrustedIssuerValidationService: Was not able to convert context. Err: %v", recErr)
			err = ErrorCannotConverContext
		}
	}()
	trustContext := validationContext.(TrustRegistriesValidationContext)

	tilSpecified := false
	for _, tl := range trustContext.GetTrustedIssuersLists() {
		if len(tl) > 0 {
			tilSpecified = true
		}
	}

	if !tilSpecified {
		logging.Log().Debug("The validation context does not specify a trusted issuers list, therefor we consider no issuer as trusted.")
		return false, ErrorEmptyTilList
	}

	til := trustContext.GetTrustedIssuersLists()
	for _, credentialType := range verifiableCredential.Contents().Types {
		isWildcard, err := isWildcardTil(til[credentialType])
		if isWildcard {
			logging.Log().Debugf("Wildcard til is configured for type %s.", credentialType)
			continue
		}
		if err != nil {
			logging.Log().Warnf("Invalid til configured for type %s.", credentialType)
			return false, err
		}

		tilAddress, credentialSupported := til[credentialType]
		if !credentialSupported {
			logging.Log().Debugf("No trusted issuers list configured for type %s", credentialType)
			return false, ErrorNoTilForType
		}

		exist, trustedIssuer, err := tpvs.tirClient.GetTrustedIssuer(tilAddress, verifiableCredential.Contents().Issuer.ID)

		if err != nil {
			logging.Log().Warnf("Was not able to validate trusted issuer. Err: %v", err)
			return false, err
		}
		if !exist {
			logging.Log().Warnf("Trusted issuer for %s does not exist in context %s.", logging.PrettyPrintObject(verifiableCredential), logging.PrettyPrintObject(validationContext))
			return false, ErrorNoTilDefined
		}
		credentials, err := parseAttributes(trustedIssuer)
		if err != nil {
			logging.Log().Warnf("Was not able to parse the issuer %s. Err: %v", logging.PrettyPrintObject(trustedIssuer), err)
			return false, err
		}
		result, err := verifyWithCredentialsConfig(verifiableCredential, credentials)
		if err != nil || !result {
			return result, err
		}
	}

	return true, err
}

func isWildcardTil(tilList []string) (isWildcard bool, err error) {
	if len(tilList) == 1 && tilList[0] == WILDCARD_TIL {
		return true, err
	}
	if len(tilList) > 1 && slices.Contains(tilList, WILDCARD_TIL) {
		return false, ErrorInvalidTil
	}
	return false, err
}

func verifyWithCredentialsConfig(verifiableCredential *verifiable.Credential, credentials []tir.Credential) (result bool, err error) {

	credentialsConfigMap := map[string]tir.Credential{}

	// format for better validation
	for _, credential := range credentials {
		credentialsConfigMap[credential.CredentialsType] = credential
	}

	// initalize to true, since everything without a specific rule is considered to be allowed
	var subjectAllowed = true

	// validate that the type(s) is allowed
	for _, credentialType := range verifiableCredential.Contents().Types {
		config, exists := credentialsConfigMap[credentialType]
		if !exists {
			logging.Log().Warnf("The credential type %s is not allowed by the config %s.", credentialType, logging.PrettyPrintObject(credentialsConfigMap))
			subjectAllowed = false
			break
		}
		// as of now, we only allow single subject credentials
		subjectAllowed = subjectAllowed && verifyForType(verifiableCredential.Contents().Subject[0], config)
	}
	if !subjectAllowed {
		logging.Log().Debugf("The subject contains forbidden claims or values: %s.", logging.PrettyPrintObject(verifiableCredential.Contents().Subject[0]))
		return false, ErrorForbiddenClaims
	}
	logging.Log().Debugf("Credential %s is allowed by the config %s.", logging.PrettyPrintObject(verifiableCredential), logging.PrettyPrintObject(credentials))
	return true, err
}

func verifyForType(subjectToVerfiy verifiable.Subject, credentialConfig tir.Credential) (result bool) {
	for _, claim := range credentialConfig.Claims {

		if claim.Path != "" {
			validClaim := verifyWithJsonPath(subjectToVerfiy, claim)
			if validClaim {
				logging.Log().Debugf("Claim with path %s is valid. Credential Subject %s", claim.Path, logging.PrettyPrintObject(subjectToVerfiy))
				continue
			} else {
				logging.Log().Warnf("Claim with path %s is not valid.", claim.Path)
				return false
			}
		} else {
			// old name base logic
			claimValue, exists := subjectToVerfiy.CustomFields[claim.Name]
			if !exists {
				logging.Log().Debugf("Restricted claim %s is not part of the subject %s.", claim.Name, logging.PrettyPrintObject(subjectToVerfiy))
				continue
			}
			isAllowed := contains(claim.AllowedValues, claimValue)
			if !isAllowed {
				logging.Log().Debugf("The claim value %s is not allowed by the config %s.", logging.PrettyPrintObject(claimValue), logging.PrettyPrintObject(credentialConfig))
				return false
			}
		}

	}
	logging.Log().Debugf("No forbidden claim found for subject %s. Checked config was %s.", logging.PrettyPrintObject(subjectToVerfiy), logging.PrettyPrintObject(credentialConfig))
	return true
}

func verifyWithJsonPath(subjectToVerfiy verifiable.Subject, claim tir.Claim) (result bool) {
	jsonSubject, _ := json.Marshal(subjectToVerfiy.CustomFields)
	var subjectAsMap map[string]interface{}
	if err := json.Unmarshal(jsonSubject, &subjectAsMap); err != nil {
		logging.Log().Warnf("Was not able to unmarshal the subject, set to invalid. Err: %v", err)
		return false
	}
	claimValues, err := jsonpath.Get(claim.Path, subjectAsMap)
	if err != nil {
		logging.Log().Warnf("Path %s does not exist in the subject, thus cannot contain invalid values. Set to valid. Err: %v", claim.Path, err)
		return true
	}
	switch claimValues := claimValues.(type) {
	case []interface{}:
		return isSubset(claimValues, claim.AllowedValues)
	case map[string]interface{}:
		return containsMap(toSliceOfMaps(claim.AllowedValues), claimValues)
	default:
		return slices.Contains(claim.AllowedValues, claimValues)
	}

}

func toSliceOfMaps(raw []interface{}) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(raw))

	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			logging.Log().Warnf("Was not able to convert the allowed values, dont allow anything. V: %v", item)
			return []map[string]interface{}{}
		}
		result = append(result, m)
	}

	return result
}

func containsMap(slice []map[string]interface{}, target map[string]interface{}) bool {
	for _, item := range slice {
		if cmp.Equal(item, target) {
			return true
		}
	}
	return false
}

func isSubset(subSet, superSet []interface{}) bool {
	for _, subVal := range subSet {
		found := false
		for _, superVal := range superSet {
			if cmp.Equal(subVal, superVal) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

/**
* Check if the given interface is contained. In order to avoid type issues(f.e. if numbers are parsed to different interfaces),
* we marshal and compare the json representation.
 */
func contains(interfaces []interface{}, interfaceToCheck interface{}) bool {
	jsonBytesToCheck, err := json.Marshal(interfaceToCheck)
	if err != nil {
		logging.Log().Warn("Was not able to marshal the interface.")
		return false
	}
	for _, i := range interfaces {
		jsonBytes, err := json.Marshal(i)
		if err != nil {
			logging.Log().Warn("Not able to marshal one of the intefaces.")
			continue
		}
		if slices.Compare(jsonBytes, jsonBytesToCheck) == 0 {
			return true
		}
	}
	logging.Log().Debugf("%s does not contain %s", logging.PrettyPrintObject(interfaces), logging.PrettyPrintObject(interfaceToCheck))

	return false
}

func parseAttributes(trustedIssuer tir.TrustedIssuer) (credentials []tir.Credential, err error) {
	credentials = []tir.Credential{}
	for _, attribute := range trustedIssuer.Attributes {
		parsedCredential, err := parseAttribute(attribute)
		if err != nil {
			logging.Log().Warnf("Was not able to parse attribute %s. Err: %v", logging.PrettyPrintObject(attribute), err)
			return credentials, err
		}
		credentials = append(credentials, parsedCredential)
	}
	return credentials, err
}

func parseAttribute(attribute tir.IssuerAttribute) (credential tir.Credential, err error) {
	decodedAttribute, err := base64.StdEncoding.DecodeString(attribute.Body)
	if err != nil {
		logging.Log().Warnf("The attribute body %s is not correctly base64 encoded. Err: %v", attribute.Body, err)
		return credential, err
	}
	err = json.Unmarshal(decodedAttribute, &credential)
	if err != nil {
		logging.Log().Warnf("Was not able to unmarshal the credential %s. Err: %v", attribute.Body, err)
	}
	return
}
