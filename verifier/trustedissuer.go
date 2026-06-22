package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/PaesslerAG/jsonpath"
	"github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/exp/slices"
)

const WILDCARD_TIL = "*"

// baseCredentialTypes are the generic W3C container types that are present on
// every credential (e.g. a `jwt_vc_json` credential carries the base
// `VerifiableCredential` type alongside its specific type). They are not
// trust-governed credential types of their own, so they must be skipped when
// validating issuers/types against the trust registry. Without this, a
// spec-compliant W3C credential of type ["VerifiableCredential", "<specific>"]
// would be rejected because no trusted-issuer entry exists for the base type.
var baseCredentialTypes = map[string]bool{
	"VerifiableCredential":   true,
	"VerifiablePresentation": true,
}

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

func (tpvs *TrustedIssuerValidationService) ValidateVC(verifiableCredential *common.Credential, validationContext ValidationContext) (result bool, err error) {

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

		tilEntries, credentialSupported := til[credentialType]
		if !credentialSupported {
			// A spec-compliant W3C credential carries the generic base type
			// (e.g. "VerifiableCredential") alongside its specific type. The
			// base type is not a trust-governed type, so when it has no TIL
			// configured we skip it instead of rejecting the whole credential.
			// A base type that IS explicitly configured still gets validated.
			if baseCredentialTypes[credentialType] {
				logging.Log().Debugf("Skipping unconfigured base credential type %s.", credentialType)
				continue
			}
			logging.Log().Debugf("No trusted issuers list configured for type %s", credentialType)
			return false, ErrorNoTilForType
		}

		// Dispatch by type: collect URLs per registry type and try each.
		// "ebsi" (or empty/default) uses v3/v4 auto-detection; "ebsi-v5" uses the v5 API.
		ebsiURLs := extractTilURLsByType(tilEntries, typeEbsi)
		ebsiV5URLs := extractTilURLsByType(tilEntries, typeEbsiV5)

		var exist bool
		var trustedIssuer tir.TrustedIssuer

		// Try ebsi (v3/v4) endpoints first.
		if len(ebsiURLs) > 0 {
			exist, trustedIssuer, err = tpvs.tirClient.GetTrustedIssuer(ebsiURLs, verifiableCredential.Contents().Issuer.ID)
			if err != nil {
				logging.Log().Warnf("Was not able to validate trusted issuer via ebsi. Err: %v", err)
				return false, err
			}
		}

		// If not found via ebsi, try ebsi-v5 endpoints.
		if !exist && len(ebsiV5URLs) > 0 {
			exist, trustedIssuer, err = tpvs.tirClient.GetTrustedIssuerV5(ebsiV5URLs, verifiableCredential.Contents().Issuer.ID)
			if err != nil {
				logging.Log().Warnf("Was not able to validate trusted issuer via ebsi-v5. Err: %v", err)
				return false, err
			}
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

// isWildcardTil checks whether the given TIL list contains the wildcard
// entry ("*"). A wildcard must be the only entry; mixing it with other
// entries is considered invalid configuration.
func isWildcardTil(tilList []configModel.TrustedIssuersList) (isWildcard bool, err error) {
	if len(tilList) == 1 && tilList[0].Url == WILDCARD_TIL {
		return true, err
	}
	urls := make([]string, len(tilList))
	for i, entry := range tilList {
		urls[i] = entry.Url
	}
	if len(tilList) > 1 && slices.Contains(urls, WILDCARD_TIL) { //nolint:govet
		return false, ErrorInvalidTil
	}
	return false, err
}

// extractTilURLsByType collects URL strings from TrustedIssuersList entries
// matching the given registry type. Entries with an empty type are treated
// as "ebsi" (the default) for backward compatibility.
func extractTilURLsByType(entries []configModel.TrustedIssuersList, listType string) []string {
	urls := make([]string, 0, len(entries))
	for _, entry := range entries {
		entryType := entry.Type
		if entryType == "" {
			entryType = typeEbsi
		}
		if entryType == listType {
			urls = append(urls, entry.Url)
		}
	}
	return urls
}

func verifyWithCredentialsConfig(verifiableCredential *common.Credential, credentials []tir.Credential) (result bool, err error) {

	credentialsConfigMap := map[string][]tir.Credential{}

	// format for better validation
	for _, credential := range credentials {
		credentialsConfigMap[credential.CredentialsType] = append(credentialsConfigMap[credential.CredentialsType], credential)
	}

	// initialize to true, since everything without a specific rule is considered to be allowed
	var subjectAllowed = true

	// validate that the type(s) is allowed
	for _, credentialType := range verifiableCredential.Contents().Types {
		config, exists := credentialsConfigMap[credentialType]
		if !exists {
			// The generic base type (e.g. "VerifiableCredential") is not a
			// trust-governed type; when the issuer has no entry for it we skip
			// it rather than rejecting the credential. An explicitly configured
			// base type still gets validated.
			if baseCredentialTypes[credentialType] {
				continue
			}
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

// verifyForType returns true if the subject satisfies at least one credential config (OR).
// Each config is satisfied only if all its claims are valid (AND).
func verifyForType(subjectToVerify common.Subject, credentialConfig []tir.Credential) bool {
	for _, config := range credentialConfig {
		allClaimsValid := true
		for _, claim := range config.Claims {
			if claim.Path != "" {
				if !verifyWithJsonPath(subjectToVerify, claim) {
					logging.Log().Warnf("Claim with path %s is not valid.", claim.Path)
					allClaimsValid = false
					break
				}
				logging.Log().Debugf("Claim with path %s is valid. Credential Subject %s", claim.Path, logging.PrettyPrintObject(subjectToVerify))
			} else {
				// legacy name-based validation
				claimValue, exists := subjectToVerify.CustomFields[claim.Name]
				if !exists {
					logging.Log().Debugf("Claim %s is not present in subject %s, skipping.", claim.Name, logging.PrettyPrintObject(subjectToVerify))
					continue
				}
				if !contains(claim.AllowedValues, claimValue) {
					logging.Log().Debugf("Claim value %s is not allowed by config %s.", logging.PrettyPrintObject(claimValue), logging.PrettyPrintObject(credentialConfig))
					allClaimsValid = false
					break
				}
			}
		}
		if allClaimsValid {
			logging.Log().Debugf("No forbidden claim found for subject %s. Checked config was %s.", logging.PrettyPrintObject(subjectToVerify), logging.PrettyPrintObject(credentialConfig))
			return true
		}
	}
	logging.Log().Debugf("No credential config matched for subject %s. Config: %s.", logging.PrettyPrintObject(subjectToVerify), logging.PrettyPrintObject(credentialConfig))
	return false
}

func verifyWithJsonPath(subjectToVerfiy common.Subject, claim tir.Claim) (result bool) {
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
		return slices.Contains(claim.AllowedValues, claimValues) //nolint:govet
	}

}

func toSliceOfMaps(raw []interface{}) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(raw))

	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			logging.Log().Warnf("Was not able to convert the allowed values, don't allow anything. V: %v", item)
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
			logging.Log().Warn("Not able to marshal one of the interfaces.")
			continue
		}
		if slices.Compare(jsonBytes, jsonBytesToCheck) == 0 { //nolint:govet
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
