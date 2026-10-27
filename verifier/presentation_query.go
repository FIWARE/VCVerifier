package verifier

import (
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/PaesslerAG/jsonpath"
	common "github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
)

func matchesDCQLQuery(query configModel.CredentialQuery, credential *common.Credential) bool {
	if query.Format != "" && !matchesCredentialFormat(query.Format, credential) {
		return false
	}

	raw := credentialQueryDocument(credential)
	if query.Meta != nil {
		if len(query.Meta.VctValues) > 0 {
			vct, ok := raw[common.JWTClaimVct].(string)
			if !ok {
				types := credential.Contents().Types
				if credential.Format() == common.FormatSDJWT && len(types) == 1 {
					vct, ok = types[0], true
				}
			}
			if !ok || !slices.Contains(query.Meta.VctValues, vct) {
				return false
			}
		}
		if query.Meta.DoctypeValue != "" || len(query.Meta.TypeValues) > 0 {
			if query.Meta.DoctypeValue != "" || credential.Format() != common.FormatLDPVC {
				return false
			}
			types := credential.Contents().Types
			matches := false
			for _, allowedTypes := range query.Meta.TypeValues {
				if stringSliceSubset(types, allowedTypes) {
					matches = true
					break
				}
			}
			if len(query.Meta.TypeValues) > 0 && !matches {
				return false
			}
		}
	}
	if len(query.TrustedAuthorities) > 0 {
		return false
	}

	claimMatches := make([]bool, len(query.Claims))
	for i, claim := range query.Claims {
		value, found := dcqlClaimValue(raw, claim.Path)
		claimMatches[i] = found && (len(claim.Values) == 0 || anyJSONValueEqual(value, claim.Values))
	}
	if len(query.ClaimSets) == 0 {
		for _, matched := range claimMatches {
			if !matched {
				return false
			}
		}
		return true
	}

	claimIndexes := make(map[string]int, len(query.Claims))
	for i, claim := range query.Claims {
		if claim.Id == "" {
			return false
		}
		claimIndexes[claim.Id] = i
	}
	for _, claimSet := range query.ClaimSets {
		if len(claimSet) == 0 {
			continue
		}
		allMatched := true
		for _, claimID := range claimSet {
			index, ok := claimIndexes[claimID]
			if !ok || !claimMatches[index] {
				allMatched = false
				break
			}
		}
		if allMatched {
			return true
		}
	}
	return false
}

func dcqlClaimValue(raw map[string]interface{}, path []interface{}) (interface{}, bool) {
	if len(path) == 0 {
		return nil, false
	}
	var current interface{} = raw
	for _, segment := range path {
		switch key := segment.(type) {
		case string:
			object, ok := current.(map[string]interface{})
			if !ok {
				return nil, false
			}
			current, ok = object[key]
			if !ok {
				return nil, false
			}
		case float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			number, ok := jsonNumber(segment)
			if !ok || math.Trunc(number) != number || number > float64(int(^uint(0)>>1)) || number < 0 {
				return nil, false
			}
			current, ok = arrayValue(current, int(number))
			if !ok {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	return current, true
}

func credentialQueryDocument(credential *common.Credential) map[string]interface{} {
	raw := credential.ToRawJSON()
	if credential.Format() != common.FormatSDJWT {
		return raw
	}

	document := make(map[string]interface{}, len(credential.CustomFields())+2)
	for key, value := range credential.CustomFields() {
		document[key] = value
	}
	for _, subject := range credential.Contents().Subject {
		for key, value := range subject.CustomFields {
			document[key] = value
		}
	}
	if issuer := credential.Contents().Issuer; issuer != nil {
		document[common.JWTClaimIss] = issuer.ID
	}
	if types := credential.Contents().Types; len(types) == 1 {
		document[common.JWTClaimVct] = types[0]
	}
	return document
}

func arrayValue(value interface{}, index int) (interface{}, bool) {
	array, ok := interfaceSlice(value)
	if !ok || index < 0 || index >= len(array) {
		return nil, false
	}
	return array[index], true
}

func interfaceSlice(value interface{}) ([]interface{}, bool) {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() || (reflected.Kind() != reflect.Slice && reflected.Kind() != reflect.Array) {
		return nil, false
	}
	values := make([]interface{}, reflected.Len())
	for i := range values {
		values[i] = reflected.Index(i).Interface()
	}
	return values, true
}

func matchesCredentialFormat(requested string, credential *common.Credential) bool {
	actual := credential.Format()
	switch requested {
	case "jwt_vc_json":
		return actual == common.FormatJWTVC
	case "jwt_vc":
		return actual == common.FormatJWTVC
	case "jwt_vc_json-ld":
		_, hasContext := credential.ToRawJSON()[common.JSONLDKeyContext]
		return actual == common.FormatJWTVC && hasContext
	case "ldp_vc":
		return actual == common.FormatLDPVC
	case "dc+sd-jwt", "vc+sd-jwt", "sd-jwt-vc", "sd+jwt-vc":
		return actual == common.FormatSDJWT
	case "vc+jwt":
		return actual == common.FormatVCJWT
	default:
		return false
	}
}

func stringSliceSubset(values, allowed []string) bool {
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return len(values) > 0
}

func anyJSONValueEqual(value interface{}, expected []interface{}) bool {
	for _, candidate := range expected {
		if jsonValuesEqual(value, candidate) {
			return true
		}
	}
	return false
}

func jsonValuesEqual(left, right interface{}) bool {
	leftNumber, leftOK := jsonNumber(left)
	rightNumber, rightOK := jsonNumber(right)
	if leftOK || rightOK {
		return leftOK && rightOK && leftNumber == rightNumber
	}
	return reflect.DeepEqual(left, right)
}

func jsonNumber(value interface{}) (float64, bool) {
	const maxExactInteger = 1 << 53
	exactInteger := func(number float64) bool {
		return math.Trunc(number) != number || math.Abs(number) <= maxExactInteger
	}
	switch number := value.(type) {
	case float64:
		return number, !math.IsNaN(number) && !math.IsInf(number, 0) && exactInteger(number)
	case float32:
		converted := float64(number)
		return converted, !math.IsNaN(converted) && !math.IsInf(converted, 0) && exactInteger(converted)
	case int:
		return exactIntegerNumber(float64(number))
	case int8:
		return exactIntegerNumber(float64(number))
	case int16:
		return exactIntegerNumber(float64(number))
	case int32:
		return exactIntegerNumber(float64(number))
	case int64:
		return exactIntegerNumber(float64(number))
	case uint:
		return exactIntegerNumber(float64(number))
	case uint8:
		return exactIntegerNumber(float64(number))
	case uint16:
		return exactIntegerNumber(float64(number))
	case uint32:
		return exactIntegerNumber(float64(number))
	case uint64:
		return exactIntegerNumber(float64(number))
	default:
		return 0, false
	}
}

func exactIntegerNumber(number float64) (float64, bool) {
	const maxExactInteger = 1 << 53
	return number, math.Abs(number) <= maxExactInteger
}

func matchesPresentationDescriptor(descriptor configModel.InputDescriptor, definition *configModel.PresentationDefinition, credential *common.Credential) bool {
	if !matchesFormatRestrictions(definition.Format, credential) ||
		!matchesFormatRestrictions(descriptor.Format, credential) {
		return false
	}

	raw := credentialQueryDocument(credential)
	for _, field := range descriptor.Constraints.Fields {
		found := false
		resolved := false
		for _, path := range field.Path {
			value, err := jsonpath.Get(path, raw)
			if err != nil {
				continue
			}
			resolved = true
			if field.Filter == nil || matchesJSONSchema(field.Filter, value) ||
				(strings.Contains(path, "[*]") && arrayHasMatchingValue(field.Filter, value)) {
				found = true
				break
			}
		}
		optional := field.Optional == nil || *field.Optional
		if !found && (resolved || !optional) {
			return false
		}
	}
	return true
}

func matchesFormatRestrictions(restrictions map[string]configModel.FormatObject, credential *common.Credential) bool {
	if len(restrictions) == 0 {
		return true
	}
	for requested, format := range restrictions {
		if matchesCredentialFormat(requested, credential) {
			if len(format.Alg) > 0 {
				return false
			}
			if len(format.ProofType) > 0 {
				proofs := credential.Proofs()
				if len(proofs) == 0 {
					return false
				}
				matchesProofType := false
				for _, proof := range proofs {
					if slices.Contains(format.ProofType, proof.Type) {
						matchesProofType = true
						break
					}
				}
				if !matchesProofType {
					return false
				}
			}
			return true
		}
	}

	return false
}

func arrayHasMatchingValue(schema, value interface{}) bool {
	values, ok := interfaceSlice(value)
	if !ok {
		return false
	}
	for _, item := range values {
		if matchesJSONSchema(schema, item) {
			return true
		}
	}
	return false
}

func matchesJSONSchema(schema, value interface{}) bool {
	object, ok := schema.(map[string]interface{})
	if !ok {
		return false
	}
	for keyword, constraint := range object {
		switch keyword {
		case "type":
			if !matchesJSONType(constraint, value) {
				return false
			}
		case "const":
			if !jsonValuesEqual(value, constraint) {
				return false
			}
		case "enum":
			values, ok := constraint.([]interface{})
			if !ok || !anyJSONValueEqual(value, values) {
				return false
			}
		case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum":
			valueNumber, valueOK := jsonNumber(value)
			constraintNumber, constraintOK := jsonNumber(constraint)
			if !valueOK || !constraintOK {
				return false
			}
			switch keyword {
			case "minimum":
				if valueNumber < constraintNumber {
					return false
				}
			case "maximum":
				if valueNumber > constraintNumber {
					return false
				}
			case "exclusiveMinimum":
				if valueNumber <= constraintNumber {
					return false
				}
			case "exclusiveMaximum":
				if valueNumber >= constraintNumber {
					return false
				}
			}
		case "minLength", "maxLength":
			text, textOK := value.(string)
			length, lengthOK := jsonNumber(constraint)
			if !textOK || !lengthOK {
				return false
			}
			if (keyword == "minLength" && float64(len([]rune(text))) < length) ||
				(keyword == "maxLength" && float64(len([]rune(text))) > length) {
				return false
			}
		case "pattern":
			pattern, patternOK := constraint.(string)
			text, textOK := value.(string)
			if !patternOK || !textOK {
				return false
			}
			matched, err := regexp.MatchString(pattern, text)
			if err != nil || !matched {
				return false
			}
		case "minItems", "maxItems":
			values, valuesOK := interfaceSlice(value)
			length, lengthOK := jsonNumber(constraint)
			if !valuesOK || !lengthOK {
				return false
			}
			if (keyword == "minItems" && float64(len(values)) < length) ||
				(keyword == "maxItems" && float64(len(values)) > length) {
				return false
			}
		case "items":
			values, valuesOK := interfaceSlice(value)
			if !valuesOK {
				return false
			}
			for _, item := range values {
				if !matchesJSONSchema(constraint, item) {
					return false
				}
			}
		case "required":
			objectValue, objectOK := value.(map[string]interface{})
			required, requiredOK := constraint.([]interface{})
			if !objectOK || !requiredOK {
				return false
			}
			for _, name := range required {
				key, ok := name.(string)
				if !ok {
					return false
				}
				if _, exists := objectValue[key]; !exists {
					return false
				}
			}
		case "properties":
			objectValue, objectOK := value.(map[string]interface{})
			properties, propertiesOK := constraint.(map[string]interface{})
			if !objectOK || !propertiesOK {
				return false
			}
			for name, propertySchema := range properties {
				propertyValue, exists := objectValue[name]
				if exists && !matchesJSONSchema(propertySchema, propertyValue) {
					return false
				}
			}
		case "allOf", "anyOf":
			schemas, schemasOK := constraint.([]interface{})
			if !schemasOK || len(schemas) == 0 {
				return false
			}
			matched := 0
			for _, child := range schemas {
				if matchesJSONSchema(child, value) {
					matched++
				}
			}
			if (keyword == "allOf" && matched != len(schemas)) || (keyword == "anyOf" && matched == 0) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func matchesJSONType(expected interface{}, value interface{}) bool {
	types, ok := expected.([]interface{})
	if !ok {
		types = []interface{}{expected}
	}
	for _, candidate := range types {
		name, ok := candidate.(string)
		if !ok {
			continue
		}
		switch name {
		case "null":
			if value == nil {
				return true
			}
		case "boolean":
			if _, ok := value.(bool); ok {
				return true
			}
		case "object":
			if _, ok := value.(map[string]interface{}); ok {
				return true
			}
		case "array":
			if _, ok := interfaceSlice(value); ok {
				return true
			}
		case "number":
			if _, ok := jsonNumber(value); ok {
				return true
			}
		case "integer":
			if number, ok := jsonNumber(value); ok && math.Trunc(number) == number {
				return true
			}
		case "string":
			if _, ok := value.(string); ok {
				return true
			}
		}
	}
	return false
}
