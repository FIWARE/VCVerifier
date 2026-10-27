package verifier

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDCQLClaimValueResolvesObjectAndArrayPaths(t *testing.T) {
	document := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"roles": []interface{}{"user", "admin"},
		},
	}

	value, found := dcqlClaimValue(document, []interface{}{"credentialSubject", "roles", float64(1)})
	assert.True(t, found)
	assert.Equal(t, "admin", value)

	for _, path := range [][]interface{}{
		nil,
		{"missing"},
		{"credentialSubject", "roles", float64(2)},
		{"credentialSubject", "roles", -1},
		{"credentialSubject", "roles", 1.5},
		{"credentialSubject", "roles", true},
	} {
		_, found := dcqlClaimValue(document, path)
		assert.False(t, found, "path %v should not resolve", path)
	}
}

func TestArrayValueAndInterfaceSlice(t *testing.T) {
	for _, value := range []interface{}{
		[]interface{}{"a", "b"},
		[2]string{"a", "b"},
	} {
		values, ok := interfaceSlice(value)
		assert.True(t, ok)
		assert.Equal(t, []interface{}{"a", "b"}, values)
		got, found := arrayValue(value, 1)
		assert.True(t, found)
		assert.Equal(t, "b", got)
	}

	for _, value := range []interface{}{nil, "not an array"} {
		_, ok := interfaceSlice(value)
		assert.False(t, ok)
	}
	for _, index := range []int{-1, 2} {
		_, found := arrayValue([]string{"a", "b"}, index)
		assert.False(t, found)
	}
}

func TestMatchesJSONSchemaSupportedConstraints(t *testing.T) {
	tests := []struct {
		name   string
		schema interface{}
		value  interface{}
		match  bool
	}{
		{"string type", map[string]interface{}{"type": "string"}, "ok", true},
		{"type union", map[string]interface{}{"type": []interface{}{"null", "integer"}}, 3, true},
		{"unknown type", map[string]interface{}{"type": "unknown"}, "ok", false},
		{"constant", map[string]interface{}{"const": "admin"}, "admin", true},
		{"enum", map[string]interface{}{"enum": []interface{}{"user", "admin"}}, "admin", true},
		{"enum mismatch", map[string]interface{}{"enum": []interface{}{"user"}}, "admin", false},
		{"numeric bounds", map[string]interface{}{
			"minimum": 1, "maximum": 5, "exclusiveMinimum": 0, "exclusiveMaximum": 6,
		}, 3, true},
		{"below minimum", map[string]interface{}{"minimum": 2}, 1, false},
		{"wrong numeric value", map[string]interface{}{"minimum": 2}, "2", false},
		{"unicode string length", map[string]interface{}{"minLength": 2, "maxLength": 2}, "éx", true},
		{"pattern", map[string]interface{}{"pattern": "^admin$"}, "admin", true},
		{"invalid pattern", map[string]interface{}{"pattern": "["}, "admin", false},
		{"array sizes and items", map[string]interface{}{
			"minItems": 1, "maxItems": 2, "items": map[string]interface{}{"type": "string"},
		}, []interface{}{"admin"}, true},
		{"item mismatch", map[string]interface{}{
			"items": map[string]interface{}{"type": "string"},
		}, []interface{}{"admin", 3}, false},
		{"required properties", map[string]interface{}{
			"required": []interface{}{"role"},
			"properties": map[string]interface{}{
				"role": map[string]interface{}{"enum": []interface{}{"admin", "user"}},
			},
		}, map[string]interface{}{"role": "admin"}, true},
		{"missing required property", map[string]interface{}{
			"required": []interface{}{"role"},
		}, map[string]interface{}{}, false},
		{"allOf", map[string]interface{}{
			"allOf": []interface{}{
				map[string]interface{}{"minimum": 1},
				map[string]interface{}{"maximum": 5},
			},
		}, 3, true},
		{"anyOf", map[string]interface{}{
			"anyOf": []interface{}{
				map[string]interface{}{"const": "admin"},
				map[string]interface{}{"const": "user"},
			},
		}, "user", true},
		{"unsupported keyword", map[string]interface{}{"not": map[string]interface{}{}}, "admin", false},
		{"non-object schema", "type:string", "admin", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.match, matchesJSONSchema(tc.schema, tc.value))
		})
	}
}

func TestJsonNumberAcceptsExactNumbersAndRejectsInvalidValues(t *testing.T) {
	for _, value := range []interface{}{
		float64(2), float32(2), int(2), int8(2), int16(2), int32(2), int64(2),
		uint(2), uint8(2), uint16(2), uint32(2), uint64(2),
	} {
		number, ok := jsonNumber(value)
		assert.True(t, ok, "value %T(%v) should be an exact number", value, value)
		assert.Equal(t, float64(2), number)
	}

	for _, value := range []interface{}{
		math.NaN(), math.Inf(1), math.Pow(2, 53) + 2, uint64(1<<53 + 1), "2",
	} {
		_, ok := jsonNumber(value)
		assert.False(t, ok, "value %T(%v) should not be accepted", value, value)
	}
}
