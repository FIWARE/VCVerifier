package common

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The vectors in this file come from RFC 8785 itself. JCS exists to make a
// signature reproducible across implementations, so an implementation checked
// only against itself is worth very little.

// rfc8785SampleDocument is the sample of RFC 8785 section 3.2.2, transcribed
// as a raw string so its JSON escapes reach the parser unchanged.
const rfc8785SampleDocument = `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`

// rfc8785SampleCanonical is the canonical form RFC 8785 section 3.2.3 gives
// for that sample.
const rfc8785SampleCanonical = `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`

// rfc8785SortingDocument is the sorting test data of RFC 8785 section 3.2.3.
// Its point is that UTF-16 and UTF-8 order disagree: the emoji is a surrogate
// pair, so it sorts before U+FB33 in UTF-16 and after it in UTF-8.
const rfc8785SortingDocument = `{
  "€": "Euro Sign",
  "\r": "Carriage Return",
  "דּ": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "😀": "Emoji: Grinning Face",
  "\u0080": "Control",
  "ö": "Latin Small Letter O With Diaeresis"
}`

// TestCanonicalizeJSONRFC8785Sample canonicalizes the RFC's own sample.
func TestCanonicalizeJSONRFC8785Sample(t *testing.T) {
	canonical, err := CanonicalizeJSONDocument([]byte(rfc8785SampleDocument))
	require.NoError(t, err)
	assert.Equal(t, rfc8785SampleCanonical, canonical)
}

// TestCanonicalizeJSONPropertyOrder verifies the UTF-16 code unit ordering of
// property names.
func TestCanonicalizeJSONPropertyOrder(t *testing.T) {
	canonical, err := CanonicalizeJSONDocument([]byte(rfc8785SortingDocument))
	require.NoError(t, err)

	// The expected argument order after sorting, from RFC 8785 section 3.2.3.
	wantOrder := []string{
		"Carriage Return",
		"One",
		"Control",
		"Latin Small Letter O With Diaeresis",
		"Euro Sign",
		"Emoji: Grinning Face",
		"Hebrew Letter Dalet With Dagesh",
	}

	var canonicalized map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(canonical), &canonicalized))
	require.Len(t, canonicalized, len(wantOrder))

	gotOrder := make([]string, 0, len(wantOrder))
	var current int
	for _, want := range wantOrder {
		index := indexOfValue(t, canonical, want)
		require.Greater(t, index, current, "%q is out of order in %s", want, canonical)
		current = index
		gotOrder = append(gotOrder, want)
	}
	assert.Equal(t, wantOrder, gotOrder)
}

// indexOfValue returns the position of a property value inside the canonical
// document, which is what the ordering assertions compare.
func indexOfValue(t *testing.T, canonical string, value string) int {
	t.Helper()
	quoted := `"` + value + `"`
	index := len(canonical)
	for offset := 0; offset+len(quoted) <= len(canonical); offset++ {
		if canonical[offset:offset+len(quoted)] == quoted {
			return offset
		}
	}
	require.Fail(t, "value not found", "%q is not in %s", value, canonical)
	return index
}

// TestCanonicalizeJSONNumbers covers the IEEE 754 samples of RFC 8785
// appendix B, including the edge cases where Go's formatting and ECMAScript's
// disagree: the exponential thresholds and the zero-padded exponent.
func TestCanonicalizeJSONNumbers(t *testing.T) {
	tests := []struct {
		bits string
		want string
		note string
	}{
		{bits: "0000000000000000", want: "0", note: "zero"},
		{bits: "8000000000000000", want: "0", note: "minus zero"},
		{bits: "0000000000000001", want: "5e-324", note: "min pos number"},
		{bits: "8000000000000001", want: "-5e-324", note: "min neg number"},
		{bits: "7fefffffffffffff", want: "1.7976931348623157e+308", note: "max pos number"},
		{bits: "ffefffffffffffff", want: "-1.7976931348623157e+308", note: "max neg number"},
		{bits: "4340000000000000", want: "9007199254740992", note: "max pos int"},
		{bits: "c340000000000000", want: "-9007199254740992", note: "max neg int"},
		{bits: "4430000000000000", want: "295147905179352830000", note: "~2**68"},
		{bits: "44b52d02c7e14af5", want: "9.999999999999997e+22"},
		{bits: "44b52d02c7e14af6", want: "1e+23"},
		{bits: "44b52d02c7e14af7", want: "1.0000000000000001e+23"},
		{bits: "444b1ae4d6e2ef4e", want: "999999999999999700000"},
		{bits: "444b1ae4d6e2ef4f", want: "999999999999999900000"},
		{bits: "444b1ae4d6e2ef50", want: "1e+21", note: "exponential threshold"},
		{bits: "3eb0c6f7a0b5ed8c", want: "9.999999999999997e-7"},
		{bits: "3eb0c6f7a0b5ed8d", want: "0.000001", note: "exponential threshold"},
		{bits: "41b3de4355555553", want: "333333333.3333332"},
		{bits: "41b3de4355555554", want: "333333333.33333325"},
		{bits: "41b3de4355555555", want: "333333333.3333333"},
		{bits: "41b3de4355555556", want: "333333333.3333334"},
	}

	for _, tc := range tests {
		name := tc.bits
		if tc.note != "" {
			name = tc.bits + "_" + tc.note
		}
		t.Run(name, func(t *testing.T) {
			raw, err := strconv.ParseUint(tc.bits, 16, 64)
			require.NoError(t, err)
			value := math.Float64frombits(raw)

			canonical, err := CanonicalizeJSON(value)
			require.NoError(t, err)
			assert.Equal(t, tc.want, canonical)
		})
	}
}

// TestCanonicalizeJSONSingleDigitExponent guards the exponent fix-up: Go pads
// an exponent to two digits, ECMAScript does not.
func TestCanonicalizeJSONSingleDigitExponent(t *testing.T) {
	tests := map[float64]string{
		1e21:  "1e+21",
		1e22:  "1e+22",
		1e-7:  "1e-7",
		1e-9:  "1e-9",
		5e-10: "5e-10",
		1e100: "1e+100",
	}
	for value, want := range tests {
		t.Run(want, func(t *testing.T) {
			canonical, err := CanonicalizeJSON(value)
			require.NoError(t, err)
			assert.Equal(t, want, canonical)
		})
	}
}

// TestCanonicalizeJSONStrings covers the escaping rules of RFC 8785
// section 3.2.2.2.
func TestCanonicalizeJSONStrings(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "plain", value: "abc", want: `"abc"`},
		{name: "quote", value: `a"b`, want: `"a\"b"`},
		{name: "backslash", value: `a\b`, want: `"a\\b"`},
		{name: "backspace", value: "a\bb", want: `"a\bb"`},
		{name: "tab", value: "a\tb", want: `"a\tb"`},
		{name: "newline", value: "a\nb", want: `"a\nb"`},
		{name: "form_feed", value: "a\fb", want: `"a\fb"`},
		{name: "carriage_return", value: "a\rb", want: `"a\rb"`},
		{name: "other_control_lowercase_hex", value: "a\x0fb", want: `"a\u000fb"`},
		{name: "control_at_zero", value: "a\x00b", want: `"a\u0000b"`},
		{name: "solidus_is_not_escaped", value: "a/b", want: `"a/b"`},
		{name: "non_ascii_stays_literal", value: "€ö", want: `"€ö"`},
		{name: "astral_stays_literal", value: "\U0001F600", want: "\"\U0001F600\""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			canonical, err := CanonicalizeJSON(tc.value)
			require.NoError(t, err)
			assert.Equal(t, tc.want, canonical)
		})
	}
}

// TestCanonicalizeJSONRejectsUnrepresentableNumbers verifies that NaN and the
// infinities terminate canonicalization, as RFC 8785 section 3.2.2.3 requires.
func TestCanonicalizeJSONRejectsUnrepresentableNumbers(t *testing.T) {
	tests := map[string]float64{
		"nan":               math.NaN(),
		"positive_infinity": math.Inf(1),
		"negative_infinity": math.Inf(-1),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := CanonicalizeJSON(value)
			assert.ErrorIs(t, err, ErrorJCSInvalidNumber)
		})
	}
}

// TestCanonicalizeJSONRejectsInvalidUTF8 verifies that a string which is not
// valid Unicode is rejected rather than silently repaired: repairing it would
// canonicalize differently in different implementations.
func TestCanonicalizeJSONRejectsInvalidUTF8(t *testing.T) {
	_, err := CanonicalizeJSON(string([]byte{0xff, 0xfe}))
	assert.ErrorIs(t, err, ErrorJCSInvalidString)
}

// TestCanonicalizeJSONNestedStructures verifies that objects nested in arrays
// have their properties sorted while array order itself is preserved.
func TestCanonicalizeJSONNestedStructures(t *testing.T) {
	document := `{"b":[{"z":1,"a":2},{"y":3}],"a":{"d":{"f":4,"e":5}}}`
	canonical, err := CanonicalizeJSONDocument([]byte(document))
	require.NoError(t, err)
	assert.Equal(t, `{"a":{"d":{"e":5,"f":4}},"b":[{"a":2,"z":1},{"y":3}]}`, canonical)
}

// TestCanonicalizeJSONAcceptsGoValues verifies that values that are not
// already in encoding/json's shape go through JSON first, so an int or a
// []string canonicalizes as the JSON it stands for.
func TestCanonicalizeJSONAcceptsGoValues(t *testing.T) {
	canonical, err := CanonicalizeJSON(map[string]interface{}{
		"count": 42,
		"tags":  []string{"b", "a"},
	})
	require.NoError(t, err)
	assert.Equal(t, `{"count":42,"tags":["b","a"]}`, canonical)
}

// TestCanonicalizeJSONBigEndianRoundTrip is a sanity check on the bit patterns
// the appendix B table is expressed in.
func TestCanonicalizeJSONBigEndianRoundTrip(t *testing.T) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], math.Float64bits(1))
	assert.Equal(t, "3ff0000000000000", strconv.FormatUint(binary.BigEndian.Uint64(encoded[:]), 16))
}
