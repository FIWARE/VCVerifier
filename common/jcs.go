package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// JSON Canonicalization Scheme (RFC 8785).
//
// JCS is the canonicalization the `-jcs-` Data Integrity cryptosuites use
// instead of RDF Dataset Canonicalization. It is a pure JSON transform: no
// JSON-LD context is consulted, nothing is expanded, and nothing is dropped.
// That makes it available to issuers who cannot run an RDF canonicalizer, and
// it is why the proof options of a JCS proof need no coverage assertion - a
// member that is present is canonicalized, whether or not any context defines
// it.
//
// The three rules, from RFC 8785 section 3.2:
//   - literals, strings and numbers are serialized the way ECMAScript does;
//   - object properties are sorted by their UTF-16 code units, recursively;
//   - the result is UTF-8 with no insignificant whitespace.

var (
	// ErrorJCSInvalidNumber is returned for a number JSON cannot represent:
	// NaN and both infinities. RFC 8785 section 3.2.2.3 requires a compliant
	// implementation to fail rather than invent a serialization.
	ErrorJCSInvalidNumber = errors.New("jcs_invalid_number")

	// ErrorJCSInvalidString is returned for a string that is not valid
	// Unicode, such as a lone surrogate. RFC 8785 section 3.2.2.2 requires
	// these to fail: they would otherwise canonicalize differently in
	// different implementations and break the signature.
	//
	// It is unreachable from the Data Integrity verification path, where every
	// string arrives through encoding/json, which substitutes U+FFFD for
	// invalid UTF-8 and for unpaired surrogate escapes while unmarshalling.
	// The check guards the exported CanonicalizeJSON against values built in
	// Go, where nothing has made that substitution.
	ErrorJCSInvalidString = errors.New("jcs_invalid_string")

	// ErrorJCSUnsupportedType is returned for a value that has no JSON
	// representation.
	ErrorJCSUnsupportedType = errors.New("jcs_unsupported_type")
)

// JCS serialization limits, from ECMAScript's Number::toString.
const (
	// es6ExponentialUpperBound is the magnitude at and above which
	// ECMAScript switches to exponential notation.
	es6ExponentialUpperBound = 1e21
	// es6ExponentialLowerBound is the magnitude below which ECMAScript
	// switches to exponential notation.
	es6ExponentialLowerBound = 1e-6
	// es6ExponentPrefixLength is the length of the "e+" / "e-" that follows
	// the mantissa in Go's exponential format.
	es6ExponentPrefixLength = 2
)

// Pieces of the \uhhhh escape RFC 8785 section 3.2.2.2 prescribes for the
// control characters that have no short form.
const (
	// controlEscapePrefix is the constant part of the escape. Every character
	// that needs it is below U+0020, so the two high hex digits are always 0.
	controlEscapePrefix = `\u00`
	// lowercaseHexDigits indexes the two remaining digits. The RFC asks for
	// lowercase hexadecimal specifically.
	lowercaseHexDigits = "0123456789abcdef"
	// hexNibbleBits and hexNibbleMask split a byte into its two hex digits.
	hexNibbleBits = 4
	hexNibbleMask = 0x0f
)

// CanonicalizeJSON returns the RFC 8785 canonical form of a JSON value.
//
// The value is what encoding/json produces when unmarshalling into an
// interface{}: nil, bool, float64, string, []interface{} or
// map[string]interface{}. Any other value is marshalled and re-read first, so
// a struct or a typed map canonicalizes as the JSON it would serialize to.
func CanonicalizeJSON(value interface{}) (string, error) {
	var builder strings.Builder
	if err := writeCanonicalJSON(&builder, value); err != nil {
		return "", err
	}
	return builder.String(), nil
}

// CanonicalizeJSONDocument returns the RFC 8785 canonical form of an already
// serialized JSON document.
func CanonicalizeJSONDocument(documentJSON []byte) (string, error) {
	var value interface{}
	if err := json.Unmarshal(documentJSON, &value); err != nil {
		return "", fmt.Errorf("%w: %v", ErrorJCSUnsupportedType, err)
	}
	return CanonicalizeJSON(value)
}

// writeCanonicalJSON writes the canonical form of one value.
func writeCanonicalJSON(builder *strings.Builder, value interface{}) error {
	switch typed := value.(type) {
	case nil:
		builder.WriteString("null")
		return nil
	case bool:
		builder.WriteString(strconv.FormatBool(typed))
		return nil
	case string:
		return writeCanonicalString(builder, typed)
	case float64:
		return writeCanonicalNumber(builder, typed)
	case json.Number:
		number, err := typed.Float64()
		if err != nil {
			return fmt.Errorf("%w: %s", ErrorJCSInvalidNumber, typed.String())
		}
		return writeCanonicalNumber(builder, number)
	case []interface{}:
		return writeCanonicalArray(builder, typed)
	case map[string]interface{}:
		// JSONObject is a map[string]interface{}, so this case covers it too.
		return writeCanonicalObject(builder, typed)
	default:
		return writeCanonicalReserialized(builder, value)
	}
}

// writeCanonicalReserialized handles a value that is not already in the shape
// encoding/json produces, by taking it through JSON once. A struct, an int or
// a []string reaches the canonicalizer as the JSON it stands for.
func writeCanonicalReserialized(builder *strings.Builder, value interface{}) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("%w: %T: %v", ErrorJCSUnsupportedType, value, err)
	}
	var reread interface{}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&reread); err != nil {
		return fmt.Errorf("%w: %T: %v", ErrorJCSUnsupportedType, value, err)
	}
	// The re-read value is one of the basic JSON types, so this recursion
	// terminates.
	return writeCanonicalJSON(builder, reread)
}

// writeCanonicalArray writes an array. Element order is data and is left
// alone; only objects nested inside get their properties sorted.
func writeCanonicalArray(builder *strings.Builder, values []interface{}) error {
	builder.WriteByte('[')
	for index, value := range values {
		if index > 0 {
			builder.WriteByte(',')
		}
		if err := writeCanonicalJSON(builder, value); err != nil {
			return err
		}
	}
	builder.WriteByte(']')
	return nil
}

// writeCanonicalObject writes an object with its properties sorted by UTF-16
// code units, as RFC 8785 section 3.2.3 requires.
func writeCanonicalObject(builder *strings.Builder, members map[string]interface{}) error {
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sortPropertyNames(names)

	builder.WriteByte('{')
	for index, name := range names {
		if index > 0 {
			builder.WriteByte(',')
		}
		if err := writeCanonicalString(builder, name); err != nil {
			return err
		}
		builder.WriteByte(':')
		if err := writeCanonicalJSON(builder, members[name]); err != nil {
			return err
		}
	}
	builder.WriteByte('}')
	return nil
}

// sortPropertyNames sorts property names by their UTF-16 code units.
//
// Sorting the UTF-8 bytes instead would agree for everything below U+FFFF but
// not above it: a surrogate pair starts with 0xD800-0xDBFF, which in UTF-16
// sorts before U+E000-U+FFFF and in UTF-8 sorts after. The RFC's own sorting
// test data is built from exactly that difference.
func sortPropertyNames(names []string) {
	encoded := make(map[string][]uint16, len(names))
	for _, name := range names {
		encoded[name] = utf16.Encode([]rune(name))
	}
	sort.Slice(names, func(i, j int) bool {
		return lessUTF16(encoded[names[i]], encoded[names[j]])
	})
}

// lessUTF16 compares two UTF-16 code unit sequences as unsigned integers,
// the shorter sequence preceding the longer when one is a prefix of the other.
func lessUTF16(left, right []uint16) bool {
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] != right[index] {
			return left[index] < right[index]
		}
	}
	return len(left) < len(right)
}

// writeCanonicalString writes a JSON string per RFC 8785 section 3.2.2.2:
// the five predefined escapes, \uhhhh in lowercase hex for the remaining
// control characters, \\ and \" for backslash and quote, and every other code
// point as itself.
func writeCanonicalString(builder *strings.Builder, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: not valid UTF-8", ErrorJCSInvalidString)
	}

	builder.WriteByte('"')
	for _, codePoint := range value {
		switch codePoint {
		case '"':
			builder.WriteString(`\"`)
		case '\\':
			builder.WriteString(`\\`)
		case '\b':
			builder.WriteString(`\b`)
		case '\t':
			builder.WriteString(`\t`)
		case '\n':
			builder.WriteString(`\n`)
		case '\f':
			builder.WriteString(`\f`)
		case '\r':
			builder.WriteString(`\r`)
		default:
			if codePoint < 0x20 {
				builder.WriteString(controlEscapePrefix)
				builder.WriteByte(lowercaseHexDigits[codePoint>>hexNibbleBits])
				builder.WriteByte(lowercaseHexDigits[codePoint&hexNibbleMask])
				continue
			}
			// A RuneError here is a literal U+FFFD and is written as itself:
			// range over a string also yields it for invalid encoding, which
			// ValidString has already ruled out.
			builder.WriteRune(codePoint)
		}
	}
	builder.WriteByte('"')
	return nil
}

// writeCanonicalNumber writes a number the way ECMAScript's Number::toString
// does, which is what RFC 8785 section 3.2.2.3 prescribes.
//
// Go's shortest-round-trip formatting agrees with ECMAScript's digits; the two
// differ in when exponential notation is used and in how the exponent is
// written, and this function bridges exactly that.
func writeCanonicalNumber(builder *strings.Builder, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return fmt.Errorf("%w: %v", ErrorJCSInvalidNumber, value)
	}

	// ECMAScript prints both zeroes as "0"; Go prints "-0" for negative zero.
	if value == 0 {
		builder.WriteByte('0')
		return nil
	}

	sign := ""
	magnitude := value
	if magnitude < 0 {
		sign = "-"
		magnitude = -magnitude
	}

	// ECMAScript uses plain notation in [1e-6, 1e21) and exponential outside
	// it - a rule neither of Go's 'f', 'e' or 'g' formats reproduces.
	format := byte('e')
	if magnitude >= es6ExponentialLowerBound && magnitude < es6ExponentialUpperBound {
		format = 'f'
	}
	formatted := strconv.FormatFloat(magnitude, format, -1, 64)

	// Go pads the exponent to two digits ("1e+09"), ECMAScript does not
	// ("1e+9").
	if exponent := strings.IndexByte(formatted, 'e'); exponent >= 0 {
		digits := exponent + es6ExponentPrefixLength
		if digits < len(formatted)-1 && formatted[digits] == '0' {
			formatted = formatted[:digits] + formatted[digits+1:]
		}
	}

	builder.WriteString(sign)
	builder.WriteString(formatted)
	return nil
}
