package common

import (
	"strconv"
	"strings"
)

// N-Quads term delimiters as defined by https://www.w3.org/TR/n-quads/.
const (
	nQuadIRIOpen         = '<'
	nQuadIRIClose        = '>'
	nQuadLiteralQuote    = '"'
	nQuadEscape          = '\\'
	nQuadDatatypeMarker  = "^^"
	nQuadLanguageMarker  = "@"
	nQuadTermWhitespace  = " \t"
	nQuadStatementEnd    = "."
	nQuadLineSeparator   = "\n"
	nQuadBlankNodePrefix = "_:"
)

// NQuad is a minimally parsed N-Quads statement. Only the parts needed to
// assert that a specific triple exists are retained.
type NQuad struct {
	// Subject is the subject IRI or blank-node label.
	Subject string
	// Predicate is the predicate IRI, without its angle brackets.
	Predicate string
	// Object is the object's value: an IRI, a blank-node label, or the
	// lexical form of a literal (without quotes, datatype or language tag).
	Object string
	// ObjectIsIRI reports whether the object was an IRI (or blank node)
	// rather than a literal. It distinguishes `<https://example.org>` from
	// the literal `"https://example.org"`, which canonicalize to the same
	// value but mean different things.
	ObjectIsIRI bool
}

// ParseNQuads parses a canonical N-Quads document into its statements.
//
// The parser is deliberately lenient: lines it cannot make sense of are
// skipped rather than reported. It exists to answer "does this document
// contain a statement with predicate P and object O?" — a question for which
// an unparseable line is simply not an answer. Callers that need the absence
// of a statement to be a hard failure get that from the missing statement,
// not from a parse error.
func ParseNQuads(document string) []NQuad {
	lines := strings.Split(document, nQuadLineSeparator)
	quads := make([]NQuad, 0, len(lines))
	for _, line := range lines {
		if quad, ok := parseNQuadLine(line); ok {
			quads = append(quads, quad)
		}
	}
	return quads
}

// parseNQuadLine parses a single `subject predicate object [graph] .` line.
func parseNQuadLine(line string) (NQuad, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line == nQuadStatementEnd {
		return NQuad{}, false
	}

	subject, rest, ok := readNQuadTerm(line)
	if !ok {
		return NQuad{}, false
	}
	predicate, rest, ok := readNQuadTerm(rest)
	if !ok {
		return NQuad{}, false
	}
	object, isIRI, _, ok := readNQuadObject(rest)
	if !ok {
		return NQuad{}, false
	}

	return NQuad{Subject: subject, Predicate: predicate, Object: object, ObjectIsIRI: isIRI}, true
}

// readNQuadTerm reads an IRI or blank-node term from the start of s and
// returns its value together with the unread remainder of the line.
func readNQuadTerm(s string) (value string, rest string, ok bool) {
	s = strings.TrimLeft(s, nQuadTermWhitespace)
	if s == "" {
		return "", "", false
	}
	if s[0] == nQuadIRIOpen {
		end := strings.IndexByte(s, nQuadIRIClose)
		if end < 0 {
			return "", "", false
		}
		return s[1:end], s[end+1:], true
	}
	if !strings.HasPrefix(s, nQuadBlankNodePrefix) {
		return "", "", false
	}
	end := strings.IndexAny(s, nQuadTermWhitespace)
	if end < 0 {
		return s, "", true
	}
	return s[:end], s[end:], true
}

// readNQuadObject reads the object term from the start of s. In addition to
// IRIs and blank nodes it handles literals, returning their lexical form with
// escapes resolved and any datatype or language tag stripped.
func readNQuadObject(s string) (value string, isIRI bool, rest string, ok bool) {
	s = strings.TrimLeft(s, nQuadTermWhitespace)
	if s == "" {
		return "", false, "", false
	}
	if s[0] != nQuadLiteralQuote {
		value, rest, ok = readNQuadTerm(s)
		return value, ok, rest, ok
	}

	closing := indexNQuadLiteralEnd(s)
	if closing < 0 {
		return "", false, "", false
	}
	return unescapeNQuadLiteral(s[1:closing]), false, skipLiteralSuffix(s[closing+1:]), true
}

// indexNQuadLiteralEnd returns the index of the quote closing the literal
// that starts at s[0], honouring backslash escapes, or -1 when unterminated.
func indexNQuadLiteralEnd(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case nQuadEscape:
			i++
		case nQuadLiteralQuote:
			return i
		}
	}
	return -1
}

// skipLiteralSuffix drops an optional `^^<datatype>` or `@language` suffix
// following a literal and returns the remainder of the line.
func skipLiteralSuffix(s string) string {
	if strings.HasPrefix(s, nQuadDatatypeMarker) {
		if end := strings.IndexByte(s, nQuadIRIClose); end >= 0 {
			return s[end+1:]
		}
		return ""
	}
	if strings.HasPrefix(s, nQuadLanguageMarker) {
		if end := strings.IndexAny(s, nQuadTermWhitespace); end >= 0 {
			return s[end:]
		}
		return ""
	}
	return s
}

// unescapeNQuadLiteral resolves the escape sequences allowed inside an
// N-Quads literal. The N-Quads escape set is a subset of Go's, so the Go
// unquoting rules apply; an input Go rejects is returned verbatim, which can
// only ever make a comparison fail, never succeed spuriously.
func unescapeNQuadLiteral(lexical string) string {
	unquoted, err := strconv.Unquote(string(nQuadLiteralQuote) + lexical + string(nQuadLiteralQuote))
	if err != nil {
		return lexical
	}
	return unquoted
}

// HasNQuad reports whether quads contain a statement with the given predicate
// IRI. When expectedObject is non-empty the object must match it as well.
func HasNQuad(quads []NQuad, predicate string, expectedObject string) bool {
	for _, quad := range quads {
		if quad.Predicate != predicate {
			continue
		}
		if expectedObject == "" || quad.Object == expectedObject {
			return true
		}
	}
	return false
}
