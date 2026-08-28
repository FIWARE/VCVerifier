package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseNQuads covers the term forms the canonicalized proof options can
// contain: IRI and blank-node subjects, IRI and literal objects, typed and
// language-tagged literals, and escaped literal content.
func TestParseNQuads(t *testing.T) {
	tests := []struct {
		name     string
		document string
		expected []NQuad
	}{
		{
			name:     "iri_object",
			document: `_:c14n0 <https://w3id.org/security#verificationMethod> <did:web:example.org#key-1> .`,
			expected: []NQuad{{Subject: "_:c14n0", Predicate: "https://w3id.org/security#verificationMethod", Object: "did:web:example.org#key-1", ObjectIsIRI: true}},
		},
		{
			name:     "plain_literal_object",
			document: `_:c14n0 <https://w3id.org/security#challenge> "my-nonce" .`,
			expected: []NQuad{{Subject: "_:c14n0", Predicate: "https://w3id.org/security#challenge", Object: "my-nonce"}},
		},
		{
			name:     "typed_literal_object",
			document: `_:c14n0 <http://purl.org/dc/terms/created> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`,
			expected: []NQuad{{Subject: "_:c14n0", Predicate: "http://purl.org/dc/terms/created", Object: "2024-01-01T00:00:00Z"}},
		},
		{
			name:     "language_tagged_literal_object",
			document: `<https://example.org/doc> <https://example.org/label> "hello"@en .`,
			expected: []NQuad{{Subject: "https://example.org/doc", Predicate: "https://example.org/label", Object: "hello"}},
		},
		{
			name:     "escaped_literal_object",
			document: `_:c14n0 <https://w3id.org/security#domain> "did:key:a\"b" .`,
			expected: []NQuad{{Subject: "_:c14n0", Predicate: "https://w3id.org/security#domain", Object: `did:key:a"b`}},
		},
		{
			name: "multiple_statements_and_blank_lines",
			document: `_:c14n0 <https://w3id.org/security#challenge> "n" .

_:c14n0 <https://w3id.org/security#domain> "d" .
`,
			expected: []NQuad{
				{Subject: "_:c14n0", Predicate: "https://w3id.org/security#challenge", Object: "n"},
				{Subject: "_:c14n0", Predicate: "https://w3id.org/security#domain", Object: "d"},
			},
		},
		{
			name:     "unterminated_literal_is_skipped",
			document: `_:c14n0 <https://w3id.org/security#domain> "never closed .`,
			expected: []NQuad{},
		},
		{
			name:     "empty_document",
			document: "",
			expected: []NQuad{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ParseNQuads(tc.document))
		})
	}
}

// TestHasNQuad verifies that a statement is matched on its predicate, and on
// its object when one is expected.
func TestHasNQuad(t *testing.T) {
	quads := ParseNQuads(`_:c14n0 <https://w3id.org/security#challenge> "my-nonce" .
_:c14n0 <https://w3id.org/security#domain> "did:key:verifier" .`)

	tests := []struct {
		name           string
		predicate      string
		expectedObject string
		expected       bool
	}{
		{name: "predicate_and_object_match", predicate: IRIProofChallenge, expectedObject: "my-nonce", expected: true},
		{name: "predicate_only", predicate: IRIProofChallenge, expectedObject: "", expected: true},
		{name: "object_mismatch", predicate: IRIProofChallenge, expectedObject: "other-nonce", expected: false},
		{name: "unknown_predicate", predicate: IRIProofPurpose, expectedObject: "", expected: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, HasNQuad(quads, tc.predicate, tc.expectedObject))
		})
	}
}

// TestAssertProofOptionsCovered_PredicateConfusion is the regression guard for
// the substring-matching flaw: the coverage check used to search the raw
// N-Quads text, so a proof could satisfy the challenge requirement by putting
// the challenge predicate IRI into some other field's literal value — no
// challenge triple needed. Parsing the quads and comparing predicates (and
// objects) closes that.
func TestAssertProofOptionsCovered_PredicateConfusion(t *testing.T) {
	tests := []struct {
		name    string
		quads   string
		proof   *LDProof
		wantErr error
	}{
		{
			name: "all_fields_covered",
			quads: `_:c14n0 <http://purl.org/dc/terms/created> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <https://w3id.org/security#challenge> "my-nonce" .
_:c14n0 <https://w3id.org/security#domain> "did:key:verifier" .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#authenticationMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:web:example.org#key-1> .`,
			proof: &LDProof{
				Created:            "2024-01-01T00:00:00Z",
				Challenge:          "my-nonce",
				Domain:             "did:key:verifier",
				ProofPurpose:       ProofPurposeAuthentication,
				VerificationMethod: "did:web:example.org#key-1",
			},
		},
		{
			// The domain literal spells out the challenge predicate IRI. A
			// substring search finds it; a predicate comparison does not.
			name: "challenge_iri_inside_domain_literal_does_not_cover_the_challenge",
			quads: `_:c14n0 <http://purl.org/dc/terms/created> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <https://w3id.org/security#domain> "<https://w3id.org/security#challenge>" .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:web:example.org#key-1> .`,
			proof: &LDProof{
				Created:            "2024-01-01T00:00:00Z",
				Challenge:          "my-nonce",
				Domain:             "<https://w3id.org/security#challenge>",
				VerificationMethod: "did:web:example.org#key-1",
			},
			wantErr: ErrorLDProofOptionsNotCovered,
		},
		{
			// A triple with the right predicate but a different value does
			// not cover the field either.
			name: "challenge_triple_with_another_value_does_not_cover_the_challenge",
			quads: `_:c14n0 <http://purl.org/dc/terms/created> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <https://w3id.org/security#challenge> "somebody-elses-nonce" .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:web:example.org#key-1> .`,
			proof: &LDProof{
				Created:            "2024-01-01T00:00:00Z",
				Challenge:          "my-nonce",
				VerificationMethod: "did:web:example.org#key-1",
			},
			wantErr: ErrorLDProofOptionsNotCovered,
		},
		{
			name:  "unset_fields_are_not_required",
			quads: `_:c14n0 <http://purl.org/dc/terms/created> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`,
			proof: &LDProof{Created: "2024-01-01T00:00:00Z"},
		},
		{
			name:    "missing_created_triple_is_rejected",
			quads:   `_:c14n0 <https://w3id.org/security#challenge> "my-nonce" .`,
			proof:   &LDProof{Created: "2024-01-01T00:00:00Z", Challenge: "my-nonce"},
			wantErr: ErrorLDProofOptionsNotCovered,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := assertProofOptionsCovered(tc.quads, tc.proof)
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}
