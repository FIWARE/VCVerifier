package did

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDocAllowsForRelationship covers the verification-relationship lookup,
// including the relative fragment references DID documents are allowed to use
// for their own methods.
func TestDocAllowsForRelationship(t *testing.T) {
	doc := &Doc{
		ID:              "did:web:example.com",
		Authentication:  []string{"did:web:example.com#auth-key"},
		AssertionMethod: []string{"#assert-key"},
	}

	tests := []struct {
		name         string
		vmID         string
		relationship string
		want         bool
	}{
		{name: "absolute_authentication_match", vmID: "did:web:example.com#auth-key", relationship: RelationshipAuthentication, want: true},
		{name: "relative_assertion_match", vmID: "did:web:example.com#assert-key", relationship: RelationshipAssertionMethod, want: true},
		{name: "authentication_key_not_valid_for_assertion", vmID: "did:web:example.com#auth-key", relationship: RelationshipAssertionMethod, want: false},
		{name: "assertion_key_not_valid_for_authentication", vmID: "did:web:example.com#assert-key", relationship: RelationshipAuthentication, want: false},
		{name: "unknown_key", vmID: "did:web:example.com#other", relationship: RelationshipAuthentication, want: false},
		{name: "unknown_relationship", vmID: "did:web:example.com#auth-key", relationship: "keyAgreement", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, doc.AllowsForRelationship(tc.vmID, tc.relationship))
		})
	}
}

// TestDocDeclaresRelationships verifies the distinction between a document
// that models verification relationships and one that only lists methods.
func TestDocDeclaresRelationships(t *testing.T) {
	tests := []struct {
		name string
		doc  *Doc
		want bool
	}{
		{name: "no_relationships", doc: &Doc{ID: "did:web:example.com"}, want: false},
		{name: "authentication_only", doc: &Doc{Authentication: []string{"#k"}}, want: true},
		{name: "assertion_only", doc: &Doc{AssertionMethod: []string{"#k"}}, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.doc.DeclaresRelationships())
		})
	}
}

// TestParseDIDDocumentRelationships verifies that both reference-style and
// embedded verification relationship entries are parsed, and that embedded
// methods also become resolvable through the flat verificationMethod list.
func TestParseDIDDocumentRelationships(t *testing.T) {
	const document = `{
		"id": "did:web:example.com",
		"verificationMethod": [{
			"id": "did:web:example.com#key-1",
			"type": "JsonWebKey2020",
			"controller": "did:web:example.com",
			"publicKeyJwk": {"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
		}],
		"authentication": ["did:web:example.com#key-1"],
		"assertionMethod": [{
			"id": "did:web:example.com#key-2",
			"type": "JsonWebKey2020",
			"controller": "did:web:example.com",
			"publicKeyJwk": {"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
		}]
	}`

	doc, err := parseDIDDocument([]byte(document))
	require.NoError(t, err)

	assert.Equal(t, []string{"did:web:example.com#key-1"}, doc.Authentication)
	assert.Equal(t, []string{"did:web:example.com#key-2"}, doc.AssertionMethod)
	require.Len(t, doc.VerificationMethod, 2, "the embedded assertion method must be resolvable too")
	assert.True(t, doc.AllowsForRelationship("did:web:example.com#key-1", RelationshipAuthentication))
	assert.False(t, doc.AllowsForRelationship("did:web:example.com#key-1", RelationshipAssertionMethod))
}

// TestParseDIDDocumentWithoutRelationships verifies that a document listing
// only verification methods parses and reports that it declares none.
func TestParseDIDDocumentWithoutRelationships(t *testing.T) {
	const document = `{
		"id": "did:web:example.com",
		"verificationMethod": [{
			"id": "did:web:example.com#key-1",
			"type": "JsonWebKey2020",
			"controller": "did:web:example.com",
			"publicKeyJwk": {"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
		}]
	}`

	doc, err := parseDIDDocument([]byte(document))
	require.NoError(t, err)
	assert.False(t, doc.DeclaresRelationships())
}
