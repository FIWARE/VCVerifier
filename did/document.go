package did

import (
	"encoding/json"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// DocResolution contains the result of resolving a DID.
type DocResolution struct {
	DIDDocument *Doc
}

// Verification relationships as defined by the DID Core specification.
// See https://www.w3.org/TR/did-core/#verification-relationships.
const (
	// RelationshipAuthentication authorizes a key to authenticate as the DID
	// subject — the relationship a Verifiable Presentation proof needs.
	RelationshipAuthentication = "authentication"

	// RelationshipAssertionMethod authorizes a key to make assertions on
	// behalf of the DID subject — the relationship a Verifiable Credential
	// proof needs.
	RelationshipAssertionMethod = "assertionMethod"
)

// Doc represents a DID Document.
type Doc struct {
	ID                 string
	VerificationMethod []VerificationMethod
	// Authentication holds the IDs of the verification methods listed under
	// the document's `authentication` relationship.
	Authentication []string
	// AssertionMethod holds the IDs of the verification methods listed under
	// the document's `assertionMethod` relationship.
	AssertionMethod []string
}

// DeclaresRelationships reports whether the document declares any verification
// relationship at all. Documents that declare none cannot be checked against a
// relationship, so callers have to decide how to treat them.
func (d *Doc) DeclaresRelationships() bool {
	return len(d.Authentication) > 0 || len(d.AssertionMethod) > 0
}

// AllowsForRelationship reports whether the verification method identified by
// vmID is listed under the given relationship. Matching accepts both the fully
// qualified method ID and a bare fragment reference (`#key-1`), which DID
// documents are allowed to use as a relative reference to their own methods.
func (d *Doc) AllowsForRelationship(vmID string, relationship string) bool {
	var candidates []string
	switch relationship {
	case RelationshipAuthentication:
		candidates = d.Authentication
	case RelationshipAssertionMethod:
		candidates = d.AssertionMethod
	default:
		return false
	}

	for _, candidate := range candidates {
		if candidate == vmID {
			return true
		}
		// Relative references (`#key-1`) resolve against the document ID.
		if strings.HasPrefix(candidate, "#") && d.ID+candidate == vmID {
			return true
		}
	}
	return false
}

// VerificationMethod represents a verification method in a DID document.
type VerificationMethod struct {
	ID         string
	Type       string
	Controller string
	Value      []byte
	jsonWebKey jwk.Key
}

// JSONWebKey returns the JWK representation of this verification method's key, or nil.
func (vm *VerificationMethod) JSONWebKey() jwk.Key {
	return vm.jsonWebKey
}

// NewVerificationMethodFromJWK creates a VerificationMethod from a JWK key.
func NewVerificationMethodFromJWK(id, vmType, controller string, key jwk.Key) (*VerificationMethod, error) {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}

	return &VerificationMethod{
		ID:         id,
		Type:       vmType,
		Controller: controller,
		Value:      keyBytes,
		jsonWebKey: key,
	}, nil
}

// NewVerificationMethodFromBytes creates a VerificationMethod from raw key bytes.
func NewVerificationMethodFromBytes(id, vmType, controller string, value []byte) *VerificationMethod {
	return &VerificationMethod{
		ID:         id,
		Type:       vmType,
		Controller: controller,
		Value:      value,
	}
}
