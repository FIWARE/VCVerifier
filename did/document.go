package did

import (
	"encoding/json"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// DocResolution contains the result of resolving a DID.
type DocResolution struct {
	DIDDocument *Doc
}

// Doc represents a DID Document.
type Doc struct {
	ID                 string
	VerificationMethod []VerificationMethod
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
