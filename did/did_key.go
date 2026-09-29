package did

import (
	"fmt"

	"github.com/fiware/VCVerifier/logging"
)

const (
	MethodKey = "key"
)

// KeyVDR resolves did:key DIDs by decoding the multibase/multicodec key.
type KeyVDR struct{}

// NewKeyVDR creates a new did:key resolver.
func NewKeyVDR() *KeyVDR {
	return &KeyVDR{}
}

// Accept returns true for the "key" method.
func (k *KeyVDR) Accept(method string) bool {
	return method == MethodKey
}

// Read resolves a did:key DID.
// Format: did:key:<multibase-encoded-multicodec-key>
// See https://w3c-ccg.github.io/did-method-key/
func (k *KeyVDR) Read(didStr string) (*DocResolution, error) {
	logging.Log().Debugf("Resolving did:key: %s", didStr)

	// Extract the method-specific identifier (everything after "did:key:")
	if len(didStr) <= 8 { // "did:key:" = 8 chars
		return nil, fmt.Errorf("%w: %s", ErrInvalidDID, didStr)
	}
	// Remove fragment if present
	methodSpecificID := didStr[8:]
	fragIdx := -1
	for i, c := range methodSpecificID {
		if c == '#' {
			fragIdx = i
			break
		}
	}
	baseDID := didStr
	if fragIdx >= 0 {
		methodSpecificID = methodSpecificID[:fragIdx]
		baseDID = didStr[:8+fragIdx]
		logging.Log().Debugf("Stripped fragment from did:key, base DID: %s", baseDID)
	}

	// Decode multibase + multicodec prefix and convert to JWK using the shared helper
	jwkKey, vmType, err := DecodeMultibaseKeyWithType(methodSpecificID)
	if err != nil {
		logging.Log().Infof("Failed to decode did:key %s: %v", didStr, err)
		return nil, fmt.Errorf("failed to decode did:key: %w", err)
	}

	vmID := baseDID + "#" + methodSpecificID

	vm, err := NewVerificationMethodFromJWK(vmID, vmType, baseDID, jwkKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create verification method: %w", err)
	}

	logging.Log().Debugf("Successfully resolved did:key %s with type %s", baseDID, vmType)

	// did:key documents expose their single key for every verification
	// relationship, per the did:key method specification.
	doc := &Doc{
		ID:                 baseDID,
		VerificationMethod: []VerificationMethod{*vm},
		Authentication:     []string{vmID},
		AssertionMethod:    []string{vmID},
	}

	return &DocResolution{DIDDocument: doc}, nil
}
