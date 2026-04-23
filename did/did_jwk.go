package did

import (
	"encoding/base64"
	"fmt"

	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	MethodJWK          = "jwk"
	TypeJsonWebKey2020 = "JsonWebKey2020"
)

// JWKVDR resolves did:jwk DIDs by decoding the JWK from the DID string.
type JWKVDR struct{}

// NewJWKVDR creates a new did:jwk resolver.
func NewJWKVDR() *JWKVDR {
	return &JWKVDR{}
}

// Accept returns true for the "jwk" method.
func (j *JWKVDR) Accept(method string) bool {
	return method == MethodJWK
}

// Read resolves a did:jwk DID.
// Format: did:jwk:<base64url-encoded-jwk>
// See https://github.com/quartzjer/did-jwk/blob/main/spec.md
func (j *JWKVDR) Read(didStr string) (*DocResolution, error) {
	logging.Log().Debugf("Resolving did:jwk: %s", didStr)

	// Extract the base64url-encoded JWK from the DID
	// did:jwk:<encoded-jwk>
	if len(didStr) <= 8 { // "did:jwk:" = 8 chars
		return nil, fmt.Errorf("%w: %s", ErrInvalidDID, didStr)
	}
	encoded := didStr[8:]

	// Remove any fragment
	fragIdx := -1
	for i, c := range encoded {
		if c == '#' {
			fragIdx = i
			break
		}
	}
	if fragIdx >= 0 {
		encoded = encoded[:fragIdx]
		logging.Log().Debug("Stripped fragment from did:jwk")
	}

	jwkBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		// Try with standard base64url (with padding)
		jwkBytes, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			logging.Log().Debugf("Failed to base64url-decode did:jwk %s: %v", didStr, err)
			return nil, fmt.Errorf("failed to decode did:jwk: %w", err)
		}
	}

	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		logging.Log().Infof("Failed to parse JWK from did:jwk %s: %v", didStr, err)
		return nil, fmt.Errorf("failed to parse JWK from did:jwk: %w", err)
	}

	vmID := didStr + "#0"
	vm := &VerificationMethod{
		ID:         vmID,
		Type:       TypeJsonWebKey2020,
		Controller: didStr,
		Value:      jwkBytes,
		jsonWebKey: key,
	}

	doc := &Doc{
		ID:                 didStr,
		VerificationMethod: []VerificationMethod{*vm},
	}

	logging.Log().Debugf("Successfully resolved did:jwk %s", didStr)

	return &DocResolution{DIDDocument: doc}, nil
}
