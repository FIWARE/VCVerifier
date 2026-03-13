package verifier

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type KeyResolver interface {
	ResolvePublicKeyFromDID(kid string) (key jwk.Key, err error)
	ExtractKIDFromJWT(tokenString string) (string, error)
}

type VdrKeyResolver struct {
	Vdr []did.VDR
}

func (kr *VdrKeyResolver) ResolvePublicKeyFromDID(kid string) (key jwk.Key, err error) {
	// Extract base DID from `did:xyz:123#key-1`
	didKeyParts := strings.SplitN(kid, "#", 2)
	var didID string
	var keyID string
	var combinedKeyId string
	if len(didKeyParts) == 1 {
		didID = didKeyParts[0]
		keyID = kid
		combinedKeyId = kid + "#" + strings.SplitN(kid, ":", 3)[2]
	} else {
		didID = didKeyParts[0]
		keyID = kid
		combinedKeyId = kid
	}

	// Resolve using the appropriate VDR
	var docRes *did.DocResolution
	for _, vdr := range kr.Vdr {
		if docRes, err = vdr.Read(didID); err == nil {
			break
		}
	}
	if docRes == nil {
		logging.Log().Warnf("Was not able to resolve the kid %s.", keyID)
		return key, err
	}
	doc := docRes.DIDDocument

	// Look for the verification method with the matching key ID
	for _, v := range doc.VerificationMethod {
		if v.ID == keyID || v.ID == combinedKeyId {
			if v.JSONWebKey() != nil {
				return v.JSONWebKey(), nil
			}
			logging.Log().Warnf("Verification method %s has no JWK key.", v.ID)
			return nil, ErrorInvalidJWT
		}
	}

	logging.Log().Warnf("KeyId %s not found in verification methods.", keyID)
	return nil, ErrorInvalidJWT
}

func (kr *VdrKeyResolver) ExtractKIDFromJWT(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return "", ErrorInvalidJWT
	}

	// Decode the first part (header)
	headerSegment := parts[0]
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerSegment)
	if err != nil {
		return "", ErrorInvalidJWT
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", ErrorInvalidJWT
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return "", ErrorInvalidJWT
	}

	return kid, nil
}
