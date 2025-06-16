package verifier

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/vdr/api"
)

type KeyResolver interface {
	ResolvePublicKeyFromDID(kid string) (key jwk.Key, err error)
	ExtractKIDFromJWT(tokenString string) (string, error)
}

type VdrKeyResolver struct {
	Vdr []api.VDR
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

	// Use the did:key resolver (or other depending on method)
	var docRes *did.DocResolution
	for _, vdr := range kr.Vdr {
		docRes, err = vdr.Read(didID)
		if err == nil {
			break
		}
	}
	if docRes == nil {
		logging.Log().Warnf("Was not able to resolve the kid %s.", keyID)
		return key, err
	}
	doc := docRes.DIDDocument

	// Look for the verification method with the matching key ID
	var vm *did.VerificationMethod
	for _, v := range doc.VerificationMethod {
		if v.ID == keyID || v.ID == combinedKeyId {
			vm = &v
			break
		}
	}

	if vm == nil {
		logging.Log().Warnf("KeyId %s not found in verification methods. Doc: %v", keyID, logging.PrettyPrintObject(doc))
		return nil, ErrorInvalidJWT
	}

	// Serialize trustbloc's JWK to JSON
	jwkBytes, err := json.Marshal(vm.JSONWebKey())
	if err != nil {
		logging.Log().Warnf("Was not able to serialize the jwk. Err: %v", err)
		return nil, err
	}

	// Convert to JWK
	jwkKey, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		logging.Log().Warnf("Was not able to deserialize the jwk. Err: %v", err)
		return nil, err
	}

	return jwkKey, nil
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
