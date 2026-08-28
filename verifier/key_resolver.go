package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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

// didElsiMethodPrefix is the prefix for did:elsi DIDs. JAdES is JWS-based
// and does not apply to Linked Data Proofs.
const didElsiMethodPrefix = "did:elsi:"

// ErrorDidElsiNotSupportedForLDProof is returned when a did:elsi verification
// method is encountered in an LD-proof context. JAdES is JWS-based and does
// not apply to Linked Data Proofs.
var ErrorDidElsiNotSupportedForLDProof = errors.New("did_elsi_not_supported_for_ld_proofs")

// ErrorVerificationRelationshipNotAllowed is returned when a verification
// method exists in the DID document but is not authorized for the
// verification relationship the proof requires (e.g. a key listed only under
// assertionMethod being used to authenticate a presentation).
var ErrorVerificationRelationshipNotAllowed = errors.New("verification_method_not_allowed_for_relationship")

// ResolveKeyFromDID resolves a DID to a public JWK key by querying the
// given did.Registry. The didStr is the full DID (e.g., "did:key:z6Mk..."),
// and kid is the key identifier used to select the correct verification
// method from the DID document (e.g., "did:key:z6Mk...#z6Mk...").
//
// This function is shared between JWTProofChecker and LDProofChecker to
// avoid duplicating DID-to-key resolution logic.
func ResolveKeyFromDID(registry *did.Registry, didStr string, kid string) (jwk.Key, error) {
	return ResolveKeyForRelationship(registry, didStr, kid, "")
}

// ResolveKeyForRelationship resolves a DID to a public JWK key and, when a
// relationship is given (did.RelationshipAuthentication or
// did.RelationshipAssertionMethod), additionally requires the verification
// method to be authorized for that relationship in the DID document.
//
// A DID document that declares no verification relationships at all cannot be
// checked — the flat verificationMethod list is then used and a warning is
// logged. Documents that declare relationships are enforced strictly.
func ResolveKeyForRelationship(registry *did.Registry, didStr string, kid string, relationship string) (jwk.Key, error) {
	docRes, err := registry.Resolve(didStr)
	if err != nil {
		logging.Log().Warnf("Failed to resolve DID %s: %v", didStr, err)
		return nil, err
	}
	doc := docRes.DIDDocument

	for _, vm := range doc.VerificationMethod {
		if !compareVerificationMethod(kid, vm.ID) {
			continue
		}
		if err := checkVerificationRelationship(doc, vm.ID, relationship); err != nil {
			return nil, err
		}
		key := vm.JSONWebKey()
		if key == nil {
			return nil, ErrorNoVerificationKey
		}
		return key, nil
	}

	logging.Log().Warnf("No matching verification method for kid=%s in DID=%s", kid, didStr)
	return nil, ErrorNoVerificationKey
}

// checkVerificationRelationship enforces that vmID is authorized for the
// requested relationship. It is a no-op when no relationship is requested or
// when the DID document does not model verification relationships.
func checkVerificationRelationship(doc *did.Doc, vmID string, relationship string) error {
	if relationship == "" {
		return nil
	}
	if !doc.DeclaresRelationships() {
		logging.Log().Warnf("DID document %s declares no verification relationships — cannot enforce %s for %s",
			doc.ID, relationship, vmID)
		return nil
	}
	if !doc.AllowsForRelationship(vmID, relationship) {
		logging.Log().Warnf("Verification method %s is not authorized for relationship %s in DID document %s",
			vmID, relationship, doc.ID)
		return ErrorVerificationRelationshipNotAllowed
	}
	return nil
}

// ExtractDIDAndFragment splits a verification method URI into a DID and a
// key ID (kid). For example, "did:key:z6Mk...#z6Mk..." returns
// ("did:key:z6Mk...", "did:key:z6Mk...#z6Mk..."). If no fragment is
// present, the full string is returned as both the DID and the kid.
func ExtractDIDAndFragment(verificationMethod string) (didStr string, kid string) {
	if idx := strings.Index(verificationMethod, "#"); idx > 0 {
		return verificationMethod[:idx], verificationMethod
	}
	return verificationMethod, verificationMethod
}

// IsDidElsi returns true if the given DID string uses the did:elsi method.
func IsDidElsi(didStr string) bool {
	return strings.HasPrefix(didStr, didElsiMethodPrefix)
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
