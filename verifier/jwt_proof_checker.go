package verifier

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/jades"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

const DidElsiPrefix = "did:elsi:"
const DidPartsSeparator = ":"
const JWSHeaderX5C = "x5c"

var ErrorNoSignatures = errors.New("no_signatures_in_jwt")
var ErrorNoDIDInJWT = errors.New("no_did_found_in_jwt")
var ErrorInvalidJAdESSignature = errors.New("invalid_jades_signature")
var ErrorNoCertInHeader = errors.New("no_certificate_found_in_jwt_header")
var ErrorCertHeaderEmpty = errors.New("cert_header_is_empty")
var ErrorPemDecodeFailed = errors.New("failed_to_decode_pem_from_header")
var ErrorIssuerValidationFailed = errors.New("isser_validation_failed")

// JWTProofChecker verifies JWT signatures using DID-resolved keys.
// Supports standard DID methods via the did.Registry and optionally did:elsi via JAdES.
type JWTProofChecker struct {
	registry       *did.Registry
	jAdESValidator jades.JAdESValidator
}

func NewJWTProofChecker(registry *did.Registry, jAdESValidator jades.JAdESValidator) *JWTProofChecker {
	return &JWTProofChecker{
		registry:       registry,
		jAdESValidator: jAdESValidator,
	}
}

// VerifyJWT verifies the JWT signature using DID-resolved keys and returns the payload.
func (jpc *JWTProofChecker) VerifyJWT(token []byte) ([]byte, error) {
	payload, _, err := jpc.VerifyJWTAndReturnKey(token)
	return payload, err
}

// VerifyJWTAndReturnKey verifies the JWT signature and returns both the payload and the
// resolved signer key. For did:elsi (JAdES-based), the key is nil since verification
// uses certificate chains instead of JWKs.
func (jpc *JWTProofChecker) VerifyJWTAndReturnKey(token []byte) ([]byte, jwk.Key, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return nil, nil, err
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, nil, ErrorNoSignatures
	}

	headers := sigs[0].ProtectedHeaders()
	kid, _ := headers.KeyID()
	issFromPayload := extractIssFromPayload(msg.Payload())

	// Determine issuer DID.
	// For did:elsi, the iss claim from the payload is authoritative (not the kid).
	// For standard DID methods, prefer kid (contains the key reference), fall back to iss.
	var issuerDID string
	if issFromPayload != "" && isDidElsiMethod(issFromPayload) {
		issuerDID = issFromPayload
	} else {
		issuerDID = extractDIDFromKid(kid)
		if issuerDID == "" {
			issuerDID = issFromPayload
		}
	}
	if issuerDID == "" {
		return nil, nil, ErrorNoDIDInJWT
	}

	// Handle did:elsi — no JWK available, returns nil key
	if jpc.jAdESValidator != nil && isDidElsiMethod(issuerDID) {
		payload, err := jpc.verifyElsiJWT(token, issuerDID)
		return payload, nil, err
	}

	// Resolve DID → public key
	key, err := jpc.resolveKey(issuerDID, kid)
	if err != nil {
		return nil, nil, err
	}

	alg, _ := headers.Algorithm()
	payload, err := jws.Verify(token, jws.WithKey(alg, key))
	if err != nil {
		logging.Log().Warnf("JWT signature verification failed for %s: %v", issuerDID, err)
		return nil, nil, err
	}
	return payload, key, nil
}

func (jpc *JWTProofChecker) resolveKey(didStr, kid string) (jwk.Key, error) {
	docRes, err := jpc.registry.Resolve(didStr)
	if err != nil {
		logging.Log().Warnf("Failed to resolve DID %s: %v", didStr, err)
		return nil, err
	}

	for _, vm := range docRes.DIDDocument.VerificationMethod {
		if compareVerificationMethod(kid, vm.ID) {
			key := vm.JSONWebKey()
			if key == nil {
				return nil, ErrorNoVerificationKey
			}
			return key, nil
		}
	}

	logging.Log().Warnf("No matching verification method for kid=%s in DID=%s", kid, didStr)
	return nil, ErrorNoVerificationKey
}

// extractDIDFromKid extracts the DID from a kid header value.
// e.g., "did:web:example.com#key-1" → "did:web:example.com"
func extractDIDFromKid(kid string) string {
	if !strings.HasPrefix(kid, "did:") {
		return ""
	}
	if idx := strings.Index(kid, "#"); idx > 0 {
		return kid[:idx]
	}
	return kid
}

// extractIssFromPayload extracts the "iss" claim from a JWT payload.
func extractIssFromPayload(payload []byte) string {
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	iss, _ := claims[common.JWTClaimIss].(string)
	return iss
}

func isDidElsiMethod(did string) bool {
	parts := strings.Split(did, DidPartsSeparator)
	return len(parts) == 3 && strings.HasPrefix(did, DidElsiPrefix)
}

func (jpc *JWTProofChecker) verifyElsiJWT(token []byte, issuerDID string) ([]byte, error) {
	certChain, err := extractX5CFromToken(token)
	if err != nil {
		return nil, err
	}
	if len(certChain) == 0 {
		return nil, ErrorCertHeaderEmpty
	}

	certificate, err := parseCertificate(certChain[0])
	if err != nil {
		return nil, err
	}

	err = validateIssuer(certificate, issuerDID)
	if err != nil {
		logging.Log().Debugf("%v is not the valid issuer.", issuerDID)
		return nil, err
	}

	base64Jwt := base64.StdEncoding.EncodeToString(token)
	isValid, err := jpc.jAdESValidator.ValidateSignature(base64Jwt)
	if err != nil {
		logging.Log().Warnf("Was not able to validate JAdES signature. Err: %v", err)
		return nil, err
	}
	if !isValid {
		logging.Log().Info("JAdES signature was invalid.")
		return nil, ErrorInvalidJAdESSignature
	}

	// Extract payload
	parts := strings.SplitN(string(token), ".", 3)
	if len(parts) < 2 {
		return nil, ErrorInvalidJWTFormat
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	logging.Log().Debug("Valid did:elsi credential.")
	return payload, nil
}

func extractX5CFromToken(token []byte) ([]string, error) {
	parts := strings.SplitN(string(token), ".", 3)
	if len(parts) < 2 {
		return nil, ErrorInvalidJWTFormat
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	x5cRaw, ok := header[JWSHeaderX5C]
	if !ok {
		return nil, ErrorNoCertInHeader
	}
	x5cArray, ok := x5cRaw.([]interface{})
	if !ok {
		return nil, ErrorCertHeaderEmpty
	}
	result := make([]string, len(x5cArray))
	for i, v := range x5cArray {
		s, ok := v.(string)
		if !ok {
			return nil, ErrorCertHeaderEmpty
		}
		result[i] = s
	}
	return result, nil
}

func parseCertificate(certBase64 string) (*x509.Certificate, error) {
	certDER, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		logging.Log().Warnf("Failed to decode the certificate header. Error: %v", err)
		return nil, ErrorPemDecodeFailed
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		logging.Log().Warnf("Failed to parse the certificate header. Error: %v", err)
		return nil, err
	}
	return cert, nil
}

func validateIssuer(certificate *x509.Certificate, issuerDid string) error {
	var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	organizationIdentifier := ""

	for _, name := range certificate.Subject.Names {
		logging.Log().Debugf("Check oid %v", name)
		if name.Type.Equal(oidOrganizationIdentifier) {
			organizationIdentifier = name.Value.(string)
			break
		}
	}
	if organizationIdentifier != "" && strings.HasSuffix(issuerDid, DidPartsSeparator+organizationIdentifier) {
		return nil
	} else {
		return ErrorIssuerValidationFailed
	}
}
