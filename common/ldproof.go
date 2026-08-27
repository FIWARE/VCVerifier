package common

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/piprate/json-gold/ld"
)

// Linked Data Proof JSON keys.
const (
	LDProofKeyCreated            = "created"
	LDProofKeyVerificationMethod = "verificationMethod"
	LDProofKeyProofPurpose       = "proofPurpose"
	LDProofKeyChallenge          = "challenge"
	LDProofKeyDomain             = "domain"
	LDProofKeyProofValue         = "proofValue"
	LDProofKeyCryptosuite        = "cryptosuite"
	LDProofKeyJWS                = "jws"
	LDProofKeyType               = "type"
)

// JWS header keys.
const (
	JWSHeaderAlg  = "alg"
	JWSHeaderB64  = "b64"
	JWSHeaderCrit = "crit"
)

// Linked Data normalization constants.
const (
	LDNormFormatNQuads   = "application/n-quads"
	LDNormAlgorithmURDNA = "URDNA2015"
)

var (
	ErrorLDProofMarshal    = errors.New("failed_to_marshal_presentation")
	ErrorLDProofUnmarshal  = errors.New("failed_to_unmarshal_presentation")
	ErrorLDProofCanonDoc   = errors.New("failed_to_canonicalize_document")
	ErrorLDProofCanonProof = errors.New("failed_to_canonicalize_proof_options")
	ErrorLDProofSign       = errors.New("failed_to_sign")

	// ErrorLDProofMissingType is returned when a proof map has no "type" field.
	ErrorLDProofMissingType = errors.New("ld_proof_missing_type")

	// ErrorLDProofInvalidFormat is returned when a proof value is neither a map nor a slice of maps.
	ErrorLDProofInvalidFormat = errors.New("ld_proof_invalid_format")

	// ErrorLDProofNoSignature is returned when a proof has neither "jws" nor "proofValue".
	ErrorLDProofNoSignature = errors.New("ld_proof_no_signature")

	// ErrorLDProofVerifyMarshal is returned when the document cannot be unmarshalled during verification.
	ErrorLDProofVerifyMarshal = errors.New("ld_proof_verify_failed_to_unmarshal_document")

	// ErrorLDProofVerifyCanonDoc is returned when the document cannot be canonicalized during verification.
	ErrorLDProofVerifyCanonDoc = errors.New("ld_proof_verify_failed_to_canonicalize_document")

	// ErrorLDProofVerifyCanonProof is returned when the proof options cannot be canonicalized during verification.
	ErrorLDProofVerifyCanonProof = errors.New("ld_proof_verify_failed_to_canonicalize_proof_options")

	// ErrorLDProofVerifySignature is returned when the JWS signature verification fails.
	ErrorLDProofVerifySignature = errors.New("ld_proof_verify_signature_failed")

	// ErrorLDProofMissingCreated is returned when a proof has no "created" timestamp.
	ErrorLDProofMissingCreated = errors.New("ld_proof_missing_created")

	// ErrorLDProofUnsupportedType is returned when a proof type is not supported for verification.
	ErrorLDProofUnsupportedType = errors.New("ld_proof_unsupported_type")

	// ErrorLDProofAlgMismatch is returned when the JWS algorithm does not match the key type.
	ErrorLDProofAlgMismatch = errors.New("ld_proof_algorithm_key_type_mismatch")

	// ErrorLDProofMissingJWS is returned when a proof has no "jws" field.
	ErrorLDProofMissingJWS = errors.New("ld_proof_missing_jws")

	// ErrorLDProofMalformedJWS is returned when the JWS is not a valid detached JWS (header..signature).
	ErrorLDProofMalformedJWS = errors.New("ld_proof_malformed_jws")

	// ErrorLDProofInvalidB64Header is returned when the JWS header is missing b64=false or crit=["b64"].
	ErrorLDProofInvalidB64Header = errors.New("ld_proof_invalid_b64_header")
)

// Supported proof type for verification.
const (
	// ProofTypeJsonWebSignature2020 is the W3C JsonWebSignature2020 proof type
	// using detached JWS with b64=false.
	ProofTypeJsonWebSignature2020 = "JsonWebSignature2020"
)

// jwsDetachedParts is the expected number of parts in a compact JWS (header.payload.signature).
const jwsDetachedParts = 3

// algKeyTypeMap maps JWS algorithms to their expected JWK key types for cross-checking.
var algKeyTypeMap = map[string]jwa.KeyType{
	"RS256": jwa.RSA(),
	"RS384": jwa.RSA(),
	"RS512": jwa.RSA(),
	"PS256": jwa.RSA(),
	"PS384": jwa.RSA(),
	"PS512": jwa.RSA(),
	"ES256": jwa.EC(),
	"ES384": jwa.EC(),
	"ES512": jwa.EC(),
	"EdDSA": jwa.OKP(),
}

// LDProof represents a Linked Data Proof (Data Integrity Proof) attached to a
// Verifiable Credential or Verifiable Presentation.
// It covers both JsonWebSignature2020 (JWS-based) and newer Data Integrity
// suites (proofValue-based). See https://www.w3.org/TR/vc-data-integrity/.
type LDProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	JWS                string `json:"jws,omitempty"`
	ProofPurpose       string `json:"proofPurpose,omitempty"`
	Challenge          string `json:"challenge,omitempty"`
	Domain             string `json:"domain,omitempty"`
	ProofValue         string `json:"proofValue,omitempty"`
	Cryptosuite        string `json:"cryptosuite,omitempty"`
}

// LDSigner signs data for use in Linked Data Proofs.
type LDSigner interface {
	Sign(data []byte) ([]byte, error)
}

// LinkedDataProofContext holds parameters for creating a JsonWebSignature2020 LD-proof.
type LinkedDataProofContext struct {
	Created            *time.Time
	SignatureType      string
	Algorithm          string // JWS algorithm name (e.g., "PS256")
	VerificationMethod string
	Signer             LDSigner
	DocumentLoader     ld.DocumentLoader
}

// ParseLDProof extracts an LDProof from a JSON map. It handles both
// JsonWebSignature2020 (JWS-based) and newer Data Integrity suites
// (proofValue-based). Returns an error if the map has no "type" field or
// contains neither "jws" nor "proofValue".
func ParseLDProof(proofMap map[string]interface{}) (*LDProof, error) {
	proofType, ok := proofMap[LDProofKeyType].(string)
	if !ok || proofType == "" {
		return nil, ErrorLDProofMissingType
	}

	proof := &LDProof{
		Type: proofType,
	}

	if v, ok := proofMap[LDProofKeyCreated].(string); ok {
		proof.Created = v
	}
	if v, ok := proofMap[LDProofKeyVerificationMethod].(string); ok {
		proof.VerificationMethod = v
	}
	if v, ok := proofMap[LDProofKeyJWS].(string); ok {
		proof.JWS = v
	}
	if v, ok := proofMap[LDProofKeyProofPurpose].(string); ok {
		proof.ProofPurpose = v
	}
	if v, ok := proofMap[LDProofKeyChallenge].(string); ok {
		proof.Challenge = v
	}
	if v, ok := proofMap[LDProofKeyDomain].(string); ok {
		proof.Domain = v
	}
	if v, ok := proofMap[LDProofKeyProofValue].(string); ok {
		proof.ProofValue = v
	}
	if v, ok := proofMap[LDProofKeyCryptosuite].(string); ok {
		proof.Cryptosuite = v
	}

	// A valid proof must carry at least one signature field.
	if proof.JWS == "" && proof.ProofValue == "" {
		return nil, ErrorLDProofNoSignature
	}

	return proof, nil
}

// ParseLDProofs parses one or more LD proofs from a raw JSON value.
// The value may be a single proof map or an array of proof maps.
// Returns nil (no error) when proofRaw is nil.
func ParseLDProofs(proofRaw interface{}) ([]*LDProof, error) {
	if proofRaw == nil {
		return nil, nil
	}

	switch v := proofRaw.(type) {
	case map[string]interface{}:
		p, err := ParseLDProof(v)
		if err != nil {
			return nil, err
		}
		return []*LDProof{p}, nil

	case []interface{}:
		proofs := make([]*LDProof, 0, len(v))
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				return nil, ErrorLDProofInvalidFormat
			}
			p, err := ParseLDProof(m)
			if err != nil {
				return nil, err
			}
			proofs = append(proofs, p)
		}
		return proofs, nil

	default:
		return nil, ErrorLDProofInvalidFormat
	}
}

// AddLinkedDataProof creates a JsonWebSignature2020 linked data proof and
// appends it to the presentation's Proofs slice.
func (p *Presentation) AddLinkedDataProof(ctx *LinkedDataProofContext) error {
	// Marshal VP to JSON (without proof)
	vpJSON, err := p.MarshalJSON()
	if err != nil {
		logging.Log().Warnf("Failed to marshal presentation for LD proof: %v", err)
		return fmt.Errorf("%w: %w", ErrorLDProofMarshal, err)
	}
	var vpMap JSONObject
	if err := json.Unmarshal(vpJSON, &vpMap); err != nil {
		logging.Log().Warnf("Failed to unmarshal presentation for LD proof: %v", err)
		return fmt.Errorf("%w: %w", ErrorLDProofUnmarshal, err)
	}
	delete(vpMap, VPKeyProof)

	// Create proof options with @context from the document
	created := ctx.Created.Format(time.RFC3339)
	proofOptions := JSONObject{
		JSONLDKeyContext:             vpMap[JSONLDKeyContext],
		JSONLDKeyType:                ctx.SignatureType,
		LDProofKeyCreated:            created,
		LDProofKeyVerificationMethod: ctx.VerificationMethod,
	}

	// Canonicalize document and proof options using URDNA2015
	proc := ld.NewJsonLdProcessor()
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Format = LDNormFormatNQuads
	ldOpts.Algorithm = LDNormAlgorithmURDNA
	ldOpts.DocumentLoader = ctx.DocumentLoader

	canonDoc, err := proc.Normalize(vpMap, ldOpts)
	if err != nil {
		logging.Log().Warnf("Failed to canonicalize document: %v", err)
		return fmt.Errorf("%w: %w", ErrorLDProofCanonDoc, err)
	}

	canonProof, err := proc.Normalize(proofOptions, ldOpts)
	if err != nil {
		logging.Log().Warnf("Failed to canonicalize proof options: %v", err)
		return fmt.Errorf("%w: %w", ErrorLDProofCanonProof, err)
	}

	// Hash both canonical forms
	docHash := sha256.Sum256([]byte(canonDoc.(string)))
	proofHash := sha256.Sum256([]byte(canonProof.(string)))

	// tbs = hash(proof_options) || hash(document)
	tbs := append(proofHash[:], docHash[:]...)

	// Create detached JWS with b64=false
	headerJSON, _ := json.Marshal(map[string]interface{}{
		JWSHeaderAlg:  ctx.Algorithm,
		JWSHeaderB64:  false,
		JWSHeaderCrit: []string{JWSHeaderB64},
	})
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Signing input: ASCII(header) || "." || payload_bytes (raw since b64=false)
	signingInput := append([]byte(headerB64+"."), tbs...)

	sig, err := ctx.Signer.Sign(signingInput)
	if err != nil {
		logging.Log().Warnf("Failed to sign LD proof: %v", err)
		return fmt.Errorf("%w: %w", ErrorLDProofSign, err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	jwsValue := headerB64 + ".." + sigB64

	proof := &LDProof{
		Type:               ctx.SignatureType,
		Created:            created,
		VerificationMethod: ctx.VerificationMethod,
		JWS:                jwsValue,
	}
	p.Proofs = append(p.Proofs, proof)

	return nil
}

// VerifyLinkedDataProof verifies a JsonWebSignature2020 linked data proof by
// canonicalizing the document and proof options, computing the tbs hash, and
// verifying the detached JWS signature against the provided public key.
//
// The documentJSON must be the full JSON-LD document (including the proof member
// if present—it will be stripped internally). The proof parameter is the parsed
// LDProof to verify. The publicKey is the JWK public key of the proof creator.
// The documentLoader is used for JSON-LD context resolution during canonicalization.
//
// Returns nil on successful verification, or a wrapped error describing the failure.
func VerifyLinkedDataProof(documentJSON []byte, proof *LDProof, publicKey jwk.Key, documentLoader ld.DocumentLoader) error {
	// 1. Validate proof type
	if proof.Type != ProofTypeJsonWebSignature2020 {
		return fmt.Errorf("%w: %s", ErrorLDProofUnsupportedType, proof.Type)
	}

	// 2. Validate created timestamp
	if proof.Created == "" {
		return ErrorLDProofMissingCreated
	}

	// 3. Validate JWS presence
	if proof.JWS == "" {
		return ErrorLDProofMissingJWS
	}

	// 4. Validate JWS structure (header..signature)
	jwsParts := strings.SplitN(proof.JWS, ".", jwsDetachedParts)
	if len(jwsParts) != jwsDetachedParts || jwsParts[0] == "" || jwsParts[2] == "" {
		return fmt.Errorf("%w: expected header..signature format", ErrorLDProofMalformedJWS)
	}
	// In a detached JWS the payload part must be empty.
	if jwsParts[1] != "" {
		return fmt.Errorf("%w: payload must be empty in detached JWS", ErrorLDProofMalformedJWS)
	}

	// 5. Decode and validate JWS header
	headerBytes, err := base64.RawURLEncoding.DecodeString(jwsParts[0])
	if err != nil {
		return fmt.Errorf("%w: failed to decode header: %v", ErrorLDProofMalformedJWS, err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("%w: failed to parse header: %v", ErrorLDProofMalformedJWS, err)
	}

	// Verify b64=false
	b64Val, ok := header[JWSHeaderB64]
	if !ok {
		return fmt.Errorf("%w: missing b64 header", ErrorLDProofInvalidB64Header)
	}
	b64Bool, ok := b64Val.(bool)
	if !ok || b64Bool {
		return fmt.Errorf("%w: b64 must be false", ErrorLDProofInvalidB64Header)
	}

	// Verify crit=["b64"]
	critVal, ok := header[JWSHeaderCrit]
	if !ok {
		return fmt.Errorf("%w: missing crit header", ErrorLDProofInvalidB64Header)
	}
	critArr, ok := critVal.([]interface{})
	if !ok || len(critArr) == 0 {
		return fmt.Errorf("%w: crit must be a non-empty array", ErrorLDProofInvalidB64Header)
	}
	hasCritB64 := false
	for _, v := range critArr {
		if s, ok := v.(string); ok && s == JWSHeaderB64 {
			hasCritB64 = true
			break
		}
	}
	if !hasCritB64 {
		return fmt.Errorf("%w: crit must contain \"b64\"", ErrorLDProofInvalidB64Header)
	}

	// 6. Extract and validate algorithm
	algStr, ok := header[JWSHeaderAlg].(string)
	if !ok || algStr == "" {
		return fmt.Errorf("%w: missing or invalid alg header", ErrorLDProofMalformedJWS)
	}

	// 7. Cross-check algorithm against key type
	expectedKeyType, known := algKeyTypeMap[algStr]
	if !known {
		return fmt.Errorf("%w: unknown algorithm %s", ErrorLDProofAlgMismatch, algStr)
	}
	if publicKey.KeyType() != expectedKeyType {
		return fmt.Errorf("%w: algorithm %s requires key type %s but got %s",
			ErrorLDProofAlgMismatch, algStr, expectedKeyType, publicKey.KeyType())
	}

	// 8. Unmarshal document and remove proof
	var docMap JSONObject
	if err := json.Unmarshal(documentJSON, &docMap); err != nil {
		return fmt.Errorf("%w: %v", ErrorLDProofVerifyMarshal, err)
	}
	delete(docMap, VPKeyProof)

	// 9. Build proof options map
	proofOptions := JSONObject{
		JSONLDKeyContext:              docMap[JSONLDKeyContext],
		JSONLDKeyType:                 proof.Type,
		LDProofKeyCreated:            proof.Created,
		LDProofKeyVerificationMethod: proof.VerificationMethod,
	}
	if proof.ProofPurpose != "" {
		proofOptions[LDProofKeyProofPurpose] = proof.ProofPurpose
	}
	if proof.Challenge != "" {
		proofOptions[LDProofKeyChallenge] = proof.Challenge
	}
	if proof.Domain != "" {
		proofOptions[LDProofKeyDomain] = proof.Domain
	}

	// 10. Canonicalize both document and proof options using URDNA2015
	proc := ld.NewJsonLdProcessor()
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Format = LDNormFormatNQuads
	ldOpts.Algorithm = LDNormAlgorithmURDNA
	ldOpts.DocumentLoader = documentLoader

	canonDoc, err := proc.Normalize(docMap, ldOpts)
	if err != nil {
		logging.Log().Warnf("VerifyLinkedDataProof: failed to canonicalize document: %v", err)
		return fmt.Errorf("%w: %v", ErrorLDProofVerifyCanonDoc, err)
	}

	canonProof, err := proc.Normalize(proofOptions, ldOpts)
	if err != nil {
		logging.Log().Warnf("VerifyLinkedDataProof: failed to canonicalize proof options: %v", err)
		return fmt.Errorf("%w: %v", ErrorLDProofVerifyCanonProof, err)
	}

	// 11. Compute tbs = sha256(canonicalProofOptions) || sha256(canonicalDocument)
	docHash := sha256.Sum256([]byte(canonDoc.(string)))
	proofHash := sha256.Sum256([]byte(canonProof.(string)))
	tbs := append(proofHash[:], docHash[:]...)

	// 12. Verify the detached JWS signature
	sigAlg, ok := jwa.LookupSignatureAlgorithm(algStr)
	if !ok {
		return fmt.Errorf("%w: unsupported JWS algorithm %s", ErrorLDProofAlgMismatch, algStr)
	}

	_, err = jws.Verify(
		[]byte(proof.JWS),
		jws.WithKey(sigAlg, publicKey),
		jws.WithDetachedPayload(tbs),
	)
	if err != nil {
		logging.Log().Warnf("VerifyLinkedDataProof: signature verification failed: %v", err)
		return fmt.Errorf("%w: %v", ErrorLDProofVerifySignature, err)
	}

	return nil
}
