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

// ContextSecuritySuiteJWS2020 is the JSON-LD context of the
// JsonWebSignature2020 cryptographic suite. It is the context that defines
// the proof terms (created, verificationMethod, proofPurpose, challenge,
// domain, jws). Without it in scope, JSON-LD expansion silently drops every
// one of those terms and the canonicalized proof options degrade to a single
// type triple — meaning nothing about the proof would actually be signed.
//
// See https://www.w3.org/TR/vc-jws-2020/.
const ContextSecuritySuiteJWS2020 = "https://w3id.org/security/suites/jws-2020/v1"

// Expanded IRIs of the proof-option terms. They are used to assert that the
// canonicalized proof options really do cover the security-relevant fields.
// The values are bare IRIs — the N-Quads angle brackets are not part of them,
// because the coverage check compares parsed predicates rather than raw text.
const (
	IRIProofCreated            = "http://purl.org/dc/terms/created"
	IRIProofVerificationMethod = "https://w3id.org/security#verificationMethod"
	IRIProofPurpose            = "https://w3id.org/security#proofPurpose"
	IRIProofChallenge          = "https://w3id.org/security#challenge"
	IRIProofDomain             = "https://w3id.org/security#domain"
)

// Proof purposes defined by the Verifiable Credential Data Integrity spec.
const (
	// ProofPurposeAssertionMethod is the purpose a credential proof must
	// carry: the issuer asserts the claims in the credential.
	ProofPurposeAssertionMethod = "assertionMethod"

	// ProofPurposeAuthentication is the purpose a presentation proof must
	// carry: the holder authenticates towards the verifier.
	ProofPurposeAuthentication = "authentication"
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

	// ErrorLDProofOptionsNotCovered is returned when the canonicalized proof
	// options do not contain the security-relevant proof fields. That means
	// the JSON-LD context in use does not define the proof terms, so those
	// fields would not be covered by the signature.
	ErrorLDProofOptionsNotCovered = errors.New("ld_proof_options_not_covered_by_signature")

	// ErrorLDProofCurveMismatch is returned when the JWS algorithm requires a
	// specific elliptic curve that the supplied key does not use.
	ErrorLDProofCurveMismatch = errors.New("ld_proof_algorithm_curve_mismatch")
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

// algCurveMap maps the ECDSA JWS algorithms to the elliptic curve they are
// defined for (RFC 7518 §3.4). An ES256 signature made with a P-384 key is
// not a valid ES256 signature, so the curve is cross-checked explicitly
// instead of relying on the JWS layer to notice.
var algCurveMap = map[string]jwa.EllipticCurveAlgorithm{
	"ES256": jwa.P256(),
	"ES384": jwa.P384(),
	"ES512": jwa.P521(),
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
	// ProofPurpose is the verification relationship the proof is made for,
	// e.g. ProofPurposeAuthentication for a presentation.
	ProofPurpose string
	// Challenge binds the proof to a verifier-supplied nonce (replay protection).
	Challenge string
	// Domain binds the proof to the intended verifier (audience binding).
	Domain string
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

// EnsureSuiteContext returns the given JSON-LD @context value with the
// JsonWebSignature2020 suite context appended when it is not already present.
//
// The suite context is what gives meaning to the proof terms (created,
// verificationMethod, proofPurpose, challenge, domain). A document that is
// signed with — or verified against — a context that lacks it produces proof
// options whose fields expand to nothing, which would leave them outside the
// signature.
func EnsureSuiteContext(contextValue interface{}) interface{} {
	switch ctx := contextValue.(type) {
	case nil:
		return []interface{}{ContextSecuritySuiteJWS2020}
	case string:
		if ctx == ContextSecuritySuiteJWS2020 {
			return ctx
		}
		return []interface{}{ctx, ContextSecuritySuiteJWS2020}
	case []interface{}:
		for _, entry := range ctx {
			if s, ok := entry.(string); ok && s == ContextSecuritySuiteJWS2020 {
				return ctx
			}
		}
		extended := make([]interface{}, 0, len(ctx)+1)
		extended = append(extended, ctx...)
		return append(extended, ContextSecuritySuiteJWS2020)
	case []string:
		for _, entry := range ctx {
			if entry == ContextSecuritySuiteJWS2020 {
				return ctx
			}
		}
		return append(append([]string{}, ctx...), ContextSecuritySuiteJWS2020)
	default:
		return []interface{}{ctx, ContextSecuritySuiteJWS2020}
	}
}

// buildProofOptions assembles the proof-options document that is
// canonicalized and hashed alongside the signed document. The @context is the
// document's own context extended with the JsonWebSignature2020 suite context
// so that every proof term expands to a real IRI.
func buildProofOptions(documentContext interface{}, proof *LDProof) JSONObject {
	proofOptions := JSONObject{
		JSONLDKeyContext:             EnsureSuiteContext(documentContext),
		JSONLDKeyType:                proof.Type,
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
	return proofOptions
}

// assertProofOptionsCovered verifies that the canonicalized proof options
// really contain a triple for every security-relevant proof field. If a
// context regression ever made the proof terms expand to nothing again, the
// signature would silently stop covering challenge, domain and created —
// this guard turns that into a hard failure instead.
//
// The canonicalized N-Quads are parsed rather than searched as text: a
// substring match cannot tell a predicate IRI apart from the same characters
// appearing inside a literal, so a proof could satisfy the challenge check by
// putting "<https://w3id.org/security#challenge>" into its domain field
// while carrying no challenge triple at all. Where the expected object is
// known verbatim it is compared too, so a term cannot be covered by some
// other value than the one the proof claims.
func assertProofOptionsCovered(canonicalProofOptions string, proof *LDProof) error {
	quads := ParseNQuads(canonicalProofOptions)
	required := []struct {
		iri   string
		field string
		value string
		// expectedObject is the object the triple must carry, or "" when the
		// canonicalized object is not the field value verbatim.
		expectedObject string
	}{
		{IRIProofCreated, LDProofKeyCreated, proof.Created, proof.Created},
		{IRIProofVerificationMethod, LDProofKeyVerificationMethod, proof.VerificationMethod, proof.VerificationMethod},
		// proofPurpose is declared as @type: @id, so "authentication" is
		// expanded to a context-defined IRI. Only its presence can be
		// asserted without duplicating that mapping here.
		{IRIProofPurpose, LDProofKeyProofPurpose, proof.ProofPurpose, ""},
		{IRIProofChallenge, LDProofKeyChallenge, proof.Challenge, proof.Challenge},
		{IRIProofDomain, LDProofKeyDomain, proof.Domain, proof.Domain},
	}
	for _, r := range required {
		if r.value == "" {
			continue
		}
		if !HasNQuad(quads, r.iri, r.expectedObject) {
			logging.Log().Warnf("Canonicalized proof options do not cover %q — the JSON-LD context does not define the proof terms", r.field)
			return fmt.Errorf("%w: %s is not covered by the signature", ErrorLDProofOptionsNotCovered, r.field)
		}
	}
	return nil
}

// AddLinkedDataProof creates a JsonWebSignature2020 linked data proof over
// the presentation and appends it to the presentation's Proofs slice.
//
// The JsonWebSignature2020 suite context is added to the presentation's
// @context when missing: without it the proof terms have no definition and a
// verifier could not expand — let alone check — the resulting proof.
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

	// The signed document itself must carry the suite context, otherwise the
	// proof it ends up holding cannot be expanded by any verifier.
	//
	// The marshalled map is the authority for what was signed: MarshalJSON
	// defaults an empty @context to credentials/v1, so deriving p.Context
	// from the original (possibly nil) value would emit a presentation whose
	// context no longer matches the one the proof was computed over — and
	// whose proof therefore no longer verifies.
	vpMap[JSONLDKeyContext] = EnsureSuiteContext(vpMap[JSONLDKeyContext])
	p.Context = toStringContext(vpMap[JSONLDKeyContext])

	proof, err := CreateLinkedDataProof(vpMap, ctx)
	if err != nil {
		return err
	}
	p.Proofs = append(p.Proofs, proof)

	return nil
}

// CreateLinkedDataProof creates a JsonWebSignature2020 linked data proof over
// an arbitrary JSON-LD document.
//
// documentMap must be the document *without* its proof member — the proof is
// computed over the proof-less document. The document's @context is extended
// with the JsonWebSignature2020 suite context for the proof options, so that
// created, verificationMethod, proofPurpose, challenge and domain are all
// covered by the signature; signing fails if they are not.
func CreateLinkedDataProof(documentMap JSONObject, ctx *LinkedDataProofContext) (*LDProof, error) {
	proof := &LDProof{
		Type:               ctx.SignatureType,
		Created:            ctx.Created.Format(time.RFC3339),
		VerificationMethod: ctx.VerificationMethod,
		ProofPurpose:       ctx.ProofPurpose,
		Challenge:          ctx.Challenge,
		Domain:             ctx.Domain,
	}
	proofOptions := buildProofOptions(documentMap[JSONLDKeyContext], proof)

	// Canonicalize document and proof options using URDNA2015
	proc := ld.NewJsonLdProcessor()
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Format = LDNormFormatNQuads
	ldOpts.Algorithm = LDNormAlgorithmURDNA
	ldOpts.DocumentLoader = ctx.DocumentLoader

	canonDoc, err := proc.Normalize(documentMap, ldOpts)
	if err != nil {
		logging.Log().Warnf("Failed to canonicalize document: %v", err)
		return nil, fmt.Errorf("%w: %w", ErrorLDProofCanonDoc, err)
	}

	canonProof, err := proc.Normalize(proofOptions, ldOpts)
	if err != nil {
		logging.Log().Warnf("Failed to canonicalize proof options: %v", err)
		return nil, fmt.Errorf("%w: %w", ErrorLDProofCanonProof, err)
	}

	if err := assertProofOptionsCovered(canonProof.(string), proof); err != nil {
		return nil, err
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
		return nil, fmt.Errorf("%w: %w", ErrorLDProofSign, err)
	}

	proof.JWS = headerB64 + ".." + base64.RawURLEncoding.EncodeToString(sig)
	return proof, nil
}

// toStringContext converts a JSON-LD @context value back into the []string
// representation used by Presentation.Context. Non-string entries are dropped
// because Presentation only models string context URIs.
func toStringContext(contextValue interface{}) []string {
	switch ctx := contextValue.(type) {
	case []string:
		return ctx
	case string:
		return []string{ctx}
	case []interface{}:
		result := make([]string, 0, len(ctx))
		for _, entry := range ctx {
			if s, ok := entry.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

// ecdsaCurveHolder is implemented by both the public and the private ECDSA
// JWK types of jwx and exposes the key's elliptic curve.
type ecdsaCurveHolder interface {
	Crv() (jwa.EllipticCurveAlgorithm, bool)
}

// assertCurveMatchesAlgorithm checks that an ECDSA key uses the curve the JWS
// algorithm is defined for (ES256 → P-256, ES384 → P-384, ES512 → P-521).
// Non-ECDSA algorithms pass through unchanged.
func assertCurveMatchesAlgorithm(algStr string, publicKey jwk.Key) error {
	expectedCurve, isECDSA := algCurveMap[algStr]
	if !isECDSA {
		return nil
	}
	curveHolder, ok := publicKey.(ecdsaCurveHolder)
	if !ok {
		return fmt.Errorf("%w: algorithm %s requires an EC key exposing a curve", ErrorLDProofCurveMismatch, algStr)
	}
	actualCurve, ok := curveHolder.Crv()
	if !ok {
		return fmt.Errorf("%w: key for algorithm %s does not declare a curve", ErrorLDProofCurveMismatch, algStr)
	}
	if actualCurve != expectedCurve {
		return fmt.Errorf("%w: algorithm %s requires curve %s but got %s",
			ErrorLDProofCurveMismatch, algStr, expectedCurve, actualCurve)
	}
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
	if err := assertCurveMatchesAlgorithm(algStr, publicKey); err != nil {
		return err
	}

	// 8. Unmarshal document and remove proof
	var docMap JSONObject
	if err := json.Unmarshal(documentJSON, &docMap); err != nil {
		return fmt.Errorf("%w: %v", ErrorLDProofVerifyMarshal, err)
	}
	delete(docMap, VPKeyProof)

	// 9. Build proof options map
	proofOptions := buildProofOptions(docMap[JSONLDKeyContext], proof)

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

	// 10b. Refuse to continue when the canonical proof options do not actually
	// cover the proof metadata — otherwise challenge, domain and created would
	// be attacker-controlled while the signature still verified.
	if err := assertProofOptionsCovered(canonProof.(string), proof); err != nil {
		return err
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
