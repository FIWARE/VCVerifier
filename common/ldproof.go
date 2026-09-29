package common

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
)

// Linked Data Proof JSON keys.
const (
	LDProofKeyCreated            = "created"
	LDProofKeyVerificationMethod = "verificationMethod"
	LDProofKeyProofPurpose       = "proofPurpose"
	LDProofKeyChallenge          = "challenge"
	LDProofKeyDomain             = "domain"
	LDProofKeyExpires            = "expires"
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
	IRIProofCryptosuite        = "https://w3id.org/security#cryptosuite"
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

	// ErrorLDProofContextMismatch is returned when a JCS-canonicalized proof
	// carries an @context that is not a prefix of the document's. VC-DI-ECDSA
	// 3.3.2 / VC-DI-EDDSA 3.3.2 step 4.1 make that a verification failure: the
	// document may only extend the context it was signed under, never reorder
	// or replace it.
	ErrorLDProofContextMismatch = errors.New("ld_proof_context_mismatch")

	// ErrorLDProofCurveMismatch is returned when the JWS algorithm requires a
	// specific elliptic curve that the supplied key does not use.
	ErrorLDProofCurveMismatch = errors.New("ld_proof_algorithm_curve_mismatch")

	// ErrorLDProofMissingProofValue is returned when a DataIntegrityProof
	// has no "proofValue" field.
	ErrorLDProofMissingProofValue = errors.New("ld_proof_missing_proof_value")

	// ErrorLDProofMalformedProofValue is returned when the multibase-encoded
	// proofValue cannot be decoded.
	ErrorLDProofMalformedProofValue = errors.New("ld_proof_malformed_proof_value")

	// ErrorLDProofUnsupportedCryptosuite is returned when a DataIntegrityProof
	// uses a cryptosuite that is not recognized or supported.
	ErrorLDProofUnsupportedCryptosuite = errors.New("ld_proof_unsupported_cryptosuite")

	// ErrorLDProofCryptosuiteKeyMismatch is returned when the public key type
	// does not match the requirements of the declared cryptosuite
	// (e.g. an RSA key with ecdsa-rdfc-2019).
	ErrorLDProofCryptosuiteKeyMismatch = errors.New("ld_proof_cryptosuite_key_mismatch")

	// ErrorLDProofVerifyDataIntegrity is returned when a Data Integrity proof
	// signature verification fails.
	ErrorLDProofVerifyDataIntegrity = errors.New("ld_proof_data_integrity_signature_failed")

	// ErrorLDProofMalformedCreated is returned when a proof carries a
	// "created" timestamp that is not a valid date-time.
	ErrorLDProofMalformedCreated = errors.New("ld_proof_malformed_created")
)

// Supported proof types for verification.
const (
	// ProofTypeJsonWebSignature2020 is the W3C JsonWebSignature2020 proof type
	// using detached JWS with b64=false.
	ProofTypeJsonWebSignature2020 = "JsonWebSignature2020"

	// ProofTypeDataIntegrityProof is the W3C Data Integrity proof type using
	// proofValue (multibase-encoded raw signature) and a declared cryptosuite.
	// See https://www.w3.org/TR/vc-data-integrity/.
	ProofTypeDataIntegrityProof = "DataIntegrityProof"
)

// Supported Data Integrity cryptosuites.
const (
	// CryptosuiteEcdsaRdfc2019 is the ecdsa-rdfc-2019 cryptosuite using
	// URDNA2015 (RDFC-1.0) canonicalization and ECDSA with P-256 or P-384.
	// See https://www.w3.org/TR/vc-di-ecdsa/.
	CryptosuiteEcdsaRdfc2019 = "ecdsa-rdfc-2019"

	// CryptosuiteEddsaRdfc2022 is the eddsa-rdfc-2022 cryptosuite using
	// URDNA2015 (RDFC-1.0) canonicalization and EdDSA with Ed25519.
	// See https://www.w3.org/TR/vc-di-eddsa/.
	CryptosuiteEddsaRdfc2022 = "eddsa-rdfc-2022"

	// CryptosuiteEcdsaJcs2019 is the ecdsa-jcs-2019 cryptosuite: the same
	// ECDSA over P-256 or P-384, canonicalized with JCS (RFC 8785) instead of
	// RDFC-1.0. See https://www.w3.org/TR/vc-di-ecdsa/.
	CryptosuiteEcdsaJcs2019 = "ecdsa-jcs-2019"

	// CryptosuiteEddsaJcs2022 is the eddsa-jcs-2022 cryptosuite: Ed25519 with
	// JCS canonicalization. See https://www.w3.org/TR/vc-di-eddsa/.
	CryptosuiteEddsaJcs2022 = "eddsa-jcs-2022"
)

// Canonicalization algorithms a Data Integrity cryptosuite can use.
const (
	// canonicalizationRDFC is RDF Dataset Canonicalization (URDNA2015). It
	// expands the document against its JSON-LD context, so a term the context
	// does not define produces no triple and is not signed over.
	canonicalizationRDFC = "rdfc"

	// canonicalizationJCS is the JSON Canonicalization Scheme (RFC 8785). It
	// is a pure JSON transform: no context is consulted and nothing is
	// dropped, which is what makes the suite available to issuers who cannot
	// run an RDF canonicalizer.
	canonicalizationJCS = "jcs"
)

// Signature algorithms a Data Integrity cryptosuite can use.
const (
	signatureAlgorithmECDSA = "ecdsa"
	signatureAlgorithmEdDSA = "eddsa"
)

// dataIntegritySuite describes what a cryptosuite identifier selects. The two
// choices are orthogonal, which is exactly why the suites come in pairs.
type dataIntegritySuite struct {
	canonicalization string
	algorithm        string
}

// dataIntegritySuites is the set of supported cryptosuites. A suite that is
// not in this map is rejected; nothing falls back to a default.
var dataIntegritySuites = map[string]dataIntegritySuite{
	CryptosuiteEcdsaRdfc2019: {canonicalization: canonicalizationRDFC, algorithm: signatureAlgorithmECDSA},
	CryptosuiteEddsaRdfc2022: {canonicalization: canonicalizationRDFC, algorithm: signatureAlgorithmEdDSA},
	CryptosuiteEcdsaJcs2019:  {canonicalization: canonicalizationJCS, algorithm: signatureAlgorithmECDSA},
	CryptosuiteEddsaJcs2022:  {canonicalization: canonicalizationJCS, algorithm: signatureAlgorithmEdDSA},
}

// usesJCSCanonicalization reports whether the cryptosuite canonicalizes with
// JCS. An unknown suite is not a JCS suite; it is rejected before it matters.
func usesJCSCanonicalization(cryptosuite string) bool {
	suite, known := dataIntegritySuites[cryptosuite]
	return known && suite.canonicalization == canonicalizationJCS
}

// p1363CoordinateSize maps supported EC curves to their IEEE P1363 coordinate
// byte size. ECDSA proofValue is r||s where each component is zero-padded to
// the curve's field size.
var p1363CoordinateSize = map[elliptic.Curve]int{
	elliptic.P256(): 32,
	elliptic.P384(): 48,
}

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
	Expires            string `json:"expires,omitempty"`
	VerificationMethod string `json:"verificationMethod"`
	JWS                string `json:"jws,omitempty"`
	ProofPurpose       string `json:"proofPurpose,omitempty"`
	Challenge          string `json:"challenge,omitempty"`
	Domain             string `json:"domain,omitempty"`
	ProofValue         string `json:"proofValue,omitempty"`
	Cryptosuite        string `json:"cryptosuite,omitempty"`

	// Raw is the proof exactly as it was parsed, before any field was mapped
	// onto this struct. The proof configuration that is canonicalized and
	// hashed is a copy of the whole proof minus its signature member
	// (VC-DI-ECDSA 3.2.5), so a member this struct has no field for still has
	// to reach it. It is nil for a proof this codebase built rather than
	// parsed; the signing path then falls back to the struct.
	Raw JSONObject `json:"-"`
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
	if v, ok := proofMap[LDProofKeyExpires].(string); ok {
		proof.Expires = v
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

	// Keep the proof as it arrived. The copy matters: a later mutation of the
	// caller's map must not change what the signature is checked against.
	proof.Raw = make(JSONObject, len(proofMap))
	for key, value := range proofMap {
		proof.Raw[key] = value
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

// proofOptionsContext returns the @context the proof options are canonicalized
// under, which differs per suite.
//
// For DataIntegrityProof it is the document's own context, verbatim:
// VC-DI-ECDSA 3.2.5 step 4 sets the proof configuration's @context to the
// unsecured document's @context, and any deviation changes the canonical form
// away from the one the issuer signed. A VCDM 2.0 document already defines
// every Data Integrity proof term, so nothing needs adding.
//
// For JsonWebSignature2020 the suite context is added when missing. That suite
// predates VCDM 2.0 and its terms are defined nowhere else, so without it the
// proof options would canonicalize to a single type triple - a signature
// covering nothing about the proof.
func proofOptionsContext(documentContext interface{}, proofType string) interface{} {
	if proofType == ProofTypeDataIntegrityProof {
		return documentContext
	}
	return EnsureSuiteContext(documentContext)
}

// buildProofOptions assembles the proof-options document from the fields this
// struct carries. It is the signing path's view of the proof: a proof being
// created has exactly these members and no others.
//
// Verification uses buildVerificationProofOptions instead, which starts from
// the proof as it was received.
func buildProofOptions(documentContext interface{}, proof *LDProof) JSONObject {
	proofOptions := JSONObject{
		JSONLDKeyContext:             proofOptionsContext(documentContext, proof.Type),
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
	if proof.Cryptosuite != "" {
		proofOptions[LDProofKeyCryptosuite] = proof.Cryptosuite
	}
	return proofOptions
}

// buildVerificationProofOptions assembles the proof-options document to verify
// a received proof against. It is a copy of the proof minus its signature
// member, per VC-DI-ECDSA 3.2.5 and the JsonWebSignature2020 equivalent - not
// a document rebuilt from the fields LDProof happens to model.
//
// The difference is not cosmetic. `expires`, `nonce`, `id` and `previousProof`
// are all defined for a proof and all expand to real triples, so the issuer
// signed over them. Reconstructing the options without them yields a different
// canonical form and rejects a conformant proof.
//
// Proofs built in code rather than parsed carry no Raw map and fall back to the
// struct, which for them holds everything there is.
func buildVerificationProofOptions(documentContext interface{}, proof *LDProof) JSONObject {
	if proof.Raw == nil {
		return buildProofOptions(documentContext, proof)
	}

	proofOptions := make(JSONObject, len(proof.Raw))
	for key, value := range proof.Raw {
		// The signature cannot cover itself.
		if key == LDProofKeyProofValue || key == LDProofKeyJWS {
			continue
		}
		proofOptions[key] = value
	}
	// A JCS proof configuration is a plain clone of the proof (VC-DI-ECDSA
	// 3.3.5): whatever @context it carries is part of it, and none is added.
	// It is not inert data either - canonicalizeForDataIntegrity binds the
	// document to it, per VC-DI-ECDSA 3.3.2 step 4.
	if usesJCSCanonicalization(proof.Cryptosuite) {
		return proofOptions
	}

	// For the RDFC suites the document's context wins over any the proof
	// carries: it is what the signer canonicalized under.
	proofOptions[JSONLDKeyContext] = proofOptionsContext(documentContext, proof.Type)
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
		// cryptosuite is typed cryptosuiteString (a plain literal), so the
		// canonicalized value is the suite name verbatim — match it the same
		// way created and challenge are checked.
		{IRIProofCryptosuite, LDProofKeyCryptosuite, proof.Cryptosuite, proof.Cryptosuite},
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

	canonicalProof, err := canonicalNQuads(canonProof, ErrorLDProofCanonProof)
	if err != nil {
		return nil, err
	}
	canonicalDoc, err := canonicalNQuads(canonDoc, ErrorLDProofCanonDoc)
	if err != nil {
		return nil, err
	}

	if err := assertProofOptionsCovered(canonicalProof, proof); err != nil {
		return nil, err
	}

	// Hash both canonical forms
	docHash := sha256.Sum256([]byte(canonicalDoc))
	proofHash := sha256.Sum256([]byte(canonicalProof))

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
	proofOptions := buildVerificationProofOptions(docMap[JSONLDKeyContext], proof)

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
	canonicalProof, err := canonicalNQuads(canonProof, ErrorLDProofVerifyCanonProof)
	if err != nil {
		return err
	}
	canonicalDoc, err := canonicalNQuads(canonDoc, ErrorLDProofVerifyCanonDoc)
	if err != nil {
		return err
	}

	if err := assertProofOptionsCovered(canonicalProof, proof); err != nil {
		return err
	}

	// 11. Compute tbs = sha256(canonicalProofOptions) || sha256(canonicalDocument)
	docHash := sha256.Sum256([]byte(canonicalDoc))
	proofHash := sha256.Sum256([]byte(canonicalProof))
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

// VerifyDataIntegrityProof verifies a W3C Data Integrity proof (type
// "DataIntegrityProof") by canonicalizing the document and proof options,
// computing the hash data, decoding the multibase-encoded proofValue and
// verifying the raw cryptographic signature.
//
// Supported cryptosuites:
//   - ecdsa-rdfc-2019 — ECDSA with P-256 (SHA-256) or P-384 (SHA-384), RDFC-1.0
//   - eddsa-rdfc-2022 — EdDSA with Ed25519 (SHA-256), RDFC-1.0
//   - ecdsa-jcs-2019  — the same ECDSA, canonicalized with JCS (RFC 8785)
//   - eddsa-jcs-2022  — the same EdDSA, canonicalized with JCS (RFC 8785)
//
// The documentJSON must be the full JSON-LD document (including the proof
// member if present — it will be stripped internally). The publicKey is the
// JWK public key of the proof creator. The documentLoader is used for
// JSON-LD context resolution during canonicalization.
//
// Returns nil on successful verification, or a wrapped error describing the
// failure.
func VerifyDataIntegrityProof(documentJSON []byte, proof *LDProof, publicKey jwk.Key, documentLoader ld.DocumentLoader) error {
	// 1. Validate proof type.
	if proof.Type != ProofTypeDataIntegrityProof {
		return fmt.Errorf("%w: %s", ErrorLDProofUnsupportedType, proof.Type)
	}

	// 2. Validate cryptosuite.
	suite, supported := dataIntegritySuites[proof.Cryptosuite]
	if !supported {
		return fmt.Errorf("%w: %s", ErrorLDProofUnsupportedCryptosuite, proof.Cryptosuite)
	}

	// 3. Validate the created timestamp when there is one. VC-DATA-INTEGRITY
	// 2.1 makes it optional; VC-DI-ECDSA 3.2.5 only requires it to be a valid
	// date-time if it is set. Presentations are bound in time separately, by
	// VerifyLDVPProofFreshness, which does insist on it.
	if err := assertCreatedWellFormed(proof.Created); err != nil {
		return err
	}

	// 4. Validate proofValue presence.
	if proof.ProofValue == "" {
		return ErrorLDProofMissingProofValue
	}

	// 5. Decode proofValue. Both suites pin the encoding: VC-DI-ECDSA 3.2.2
	// and VC-DI-EDDSA 3.1.2 take "the Multibase decoded base58-btc value",
	// and accepting another multibase alphabet would let a non-conforming
	// issuer look interoperable against this verifier alone.
	encoding, sigBytes, err := multibase.Decode(proof.ProofValue)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrorLDProofMalformedProofValue, err)
	}
	if encoding != multibase.Base58BTC {
		return fmt.Errorf("%w: proofValue must be base58-btc encoded", ErrorLDProofMalformedProofValue)
	}

	// 6. Unmarshal document and strip proof.
	var docMap JSONObject
	if err := json.Unmarshal(documentJSON, &docMap); err != nil {
		return fmt.Errorf("%w: %v", ErrorLDProofVerifyMarshal, err)
	}
	delete(docMap, VPKeyProof)

	// 7. Build proof options (includes cryptosuite).
	proofOptions := buildVerificationProofOptions(docMap[JSONLDKeyContext], proof)

	// 8. Canonicalize both document and proof options, and - for the RDFC
	// suites - assert that the proof options survived it.
	canonicalProof, canonicalDoc, err := canonicalizeForDataIntegrity(suite, docMap, proofOptions, proof, documentLoader)
	if err != nil {
		return err
	}

	// 9. Compute hash data — curve-conditional per W3C VC-DI-ECDSA specs.
	hashData, err := computeDataIntegrityHashData(suite, publicKey, canonicalProof, canonicalDoc)
	if err != nil {
		return err
	}

	// 10. Verify the raw signature over hashData.
	return verifyDataIntegritySignature(suite, publicKey, hashData, sigBytes)
}

// canonicalizeForDataIntegrity canonicalizes the unsecured document and the
// proof configuration with the algorithm the cryptosuite selects, and returns
// both canonical forms, proof configuration first.
//
// The coverage assertion only applies to the RDFC suites. There, a term the
// document's context does not define expands to nothing and silently drops out
// of what is signed, so the assertion is what keeps `challenge`, `domain` and
// the rest from becoming rewritable. JCS has no expansion step and drops
// nothing: every member of the proof configuration is in the canonical form by
// construction, so there is nothing to assert.
func canonicalizeForDataIntegrity(suite dataIntegritySuite, docMap JSONObject, proofOptions JSONObject, proof *LDProof, documentLoader ld.DocumentLoader) (canonicalProof string, canonicalDoc string, err error) {
	if suite.canonicalization == canonicalizationJCS {
		// VC-DI-ECDSA 3.3.2 step 4 (and VC-DI-EDDSA 3.3.2 step 4): a proof
		// configuration that carries an @context governs the document too.
		// The document's own context may only extend it, and the document is
		// hashed under the proof's. Without this a conformant credential
		// whose context was extended after signing would be rejected, and the
		// context the proof carries would bind nothing about the document it
		// secures.
		//
		// The prefix check is what bounds the rebinding: entries may be
		// appended, never reordered or replaced, so the base context entry
		// that DetectVCDataModelVersion reads cannot be swapped out.
		if proofContext, carried := proofOptions[JSONLDKeyContext]; carried {
			if err := assertContextPrefix(docMap[JSONLDKeyContext], proofContext); err != nil {
				return "", "", err
			}
			docMap = withContext(docMap, proofContext)
		}

		canonicalProof, err = CanonicalizeJSON(proofOptions)
		if err != nil {
			logging.Log().Warnf("VerifyDataIntegrityProof: failed to JCS-canonicalize proof options: %v", err)
			return "", "", fmt.Errorf("%w: %v", ErrorLDProofVerifyCanonProof, err)
		}
		canonicalDoc, err = CanonicalizeJSON(docMap)
		if err != nil {
			logging.Log().Warnf("VerifyDataIntegrityProof: failed to JCS-canonicalize document: %v", err)
			return "", "", fmt.Errorf("%w: %v", ErrorLDProofVerifyCanonDoc, err)
		}
		return canonicalProof, canonicalDoc, nil
	}

	proc := ld.NewJsonLdProcessor()
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Format = LDNormFormatNQuads
	ldOpts.Algorithm = LDNormAlgorithmURDNA
	ldOpts.DocumentLoader = documentLoader

	normalizedDoc, err := proc.Normalize(docMap, ldOpts)
	if err != nil {
		logging.Log().Warnf("VerifyDataIntegrityProof: failed to canonicalize document: %v", err)
		return "", "", fmt.Errorf("%w: %v", ErrorLDProofVerifyCanonDoc, err)
	}

	normalizedProof, err := proc.Normalize(proofOptions, ldOpts)
	if err != nil {
		logging.Log().Warnf("VerifyDataIntegrityProof: failed to canonicalize proof options: %v", err)
		return "", "", fmt.Errorf("%w: %v", ErrorLDProofVerifyCanonProof, err)
	}

	canonicalProof, err = canonicalNQuads(normalizedProof, ErrorLDProofVerifyCanonProof)
	if err != nil {
		return "", "", err
	}
	canonicalDoc, err = canonicalNQuads(normalizedDoc, ErrorLDProofVerifyCanonDoc)
	if err != nil {
		return "", "", err
	}

	if err := assertProofOptionsCovered(canonicalProof, proof); err != nil {
		return "", "", err
	}
	return canonicalProof, canonicalDoc, nil
}

// assertContextPrefix checks that documentContext starts with every entry of
// proofContext, in the same order (VC-DI-ECDSA 3.3.2 step 4.1).
//
// Entries are compared structurally rather than as raw values: an @context
// entry is usually a string, but an inline context object is just as legal,
// and two equal objects must compare equal however their members happen to be
// ordered in the JSON.
func assertContextPrefix(documentContext interface{}, proofContext interface{}) error {
	documentEntries := contextEntries(documentContext)
	proofEntries := contextEntries(proofContext)
	if len(proofEntries) > len(documentEntries) {
		logging.Log().Warnf("Document declares %d @context entries, the proof was created under %d", len(documentEntries), len(proofEntries))
		return fmt.Errorf("%w: the document declares fewer @context entries than the proof", ErrorLDProofContextMismatch)
	}
	for i, proofEntry := range proofEntries {
		equal, err := sameContextEntry(proofEntry, documentEntries[i])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrorLDProofContextMismatch, err)
		}
		if !equal {
			logging.Log().Warnf("Document @context entry %d does not match the one the proof was created under", i)
			return fmt.Errorf("%w: @context entry %d differs from the signed one", ErrorLDProofContextMismatch, i)
		}
	}
	return nil
}

// contextEntries normalizes an @context value to the list of its entries. A
// single string or object is a one-entry context; an absent one is empty.
func contextEntries(context interface{}) []interface{} {
	switch typed := context.(type) {
	case nil:
		return nil
	case []interface{}:
		return typed
	default:
		return []interface{}{typed}
	}
}

// sameContextEntry compares two @context entries. Strings are compared
// directly; anything else through its canonical JSON, so that member order
// inside an inline context object does not decide the outcome.
func sameContextEntry(left interface{}, right interface{}) (bool, error) {
	leftString, leftIsString := left.(string)
	rightString, rightIsString := right.(string)
	if leftIsString || rightIsString {
		return leftIsString && rightIsString && leftString == rightString, nil
	}
	canonicalLeft, err := CanonicalizeJSON(left)
	if err != nil {
		return false, err
	}
	canonicalRight, err := CanonicalizeJSON(right)
	if err != nil {
		return false, err
	}
	return canonicalLeft == canonicalRight, nil
}

// withContext returns a shallow copy of document with its @context replaced,
// leaving the caller's map untouched.
func withContext(document JSONObject, context interface{}) JSONObject {
	rebound := make(JSONObject, len(document))
	for key, value := range document {
		rebound[key] = value
	}
	rebound[JSONLDKeyContext] = context
	return rebound
}

// canonicalNQuads converts the result of ld.JsonLdProcessor.Normalize into the
// N-Quads string the hashing steps operate on. The processor returns a string
// for the N-Quads format and a structured object otherwise, so a non-string
// result means the options were not the ones this code passed - a bug rather
// than bad input, but not one that should reach a type assertion panic on a
// verification path.
func canonicalNQuads(normalized interface{}, wrapped error) (string, error) {
	nquads, ok := normalized.(string)
	if !ok {
		return "", fmt.Errorf("%w: canonicalization did not return N-Quads", wrapped)
	}
	return nquads, nil
}

// assertCreatedWellFormed checks the proof's "created" timestamp when it
// carries one. An empty value is not an error here: the property is optional
// (VC-DATA-INTEGRITY 2.1). A value that is present but unparseable is, since
// nothing downstream could bound the proof in time with it.
func assertCreatedWellFormed(created string) error {
	if created == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, created); err != nil {
		logging.Log().Warnf("Proof created timestamp %q is not a valid RFC3339 date-time: %v", created, err)
		return fmt.Errorf("%w: %s", ErrorLDProofMalformedCreated, created)
	}
	return nil
}

// computeDataIntegrityHashData computes the hash data for a Data Integrity
// proof. The hash algorithm is curve-conditional:
//   - P-256 and Ed25519: sha256(canonProofOptions) || sha256(canonDoc)
//   - P-384: sha384(canonProofOptions) || sha384(canonDoc)
func computeDataIntegrityHashData(suite dataIntegritySuite, publicKey jwk.Key, canonProof string, canonDoc string) ([]byte, error) {
	useSHA384, err := shouldUseSHA384(suite, publicKey)
	if err != nil {
		return nil, err
	}

	if useSHA384 {
		proofHash := sha512.Sum384([]byte(canonProof))
		docHash := sha512.Sum384([]byte(canonDoc))
		return append(proofHash[:], docHash[:]...), nil
	}

	proofHash := sha256.Sum256([]byte(canonProof))
	docHash := sha256.Sum256([]byte(canonDoc))
	return append(proofHash[:], docHash[:]...), nil
}

// shouldUseSHA384 determines if the SHA-384 hash should be used instead of
// SHA-256 for the given cryptosuite and key. Returns true for P-384 keys
// with ecdsa-rdfc-2019, false for P-256 and eddsa-rdfc-2022.
func shouldUseSHA384(suite dataIntegritySuite, publicKey jwk.Key) (bool, error) {
	if suite.algorithm != signatureAlgorithmECDSA {
		return false, nil
	}

	curve, err := extractECCurve(publicKey)
	if err != nil {
		return false, err
	}

	return curve == elliptic.P384(), nil
}

// extractECCurve extracts the elliptic curve from a JWK EC key.
// Returns an error if the key is not an EC key or does not expose a curve.
func extractECCurve(key jwk.Key) (elliptic.Curve, error) {
	curveHolder, ok := key.(ecdsaCurveHolder)
	if !ok {
		return nil, fmt.Errorf("%w: expected EC key, got %s", ErrorLDProofCryptosuiteKeyMismatch, key.KeyType())
	}

	crv, ok := curveHolder.Crv()
	if !ok {
		return nil, fmt.Errorf("%w: EC key does not declare a curve", ErrorLDProofCryptosuiteKeyMismatch)
	}

	switch {
	case crv == jwa.P256():
		return elliptic.P256(), nil
	case crv == jwa.P384():
		return elliptic.P384(), nil
	default:
		return nil, fmt.Errorf("%w: the ECDSA cryptosuites require P-256 or P-384, got %s", ErrorLDProofCryptosuiteKeyMismatch, crv)
	}
}

// verifyDataIntegritySignature dispatches the raw signature verification to
// the appropriate algorithm based on the cryptosuite.
func verifyDataIntegritySignature(suite dataIntegritySuite, publicKey jwk.Key, hashData []byte, sigBytes []byte) error {
	switch suite.algorithm {
	case signatureAlgorithmECDSA:
		return verifyECDSASignature(publicKey, hashData, sigBytes)
	case signatureAlgorithmEdDSA:
		return verifyEdDSASignature(publicKey, hashData, sigBytes)
	default:
		return fmt.Errorf("%w: %s", ErrorLDProofUnsupportedCryptosuite, suite.algorithm)
	}
}

// verifyECDSASignature verifies an ECDSA signature in IEEE P1363 format
// (r || s, each zero-padded to the curve's field size). The hashData is
// the concatenation of the proof-options hash and the document hash; per
// W3C VC-DI-ECDSA the ECDSA verification algorithm hashes this
// concatenation once more with the curve's hash algorithm before verifying.
func verifyECDSASignature(publicKey jwk.Key, hashData []byte, sigBytes []byte) error {
	// Validate key type.
	if publicKey.KeyType() != jwa.EC() {
		return fmt.Errorf("%w: the ECDSA cryptosuites require an EC key, got %s",
			ErrorLDProofCryptosuiteKeyMismatch, publicKey.KeyType())
	}

	// Extract the raw ecdsa.PublicKey from the JWK.
	var rawKey ecdsa.PublicKey
	if err := jwk.Export(publicKey, &rawKey); err != nil {
		return fmt.Errorf("%w: failed to extract raw EC key: %v",
			ErrorLDProofCryptosuiteKeyMismatch, err)
	}

	// Determine coordinate size from the curve.
	coordSize, ok := p1363CoordinateSize[rawKey.Curve]
	if !ok {
		return fmt.Errorf("%w: unsupported curve %v for the ECDSA cryptosuites",
			ErrorLDProofCryptosuiteKeyMismatch, rawKey.Curve.Params().Name)
	}

	// P1363 format: r || s, each coordSize bytes.
	expectedSigLen := coordSize * 2
	if len(sigBytes) != expectedSigLen {
		return fmt.Errorf("%w: expected %d-byte P1363 signature, got %d bytes",
			ErrorLDProofMalformedProofValue, expectedSigLen, len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:coordSize])
	s := new(big.Int).SetBytes(sigBytes[coordSize:])

	// Per W3C VC-DI-ECDSA, the ECDSA verification algorithm hashes
	// hashData with the curve's hash (SHA-256 for P-256, SHA-384 for
	// P-384) before ECDSA verification. Go's ecdsa.Verify expects the
	// pre-computed digest.
	var digest []byte
	if rawKey.Curve == elliptic.P384() {
		h := sha512.Sum384(hashData)
		digest = h[:]
	} else {
		h := sha256.Sum256(hashData)
		digest = h[:]
	}

	if !ecdsa.Verify(&rawKey, digest, r, s) {
		return ErrorLDProofVerifyDataIntegrity
	}

	return nil
}

// verifyEdDSASignature verifies an Ed25519 signature. The hashData is signed
// directly (Ed25519 performs its own internal hashing).
func verifyEdDSASignature(publicKey jwk.Key, hashData []byte, sigBytes []byte) error {
	// Validate key type.
	if publicKey.KeyType() != jwa.OKP() {
		return fmt.Errorf("%w: the EdDSA cryptosuites require an OKP key, got %s",
			ErrorLDProofCryptosuiteKeyMismatch, publicKey.KeyType())
	}

	// Extract the raw ed25519.PublicKey from the JWK.
	var rawKey ed25519.PublicKey
	if err := jwk.Export(publicKey, &rawKey); err != nil {
		return fmt.Errorf("%w: failed to extract raw Ed25519 key: %v",
			ErrorLDProofCryptosuiteKeyMismatch, err)
	}

	// Ed25519 signature must be exactly ed25519.SignatureSize (64) bytes.
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: expected %d-byte Ed25519 signature, got %d bytes",
			ErrorLDProofMalformedProofValue, ed25519.SignatureSize, len(sigBytes))
	}

	if !ed25519.Verify(rawKey, hashData, sigBytes) {
		return ErrorLDProofVerifyDataIntegrity
	}

	return nil
}
