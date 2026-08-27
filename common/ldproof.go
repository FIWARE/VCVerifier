package common

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fiware/VCVerifier/logging"
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
)

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
	jws := headerB64 + ".." + sigB64

	proof := &LDProof{
		Type:               ctx.SignatureType,
		Created:            created,
		VerificationMethod: ctx.VerificationMethod,
		JWS:                jws,
	}
	p.Proofs = append(p.Proofs, proof)

	return nil
}
