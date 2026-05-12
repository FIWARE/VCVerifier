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
)

// LDProof represents a Linked Data Proof attached to a Verifiable Presentation.
type LDProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	JWS                string `json:"jws"`
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

// AddLinkedDataProof creates a JsonWebSignature2020 linked data proof and attaches it to the presentation.
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

	p.Proof = &LDProof{
		Type:               ctx.SignatureType,
		Created:            created,
		VerificationMethod: ctx.VerificationMethod,
		JWS:                jws,
	}

	return nil
}
