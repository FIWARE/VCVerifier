package verifier

import (
	"fmt"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/piprate/json-gold/ld"
)

// LDProofChecker verifies Linked Data Proofs (JsonWebSignature2020) on
// Verifiable Presentations and Verifiable Credentials by resolving the
// proof's verificationMethod DID to a public key and delegating
// cryptographic verification to common.VerifyLinkedDataProof.
type LDProofChecker struct {
	registry  *did.Registry
	docLoader ld.DocumentLoader
}

// NewLDProofChecker creates an LDProofChecker that resolves DIDs via the
// given registry and uses docLoader for JSON-LD context resolution during
// canonicalization.
func NewLDProofChecker(registry *did.Registry, docLoader ld.DocumentLoader) *LDProofChecker {
	return &LDProofChecker{
		registry:  registry,
		docLoader: docLoader,
	}
}

// VerifyPresentation verifies a Linked Data Proof on a JSON-LD Verifiable
// Presentation. It resolves the proof's verificationMethod DID to obtain
// the signer's public key, then delegates to common.VerifyLinkedDataProof
// for cryptographic verification.
//
// Returns the resolved public key on success (for downstream holder binding),
// or an error describing the verification failure.
//
// did:elsi is explicitly rejected because JAdES is JWS-based and does not
// apply to Linked Data Proofs.
func (lpc *LDProofChecker) VerifyPresentation(vpJSON []byte, proof *common.LDProof) (jwk.Key, error) {
	key, err := lpc.resolveProofKey(proof)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve VP proof key: %w", err)
	}

	if err := common.VerifyLinkedDataProof(vpJSON, proof, key, lpc.docLoader); err != nil {
		logging.Log().Warnf("VP LD proof verification failed: %v", err)
		return nil, err
	}

	return key, nil
}

// VerifyCredential verifies a Linked Data Proof on a JSON-LD Verifiable
// Credential. It resolves the proof's verificationMethod DID to obtain
// the issuer's public key, then delegates to common.VerifyLinkedDataProof
// for cryptographic verification.
//
// did:elsi is explicitly rejected because JAdES is JWS-based and does not
// apply to Linked Data Proofs.
func (lpc *LDProofChecker) VerifyCredential(vcJSON []byte, proof *common.LDProof) error {
	key, err := lpc.resolveProofKey(proof)
	if err != nil {
		return fmt.Errorf("failed to resolve VC proof key: %w", err)
	}

	if err := common.VerifyLinkedDataProof(vcJSON, proof, key, lpc.docLoader); err != nil {
		logging.Log().Warnf("VC LD proof verification failed: %v", err)
		return err
	}

	return nil
}

// resolveProofKey extracts the DID from the proof's VerificationMethod,
// rejects did:elsi, and resolves the DID to a public key via the shared
// ResolveKeyFromDID helper.
func (lpc *LDProofChecker) resolveProofKey(proof *common.LDProof) (jwk.Key, error) {
	if proof.VerificationMethod == "" {
		return nil, ErrorNoVerificationKey
	}

	didStr, kid := ExtractDIDAndFragment(proof.VerificationMethod)

	// Reject did:elsi — JAdES is JWS-based and does not apply to LD proofs.
	if IsDidElsi(didStr) {
		logging.Log().Warnf("Rejecting did:elsi in LD-proof context: %s", didStr)
		return nil, ErrorDidElsiNotSupportedForLDProof
	}

	return ResolveKeyFromDID(lpc.registry, didStr, kid)
}
