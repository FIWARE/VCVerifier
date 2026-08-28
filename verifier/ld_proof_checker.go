package verifier

import (
	"errors"
	"fmt"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/piprate/json-gold/ld"
)

// ErrorProofIssuerMismatch is returned when the DID of a credential proof's
// verificationMethod is not the credential's issuer. Without this check any
// self-minted key could sign a credential that claims an arbitrary issuer.
var ErrorProofIssuerMismatch = errors.New("ld_proof_signer_is_not_the_credential_issuer")

// ErrorProofHolderMismatch is returned when the DID of a presentation proof's
// verificationMethod is not the presentation's holder.
var ErrorProofHolderMismatch = errors.New("ld_proof_signer_is_not_the_presentation_holder")

// ErrorProofPurposeMismatch is returned when an LD proof carries no
// proofPurpose or one that does not match the purpose required for the
// document being verified.
var ErrorProofPurposeMismatch = errors.New("ld_proof_purpose_mismatch")

// ErrorMissingProofSubject is returned when the identity a proof has to be
// bound to (a credential's issuer or a presentation's holder) is absent from
// the document.
var ErrorMissingProofSubject = errors.New("ld_proof_binding_subject_missing")

// LDProofChecker verifies Linked Data Proofs (JsonWebSignature2020) on
// Verifiable Presentations and Verifiable Credentials by resolving the
// proof's verificationMethod DID to a public key and delegating
// cryptographic verification to common.VerifyLinkedDataProof.
//
// Verifying the signature is only half the job: the checker also binds the
// signing key to the identity the document claims (issuer for credentials,
// holder for presentations) and requires the proof to declare the matching
// proof purpose. A valid signature by an unrelated key is rejected.
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
// Presentation. It requires the proof to be made for the authentication
// purpose, resolves the proof's verificationMethod to the holder's public
// key, checks that the key belongs to expectedHolder, and delegates to
// common.VerifyLinkedDataProof for cryptographic verification.
//
// expectedHolder is the `holder` member of the presentation. It must not be
// empty: an unbound presentation proof only proves that somebody signed the
// document, not that the presenter did.
//
// Returns the resolved public key on success (for downstream holder binding),
// or an error describing the verification failure.
//
// did:elsi is explicitly rejected because JAdES is JWS-based and does not
// apply to Linked Data Proofs.
func (lpc *LDProofChecker) VerifyPresentation(vpJSON []byte, proof *common.LDProof, expectedHolder string) (jwk.Key, error) {
	if expectedHolder == "" {
		logging.Log().Warn("JSON-LD VP has no holder — the proof cannot be bound to a presenter")
		return nil, ErrorMissingProofSubject
	}

	if err := assertProofPurpose(proof, common.ProofPurposeAuthentication); err != nil {
		return nil, err
	}

	signerDID, err := lpc.assertProofSigner(proof, expectedHolder, ErrorProofHolderMismatch)
	if err != nil {
		return nil, err
	}

	key, err := lpc.resolveProofKey(proof, signerDID, did.RelationshipAuthentication)
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
// Credential. It requires the proof to be made for the assertionMethod
// purpose, resolves the proof's verificationMethod to a public key, checks
// that the key belongs to expectedIssuer, and delegates to
// common.VerifyLinkedDataProof for cryptographic verification.
//
// expectedIssuer is the credential's `issuer` (its `id` when the issuer is
// given in object form). It must not be empty — downstream trust-registry
// checks key off the claimed issuer, so a proof that is not bound to it
// proves nothing about who issued the credential.
//
// did:elsi is explicitly rejected because JAdES is JWS-based and does not
// apply to Linked Data Proofs.
func (lpc *LDProofChecker) VerifyCredential(vcJSON []byte, proof *common.LDProof, expectedIssuer string) error {
	if expectedIssuer == "" {
		logging.Log().Warn("JSON-LD VC has no issuer — the proof cannot be bound to an issuer")
		return ErrorMissingProofSubject
	}

	if err := assertProofPurpose(proof, common.ProofPurposeAssertionMethod); err != nil {
		return err
	}

	signerDID, err := lpc.assertProofSigner(proof, expectedIssuer, ErrorProofIssuerMismatch)
	if err != nil {
		return err
	}

	key, err := lpc.resolveProofKey(proof, signerDID, did.RelationshipAssertionMethod)
	if err != nil {
		return fmt.Errorf("failed to resolve VC proof key: %w", err)
	}

	if err := common.VerifyLinkedDataProof(vcJSON, proof, key, lpc.docLoader); err != nil {
		logging.Log().Warnf("VC LD proof verification failed: %v", err)
		return err
	}

	return nil
}

// assertProofPurpose requires the proof to declare the proof purpose the
// document type demands: `authentication` for presentations,
// `assertionMethod` for credentials. A key authorized for one purpose must
// not be usable for the other.
func assertProofPurpose(proof *common.LDProof, expectedPurpose string) error {
	if proof.ProofPurpose == "" {
		logging.Log().Warnf("LD proof has no proofPurpose, expected %q", expectedPurpose)
		return fmt.Errorf("%w: expected %s but the proof declares none", ErrorProofPurposeMismatch, expectedPurpose)
	}
	if proof.ProofPurpose != expectedPurpose {
		logging.Log().Warnf("LD proof purpose %q does not match the expected purpose %q", proof.ProofPurpose, expectedPurpose)
		return fmt.Errorf("%w: expected %s but got %s", ErrorProofPurposeMismatch, expectedPurpose, proof.ProofPurpose)
	}
	return nil
}

// assertProofSigner checks that the DID of the proof's verificationMethod is
// the identity the document claims (issuer or holder) and returns that DID.
// mismatchErr distinguishes the credential case from the presentation case.
func (lpc *LDProofChecker) assertProofSigner(proof *common.LDProof, expectedDID string, mismatchErr error) (string, error) {
	if proof.VerificationMethod == "" {
		return "", ErrorNoVerificationKey
	}

	signerDID, _ := ExtractDIDAndFragment(proof.VerificationMethod)
	if signerDID != expectedDID {
		logging.Log().Warnf("LD proof was created by %s but the document claims %s", signerDID, expectedDID)
		return "", fmt.Errorf("%w: proof signer %s, document claims %s", mismatchErr, signerDID, expectedDID)
	}
	return signerDID, nil
}

// resolveProofKey rejects did:elsi and resolves the proof's verification
// method to a public key, requiring the key to be authorized for the given
// verification relationship.
func (lpc *LDProofChecker) resolveProofKey(proof *common.LDProof, signerDID string, relationship string) (jwk.Key, error) {
	_, kid := ExtractDIDAndFragment(proof.VerificationMethod)

	// Reject did:elsi — JAdES is JWS-based and does not apply to LD proofs.
	if IsDidElsi(signerDID) {
		logging.Log().Warnf("Rejecting did:elsi in LD-proof context: %s", signerDID)
		return nil, ErrorDidElsiNotSupportedForLDProof
	}

	return ResolveKeyForRelationship(lpc.registry, signerDID, kid, relationship)
}
