package verifier

// End-to-end tests for Data Integrity proof verification through the full
// VP parsing pipeline. These tests exercise the complete chain: construct a
// JSON-LD Verifiable Presentation containing Verifiable Credentials, sign
// with DataIntegrityProof (ecdsa-rdfc-2019 or eddsa-rdfc-2022), parse the
// VP token via ConfigurablePresentationParser.ParsePresentation, and verify
// both the presentation proof and the embedded credential proofs.
//
// Mixed proof type scenarios (JWS + DI) and proof freshness are also covered.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// E2E helpers
// ---------------------------------------------------------------------------

// e2eDIDEntry holds the registration data for a single DID in the e2e
// test registry.
type e2eDIDEntry struct {
	keyID  string
	pubJWK jwk.Key
	vmType string
}

// e2eCreateMultiDIDRegistry creates a mock DID registry supporting multiple
// DIDs, each with one verification method. Every key is registered for both
// the authentication and assertionMethod relationships.
func e2eCreateMultiDIDRegistry(t *testing.T, entries map[string]e2eDIDEntry) *did.Registry {
	t.Helper()

	docsByDID := make(map[string]*did.DocResolution, len(entries))
	for didStr, entry := range entries {
		vm, err := did.NewVerificationMethodFromJWK(entry.keyID, entry.vmType, didStr, entry.pubJWK)
		require.NoError(t, err, "creating VM for %s", entry.keyID)

		docsByDID[didStr] = &did.DocResolution{
			DIDDocument: &did.Doc{
				ID:                 didStr,
				VerificationMethod: []did.VerificationMethod{*vm},
				Authentication:     []string{entry.keyID},
				AssertionMethod:    []string{entry.keyID},
			},
		}
	}

	return did.NewRegistry(did.WithVDR(&mockVDR{
		readFunc: func(didStr string) (*did.DocResolution, error) {
			doc, ok := docsByDID[didStr]
			if !ok {
				return nil, errors.New("e2e test: unknown DID " + didStr)
			}
			return doc, nil
		},
	}))
}

// signDIVPWithCredentials builds a VCDM 2.0 JSON-LD VP containing the given
// signed credential maps and signs the VP with a DataIntegrityProof using
// ecdsa-rdfc-2019 (P-256). Returns the complete signed VP JSON.
func signDIVPWithCredentials(t *testing.T, holderDID string, holderPrivKey *ecdsa.PrivateKey, holderKeyID string, credentials []interface{}) []byte {
	t.Helper()

	vpMap := map[string]interface{}{
		common.JSONLDKeyContext:          []interface{}{common.ContextCredentialsV2},
		common.JSONLDKeyType:             []interface{}{common.TypeVerifiablePresentation},
		common.VPKeyHolder:               holderDID,
		common.VPKeyVerifiableCredential: credentials,
	}

	signedJSON, _ := signDIPresentation(t, vpMap, holderPrivKey, holderKeyID)
	return signedJSON
}

// signDIVPWithCredentialsEd25519 builds a VCDM 2.0 JSON-LD VP containing
// signed credential maps and signs the VP with eddsa-rdfc-2022 (Ed25519).
func signDIVPWithCredentialsEd25519(t *testing.T, holderDID string, holderPrivKey ed25519.PrivateKey, holderKeyID string, credentials []interface{}) []byte {
	t.Helper()

	vpMap := map[string]interface{}{
		common.JSONLDKeyContext:          []interface{}{common.ContextCredentialsV2},
		common.JSONLDKeyType:             []interface{}{common.TypeVerifiablePresentation},
		common.VPKeyHolder:               holderDID,
		common.VPKeyVerifiableCredential: credentials,
	}

	signedJSON, _ := signDIPresentationEd25519(t, vpMap, holderPrivKey, holderKeyID)
	return signedJSON
}

// signDICredentialAsMap signs a VC with a DataIntegrityProof (ecdsa-rdfc-2019)
// and returns the signed document as a map suitable for embedding in a VP's
// verifiableCredential array.
func signDICredentialAsMap(t *testing.T, vcMap map[string]interface{}, privKey *ecdsa.PrivateKey, verificationMethod string) map[string]interface{} {
	t.Helper()
	signedJSON, _ := signDICredential(t, vcMap, privKey, verificationMethod)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(signedJSON, &result))
	return result
}

// signDICredentialAsMapEd25519 signs a VC with eddsa-rdfc-2022 and returns
// the signed document as a map.
func signDICredentialAsMapEd25519(t *testing.T, vcMap map[string]interface{}, privKey ed25519.PrivateKey, verificationMethod string) map[string]interface{} {
	t.Helper()
	signedJSON, _ := signDICredentialEd25519(t, vcMap, privKey, verificationMethod)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(signedJSON, &result))
	return result
}

// signDIDocumentWithCreated signs a document with a DataIntegrityProof
// where the created timestamp is set to (now - age). This is needed to test
// proof freshness without waiting real time.
func signDIDocumentWithCreated(t *testing.T, doc map[string]interface{}, privKey *ecdsa.PrivateKey, verificationMethod string, age time.Duration) ([]byte, *common.LDProof) {
	t.Helper()

	proof := &common.LDProof{
		Type:               common.ProofTypeDataIntegrityProof,
		Cryptosuite:        common.CryptosuiteEcdsaRdfc2019,
		Created:            time.Now().Add(-age).UTC().Format(time.RFC3339),
		VerificationMethod: verificationMethod,
		ProofPurpose:       common.ProofPurposeAuthentication,
	}

	// The freshness tests are about `created`, not about the curve, so this
	// helper stays on P-256 and its SHA-256 hash.
	hashData := computeDITestHashData(t, doc, proof, false)

	// ECDSA P-256: hash then sign.
	digest := sha256.Sum256(hashData)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	require.NoError(t, err)

	// Encode as IEEE P1363 (r || s).
	sigBytes := make([]byte, testP256KeySize*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[testP256KeySize-len(rBytes):testP256KeySize], rBytes)
	copy(sigBytes[2*testP256KeySize-len(sBytes):], sBytes)

	proof.ProofValue, err = multibase.Encode(multibase.Base58BTC, sigBytes)
	require.NoError(t, err)

	return marshalDocWithDIProof(t, doc, proof), proof
}

// ---------------------------------------------------------------------------
// Test: Full pipeline — VP and VC both signed with ecdsa-rdfc-2019
// ---------------------------------------------------------------------------

// TestE2E_DI_FullPipeline_EcdsaRdfc2019 exercises the complete chain:
// 1. Create a VCDM 2.0 VC, sign it with DataIntegrityProof (ecdsa-rdfc-2019).
// 2. Embed it in a VCDM 2.0 VP, sign the VP with DataIntegrityProof.
// 3. Parse the VP via ConfigurablePresentationParser.ParsePresentation.
// 4. Verify the presentation proof and embedded credential proof are accepted.
func TestE2E_DI_FullPipeline_EcdsaRdfc2019(t *testing.T) {
	docLoader := newTestDocumentLoader()

	// Generate distinct keys for issuer and holder.
	issuerPrivKey, _, issuerPubJWK := generateTestECKeys(t)
	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)

	issuerDID := "did:web:issuer.e2e.example.com"
	issuerKeyID := issuerDID + "#key-1"
	holderDID := "did:web:holder.e2e.example.com"
	holderKeyID := holderDID + "#key-1"

	registry := e2eCreateMultiDIDRegistry(t, map[string]e2eDIDEntry{
		issuerDID: {keyID: issuerKeyID, pubJWK: issuerPubJWK, vmType: "JsonWebKey2020"},
		holderDID: {keyID: holderKeyID, pubJWK: holderPubJWK, vmType: "JsonWebKey2020"},
	})

	// Sign the credential.
	vcMap := createDITestVC(issuerDID, holderDID)
	signedVC := signDICredentialAsMap(t, vcMap, issuerPrivKey, issuerKeyID)

	// Sign the VP with the embedded credential.
	vpJSON := signDIVPWithCredentials(t, holderDID, holderPrivKey, holderKeyID, []interface{}{signedVC})

	// Parse through the full pipeline.
	parser := &ConfigurablePresentationParser{
		LDProofChecker: NewLDProofChecker(registry, docLoader),
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err, "full pipeline should accept VP+VC with ecdsa-rdfc-2019 DI proofs")
	require.NotNil(t, result)
	assert.Equal(t, holderDID, result.Holder)
	assert.NotNil(t, result.HolderKey(), "holder key must be populated from DI proof")

	credentials := result.Credentials()
	require.Len(t, credentials, 1, "VP should contain one credential")
	assert.Equal(t, issuerDID, credentials[0].Contents().Issuer.ID)
}

// ---------------------------------------------------------------------------
// Test: Full pipeline — ecdsa-rdfc-2019 on P-384 with Multikey methods
// ---------------------------------------------------------------------------

// TestE2E_DI_FullPipeline_EcdsaRdfc2019P384 exercises the combination a P-384
// Data Integrity issuer actually produces: Multikey verification methods in
// the DID document and SHA-384 hashing throughout. It is the only end-to-end
// test that reaches the SHA-384 branch — the other suites hash with SHA-256,
// so a curve-conditional regression would otherwise only be caught by the
// unit tests in common.
func TestE2E_DI_FullPipeline_EcdsaRdfc2019P384(t *testing.T) {
	docLoader := newTestDocumentLoader()

	issuerPrivKey, _, issuerPubJWK := generateTestECKeysP384(t)
	holderPrivKey, _, holderPubJWK := generateTestECKeysP384(t)

	issuerDID := "did:web:issuer.e2e.example.com"
	issuerKeyID := issuerDID + "#key-1"
	holderDID := "did:web:holder.e2e.example.com"
	holderKeyID := holderDID + "#key-1"

	registry := e2eCreateMultiDIDRegistry(t, map[string]e2eDIDEntry{
		issuerDID: {keyID: issuerKeyID, pubJWK: issuerPubJWK, vmType: did.TypeMultikey},
		holderDID: {keyID: holderKeyID, pubJWK: holderPubJWK, vmType: did.TypeMultikey},
	})

	vcMap := createDITestVC(issuerDID, holderDID)
	signedVC := signDICredentialAsMap(t, vcMap, issuerPrivKey, issuerKeyID)

	vpJSON := signDIVPWithCredentials(t, holderDID, holderPrivKey, holderKeyID, []interface{}{signedVC})

	parser := &ConfigurablePresentationParser{
		LDProofChecker: NewLDProofChecker(registry, docLoader),
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err, "full pipeline should accept VP+VC with ecdsa-rdfc-2019 P-384 DI proofs")
	require.NotNil(t, result)
	assert.Equal(t, holderDID, result.Holder)
	assert.NotNil(t, result.HolderKey(), "holder key must be populated from DI proof")

	credentials := result.Credentials()
	require.Len(t, credentials, 1)
	assert.Equal(t, issuerDID, credentials[0].Contents().Issuer.ID)
}

// ---------------------------------------------------------------------------
// Test: Full pipeline — VP and VC both signed with eddsa-rdfc-2022
// ---------------------------------------------------------------------------

// TestE2E_DI_FullPipeline_EddsaRdfc2022 exercises the same pipeline with
// Ed25519 keys and the eddsa-rdfc-2022 cryptosuite.
func TestE2E_DI_FullPipeline_EddsaRdfc2022(t *testing.T) {
	docLoader := newTestDocumentLoader()

	issuerPrivKey, _, issuerPubJWK := generateTestEd25519Keys(t)
	holderPrivKey, _, holderPubJWK := generateTestEd25519Keys(t)

	issuerDID := "did:web:issuer.e2e.example.com"
	issuerKeyID := issuerDID + "#key-1"
	holderDID := "did:web:holder.e2e.example.com"
	holderKeyID := holderDID + "#key-1"

	registry := e2eCreateMultiDIDRegistry(t, map[string]e2eDIDEntry{
		issuerDID: {keyID: issuerKeyID, pubJWK: issuerPubJWK, vmType: "JsonWebKey2020"},
		holderDID: {keyID: holderKeyID, pubJWK: holderPubJWK, vmType: "JsonWebKey2020"},
	})

	vcMap := createDITestVC(issuerDID, holderDID)
	signedVC := signDICredentialAsMapEd25519(t, vcMap, issuerPrivKey, issuerKeyID)

	vpJSON := signDIVPWithCredentialsEd25519(t, holderDID, holderPrivKey, holderKeyID, []interface{}{signedVC})

	parser := &ConfigurablePresentationParser{
		LDProofChecker: NewLDProofChecker(registry, docLoader),
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err, "full pipeline should accept VP+VC with eddsa-rdfc-2022 DI proofs")
	require.NotNil(t, result)
	assert.Equal(t, holderDID, result.Holder)
	assert.NotNil(t, result.HolderKey())

	credentials := result.Credentials()
	require.Len(t, credentials, 1)
	assert.Equal(t, issuerDID, credentials[0].Contents().Issuer.ID)
}

// ---------------------------------------------------------------------------
// Test: Mixed proof types — JWS VP with DI credential
// ---------------------------------------------------------------------------

// TestE2E_DI_MixedProofs_JWSVP_DICredential verifies that a
// JsonWebSignature2020 VP can contain a DataIntegrityProof credential —
// both proof types coexist in the same verification pipeline.
func TestE2E_DI_MixedProofs_JWSVP_DICredential(t *testing.T) {
	docLoader := newTestDocumentLoader()

	// Issuer signs the credential with DI, holder signs the VP with JWS.
	issuerPrivKey, _, issuerPubJWK := generateTestECKeys(t)
	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)
	holderSigner := &testES256Signer{key: holderPrivKey}

	issuerDID := "did:web:issuer.mixed.example.com"
	issuerKeyID := issuerDID + "#key-1"
	holderDID := testHolderDID
	holderKeyID := testHolderKeyID

	registry := e2eCreateMultiDIDRegistry(t, map[string]e2eDIDEntry{
		issuerDID: {keyID: issuerKeyID, pubJWK: issuerPubJWK, vmType: "JsonWebKey2020"},
		holderDID: {keyID: holderKeyID, pubJWK: holderPubJWK, vmType: "JsonWebKey2020"},
	})

	// Sign the credential with DI (ecdsa-rdfc-2019).
	vcMap := createDITestVC(issuerDID, holderDID)
	signedVC := signDICredentialAsMap(t, vcMap, issuerPrivKey, issuerKeyID)

	// Sign the VP with JWS (uses signVPWithCredentialsV2 for VCDM 2.0 context).
	vpJSON := signVPWithCredentialsV2(t, holderSigner, holderKeyID, docLoader,
		[]interface{}{signedVC},
		ldProofTestOptions{proofPurpose: common.ProofPurposeAuthentication})

	parser := &ConfigurablePresentationParser{
		LDProofChecker: NewLDProofChecker(registry, docLoader),
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err, "JWS VP with DI credential should be accepted")
	require.NotNil(t, result)

	credentials := result.Credentials()
	require.Len(t, credentials, 1, "VP should contain one credential")
	assert.Equal(t, issuerDID, credentials[0].Contents().Issuer.ID)
}

// ---------------------------------------------------------------------------
// Test: Mixed proof types — DI VP with JWS credential
// ---------------------------------------------------------------------------

// TestE2E_DI_MixedProofs_DIVP_JWSCredential verifies that a
// DataIntegrityProof VP can contain a JsonWebSignature2020 credential.
func TestE2E_DI_MixedProofs_DIVP_JWSCredential(t *testing.T) {
	docLoader := newTestDocumentLoader()

	// Issuer signs the credential with JWS, holder signs the VP with DI.
	issuerPrivKey, _, issuerPubJWK := generateTestECKeys(t)
	issuerSigner := &testES256Signer{key: issuerPrivKey}
	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)

	issuerDID := "did:web:issuer.mixed.example.com"
	issuerKeyID := issuerDID + "#key-1"
	holderDID := "did:web:holder.mixed.example.com"
	holderKeyID := holderDID + "#key-1"

	registry := e2eCreateMultiDIDRegistry(t, map[string]e2eDIDEntry{
		issuerDID: {keyID: issuerKeyID, pubJWK: issuerPubJWK, vmType: "JsonWebKey2020"},
		holderDID: {keyID: holderKeyID, pubJWK: holderPubJWK, vmType: "JsonWebKey2020"},
	})

	// Sign the credential with JWS. Use createTestVCForSubject so the
	// credentialSubject.id matches the VP holder (holder binding check).
	vcMap := createTestVCForSubject(issuerDID, holderDID)
	vcMap[common.VPKeyProof] = signDocument(t, vcMap, issuerSigner, issuerKeyID, docLoader,
		ldProofTestOptions{proofPurpose: common.ProofPurposeAssertionMethod})

	// Sign the VP with DI. The VP uses VCDM 2.0 context.
	vpMap := map[string]interface{}{
		common.JSONLDKeyContext:          []interface{}{common.ContextCredentialsV2},
		common.JSONLDKeyType:             []interface{}{common.TypeVerifiablePresentation},
		common.VPKeyHolder:               holderDID,
		common.VPKeyVerifiableCredential: []interface{}{vcMap},
	}

	signedVPJSON, _ := signDIPresentation(t, vpMap, holderPrivKey, holderKeyID)

	parser := &ConfigurablePresentationParser{
		LDProofChecker: NewLDProofChecker(registry, docLoader),
	}

	result, err := parser.ParsePresentation(signedVPJSON)
	require.NoError(t, err, "DI VP with JWS credential should be accepted")
	require.NotNil(t, result)
	assert.Equal(t, holderDID, result.Holder)

	credentials := result.Credentials()
	require.Len(t, credentials, 1)
	assert.Equal(t, issuerDID, credentials[0].Contents().Issuer.ID)
}

// ---------------------------------------------------------------------------
// Test: Multikey VM type in DID document
// ---------------------------------------------------------------------------

// TestE2E_DI_MultikeyVM verifies that credentials and presentations signed
// with DataIntegrityProof verify correctly when the DID document declares
// Multikey verification methods.
func TestE2E_DI_MultikeyVM(t *testing.T) {
	docLoader := newTestDocumentLoader()

	issuerPrivKey, _, issuerPubJWK := generateTestECKeys(t)
	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)

	issuerDID := "did:web:issuer.multikey.example.com"
	issuerKeyID := issuerDID + "#key-1"
	holderDID := "did:web:holder.multikey.example.com"
	holderKeyID := holderDID + "#key-1"

	// Register both DIDs with Multikey VM type.
	registry := e2eCreateMultiDIDRegistry(t, map[string]e2eDIDEntry{
		issuerDID: {keyID: issuerKeyID, pubJWK: issuerPubJWK, vmType: did.TypeMultikey},
		holderDID: {keyID: holderKeyID, pubJWK: holderPubJWK, vmType: did.TypeMultikey},
	})

	vcMap := createDITestVC(issuerDID, holderDID)
	signedVC := signDICredentialAsMap(t, vcMap, issuerPrivKey, issuerKeyID)

	vpJSON := signDIVPWithCredentials(t, holderDID, holderPrivKey, holderKeyID, []interface{}{signedVC})

	parser := &ConfigurablePresentationParser{
		LDProofChecker: NewLDProofChecker(registry, docLoader),
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err, "DI proof with Multikey VM type should verify successfully")
	require.NotNil(t, result)
	assert.Equal(t, holderDID, result.Holder)

	credentials := result.Credentials()
	require.Len(t, credentials, 1)
	assert.Equal(t, issuerDID, credentials[0].Contents().Issuer.ID)
}

// ---------------------------------------------------------------------------
// Test: Proof freshness check for DI proofs (vp_token grant type)
// ---------------------------------------------------------------------------

// TestE2E_DI_ProofFreshness verifies that VerifyLDVPProofFreshness works
// correctly for DataIntegrityProof-signed presentations, applying the same
// created-timestamp freshness check as for JWS proofs.
func TestE2E_DI_ProofFreshness(t *testing.T) {
	// proofFreshnessMaxAge is the maximum age used by the freshness tests.
	const proofFreshnessMaxAge = 5 * time.Minute

	tests := []struct {
		name      string
		proofAge  time.Duration
		maxAge    time.Duration
		wantErr   bool
		wantErrIs error
	}{
		{
			name:     "fresh_proof_accepted",
			proofAge: 30 * time.Second,
			maxAge:   proofFreshnessMaxAge,
		},
		{
			name:      "stale_proof_rejected",
			proofAge:  10 * time.Minute,
			maxAge:    proofFreshnessMaxAge,
			wantErr:   true,
			wantErrIs: ErrorProofNotFresh,
		},
		{
			name:     "freshness_disabled_with_zero_maxAge",
			proofAge: 1 * time.Hour,
			maxAge:   0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			holderPrivKey, _, holderPubJWK := generateTestECKeys(t)
			holderDID := "did:web:holder.freshness.example.com"
			holderKeyID := holderDID + "#key-1"

			registry := e2eCreateMultiDIDRegistry(t, map[string]e2eDIDEntry{
				holderDID: {keyID: holderKeyID, pubJWK: holderPubJWK, vmType: "JsonWebKey2020"},
			})
			docLoader := newTestDocumentLoader()

			// Build a VP with a proof whose created timestamp is (now - proofAge).
			vpMap := createDITestVP(holderDID)
			signedJSON, _ := signDIDocumentWithCreated(t, vpMap, holderPrivKey, holderKeyID, tc.proofAge)

			// Parse the VP to get a Presentation with proofs populated.
			parser := &ConfigurablePresentationParser{
				LDProofChecker: NewLDProofChecker(registry, docLoader),
			}
			pres, parseErr := parser.ParsePresentation(signedJSON)
			require.NoError(t, parseErr, "VP should parse regardless of proof age")
			require.NotNil(t, pres)
			require.Len(t, pres.Proofs, 1, "VP should have exactly one proof")

			// The freshness check is a separate call (not part of ParsePresentation).
			// In the verifier, it is called for the vp_token and token-exchange grants.
			freshErr := VerifyLDVPProofFreshness(pres, time.Now(), tc.maxAge)

			if tc.wantErr {
				assert.Error(t, freshErr)
				if tc.wantErrIs != nil {
					assert.True(t, errors.Is(freshErr, tc.wantErrIs),
						"expected %v, got: %v", tc.wantErrIs, freshErr)
				}
			} else {
				assert.NoError(t, freshErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Tampered credential rejected in full pipeline
// ---------------------------------------------------------------------------

// TestE2E_DI_TamperedCredentialRejected verifies that a tampered credential
// inside a correctly-signed VP is rejected at the credential proof check
// stage, even though the VP proof itself is valid.
func TestE2E_DI_TamperedCredentialRejected(t *testing.T) {
	docLoader := newTestDocumentLoader()

	issuerPrivKey, _, issuerPubJWK := generateTestECKeys(t)
	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)

	issuerDID := "did:web:issuer.tampered.example.com"
	issuerKeyID := issuerDID + "#key-1"
	holderDID := "did:web:holder.tampered.example.com"
	holderKeyID := holderDID + "#key-1"

	registry := e2eCreateMultiDIDRegistry(t, map[string]e2eDIDEntry{
		issuerDID: {keyID: issuerKeyID, pubJWK: issuerPubJWK, vmType: "JsonWebKey2020"},
		holderDID: {keyID: holderKeyID, pubJWK: holderPubJWK, vmType: "JsonWebKey2020"},
	})

	// Sign a credential.
	vcMap := createDITestVC(issuerDID, holderDID)
	signedVC := signDICredentialAsMap(t, vcMap, issuerPrivKey, issuerKeyID)

	// Tamper with credentialSubject — this is a term defined in the
	// VCDM 2.0 context, so it survives URDNA2015 canonicalization and
	// will cause the proof verification to fail.
	signedVC[common.VCKeyCredentialSubject] = map[string]interface{}{
		common.JSONLDKeyID: "did:web:tampered-subject.example.com",
	}

	// Embed the tampered credential in a correctly-signed VP.
	vpJSON := signDIVPWithCredentials(t, holderDID, holderPrivKey, holderKeyID, []interface{}{signedVC})

	parser := &ConfigurablePresentationParser{
		LDProofChecker: NewLDProofChecker(registry, docLoader),
	}

	_, err := parser.ParsePresentation(vpJSON)
	require.Error(t, err, "tampered credential should be rejected")
	assert.True(t, errors.Is(err, common.ErrorLDProofVerifyDataIntegrity),
		"expected ErrorLDProofVerifyDataIntegrity, got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Unsigned credential inside DI VP rejected
// ---------------------------------------------------------------------------

// TestE2E_DI_UnsignedCredentialRejected verifies that an unsigned credential
// inside a DataIntegrityProof-signed VP is rejected.
func TestE2E_DI_UnsignedCredentialRejected(t *testing.T) {
	docLoader := newTestDocumentLoader()

	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)
	holderDID := "did:web:holder.unsigned.example.com"
	holderKeyID := holderDID + "#key-1"

	registry := e2eCreateMultiDIDRegistry(t, map[string]e2eDIDEntry{
		holderDID: {keyID: holderKeyID, pubJWK: holderPubJWK, vmType: "JsonWebKey2020"},
	})

	// An unsigned credential (no proof).
	unsignedVC := map[string]interface{}{
		common.JSONLDKeyContext:       []interface{}{common.ContextCredentialsV2},
		common.JSONLDKeyType:          []interface{}{common.TypeVerifiableCredential},
		common.VCKeyIssuer:            "did:web:issuer.unsigned.example.com",
		common.VCKeyCredentialSubject: map[string]interface{}{common.JSONLDKeyID: holderDID},
	}

	vpJSON := signDIVPWithCredentials(t, holderDID, holderPrivKey, holderKeyID, []interface{}{unsignedVC})

	parser := &ConfigurablePresentationParser{
		LDProofChecker: NewLDProofChecker(registry, docLoader),
	}

	_, err := parser.ParsePresentation(vpJSON)
	require.Error(t, err, "unsigned credential must be rejected")
	assert.True(t, errors.Is(err, ErrorUnsignedCredential),
		"expected ErrorUnsignedCredential, got: %v", err)
}

// ---------------------------------------------------------------------------
// Test: Holder binding with DI proofs
// ---------------------------------------------------------------------------

// TestE2E_DI_HolderBinding verifies that the JSON-LD holder binding check
// (credentialSubject.id == VP holder) works correctly when both the VP and
// VC are signed with DataIntegrityProof. A credential issued to a different
// subject should be rejected.
func TestE2E_DI_HolderBinding(t *testing.T) {
	docLoader := newTestDocumentLoader()

	issuerPrivKey, _, issuerPubJWK := generateTestECKeys(t)
	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)

	issuerDID := "did:web:issuer.binding.example.com"
	issuerKeyID := issuerDID + "#key-1"
	holderDID := "did:web:holder.binding.example.com"
	holderKeyID := holderDID + "#key-1"
	foreignSubjectDID := "did:web:someone-else.example.com"

	registry := e2eCreateMultiDIDRegistry(t, map[string]e2eDIDEntry{
		issuerDID: {keyID: issuerKeyID, pubJWK: issuerPubJWK, vmType: "JsonWebKey2020"},
		holderDID: {keyID: holderKeyID, pubJWK: holderPubJWK, vmType: "JsonWebKey2020"},
	})

	// Sign a credential issued to a different subject.
	vcMap := createDITestVC(issuerDID, foreignSubjectDID)
	signedVC := signDICredentialAsMap(t, vcMap, issuerPrivKey, issuerKeyID)

	vpJSON := signDIVPWithCredentials(t, holderDID, holderPrivKey, holderKeyID, []interface{}{signedVC})

	parser := &ConfigurablePresentationParser{
		LDProofChecker: NewLDProofChecker(registry, docLoader),
	}

	_, err := parser.ParsePresentation(vpJSON)
	require.Error(t, err, "credential issued to wrong subject should be rejected")
	assert.True(t, errors.Is(err, ErrorHolderSubjectMismatch),
		"expected ErrorHolderSubjectMismatch, got: %v", err)
}
