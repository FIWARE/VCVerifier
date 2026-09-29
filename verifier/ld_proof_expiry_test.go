package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fiware/VCVerifier/common"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ed25519PublicJWK returns the public JWK of an Ed25519 private key.
func ed25519PublicJWK(t *testing.T, privateKey ed25519.PrivateKey) jwk.Key {
	t.Helper()
	key, err := jwk.Import(privateKey.Public())
	require.NoError(t, err)
	return key
}

// expiryTestNow is the instant the fixed clock in these tests reports.
var expiryTestNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// signDIWithProofMembers signs a document with an eddsa-rdfc-2022 proof built
// from the given proof members. Unlike the other Data Integrity helpers in
// this package it takes the proof as a map, so a member LDProof does not model
// - `expires` here - is part of the signed proof configuration, the way an
// issuer produces it.
func signDIWithProofMembers(t *testing.T, doc map[string]interface{}, privateKey ed25519.PrivateKey, proofMembers map[string]interface{}) (documentJSON []byte, proof *common.LDProof) {
	t.Helper()

	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = common.LDNormFormatNQuads
	options.Algorithm = common.LDNormAlgorithmURDNA
	options.DocumentLoader = newTestDocumentLoader()

	canonicalDocument, err := processor.Normalize(doc, options)
	require.NoError(t, err)

	configuration := map[string]interface{}{}
	for key, value := range proofMembers {
		configuration[key] = value
	}
	configuration[common.JSONLDKeyContext] = doc[common.JSONLDKeyContext]
	canonicalConfiguration, err := processor.Normalize(configuration, options)
	require.NoError(t, err)

	configurationHash := sha256.Sum256([]byte(canonicalConfiguration.(string)))
	documentHash := sha256.Sum256([]byte(canonicalDocument.(string)))
	signature := ed25519.Sign(privateKey, append(configurationHash[:], documentHash[:]...))

	signedProof := map[string]interface{}{}
	for key, value := range proofMembers {
		signedProof[key] = value
	}
	signedProof[common.LDProofKeyProofValue], err = multibase.Encode(multibase.Base58BTC, signature)
	require.NoError(t, err)

	proof, err = common.ParseLDProof(signedProof)
	require.NoError(t, err)

	documentJSON, err = json.Marshal(doc)
	require.NoError(t, err)
	return documentJSON, proof
}

// diProofMembers returns the proof members of a valid Data Integrity proof for
// the given purpose, with `expires` added when one is given.
func diProofMembers(verificationMethod string, proofPurpose string, expires string) map[string]interface{} {
	members := map[string]interface{}{
		common.LDProofKeyType:               common.ProofTypeDataIntegrityProof,
		common.LDProofKeyCryptosuite:        common.CryptosuiteEddsaRdfc2022,
		common.LDProofKeyCreated:            expiryTestNow.Add(-time.Minute).Format(time.RFC3339),
		common.LDProofKeyVerificationMethod: verificationMethod,
		common.LDProofKeyProofPurpose:       proofPurpose,
	}
	if expires != "" {
		members[common.LDProofKeyExpires] = expires
	}
	return members
}

// expiryTestCases are shared by the credential and the presentation test: the
// rule is the same for both, only the document differs.
var expiryTestCases = []struct {
	name            string
	expires         string
	wantErrSentinel error
}{
	{
		name:    "no_expires_never_expires",
		expires: "",
	},
	{
		name:    "expires_in_the_future",
		expires: expiryTestNow.Add(time.Hour).Format(time.RFC3339),
	},
	{
		// Holder and verifier clocks run independently, so the same skew the
		// freshness check tolerates applies to the expiry.
		name:    "expired_within_the_clock_skew",
		expires: expiryTestNow.Add(-ldProofClockSkew / 2).Format(time.RFC3339),
	},
	{
		name:            "expired",
		expires:         expiryTestNow.Add(-time.Hour).Format(time.RFC3339),
		wantErrSentinel: ErrorProofExpired,
	},
	{
		name:            "expires_unparseable",
		expires:         "the day after tomorrow",
		wantErrSentinel: ErrorProofExpiresUnparseable,
	},
}

// TestLDProofChecker_VerifyCredential_Expires verifies that an expired
// credential proof is rejected. `expires` is part of the signed proof
// configuration, so the value cannot be extended by whoever presents the
// credential.
func TestLDProofChecker_VerifyCredential_Expires(t *testing.T) {
	docLoader := newTestDocumentLoader()

	for _, tc := range expiryTestCases {
		t.Run(tc.name, func(t *testing.T) {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			publicJWK := ed25519PublicJWK(t, privateKey)

			vcMap := createDITestVC(testIssuerDID, testSubjectDID)
			vcJSON, proof := signDIWithProofMembers(t, vcMap, privateKey,
				diProofMembers(testIssuerKeyID, common.ProofPurposeAssertionMethod, tc.expires))

			registry := createMockRegistry(t, "web", testIssuerKeyID, publicJWK)
			checker := NewLDProofChecker(registry, docLoader).WithClock(fixedClock{t: expiryTestNow})

			err = checker.VerifyCredential(vcJSON, proof, testIssuerDID)

			if tc.wantErrSentinel == nil {
				assert.NoError(t, err)
				return
			}
			assert.True(t, errors.Is(err, tc.wantErrSentinel),
				"expected %v, got: %v", tc.wantErrSentinel, err)
		})
	}
}

// TestLDProofChecker_VerifyPresentation_Expires is the presentation half of
// the same rule.
func TestLDProofChecker_VerifyPresentation_Expires(t *testing.T) {
	docLoader := newTestDocumentLoader()

	for _, tc := range expiryTestCases {
		t.Run(tc.name, func(t *testing.T) {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			publicJWK := ed25519PublicJWK(t, privateKey)

			holderDID := testIssuerDID
			holderKeyID := testIssuerKeyID

			vpMap := createDITestVP(holderDID)
			vpJSON, proof := signDIWithProofMembers(t, vpMap, privateKey,
				diProofMembers(holderKeyID, common.ProofPurposeAuthentication, tc.expires))

			registry := createMockRegistry(t, "web", holderKeyID, publicJWK)
			checker := NewLDProofChecker(registry, docLoader).WithClock(fixedClock{t: expiryTestNow})

			_, err = checker.VerifyPresentation(vpJSON, proof, holderDID)

			if tc.wantErrSentinel == nil {
				assert.NoError(t, err)
				return
			}
			assert.True(t, errors.Is(err, tc.wantErrSentinel),
				"expected %v, got: %v", tc.wantErrSentinel, err)
		})
	}
}

// TestLDProofChecker_ExpiresCannotBeExtended is what makes the expiry check
// meaningful: `expires` is covered by the signature, so rewriting it in a
// captured document invalidates the proof instead of prolonging it.
func TestLDProofChecker_ExpiresCannotBeExtended(t *testing.T) {
	docLoader := newTestDocumentLoader()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicJWK := ed25519PublicJWK(t, privateKey)

	vcMap := createDITestVC(testIssuerDID, testSubjectDID)
	expired := expiryTestNow.Add(-time.Hour).Format(time.RFC3339)
	vcJSON, proof := signDIWithProofMembers(t, vcMap, privateKey,
		diProofMembers(testIssuerKeyID, common.ProofPurposeAssertionMethod, expired))

	// Extend the expiry in the proof the way a holder of the signed document
	// would.
	extended := map[string]interface{}{}
	for key, value := range proof.Raw {
		extended[key] = value
	}
	extended[common.LDProofKeyExpires] = expiryTestNow.Add(time.Hour).Format(time.RFC3339)
	extendedProof, err := common.ParseLDProof(extended)
	require.NoError(t, err)

	registry := createMockRegistry(t, "web", testIssuerKeyID, publicJWK)
	checker := NewLDProofChecker(registry, docLoader).WithClock(fixedClock{t: expiryTestNow})

	err = checker.VerifyCredential(vcJSON, extendedProof, testIssuerDID)
	assert.True(t, errors.Is(err, common.ErrorLDProofVerifyDataIntegrity),
		"an extended expiry must break the signature, got: %v", err)
}
