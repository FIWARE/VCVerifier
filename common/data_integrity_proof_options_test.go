package common

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file cover the proof configuration a received proof is
// verified against: a copy of the whole proof minus its signature member
// (VC-DI-ECDSA 3.2.5), rather than a document rebuilt from the fields LDProof
// models.
//
// They sign through signDataIntegrityFromProofMap, which is deliberately
// independent of buildProofOptions: it takes the proof map as the source of
// truth the way an issuer does. A verifier that reconstructs the options from
// a fixed field set cannot verify what it produces.

// proofMemberExpires and the constants below are proof members that
// VC-DATA-INTEGRITY 2.1 defines but LDProof does not model. They are the
// members an issuer may legitimately add.
const (
	proofMemberExpires = "expires"
	proofMemberNonce   = "nonce"
	proofMemberID      = "id"
)

// signDataIntegrityFromProofMap signs doc with an eddsa-rdfc-2022 proof whose
// configuration is the given proof map minus proofValue, canonicalized under
// the document's own context. It returns the secured document and the proof
// map including the proofValue it computed.
func signDataIntegrityFromProofMap(t *testing.T, doc JSONObject, proofMap JSONObject, privateKey ed25519.PrivateKey) ([]byte, JSONObject) {
	t.Helper()

	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = LDNormFormatNQuads
	options.Algorithm = LDNormAlgorithmURDNA
	options.DocumentLoader = newTestDocumentLoader()

	unsecured := JSONObject{}
	for key, value := range doc {
		if key != VPKeyProof {
			unsecured[key] = value
		}
	}
	canonicalDocument, err := processor.Normalize(unsecured, options)
	require.NoError(t, err)

	configuration := JSONObject{}
	for key, value := range proofMap {
		if key != LDProofKeyProofValue {
			configuration[key] = value
		}
	}
	configuration[JSONLDKeyContext] = unsecured[JSONLDKeyContext]
	canonicalConfiguration, err := processor.Normalize(configuration, options)
	require.NoError(t, err)

	configurationHash := sha256.Sum256([]byte(canonicalConfiguration.(string)))
	documentHash := sha256.Sum256([]byte(canonicalDocument.(string)))
	signature := ed25519.Sign(privateKey, append(configurationHash[:], documentHash[:]...))

	signed := JSONObject{}
	for key, value := range proofMap {
		signed[key] = value
	}
	signed[LDProofKeyProofValue], err = multibase.Encode(multibase.Base58BTC, signature)
	require.NoError(t, err)

	secured := JSONObject{}
	for key, value := range unsecured {
		secured[key] = value
	}
	secured[VPKeyProof] = map[string]interface{}(signed)

	securedJSON, err := json.Marshal(secured)
	require.NoError(t, err)
	return securedJSON, signed
}

// baseDataIntegrityProofMap returns the proof members every test case here
// starts from.
func baseDataIntegrityProofMap() JSONObject {
	return JSONObject{
		LDProofKeyType:               ProofTypeDataIntegrityProof,
		LDProofKeyCryptosuite:        CryptosuiteEddsaRdfc2022,
		LDProofKeyCreated:            "2024-01-01T00:00:00Z",
		LDProofKeyVerificationMethod: "did:web:example.com#key-1",
		LDProofKeyProofPurpose:       ProofPurposeAssertionMethod,
	}
}

// TestVerifyDataIntegrityProof_AdditionalProofMembers verifies proofs that
// carry members LDProof does not model. Each of them expands to a real triple
// under the VCDM 2.0 context, so the issuer signed over it and the verifier
// has to canonicalize it too.
func TestVerifyDataIntegrityProof_AdditionalProofMembers(t *testing.T) {
	loader := newTestDocumentLoader()

	tests := []struct {
		name   string
		member string
		value  interface{}
	}{
		{name: "expires", member: proofMemberExpires, value: "2034-01-01T00:00:00Z"},
		{name: "nonce", member: proofMemberNonce, value: "n-0S6_WzA2Mj"},
		{name: "id", member: proofMemberID, value: "urn:uuid:26329f4c-7a1e-4f0e-9e33-1f0b19c0d0a2"},
		{
			// A member the context does not define drops out of
			// canonicalization on both sides, so it neither helps nor breaks
			// verification. It must not break it.
			name:   "undefined_vendor_member",
			member: "https://vendor.example.com/unmodelled",
			value:  "whatever",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			key, err := jwk.Import(publicKey)
			require.NoError(t, err)

			proofMap := baseDataIntegrityProofMap()
			proofMap[tc.member] = tc.value

			securedJSON, signedProof := signDataIntegrityFromProofMap(
				t, dataIntegrityTestDocument(), proofMap, privateKey)

			proof, err := ParseLDProof(signedProof)
			require.NoError(t, err)

			assert.NoError(t, VerifyDataIntegrityProof(securedJSON, proof, key, loader),
				"a proof carrying %q must verify", tc.member)
		})
	}
}

// TestVerifyDataIntegrityProof_AdditionalProofMemberTampered is the check that
// earns the previous test: a member that is carried into the proof options is
// covered by the signature, so changing it after signing must be detected.
func TestVerifyDataIntegrityProof_AdditionalProofMemberTampered(t *testing.T) {
	loader := newTestDocumentLoader()

	tests := []struct {
		name     string
		member   string
		original interface{}
		tampered interface{}
	}{
		{
			name:     "expires_extended",
			member:   proofMemberExpires,
			original: "2024-06-01T00:00:00Z",
			tampered: "2044-06-01T00:00:00Z",
		},
		{
			name:     "nonce_replaced",
			member:   proofMemberNonce,
			original: "n-0S6_WzA2Mj",
			tampered: "n-attacker",
		},
		{
			name:     "expires_removed",
			member:   proofMemberExpires,
			original: "2024-06-01T00:00:00Z",
			tampered: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			key, err := jwk.Import(publicKey)
			require.NoError(t, err)

			proofMap := baseDataIntegrityProofMap()
			proofMap[tc.member] = tc.original

			securedJSON, signedProof := signDataIntegrityFromProofMap(
				t, dataIntegrityTestDocument(), proofMap, privateKey)

			// Re-read the secured document and rewrite the member in it, the
			// way an attacker who only has the signed document would.
			var secured JSONObject
			require.NoError(t, json.Unmarshal(securedJSON, &secured))
			tamperedProof, ok := secured[VPKeyProof].(map[string]interface{})
			require.True(t, ok)
			if tc.tampered == nil {
				delete(tamperedProof, tc.member)
			} else {
				tamperedProof[tc.member] = tc.tampered
			}
			tamperedJSON, err := json.Marshal(secured)
			require.NoError(t, err)

			proof, err := ParseLDProof(tamperedProof)
			require.NoError(t, err)

			err = VerifyDataIntegrityProof(tamperedJSON, proof, key, loader)
			assert.True(t, errors.Is(err, ErrorLDProofVerifyDataIntegrity),
				"tampering with %q must be detected, got: %v", tc.member, err)

			// The untampered document still verifies, so the rejection above
			// is about the tampering and not about the member itself.
			original, err := ParseLDProof(signedProof)
			require.NoError(t, err)
			assert.NoError(t, VerifyDataIntegrityProof(securedJSON, original, key, loader))
		})
	}
}

// TestBuildVerificationProofOptions covers the builder directly, including the
// JsonWebSignature2020 branch, whose suite context must still be added.
func TestBuildVerificationProofOptions(t *testing.T) {
	documentContext := []interface{}{ContextCredentialsV2}

	t.Run("carries every member but the signature", func(t *testing.T) {
		proofMap := baseDataIntegrityProofMap()
		proofMap[proofMemberExpires] = "2034-01-01T00:00:00Z"
		proofMap[LDProofKeyProofValue] = "zSignature"

		proof, err := ParseLDProof(proofMap)
		require.NoError(t, err)

		options := buildVerificationProofOptions(documentContext, proof)

		assert.Equal(t, "2034-01-01T00:00:00Z", options[proofMemberExpires])
		assert.Equal(t, ProofTypeDataIntegrityProof, options[JSONLDKeyType])
		assert.NotContains(t, options, LDProofKeyProofValue)
		assert.Equal(t, documentContext, options[JSONLDKeyContext],
			"a Data Integrity proof is canonicalized under the document's context verbatim")
	})

	t.Run("strips the jws of a JsonWebSignature2020 proof and adds the suite context", func(t *testing.T) {
		proofMap := JSONObject{
			LDProofKeyType:               ProofTypeJsonWebSignature2020,
			LDProofKeyCreated:            "2024-01-01T00:00:00Z",
			LDProofKeyVerificationMethod: "did:web:example.com#key-1",
			LDProofKeyProofPurpose:       ProofPurposeAssertionMethod,
			LDProofKeyJWS:                "eyJhbGciOiJFUzI1NiJ9..signature",
		}

		proof, err := ParseLDProof(proofMap)
		require.NoError(t, err)

		options := buildVerificationProofOptions(documentContext, proof)

		assert.NotContains(t, options, LDProofKeyJWS)
		assert.Equal(t, []interface{}{ContextCredentialsV2, ContextSecuritySuiteJWS2020},
			options[JSONLDKeyContext])
	})

	t.Run("falls back to the struct for a proof that was never parsed", func(t *testing.T) {
		proof := &LDProof{
			Type:               ProofTypeDataIntegrityProof,
			Cryptosuite:        CryptosuiteEddsaRdfc2022,
			Created:            "2024-01-01T00:00:00Z",
			VerificationMethod: "did:web:example.com#key-1",
			ProofPurpose:       ProofPurposeAssertionMethod,
		}
		require.Nil(t, proof.Raw)

		assert.Equal(t, buildProofOptions(documentContext, proof),
			buildVerificationProofOptions(documentContext, proof))
	})
}

// TestParseLDProofRawIsIndependentOfTheCaller verifies that the raw proof is
// copied rather than aliased: a caller mutating its own map afterwards must
// not change what the signature is verified against.
func TestParseLDProofRawIsIndependentOfTheCaller(t *testing.T) {
	proofMap := baseDataIntegrityProofMap()
	proofMap[LDProofKeyProofValue] = "zSignature"

	proof, err := ParseLDProof(proofMap)
	require.NoError(t, err)

	proofMap[proofMemberNonce] = "injected-after-parsing"

	assert.NotContains(t, proof.Raw, proofMemberNonce)
}

// TestVerifyDataIntegrityProof_WithoutCreated verifies a proof that carries no
// `created` timestamp. VC-DATA-INTEGRITY §2.1 makes the property OPTIONAL, and
// VC-DI-ECDSA §3.2.5 only constrains it "if proofConfig.created is set", so a
// credential proof without one is conformant. Presentations are bounded in
// time separately, by VerifyLDVPProofFreshness.
func TestVerifyDataIntegrityProof_WithoutCreated(t *testing.T) {
	loader := newTestDocumentLoader()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(publicKey)
	require.NoError(t, err)

	proofMap := baseDataIntegrityProofMap()
	delete(proofMap, LDProofKeyCreated)

	securedJSON, signedProof := signDataIntegrityFromProofMap(
		t, dataIntegrityTestDocument(), proofMap, privateKey)

	proof, err := ParseLDProof(signedProof)
	require.NoError(t, err)
	require.Empty(t, proof.Created)

	assert.NoError(t, VerifyDataIntegrityProof(securedJSON, proof, key, loader))
}
