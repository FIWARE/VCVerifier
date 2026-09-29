package common

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file cover VC-DI-ECDSA 3.3.2 / VC-DI-EDDSA 3.3.2 step 4:
// an @context carried by a JCS proof configuration governs the document too.
// The document may extend it, and is hashed under the proof's context; it may
// not reorder or replace it.
//
// They sign with a helper that binds the document to the proof's context the
// way a conforming issuer does, so the "document extended after signing" case
// is the one signature the verifier must accept without ever having seen the
// extended document.

// jcsTestExtraContext is a second @context entry for the extension cases. The
// JCS suites never expand a context, so it is never dereferenced — only
// compared.
const jcsTestExtraContext = "https://www.w3.org/ns/credentials/examples/v2"

// jcsSigner signs the hash data of a JCS Data Integrity proof and carries the
// public key and cryptosuite that go with it.
type jcsSigner struct {
	cryptosuite string
	publicKey   jwk.Key
	sign        func(t *testing.T, hashData []byte) []byte
}

// newJcsEd25519Signer returns a signer for eddsa-jcs-2022, which signs the
// hash data directly.
func newJcsEd25519Signer(t *testing.T) jcsSigner {
	t.Helper()
	privateKey, _, publicJWK := generateEd25519TestKeys(t)
	return jcsSigner{
		cryptosuite: CryptosuiteEddsaJcs2022,
		publicKey:   publicJWK,
		sign: func(t *testing.T, hashData []byte) []byte {
			t.Helper()
			return ed25519.Sign(privateKey, hashData)
		},
	}
}

// newJcsP256Signer returns a signer for ecdsa-jcs-2019 on P-256, which hashes
// the hash data once more with SHA-256 before signing and encodes r||s.
func newJcsP256Signer(t *testing.T) jcsSigner {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicJWK, err := jwk.Import(&privateKey.PublicKey)
	require.NoError(t, err)

	return jcsSigner{
		cryptosuite: CryptosuiteEcdsaJcs2019,
		publicKey:   publicJWK,
		sign: func(t *testing.T, hashData []byte) []byte {
			t.Helper()
			digest := sha256.Sum256(hashData)
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
			require.NoError(t, err)
			signature := make([]byte, 2*p256CoordSize)
			r.FillBytes(signature[:p256CoordSize])
			s.FillBytes(signature[p256CoordSize:])
			return signature
		},
	}
}

// signDataIntegrityJCS signs doc with a JCS proof that carries signedContext
// as its own @context, per VC-DI-ECDSA 3.3.5. The document is canonicalized
// under that same context, which is what step 4 of the verification algorithm
// reproduces. It returns the proof map including its proofValue.
func signDataIntegrityJCS(t *testing.T, doc JSONObject, signedContext interface{}, signer jcsSigner) JSONObject {
	t.Helper()

	unsecured := withContext(doc, signedContext)
	delete(unsecured, VPKeyProof)

	configuration := JSONObject{
		JSONLDKeyContext:             signedContext,
		LDProofKeyType:               ProofTypeDataIntegrityProof,
		LDProofKeyCryptosuite:        signer.cryptosuite,
		LDProofKeyCreated:            "2024-01-01T00:00:00Z",
		LDProofKeyVerificationMethod: "did:web:example.com#key-1",
		LDProofKeyProofPurpose:       ProofPurposeAssertionMethod,
	}

	canonicalConfiguration, err := CanonicalizeJSON(configuration)
	require.NoError(t, err)
	canonicalDocument, err := CanonicalizeJSON(unsecured)
	require.NoError(t, err)

	configurationHash := sha256.Sum256([]byte(canonicalConfiguration))
	documentHash := sha256.Sum256([]byte(canonicalDocument))
	signature := signer.sign(t, append(configurationHash[:], documentHash[:]...))

	proofMap := JSONObject{}
	for key, value := range configuration {
		proofMap[key] = value
	}
	proofMap[LDProofKeyProofValue], err = multibase.Encode(multibase.Base58BTC, signature)
	require.NoError(t, err)
	return proofMap
}

// secureDocumentWithProof attaches proofMap to a copy of doc whose @context is
// presentedContext, and returns the serialized document together with the
// parsed proof — the pair a verifier receives.
func secureDocumentWithProof(t *testing.T, doc JSONObject, presentedContext interface{}, proofMap JSONObject) ([]byte, *LDProof) {
	t.Helper()

	secured := withContext(doc, presentedContext)
	secured[VPKeyProof] = map[string]interface{}(proofMap)
	securedJSON, err := json.Marshal(secured)
	require.NoError(t, err)

	proof, err := ParseLDProof(map[string]interface{}(proofMap))
	require.NoError(t, err)
	return securedJSON, proof
}

// jcsContextTestDocument returns a credential without its @context, so each
// case can supply the one it needs.
func jcsContextTestDocument() JSONObject {
	document := JSONObject{}
	for key, value := range dataIntegrityTestDocument() {
		document[key] = value
	}
	delete(document, JSONLDKeyContext)
	return document
}

// TestVerifyDataIntegrityProof_JCSContextBinding covers the four ways a
// presented @context can relate to the one a JCS proof was created under.
// Extending it is the case the specification explicitly permits; every other
// deviation is a verification failure.
func TestVerifyDataIntegrityProof_JCSContextBinding(t *testing.T) {
	loader := newTestDocumentLoader()

	signedContext := []interface{}{ContextCredentialsV2}
	contextTests := []struct {
		name             string
		presentedContext interface{}
		expectedError    error
	}{
		{
			// The case the specification exists for: an intermediary appended
			// a context entry after issuance. The document the verifier sees
			// is not the one that was signed, and it still verifies.
			name:             "context extended after signing",
			presentedContext: []interface{}{ContextCredentialsV2, jcsTestExtraContext},
			expectedError:    nil,
		},
		{
			name:             "context unchanged",
			presentedContext: []interface{}{ContextCredentialsV2},
			expectedError:    nil,
		},
		{
			// Prepending rather than appending: the base context entry that
			// DetectVCDataModelVersion reads is no longer the signed one.
			name:             "context reordered",
			presentedContext: []interface{}{jcsTestExtraContext, ContextCredentialsV2},
			expectedError:    ErrorLDProofContextMismatch,
		},
		{
			name:             "first context entry replaced",
			presentedContext: []interface{}{ContextCredentialsV1},
			expectedError:    ErrorLDProofContextMismatch,
		},
		{
			name:             "context dropped",
			presentedContext: nil,
			expectedError:    ErrorLDProofContextMismatch,
		},
	}

	signers := []struct {
		name      string
		newSigner func(t *testing.T) jcsSigner
	}{
		{"eddsa-jcs-2022", newJcsEd25519Signer},
		{"ecdsa-jcs-2019 (P-256)", newJcsP256Signer},
	}

	for _, signerCase := range signers {
		for _, test := range contextTests {
			t.Run(signerCase.name+"/"+test.name, func(t *testing.T) {
				signer := signerCase.newSigner(t)
				document := jcsContextTestDocument()
				proofMap := signDataIntegrityJCS(t, document, signedContext, signer)
				securedJSON, proof := secureDocumentWithProof(t, document, test.presentedContext, proofMap)

				err := VerifyDataIntegrityProof(securedJSON, proof, signer.publicKey, loader)

				if test.expectedError == nil {
					assert.NoError(t, err)
					return
				}
				assert.ErrorIs(t, err, test.expectedError)
			})
		}
	}
}

// TestVerifyDataIntegrityProof_JCSProofWithoutContext asserts that a proof
// carrying no @context leaves the document's own in place: step 4 is
// conditional on the proof having one, and the published test vectors that
// omit it must keep verifying.
func TestVerifyDataIntegrityProof_JCSProofWithoutContext(t *testing.T) {
	loader := newTestDocumentLoader()
	signer := newJcsEd25519Signer(t)

	documentContext := []interface{}{ContextCredentialsV2}
	document := withContext(jcsContextTestDocument(), documentContext)

	proofMap := signDataIntegrityJCS(t, document, documentContext, signer)
	delete(proofMap, JSONLDKeyContext)

	// Re-sign without the context member, the way an issuer that omits it does.
	configuration := JSONObject{}
	for key, value := range proofMap {
		if key != LDProofKeyProofValue {
			configuration[key] = value
		}
	}
	canonicalConfiguration, err := CanonicalizeJSON(configuration)
	require.NoError(t, err)
	canonicalDocument, err := CanonicalizeJSON(document)
	require.NoError(t, err)
	configurationHash := sha256.Sum256([]byte(canonicalConfiguration))
	documentHash := sha256.Sum256([]byte(canonicalDocument))
	proofMap[LDProofKeyProofValue], err = multibase.Encode(multibase.Base58BTC, signer.sign(t, append(configurationHash[:], documentHash[:]...)))
	require.NoError(t, err)

	securedJSON, proof := secureDocumentWithProof(t, document, documentContext, proofMap)

	assert.NoError(t, VerifyDataIntegrityProof(securedJSON, proof, signer.publicKey, loader))
}

// TestAssertContextPrefix covers the comparison itself, including the shapes
// an @context can take beyond a list of strings.
func TestAssertContextPrefix(t *testing.T) {
	inlineContext := map[string]interface{}{"name": "https://schema.org/name", "id": "@id"}
	reorderedInlineContext := map[string]interface{}{"id": "@id", "name": "https://schema.org/name"}

	tests := []struct {
		name            string
		documentContext interface{}
		proofContext    interface{}
		expectError     bool
	}{
		{
			name:            "identical single string contexts",
			documentContext: ContextCredentialsV2,
			proofContext:    ContextCredentialsV2,
			expectError:     false,
		},
		{
			name:            "string document context extended by the proof",
			documentContext: ContextCredentialsV2,
			proofContext:    []interface{}{ContextCredentialsV2, jcsTestExtraContext},
			expectError:     true,
		},
		{
			name:            "inline context object with reordered members",
			documentContext: []interface{}{ContextCredentialsV2, reorderedInlineContext},
			proofContext:    []interface{}{ContextCredentialsV2, inlineContext},
			expectError:     false,
		},
		{
			name:            "inline context object where a string is expected",
			documentContext: []interface{}{ContextCredentialsV2, inlineContext},
			proofContext:    []interface{}{ContextCredentialsV2, jcsTestExtraContext},
			expectError:     true,
		},
		{
			name:            "empty proof context matches anything",
			documentContext: []interface{}{ContextCredentialsV2},
			proofContext:    []interface{}{},
			expectError:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := assertContextPrefix(test.documentContext, test.proofContext)
			if test.expectError {
				assert.ErrorIs(t, err, ErrorLDProofContextMismatch)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// TestWithContextDoesNotMutate asserts that rebinding the document's context
// leaves the caller's map alone — the verification path hands it a map it does
// not own.
func TestWithContextDoesNotMutate(t *testing.T) {
	original := JSONObject{JSONLDKeyContext: ContextCredentialsV2, "type": "VerifiableCredential"}

	rebound := withContext(original, ContextCredentialsV1)

	assert.Equal(t, ContextCredentialsV2, original[JSONLDKeyContext])
	assert.Equal(t, ContextCredentialsV1, rebound[JSONLDKeyContext])
	assert.Equal(t, "VerifiableCredential", rebound["type"])
}
