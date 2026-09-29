package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/fiware/VCVerifier/did"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file verify the published W3C test vectors for the two
// supported Data Integrity cryptosuites.
//
// Every other Data Integrity test in this package signs its fixtures with a
// helper that mirrors the production hash-data construction, so the suite
// proves self-consistency: a systematic deviation from the specification —
// the two hashes concatenated in the wrong order, the second ECDSA hash
// omitted, SHA-256 used for P-384, the proof options canonicalized under the
// wrong context — would pass all of them. These vectors were produced by the
// specification authors, so they fail in exactly that case.
//
// Sources:
//   - eddsa-rdfc-2022: VC-DI-EDDSA §B.1, Examples 7-17
//     https://www.w3.org/TR/vc-di-eddsa/
//   - ecdsa-rdfc-2019 (P-256): VC-DI-ECDSA §A.1, Examples 5-15
//   - ecdsa-rdfc-2019 (P-384): VC-DI-ECDSA §A.3, Examples 27-37
//     https://www.w3.org/TR/vc-di-ecdsa/

// contextCredentialsExamplesV2 is the example context the W3C vectors use
// alongside the VCDM 2.0 context. It is not security-relevant and therefore
// not vendored in common/contexts; the vectors need it only because their
// credential carries an `alumniOf` claim.
const contextCredentialsExamplesV2 = "https://www.w3.org/ns/credentials/examples/v2"

// contextCredentialsExamplesV2Document is the content served for that URL. The
// published context is this single @vocab mapping.
const contextCredentialsExamplesV2Document = `{"@context":{"@vocab":"https://www.w3.org/ns/credentials/examples#"}}`

// Intermediate values of the eddsa-rdfc-2022 vector, as hex. Asserting them
// separately localizes a canonicalization regression to the stage that broke
// instead of reporting a failed signature.
const (
	// vectorEddsaDocumentHashHex is VC-DI-EDDSA §B.1, Example 10.
	vectorEddsaDocumentHashHex = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
	// vectorEddsaProofOptionsHashHex is VC-DI-EDDSA §B.1, Example 13.
	vectorEddsaProofOptionsHashHex = "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0"
)

// vectorEddsaRdfc2022Credential is the signed credential of VC-DI-EDDSA §B.1,
// Example 17. The signing key is Example 7.
const vectorEddsaRdfc2022Credential = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "proofPurpose": "assertionMethod",
    "proofValue": "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme"
  }
}`

// vectorEddsaRdfc2022PublicKey is the Ed25519 public key of VC-DI-EDDSA §B.1,
// Example 7, in the Multikey publicKeyMultibase encoding.
const vectorEddsaRdfc2022PublicKey = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"

// vectorEcdsaRdfc2019P256Credential is the signed credential of VC-DI-ECDSA
// §A.1, Example 15. The signing key is Example 5.
const vectorEcdsaRdfc2019P256Credential = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-rdfc-2019",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
    "proofPurpose": "assertionMethod",
    "proofValue": "zaHXrr7AQdydBk3ahpCDpWbxfLokDqmCToYm2dyWvpcFVyWooC2he63w1f7UNQoAMKdhaRtcnaE2KTo5o5vTCcfw"
  }
}`

// vectorEcdsaRdfc2019P256PublicKey is the P-256 public key of VC-DI-ECDSA
// §A.1, Example 5, in the Multikey publicKeyMultibase encoding.
const vectorEcdsaRdfc2019P256PublicKey = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"

// vectorEcdsaRdfc2019P384Credential is the signed credential of VC-DI-ECDSA
// §A.3, Example 37. The signing key is Example 27. It is the only vector that
// exercises the SHA-384 branch.
const vectorEcdsaRdfc2019P384Credential = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-rdfc-2019",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ#z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ",
    "proofPurpose": "assertionMethod",
    "proofValue": "z967Mvv5bxtmLNqTzPZ8KmJjFmFXaAKeQNzq7GWnQkMcLtaGSSmuozE5WtJ8PipMe178B1tE28K1vsJur9bGVJhz6jgSJsRHFSQeqgH8hhjcg8gZDFJC1b9FsR5ggNmDBqHv"
  }
}`

// vectorEcdsaRdfc2019P384PublicKey is the P-384 public key of VC-DI-ECDSA
// §A.3, Example 27, in the Multikey publicKeyMultibase encoding.
const vectorEcdsaRdfc2019P384PublicKey = "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ"

// exampleContextLoader serves the W3C example context from memory and
// delegates everything else to the embedded loader, so the vectors verify
// without a network request.
type exampleContextLoader struct {
	embedded ld.DocumentLoader
}

func (e exampleContextLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	if u != contextCredentialsExamplesV2 {
		return e.embedded.LoadDocument(u)
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(contextCredentialsExamplesV2Document), &parsed); err != nil {
		return nil, err
	}
	return &ld.RemoteDocument{DocumentURL: u, Document: parsed}, nil
}

// newVectorDocumentLoader returns the document loader the vectors are
// canonicalized with.
func newVectorDocumentLoader(t *testing.T) ld.DocumentLoader {
	t.Helper()
	embedded, err := NewEmbeddedContextLoader(nil)
	require.NoError(t, err)
	return exampleContextLoader{embedded: embedded}
}

// TestDataIntegritySpecVectors verifies the published W3C test vectors for
// every supported cryptosuite and curve.
func TestDataIntegritySpecVectors(t *testing.T) {
	loader := newVectorDocumentLoader(t)

	tests := []struct {
		name               string
		credential         string
		publicKeyMultibase string
	}{
		{"eddsa-rdfc-2022 (Ed25519)", vectorEddsaRdfc2022Credential, vectorEddsaRdfc2022PublicKey},
		{"ecdsa-rdfc-2019 (P-256)", vectorEcdsaRdfc2019P256Credential, vectorEcdsaRdfc2019P256PublicKey},
		{"ecdsa-rdfc-2019 (P-384)", vectorEcdsaRdfc2019P384Credential, vectorEcdsaRdfc2019P384PublicKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var document JSONObject
			require.NoError(t, json.Unmarshal([]byte(tc.credential), &document))

			proofMap, ok := document[VPKeyProof].(map[string]interface{})
			require.True(t, ok, "the vector must carry a proof object")
			proof, err := ParseLDProof(proofMap)
			require.NoError(t, err)

			// The vectors publish their key as publicKeyMultibase, exactly as
			// a Multikey verification method would.
			key, err := did.DecodeMultibaseKey(tc.publicKeyMultibase)
			require.NoError(t, err)

			assert.NoError(t, VerifyDataIntegrityProof([]byte(tc.credential), proof, key, loader))
		})
	}
}

// TestDataIntegritySpecVectorIntermediateHashes asserts the two hashes the
// eddsa-rdfc-2022 vector publishes. A mismatch here says which of the two
// canonicalization inputs drifted, which a failed signature alone does not.
func TestDataIntegritySpecVectorIntermediateHashes(t *testing.T) {
	loader := newVectorDocumentLoader(t)

	var document JSONObject
	require.NoError(t, json.Unmarshal([]byte(vectorEddsaRdfc2022Credential), &document))

	proofMap, ok := document[VPKeyProof].(map[string]interface{})
	require.True(t, ok)
	proof, err := ParseLDProof(proofMap)
	require.NoError(t, err)

	unsecured := JSONObject{}
	for key, value := range document {
		if key != VPKeyProof {
			unsecured[key] = value
		}
	}

	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = LDNormFormatNQuads
	options.Algorithm = LDNormAlgorithmURDNA
	options.DocumentLoader = loader

	canonicalDocument, err := processor.Normalize(unsecured, options)
	require.NoError(t, err)
	documentHash := sha256.Sum256([]byte(canonicalDocument.(string)))
	assert.Equal(t, vectorEddsaDocumentHashHex, hex.EncodeToString(documentHash[:]),
		"canonicalized document must hash to the value published in VC-DI-EDDSA Example 10")

	canonicalProofOptions, err := processor.Normalize(
		buildProofOptions(unsecured[JSONLDKeyContext], proof), options)
	require.NoError(t, err)
	proofOptionsHash := sha256.Sum256([]byte(canonicalProofOptions.(string)))
	assert.Equal(t, vectorEddsaProofOptionsHashHex, hex.EncodeToString(proofOptionsHash[:]),
		"canonicalized proof options must hash to the value published in VC-DI-EDDSA Example 13")
}

// --- JCS cryptosuite vectors -------------------------------------------
//
// The JCS suites differ from the RDFC ones in canonicalization only, but the
// difference reaches the proof itself: a JCS proof carries the document's
// `@context` as one of its own members, and that member is part of the signed
// proof configuration (VC-DI-ECDSA 3.3.5). These vectors are what says the
// implementation copies it rather than rebuilding it.
//
// Sources:
//   - ecdsa-jcs-2019 (P-256): VC-DI-ECDSA A.5, Examples 49-59
//   - ecdsa-jcs-2019 (P-384): VC-DI-ECDSA A.6, Examples 60-70
//   - eddsa-jcs-2022: VC-DI-EDDSA B.3, Examples 29-39

// vectorJcsCanonicalCredential is the JCS canonical form of the unsecured
// credential, VC-DI-ECDSA Example 51.
const vectorJcsCanonicalCredential = `{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"credentialSubject":{"alumniOf":"The School of Examples","id":"did:example:abcdefgh"},"description":"A minimum viable example of an Alumni Credential.","id":"urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33","issuer":"https://vc.example/issuers/5678","name":"Alumni Credential","type":["VerifiableCredential","AlumniCredential"],"validFrom":"2023-01-01T00:00:00Z"}`

// vectorJcsCanonicalProofOptions is the JCS canonical form of the P-256 proof
// configuration, VC-DI-ECDSA Example 54.
const vectorJcsCanonicalProofOptions = `{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"created":"2023-02-24T23:36:38Z","cryptosuite":"ecdsa-jcs-2019","proofPurpose":"assertionMethod","type":"DataIntegrityProof","verificationMethod":"did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"}`

// vectorJcsDocumentHashHex is VC-DI-ECDSA Example 52, the SHA-256 of the
// canonical credential above.
const vectorJcsDocumentHashHex = "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"

// vectorJcsProofOptionsHashHex is VC-DI-ECDSA Example 55.
const vectorJcsProofOptionsHashHex = "fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a9312648ec25"

// vectorEcdsaJcs2019P256Credential is VC-DI-ECDSA Example 59.
const vectorEcdsaJcs2019P256Credential = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-jcs-2019",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
    "proofPurpose": "assertionMethod",
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "proofValue": "z5ptCet75SaEgzG4v4zJhbJtfNi74Wv7Fq15hhKouJQQjEPQvPZKaYxcMXAMLPQS2FXrkCWokNJkFVkwxNzZfD5oT"
  }
}`

// vectorEcdsaJcs2019P384Credential is VC-DI-ECDSA Example 70.
const vectorEcdsaJcs2019P384Credential = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-jcs-2019",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ#z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ",
    "proofPurpose": "assertionMethod",
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "proofValue": "zq3EuTeLiGurmB2JR5oL8oWEsT7u2tba4HT1oZbiMYWc5qzsoW2kLYcBcF4HM5vCpJyTkceULKrVXuJQkXeN5seL4uXrFNFRMm53GWy1Yrto8rTWxZi9DkNeWP7yUPs7ELAm"
  }
}`

// vectorEddsaJcs2022Credential is VC-DI-EDDSA Example 39.
const vectorEddsaJcs2022Credential = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "proofPurpose": "assertionMethod",
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "proofValue": "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"
  }
}`

// TestDataIntegrityJCSSpecVectors verifies the published W3C vectors for the
// JCS cryptosuites.
func TestDataIntegrityJCSSpecVectors(t *testing.T) {
	loader := newVectorDocumentLoader(t)

	tests := []struct {
		name               string
		credential         string
		publicKeyMultibase string
	}{
		{"ecdsa-jcs-2019 (P-256)", vectorEcdsaJcs2019P256Credential, vectorEcdsaRdfc2019P256PublicKey},
		{"ecdsa-jcs-2019 (P-384)", vectorEcdsaJcs2019P384Credential, vectorEcdsaRdfc2019P384PublicKey},
		{"eddsa-jcs-2022 (Ed25519)", vectorEddsaJcs2022Credential, vectorEddsaRdfc2022PublicKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var document JSONObject
			require.NoError(t, json.Unmarshal([]byte(tc.credential), &document))

			proofMap, ok := document[VPKeyProof].(map[string]interface{})
			require.True(t, ok, "the vector must carry a proof object")
			proof, err := ParseLDProof(proofMap)
			require.NoError(t, err)

			key, err := did.DecodeMultibaseKey(tc.publicKeyMultibase)
			require.NoError(t, err)

			assert.NoError(t, VerifyDataIntegrityProof([]byte(tc.credential), proof, key, loader))
		})
	}
}

// TestDataIntegrityJCSSpecVectorCanonicalForms asserts the canonical forms and
// their hashes that VC-DI-ECDSA A.5 publishes. Unlike the signature check they
// say which of the two canonicalization inputs is wrong when one is.
func TestDataIntegrityJCSSpecVectorCanonicalForms(t *testing.T) {
	var document JSONObject
	require.NoError(t, json.Unmarshal([]byte(vectorEcdsaJcs2019P256Credential), &document))

	proofMap, ok := document[VPKeyProof].(map[string]interface{})
	require.True(t, ok)
	proof, err := ParseLDProof(proofMap)
	require.NoError(t, err)

	unsecured := JSONObject{}
	for key, value := range document {
		if key != VPKeyProof {
			unsecured[key] = value
		}
	}

	canonicalDocument, err := CanonicalizeJSON(unsecured)
	require.NoError(t, err)
	assert.Equal(t, vectorJcsCanonicalCredential, canonicalDocument)
	documentHash := sha256.Sum256([]byte(canonicalDocument))
	assert.Equal(t, vectorJcsDocumentHashHex, hex.EncodeToString(documentHash[:]))

	canonicalProofOptions, err := CanonicalizeJSON(
		buildVerificationProofOptions(unsecured[JSONLDKeyContext], proof))
	require.NoError(t, err)
	assert.Equal(t, vectorJcsCanonicalProofOptions, canonicalProofOptions)
	proofOptionsHash := sha256.Sum256([]byte(canonicalProofOptions))
	assert.Equal(t, vectorJcsProofOptionsHashHex, hex.EncodeToString(proofOptionsHash[:]))
}

// TestDataIntegrityJCSSpecVectorRejections checks the JCS path the way the
// RDFC one is checked: the vectors prove it accepts what it should, these
// prove it rejects what it should.
func TestDataIntegrityJCSSpecVectorRejections(t *testing.T) {
	loader := newVectorDocumentLoader(t)

	tests := []struct {
		name    string
		tamper  func(document JSONObject, proofMap map[string]interface{})
		wantErr error
	}{
		{
			name: "tampered_document",
			tamper: func(document JSONObject, _ map[string]interface{}) {
				document["name"] = "Someone Else's Credential"
			},
			wantErr: ErrorLDProofVerifyDataIntegrity,
		},
		{
			name: "tampered_proof_context",
			tamper: func(_ JSONObject, proofMap map[string]interface{}) {
				// The proof's own @context is part of a JCS proof
				// configuration, so rewriting it must break the signature.
				proofMap[JSONLDKeyContext] = []interface{}{ContextCredentialsV2}
			},
			wantErr: ErrorLDProofVerifyDataIntegrity,
		},
		{
			name: "cryptosuite_switched_to_the_rdfc_variant",
			tamper: func(_ JSONObject, proofMap map[string]interface{}) {
				// Same algorithm, different canonicalization: the suite name
				// is signed over, so this cannot be swapped.
				proofMap[LDProofKeyCryptosuite] = CryptosuiteEcdsaRdfc2019
			},
			wantErr: ErrorLDProofVerifyDataIntegrity,
		},
		{
			name: "unknown_cryptosuite",
			tamper: func(_ JSONObject, proofMap map[string]interface{}) {
				proofMap[LDProofKeyCryptosuite] = "ecdsa-jcs-2099"
			},
			wantErr: ErrorLDProofUnsupportedCryptosuite,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var document JSONObject
			require.NoError(t, json.Unmarshal([]byte(vectorEcdsaJcs2019P256Credential), &document))
			proofMap, ok := document[VPKeyProof].(map[string]interface{})
			require.True(t, ok)

			tc.tamper(document, proofMap)

			tamperedJSON, err := json.Marshal(document)
			require.NoError(t, err)
			proof, err := ParseLDProof(proofMap)
			require.NoError(t, err)

			key, err := did.DecodeMultibaseKey(vectorEcdsaRdfc2019P256PublicKey)
			require.NoError(t, err)

			err = VerifyDataIntegrityProof(tamperedJSON, proof, key, loader)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}
