package verifier

// Integration tests for the JSON-LD Linked Data Proof verification pipeline.
// These tests exercise the full chain: VP construction → LD signing → parsing →
// proof verification → credential extraction, covering both the happy path and
// several negative scenarios. Status list credential LD-proof verification is
// also covered. Regression tests for JWT and SD-JWT flows ensure the LD-proof
// changes introduce no regressions.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/did"
	ld "github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Shared helpers (integration-specific)
// ---------------------------------------------------------------------------

// integrationKeyBundle groups the key material and mocks needed by integration
// tests into a single value object, reducing parameter-passing noise.
type integrationKeyBundle struct {
	privKey   *ecdsa.PrivateKey
	signer    common.LDSigner
	registry  *did.Registry
	docLoader ld.DocumentLoader
	checker   *LDProofChecker
	verifMeth string
}

// newIntegrationKeyBundle generates fresh EC-P256 key material and wires up a
// mock DID registry + LD proof checker suitable for integration tests.
func newIntegrationKeyBundle(t *testing.T, holderDID string) integrationKeyBundle {
	t.Helper()
	privKey, _, pubJWK := generateTestECKeys(t)

	keyID := holderDID + "#key-1"
	// Extract the DID method name (e.g. "web" from "did:web:holder.example.com").
	method := extractDIDMethod(holderDID)
	registry := createMockRegistry(t, method, keyID, pubJWK)
	docLoader := newTestDocumentLoader()

	return integrationKeyBundle{
		privKey:   privKey,
		signer:    &testES256Signer{key: privKey},
		registry:  registry,
		docLoader: docLoader,
		checker:   NewLDProofChecker(registry, docLoader),
		verifMeth: keyID,
	}
}

// extractDIDMethod returns the method component from a DID string
// (e.g. "web" from "did:web:example.com").
func extractDIDMethod(didStr string) string {
	// Skip "did:" prefix
	rest := didStr[4:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == ':' {
			return rest[:i]
		}
	}
	return rest
}

// signTestVP creates a test VP, signs it with the bundle's signer, and returns
// the raw signed JSON and the VP proof.
func signTestVP(t *testing.T, bundle integrationKeyBundle, holderDID string) ([]byte, *common.LDProof) {
	t.Helper()
	pres := &common.Presentation{
		Context: []string{common.ContextCredentialsV1},
		Type:    []string{common.TypeVerifiablePresentation},
		Holder:  holderDID,
	}
	return signPresentation(t, pres, bundle.signer, bundle.verifMeth, bundle.docLoader)
}

// makeMinimalVC returns a JSON-LD VC map with no proof (unsigned).
func makeMinimalVC(issuerDID string) map[string]interface{} {
	return map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            issuerDID,
		"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com", "name": "Alice"},
	}
}

// makeStatusListVCJSONLD returns a JSON-LD BitstringStatusListCredential
// with an optional proof section. When proofMap is nil, no proof is included.
func makeStatusListVCJSONLD(issuerDID string, proofMap map[string]interface{}) string {
	doc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"id":       "https://example.com/status/1",
		"type":     []interface{}{"VerifiableCredential", "BitstringStatusListCredential"},
		"issuer":   issuerDID,
		"credentialSubject": map[string]interface{}{
			"id":            "https://example.com/status/1#list",
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   "H4sIAAAAAAAA_2NgAAMAAAAEAAEAAAAA",
		},
	}
	if proofMap != nil {
		doc["proof"] = proofMap
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

// signCredentialDocument generates a valid JsonWebSignature2020 proof for the
// given JSON-LD document (typically a credential) and returns it as a proof
// map. The document must NOT already contain a proof member.
//
// This mirrors the canonicalize-hash-sign flow of common.Presentation.AddLinkedDataProof
// adapted for arbitrary JSON-LD documents.
func signCredentialDocument(t *testing.T, docMap map[string]interface{}, bundle integrationKeyBundle) map[string]interface{} {
	t.Helper()

	// 1. Strip any existing proof (should not be present but be safe).
	docCopy := make(map[string]interface{})
	for k, v := range docMap {
		if k != "proof" {
			docCopy[k] = v
		}
	}

	// 2. Build proof options with @context from the document.
	created := time.Now().UTC().Format(time.RFC3339)
	proofOptions := map[string]interface{}{
		"@context":           docCopy["@context"],
		"type":               common.ProofTypeJsonWebSignature2020,
		"created":            created,
		"verificationMethod": bundle.verifMeth,
	}

	// 3. Canonicalize both document and proof options using URDNA2015.
	proc := ld.NewJsonLdProcessor()
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Format = "application/n-quads"
	ldOpts.Algorithm = "URDNA2015"
	ldOpts.DocumentLoader = bundle.docLoader

	canonDoc, err := proc.Normalize(docCopy, ldOpts)
	require.NoError(t, err, "canonicalize document")
	canonProof, err := proc.Normalize(proofOptions, ldOpts)
	require.NoError(t, err, "canonicalize proof options")

	// 4. Hash both canonical forms.
	docHash := sha256.Sum256([]byte(canonDoc.(string)))
	proofHash := sha256.Sum256([]byte(canonProof.(string)))

	// 5. tbs = hash(proof_options) || hash(document)
	tbs := append(proofHash[:], docHash[:]...)

	// 6. Create JWS header with b64=false.
	headerJSON, _ := json.Marshal(map[string]interface{}{
		"alg":  "ES256",
		"b64":  false,
		"crit": []string{"b64"},
	})
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// 7. Sign: ASCII(header) || "." || tbs (raw bytes since b64=false).
	signingInput := append([]byte(headerB64+"."), tbs...)
	sig, err := bundle.signer.Sign(signingInput)
	require.NoError(t, err, "sign tbs")

	// 8. Construct detached JWS: header..signature (empty payload part).
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	jwsValue := headerB64 + ".." + sigB64

	return map[string]interface{}{
		"type":               common.ProofTypeJsonWebSignature2020,
		"created":            created,
		"verificationMethod": bundle.verifMeth,
		"proofPurpose":       "assertionMethod",
		"jws":                jwsValue,
	}
}

// ---------------------------------------------------------------------------
// End-to-end: JSON-LD VP with did:web holder
// ---------------------------------------------------------------------------

// TestIntegration_JSONLDVP_DidWeb verifies the full chain: construct a JSON-LD
// VP with a did:web holder, sign with AddLinkedDataProof, submit to the parser,
// and assert that the presentation is accepted and the holder key is populated.
func TestIntegration_JSONLDVP_DidWeb(t *testing.T) {
	holderDID := "did:web:holder.integration.example.com"
	bundle := newIntegrationKeyBundle(t, holderDID)

	vpJSON, _ := signTestVP(t, bundle, holderDID)

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: bundle.checker,
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err, "valid signed VP should parse")
	require.NotNil(t, result)
	assert.Equal(t, holderDID, result.Holder)
	assert.NotNil(t, result.HolderKey(), "holder key must be populated from LD proof")
}

// ---------------------------------------------------------------------------
// End-to-end: JSON-LD VP with did:key holder
// ---------------------------------------------------------------------------

// TestIntegration_JSONLDVP_DidKey verifies parsing a JSON-LD VP signed with a
// did:key verification method. The mock registry resolves the did:key to the
// signer's public key, exercising the LD proof path for a different DID method.
func TestIntegration_JSONLDVP_DidKey(t *testing.T) {
	holderDID := "did:key:zIntegrationTest"
	bundle := newIntegrationKeyBundle(t, holderDID)

	vpJSON, _ := signTestVP(t, bundle, holderDID)

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: bundle.checker,
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err, "valid signed VP with did:key should parse")
	require.NotNil(t, result)
	assert.Equal(t, holderDID, result.Holder)
	assert.NotNil(t, result.HolderKey())
}

// ---------------------------------------------------------------------------
// Negative: unsigned JSON-LD VP rejected
// ---------------------------------------------------------------------------

// TestIntegration_JSONLDVP_UnsignedRejected submits a JSON-LD VP without any
// proof and verifies that the parser rejects it at the proof-check stage.
func TestIntegration_JSONLDVP_UnsignedRejected(t *testing.T) {
	vpJSON := `{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"type": ["VerifiablePresentation"],
		"holder": "did:web:holder.integration.example.com",
		"verifiableCredential": [{
			"@context": ["https://www.w3.org/2018/credentials/v1"],
			"type": ["VerifiableCredential"],
			"issuer": "did:web:issuer.example.com",
			"credentialSubject": {"id": "did:web:subject.example.com", "name": "Alice"}
		}]
	}`

	holderDID := "did:web:holder.integration.example.com"
	bundle := newIntegrationKeyBundle(t, holderDID)

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: bundle.checker,
	}

	_, err := parser.ParsePresentation([]byte(vpJSON))
	require.Error(t, err, "unsigned VP must be rejected")
	assert.True(t, errors.Is(err, ErrorUnsignedPresentation),
		"expected ErrorUnsignedPresentation, got: %v", err)
}

// ---------------------------------------------------------------------------
// Negative: tampered JSON-LD VP rejected
// ---------------------------------------------------------------------------

// TestIntegration_JSONLDVP_TamperedRejected signs a valid VP, then modifies the
// holder field, and verifies that the proof verification fails because the
// canonicalized content no longer matches the signature.
func TestIntegration_JSONLDVP_TamperedRejected(t *testing.T) {
	holderDID := "did:web:holder.integration.example.com"
	bundle := newIntegrationKeyBundle(t, holderDID)

	vpJSON, _ := signTestVP(t, bundle, holderDID)

	// Tamper: change the holder.
	var vpMap map[string]interface{}
	require.NoError(t, json.Unmarshal(vpJSON, &vpMap))
	vpMap["holder"] = "did:web:attacker.example.com"
	tamperedJSON, err := json.Marshal(vpMap)
	require.NoError(t, err)

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: bundle.checker,
	}

	_, err = parser.ParsePresentation(tamperedJSON)
	require.Error(t, err, "tampered VP must be rejected")
}

// ---------------------------------------------------------------------------
// JSON-LD status list credential: valid proof accepted
// ---------------------------------------------------------------------------

// TestIntegration_StatusListJSONLD_ValidProofAccepted constructs a JSON-LD
// BitstringStatusListCredential with a valid LD proof and verifies that
// parseJSONLDStatusListCredential accepts it.
func TestIntegration_StatusListJSONLD_ValidProofAccepted(t *testing.T) {
	issuerDID := "did:web:issuer.statuslist.example.com"
	bundle := newIntegrationKeyBundle(t, issuerDID)

	// Build the credential JSON without proof.
	credBody := makeStatusListVCJSONLD(issuerDID, nil)
	var docMap map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(credBody), &docMap))

	// Create a valid proof using the test key bundle.
	signedProof := signCredentialDocument(t, docMap, bundle)

	// Re-build the body with the valid proof.
	docMap["proof"] = signedProof
	bodyWithProof, err := json.Marshal(docMap)
	require.NoError(t, err)

	cred, err := parseJSONLDStatusListCredential(bodyWithProof, bundle.checker)
	require.NoError(t, err, "JSON-LD status list credential with valid proof should be accepted")
	require.NotNil(t, cred)
}

// ---------------------------------------------------------------------------
// JSON-LD status list credential: no proof rejected
// ---------------------------------------------------------------------------

// TestIntegration_StatusListJSONLD_NoProofRejected submits a JSON-LD status
// list credential without a proof to parseJSONLDStatusListCredential with a
// checker and verifies it is rejected with ErrorStatusListJSONLDProofMissing.
func TestIntegration_StatusListJSONLD_NoProofRejected(t *testing.T) {
	issuerDID := "did:web:issuer.statuslist.example.com"
	bundle := newIntegrationKeyBundle(t, issuerDID)

	credBody := makeStatusListVCJSONLD(issuerDID, nil)

	cred, err := parseJSONLDStatusListCredential([]byte(credBody), bundle.checker)
	require.Error(t, err, "credential without proof should be rejected")
	assert.ErrorIs(t, err, ErrorStatusListJSONLDProofMissing)
	assert.Nil(t, cred)
}

// ---------------------------------------------------------------------------
// JSON-LD status list credential: invalid proof rejected
// ---------------------------------------------------------------------------

// TestIntegration_StatusListJSONLD_InvalidProofRejected submits a JSON-LD
// status list credential with a bogus proof and verifies it is rejected with
// ErrorStatusListJSONLDProofInvalid.
func TestIntegration_StatusListJSONLD_InvalidProofRejected(t *testing.T) {
	issuerDID := "did:web:issuer.statuslist.example.com"
	bundle := newIntegrationKeyBundle(t, issuerDID)

	bogusProof := map[string]interface{}{
		"type":               common.ProofTypeJsonWebSignature2020,
		"created":            "2024-01-01T00:00:00Z",
		"verificationMethod": bundle.verifMeth,
		"proofPurpose":       "assertionMethod",
		"jws":                "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	credBody := makeStatusListVCJSONLD(issuerDID, bogusProof)

	cred, err := parseJSONLDStatusListCredential([]byte(credBody), bundle.checker)
	require.Error(t, err, "credential with invalid proof should be rejected")
	assert.ErrorIs(t, err, ErrorStatusListJSONLDProofInvalid)
	assert.Nil(t, cred)
}

// ---------------------------------------------------------------------------
// JSON-LD status list credential: nil checker rejects (fail-closed)
// ---------------------------------------------------------------------------

// TestIntegration_StatusListJSONLD_NilCheckerRejects verifies the fail-closed
// behavior when no LDProofChecker is provided — even a credential with a proof
// is rejected.
func TestIntegration_StatusListJSONLD_NilCheckerRejects(t *testing.T) {
	bogusProof := map[string]interface{}{
		"type":               "JsonWebSignature2020",
		"created":            "2024-01-01T00:00:00Z",
		"verificationMethod": "did:web:issuer.example.com#key-1",
		"jws":                "eyJhbGciOiJFUzI1NiJ9..sig",
	}
	credBody := makeStatusListVCJSONLD("did:web:issuer.example.com", bogusProof)

	cred, err := parseJSONLDStatusListCredential([]byte(credBody), nil)
	require.Error(t, err, "nil checker must reject")
	assert.ErrorIs(t, err, ErrorStatusListJSONLDProofUnsupported)
	assert.Nil(t, cred)
}

// ---------------------------------------------------------------------------
// JSON-LD status list credential: empty proof array rejected
// ---------------------------------------------------------------------------

// TestIntegration_StatusListJSONLD_EmptyProofArrayRejected verifies that a
// credential with an empty proof array is rejected.
func TestIntegration_StatusListJSONLD_EmptyProofArrayRejected(t *testing.T) {
	issuerDID := "did:web:issuer.statuslist.example.com"
	bundle := newIntegrationKeyBundle(t, issuerDID)

	doc := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential", "BitstringStatusListCredential"},
		"issuer":   issuerDID,
		"proof":    []interface{}{},
		"credentialSubject": map[string]interface{}{
			"id":            "https://example.com/status/1#list",
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   "H4sIAAAAAAAA_2NgAAMAAAAEAAEAAAAA",
		},
	}
	body, _ := json.Marshal(doc)

	cred, err := parseJSONLDStatusListCredential(body, bundle.checker)
	require.Error(t, err, "empty proof array must be rejected")
	assert.ErrorIs(t, err, ErrorStatusListJSONLDProofMissing)
	assert.Nil(t, cred)
}

// ---------------------------------------------------------------------------
// JSON-LD status list: end-to-end via CachingStatusListClient.Fetch
// ---------------------------------------------------------------------------

// TestIntegration_StatusListFetch_JSONLDWithProof exercises the full Fetch path
// for a JSON-LD status list credential with a valid LD proof, served via an
// httptest server.
func TestIntegration_StatusListFetch_JSONLDWithProof(t *testing.T) {
	issuerDID := "did:web:issuer.statuslist.example.com"
	bundle := newIntegrationKeyBundle(t, issuerDID)

	// Build the credential body with a valid proof.
	credBody := makeStatusListVCJSONLD(issuerDID, nil)
	var docMap map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(credBody), &docMap))
	signedProof := signCredentialDocument(t, docMap, bundle)
	docMap["proof"] = signedProof
	bodyWithProof, err := json.Marshal(docMap)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bodyWithProof)
	}))
	defer srv.Close()

	client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry, nil, bundle.checker)
	cred, err := client.Fetch(srv.URL)
	require.NoError(t, err, "Fetch with valid JSON-LD proof should succeed")
	require.NotNil(t, cred)
}

// TestIntegration_StatusListFetch_JSONLDNoProofRejected exercises Fetch for a
// JSON-LD status list credential without a proof — it must be rejected even
// when an LDProofChecker is configured.
func TestIntegration_StatusListFetch_JSONLDNoProofRejected(t *testing.T) {
	issuerDID := "did:web:issuer.statuslist.example.com"
	bundle := newIntegrationKeyBundle(t, issuerDID)

	credBody := makeStatusListVCJSONLD(issuerDID, nil)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(credBody))
	}))
	defer srv.Close()

	client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry, nil, bundle.checker)
	cred, err := client.Fetch(srv.URL)
	require.Error(t, err, "Fetch with no-proof JSON-LD must be rejected")
	assert.ErrorIs(t, err, ErrorStatusListJSONLDProofMissing)
	assert.Nil(t, cred)
}

// ---------------------------------------------------------------------------
// Regression: JWT VP still works after LD-proof changes
// ---------------------------------------------------------------------------

// TestIntegration_JWTVP_RegressionStillWorks verifies that JWT-encoded VPs
// continue to be routed to the JWT path (not the JSON-LD path) after LD-proof
// changes. A fake JWT with an unresolvable DID fails at JWT verification,
// confirming the JWT routing path is intact.
func TestIntegration_JWTVP_RegressionStillWorks(t *testing.T) {
	fakeJWT := buildFakeJWT(map[string]interface{}{
		"iss": "did:web:holder.example.com",
		"vp": map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiablePresentation"},
		},
	})

	// A parser with both checkers configured should still route JWT tokens to the
	// JWT path based on token format detection.
	holderDID := "did:web:holder.example.com"
	bundle := newIntegrationKeyBundle(t, holderDID)

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: bundle.checker,
	}

	// JWT VP with fake signature fails at JWT verification, NOT at JSON-LD parsing.
	_, err := parser.ParsePresentation([]byte(fakeJWT))
	require.Error(t, err, "fake JWT should fail verification")
	// The key assertion: the error must NOT be ErrorUnsignedPresentation (that
	// would indicate the token was misrouted to the JSON-LD path).
	assert.False(t, errors.Is(err, ErrorUnsignedPresentation),
		"JWT VP must not be routed to JSON-LD path; got: %v", err)
}

// ---------------------------------------------------------------------------
// Regression: JWT status list still works
// ---------------------------------------------------------------------------

// TestIntegration_StatusListJWT_RegressionStillWorks verifies that JWT-encoded
// status list credentials continue to be accepted after LD-proof changes.
func TestIntegration_StatusListJWT_RegressionStillWorks(t *testing.T) {
	jwtBody := testStatusListVCJWT

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentTypeCredentialJWT)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jwtBody))
	}))
	defer srv.Close()

	// Even with an LDProofChecker configured, JWT credentials must be parsed via
	// the JWT path, not the JSON-LD path.
	holderDID := "did:web:issuer.regression.example.com"
	bundle := newIntegrationKeyBundle(t, holderDID)

	client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry, nil, bundle.checker)
	cred, err := client.Fetch(srv.URL)
	require.NoError(t, err, "JWT status list should continue to work")
	require.NotNil(t, cred)
}

// ---------------------------------------------------------------------------
// WarnLDPVCFormat: startup logging
// ---------------------------------------------------------------------------

// TestIntegration_WarnLDPVCFormat exercises WarnLDPVCFormat with various
// configurations to verify that the function iterates all configuration
// locations without panicking and correctly identifies ldp_vc references.
// The actual log output is not asserted (it goes to the global logger) — this
// test ensures the iteration logic is sound for all supported config locations.
func TestIntegration_WarnLDPVCFormat(t *testing.T) {
	tests := []struct {
		name     string
		services []configModel.ConfiguredService
	}{
		{
			name: "presentation_definition_format_ldp_vc",
			services: []configModel.ConfiguredService{{
				Id: "svc-pd",
				ServiceScopes: map[string]configModel.ScopeEntry{
					"default": {
						PresentationDefinition: &configModel.PresentationDefinition{
							Format: map[string]configModel.FormatObject{
								FormatLDPVC: {Alg: []string{"EdDSA"}},
							},
						},
					},
				},
			}},
		},
		{
			name: "input_descriptor_format_ldp_vc",
			services: []configModel.ConfiguredService{{
				Id: "svc-id",
				ServiceScopes: map[string]configModel.ScopeEntry{
					"scope1": {
						PresentationDefinition: &configModel.PresentationDefinition{
							InputDescriptors: []configModel.InputDescriptor{
								{
									Format: map[string]configModel.FormatObject{
										FormatLDPVC: {ProofType: []string{"JsonWebSignature2020"}},
									},
								},
							},
						},
					},
				},
			}},
		},
		{
			name: "dcql_credential_query_format_ldp_vc",
			services: []configModel.ConfiguredService{{
				Id: "svc-dcql",
				ServiceScopes: map[string]configModel.ScopeEntry{
					"default": {
						DCQL: &configModel.DCQL{
							Credentials: []configModel.CredentialQuery{
								{Format: FormatLDPVC},
							},
						},
					},
				},
			}},
		},
		{
			name: "jwt_vc_only_no_ldp_vc",
			services: []configModel.ConfiguredService{{
				Id: "svc-jwt",
				ServiceScopes: map[string]configModel.ScopeEntry{
					"default": {
						PresentationDefinition: &configModel.PresentationDefinition{
							Format: map[string]configModel.FormatObject{
								"jwt_vc": {Alg: []string{"ES256"}},
							},
						},
					},
				},
			}},
		},
		{
			name:     "empty_services",
			services: nil,
		},
		{
			name: "nil_presentation_definition_and_dcql",
			services: []configModel.ConfiguredService{{
				Id: "svc-nil",
				ServiceScopes: map[string]configModel.ScopeEntry{
					"default": {},
				},
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// WarnLDPVCFormat must not panic for any configuration variant.
			assert.NotPanics(t, func() {
				WarnLDPVCFormat(tc.services)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// hasLDPVCInScope unit tests (supports WarnLDPVCFormat)
// ---------------------------------------------------------------------------

// TestHasLDPVCInScope_DetectsAllLocations is a table-driven test that verifies
// hasLDPVCInScope correctly identifies ldp_vc in all supported config locations.
func TestHasLDPVCInScope_DetectsAllLocations(t *testing.T) {
	tests := []struct {
		name   string
		scope  configModel.ScopeEntry
		expect bool
	}{
		{
			name: "presentation_definition_format",
			scope: configModel.ScopeEntry{
				PresentationDefinition: &configModel.PresentationDefinition{
					Format: map[string]configModel.FormatObject{
						FormatLDPVC: {Alg: []string{"EdDSA"}},
					},
				},
			},
			expect: true,
		},
		{
			name: "input_descriptor_format",
			scope: configModel.ScopeEntry{
				PresentationDefinition: &configModel.PresentationDefinition{
					InputDescriptors: []configModel.InputDescriptor{
						{Format: map[string]configModel.FormatObject{FormatLDPVC: {}}},
					},
				},
			},
			expect: true,
		},
		{
			name: "dcql_credential_query_format",
			scope: configModel.ScopeEntry{
				DCQL: &configModel.DCQL{
					Credentials: []configModel.CredentialQuery{
						{Format: FormatLDPVC},
					},
				},
			},
			expect: true,
		},
		{
			name: "jwt_vc_only",
			scope: configModel.ScopeEntry{
				PresentationDefinition: &configModel.PresentationDefinition{
					Format: map[string]configModel.FormatObject{
						"jwt_vc": {Alg: []string{"ES256"}},
					},
				},
			},
			expect: false,
		},
		{
			name:   "nil_presentation_definition_and_dcql",
			scope:  configModel.ScopeEntry{},
			expect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hasLDPVCInScope(tc.scope)
			assert.Equal(t, tc.expect, got)
		})
	}
}
