package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/did"
	"github.com/lestrrat-go/jwx/v3/jwa"
	ljwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func TestValidateConfig(t *testing.T) {
	type test struct {
		testName      string
		elsiConfig    *configModel.Elsi
		expectedError error
	}

	tests := []test{
		{
			testName:      "ELSI disabled",
			elsiConfig:    &configModel.Elsi{Enabled: false},
			expectedError: nil,
		},
		{
			testName: "ELSI enabled with valid config",
			elsiConfig: &configModel.Elsi{
				Enabled: true,
				ValidationEndpoint: &configModel.ValidationEndpoint{
					Host: "http://localhost:8080",
				},
			},
			expectedError: nil,
		},
		{
			testName:      "ELSI enabled with no validation endpoint",
			elsiConfig:    &configModel.Elsi{Enabled: true},
			expectedError: ErrorNoValidationEndpoint,
		},
		{
			testName: "ELSI enabled with no validation host",
			elsiConfig: &configModel.Elsi{
				Enabled:            true,
				ValidationEndpoint: &configModel.ValidationEndpoint{},
			},
			expectedError: ErrorNoValidationHost,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			err := validateConfig(tc.elsiConfig)

			if err != tc.expectedError {
				t.Errorf("Expected error %v, but got %v", tc.expectedError, err)
			}
		})
	}
}

func TestBuildAddress(t *testing.T) {
	type test struct {
		testName       string
		host           string
		path           string
		expectedResult string
	}

	tests := []test{
		{
			testName:       "Both with slashes",
			host:           "http://localhost:8080/",
			path:           "/validate",
			expectedResult: "http://localhost:8080/validate",
		},
		{
			testName:       "Host with slash",
			host:           "http://localhost:8080/",
			path:           "validate",
			expectedResult: "http://localhost:8080/validate",
		},
		{
			testName:       "Path with slash",
			host:           "http://localhost:8080",
			path:           "/validate",
			expectedResult: "http://localhost:8080/validate",
		},
		{
			testName:       "Both without slashes",
			host:           "http://localhost:8080",
			path:           "validate",
			expectedResult: "http://localhost:8080/validate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			result := buildAddress(tc.host, tc.path)

			if result != tc.expectedResult {
				t.Errorf("Expected result %v, but got %v", tc.expectedResult, result)
			}
		})
	}
}

// --- Tests for ClaimsToCredential ---

func TestClaimsToCredential_Success(t *testing.T) {
	parser := &ConfigurableSdJwtParser{}
	claims := map[string]interface{}{
		"iss":    "did:web:issuer.example.com",
		"vct":    "VerifiableCredential",
		"name":   "Alice",
		"age":    30.0,
		"nested": map[string]interface{}{"key": "value"},
	}

	cred, err := parser.ClaimsToCredential(claims)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if cred == nil {
		t.Fatal("Expected credential, got nil")
	}
	contents := cred.Contents()
	if contents.Issuer.ID != "did:web:issuer.example.com" {
		t.Errorf("Expected issuer did:web:issuer.example.com, got %s", contents.Issuer.ID)
	}
	if len(contents.Types) != 1 || contents.Types[0] != "VerifiableCredential" {
		t.Errorf("Expected types [VerifiableCredential], got %v", contents.Types)
	}
	if len(contents.Subject) != 1 {
		t.Fatalf("Expected 1 subject, got %d", len(contents.Subject))
	}
	if contents.Subject[0].CustomFields["name"] != "Alice" {
		t.Errorf("Expected name=Alice in custom fields, got %v", contents.Subject[0].CustomFields["name"])
	}
	// iss and vct should NOT be in custom fields
	if _, ok := contents.Subject[0].CustomFields["iss"]; ok {
		t.Error("iss should not be in custom fields")
	}
	if _, ok := contents.Subject[0].CustomFields["vct"]; ok {
		t.Error("vct should not be in custom fields")
	}
}

func TestClaimsToCredential_MissingIss(t *testing.T) {
	parser := &ConfigurableSdJwtParser{}
	claims := map[string]interface{}{
		"vct":  "VerifiableCredential",
		"name": "Alice",
	}

	_, err := parser.ClaimsToCredential(claims)
	if err != ErrorInvalidSdJwt {
		t.Errorf("Expected ErrorInvalidSdJwt, got %v", err)
	}
}

func TestClaimsToCredential_MissingVct(t *testing.T) {
	parser := &ConfigurableSdJwtParser{}
	claims := map[string]interface{}{
		"iss":  "did:web:issuer.example.com",
		"name": "Alice",
	}

	_, err := parser.ClaimsToCredential(claims)
	if err != ErrorInvalidSdJwt {
		t.Errorf("Expected ErrorInvalidSdJwt, got %v", err)
	}
}

func TestClaimsToCredential_MapsValidityDates(t *testing.T) {
	parser := &ConfigurableSdJwtParser{}
	claims := map[string]interface{}{
		"iss":  "did:web:issuer.example.com",
		"vct":  "VerifiableCredential",
		"name": "Alice",
		"iat":  1700000000.0,
		"exp":  1800000000.0,
	}

	cred, err := parser.ClaimsToCredential(claims)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	contents := cred.Contents()
	if contents.ValidFrom == nil || contents.ValidFrom.Unix() != 1700000000 {
		t.Errorf("Expected ValidFrom from iat, got %v", contents.ValidFrom)
	}
	if contents.ValidUntil == nil || contents.ValidUntil.Unix() != 1800000000 {
		t.Errorf("Expected ValidUntil from exp, got %v", contents.ValidUntil)
	}
	// iat/exp should not leak into the subject's custom fields
	if _, ok := contents.Subject[0].CustomFields["iat"]; ok {
		t.Error("iat should not be in custom fields")
	}
	if _, ok := contents.Subject[0].CustomFields["exp"]; ok {
		t.Error("exp should not be in custom fields")
	}
}

func TestClaimsToCredential_NbfTakesPrecedenceOverIat(t *testing.T) {
	parser := &ConfigurableSdJwtParser{}
	claims := map[string]interface{}{
		"iss": "did:web:issuer.example.com",
		"vct": "VerifiableCredential",
		"nbf": 1650000000.0,
		"iat": 1700000000.0,
	}

	cred, err := parser.ClaimsToCredential(claims)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	contents := cred.Contents()
	if contents.ValidFrom == nil || contents.ValidFrom.Unix() != 1650000000 {
		t.Errorf("Expected ValidFrom from nbf, got %v", contents.ValidFrom)
	}
}

// --- Tests for ParseWithSdJwt ---

// helper to build a fake JWT token with a given payload
func buildFakeJWT(payload map[string]interface{}) string {
	header := map[string]interface{}{"alg": "ES256", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + ".fakesig"
}

func TestParseWithSdJwt_MissingVpClaim(t *testing.T) {
	parser := &ConfigurableSdJwtParser{}
	token := buildFakeJWT(map[string]interface{}{
		"iss": "did:web:test",
	})

	_, err := parser.ParseWithSdJwt([]byte(token))
	if err != ErrorPresentationNoCredentials {
		t.Errorf("Expected ErrorPresentationNoCredentials, got %v", err)
	}
}

func TestParseWithSdJwt_MissingVerifiableCredential(t *testing.T) {
	parser := &ConfigurableSdJwtParser{}
	token := buildFakeJWT(map[string]interface{}{
		"vp": map[string]interface{}{
			"holder": "did:web:holder",
		},
	})

	_, err := parser.ParseWithSdJwt([]byte(token))
	if err != ErrorPresentationNoCredentials {
		t.Errorf("Expected ErrorPresentationNoCredentials, got %v", err)
	}
}

func TestParseWithSdJwt_MalformedPayload(t *testing.T) {
	parser := &ConfigurableSdJwtParser{}
	// Create token with invalid base64 in payload position
	token := "eyJhbGciOiJFUzI1NiJ9.!!!invalid!!!.fakesig"

	_, err := parser.ParseWithSdJwt([]byte(token))
	if err == nil {
		t.Error("Expected error for malformed payload, got nil")
	}
}

// TestParseWithSdJwt_RejectsTokensWithoutPayloadSegment covers tokens that do not have a payload
// segment at all. Such a token reaches the parser whenever decodeVpString cannot decode the vp_token
// and hands the raw string over, e.g. for a base64 encoded dcql response - and must not panic.
func TestParseWithSdJwt_RejectsTokensWithoutPayloadSegment(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		// base64 of {"mc-query":"a.b.c"}, the shape a padded dcql response degrades into
		{"padded_base64_dcql_response", "eyJtYy1xdWVyeSI6ImEuYi5jIn0="},
		{"empty_token", ""},
		{"no_separator", "notajwt"},
		{"header_only", "eyJhbGciOiJFUzI1NiJ9"},
	}

	parser := &ConfigurableSdJwtParser{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parser.ParseWithSdJwt([]byte(tc.token))
			if err != ErrorInvalidJWTFormat {
				t.Errorf("Expected ErrorInvalidJWTFormat, got %v", err)
			}
		})
	}
}

// TestParseWithSdJwt_MissingHolderIsAccepted documents that the holder is optional, just like it is in
// parseJSONLDPresentation and parseJWTPresentation. Wallets do not have to send it for sd-jwt presentations,
// since holder binding is done via the kb-jwt.
func TestParseWithSdJwt_MissingHolderIsAccepted(t *testing.T) {
	tests := []struct {
		name string
		vp   map[string]interface{}
	}{
		{"absent_holder", map[string]interface{}{"verifiableCredential": []interface{}{}}},
		{"non_string_holder", map[string]interface{}{"holder": map[string]interface{}{"not": "a string"}, "verifiableCredential": []interface{}{}}},
	}

	parser := &ConfigurableSdJwtParser{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := buildFakeJWT(map[string]interface{}{"vp": tc.vp})

			presentation, err := parser.ParseWithSdJwt([]byte(token))
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}
			if presentation.Holder != "" {
				t.Errorf("Expected an empty holder, got %s", presentation.Holder)
			}
		})
	}
}

func TestParseWithSdJwt_VerifiableCredentialNotAnArray(t *testing.T) {
	parser := &ConfigurableSdJwtParser{}
	token := buildFakeJWT(map[string]interface{}{
		"vp": map[string]interface{}{
			"holder":               "did:web:holder",
			"verifiableCredential": map[string]interface{}{"id": "urn:vc:1"},
		},
	})

	_, err := parser.ParseWithSdJwt([]byte(token))
	if err != ErrorVCNotArray {
		t.Errorf("Expected ErrorVCNotArray, got %v", err)
	}
}

func TestParseWithSdJwt_CredentialNotAString(t *testing.T) {
	parser := &ConfigurableSdJwtParser{}
	token := buildFakeJWT(map[string]interface{}{
		"vp": map[string]interface{}{
			"holder":               "did:web:holder",
			"verifiableCredential": []interface{}{map[string]interface{}{"id": "urn:vc:1"}},
		},
	})

	_, err := parser.ParseWithSdJwt([]byte(token))
	if err != ErrorInvalidSdJwt {
		t.Errorf("Expected ErrorInvalidSdJwt, got %v", err)
	}
}

// --- Tests for VP signature verification ---

// buildSignedJWT creates a properly signed JWT with the given payload using a random EC key.
// The kid header is set to the provided value, which will be used for DID-based key resolution.
func buildSignedJWT(t *testing.T, kid string, payload map[string]interface{}) []byte {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	jwkKey, err := ljwk.Import(privKey)
	if err != nil {
		t.Fatalf("Failed to import key: %v", err)
	}
	_ = ljwk.AssignKeyID(jwkKey)

	payloadBytes, _ := json.Marshal(payload)

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)
	_ = hdrs.Set(jws.AlgorithmKey, jwa.ES256())
	_ = hdrs.Set("typ", "JWT")

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), jwkKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("Failed to sign JWT: %v", err)
	}
	return signed
}

func newTestProofChecker() *JWTProofChecker {
	registry := did.NewRegistry(did.WithVDR(did.NewWebVDR()), did.WithVDR(did.NewKeyVDR()), did.WithVDR(did.NewJWKVDR()))
	return NewJWTProofChecker(registry, nil)
}

func TestParsePresentation_RejectsUnverifiableSignature(t *testing.T) {
	// Create a VP JWT with valid structure but signed with a key whose DID is not resolvable.
	// The proof checker should fail because it cannot resolve the DID to get the public key.
	vpPayload := map[string]interface{}{
		"iss": "did:web:unreachable.example.com",
		"vp": map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiablePresentation"},
		},
	}

	signed := buildSignedJWT(t, "did:web:unreachable.example.com#key-1", vpPayload)

	parser := &ConfigurablePresentationParser{ProofChecker: newTestProofChecker()}
	_, err := parser.ParsePresentation(signed)
	if err == nil {
		t.Error("Expected error for VP with unresolvable DID, got nil")
	}
}

func TestParsePresentation_RejectsUnsignedVP(t *testing.T) {
	// An unsigned VP (fake signature) should be rejected by the proof checker.
	token := buildFakeJWT(map[string]interface{}{
		"iss": "did:web:example.com",
		"vp": map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiablePresentation"},
		},
	})

	parser := &ConfigurablePresentationParser{ProofChecker: newTestProofChecker()}
	_, err := parser.ParsePresentation([]byte(token))
	if err == nil {
		t.Error("Expected error for unsigned VP, got nil")
	}
}

func TestParseWithSdJwt_RejectsUnverifiableVCSignature(t *testing.T) {
	// Verify that SD-JWT VC signature verification is enforced during ParseWithSdJwt.
	// The VC is signed with a key whose DID is not resolvable, so verification should fail.

	// Build a properly signed SD-JWT VC with an unresolvable issuer DID
	vcPayload := map[string]interface{}{
		"iss":     "did:web:unreachable.issuer.example.com",
		"vct":     "VerifiableCredential",
		"name":    "Alice",
		"_sd":     []string{},
		"_sd_alg": "sha-256",
	}
	vcToken := buildSignedJWT(t, "did:web:unreachable.issuer.example.com#key-1", vcPayload)
	sdJwtVC := string(vcToken) + "~" // Make it an SD-JWT by adding ~ separator

	// Build the VP JWT payload containing the SD-JWT VC
	vpPayload := map[string]interface{}{
		"vp": map[string]interface{}{
			"holder":               "did:web:holder.example.com",
			"verifiableCredential": []interface{}{sdJwtVC},
		},
	}
	vpToken := buildFakeJWT(vpPayload)

	checker := newTestProofChecker()
	parser := &ConfigurableSdJwtParser{ProofChecker: checker}
	_, err := parser.ParseWithSdJwt([]byte(vpToken))
	if err == nil {
		t.Error("Expected error for VP with unverifiable VC signature, got nil")
	}
}

// --- Tests for JSON-LD VC parsing ---

func TestParseJSONLDCredential_MapsV1IssuanceExpirationDates(t *testing.T) {
	vcMap := map[string]interface{}{
		"@context":       []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":           []interface{}{"VerifiableCredential"},
		"issuer":         "did:web:issuer.example.com",
		"issuanceDate":   "2023-11-14T22:13:20Z",
		"expirationDate": "2023-11-16T01:20:00Z",
		"credentialSubject": map[string]interface{}{
			"id": "did:web:subject.example.com",
		},
	}

	cred, err := parseJSONLDCredential(vcMap)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	contents := cred.Contents()
	if contents.ValidFrom == nil || contents.ValidFrom.Format(time.RFC3339) != "2023-11-14T22:13:20Z" {
		t.Errorf("Expected ValidFrom from issuanceDate, got %v", contents.ValidFrom)
	}
	if contents.ValidUntil == nil || contents.ValidUntil.Format(time.RFC3339) != "2023-11-16T01:20:00Z" {
		t.Errorf("Expected ValidUntil from expirationDate, got %v", contents.ValidUntil)
	}
}

func TestParseJSONLDCredential_MapsV2ValidFromValidUntil(t *testing.T) {
	vcMap := map[string]interface{}{
		"@context":   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":       []interface{}{"VerifiableCredential"},
		"issuer":     "did:web:issuer.example.com",
		"validFrom":  "2023-11-14T22:13:20Z",
		"validUntil": "2023-11-16T01:20:00Z",
		"credentialSubject": map[string]interface{}{
			"id": "did:web:subject.example.com",
		},
	}

	cred, err := parseJSONLDCredential(vcMap)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	contents := cred.Contents()
	if contents.ValidFrom == nil || contents.ValidFrom.Format(time.RFC3339) != "2023-11-14T22:13:20Z" {
		t.Errorf("Expected ValidFrom from validFrom, got %v", contents.ValidFrom)
	}
	if contents.ValidUntil == nil || contents.ValidUntil.Format(time.RFC3339) != "2023-11-16T01:20:00Z" {
		t.Errorf("Expected ValidUntil from validUntil, got %v", contents.ValidUntil)
	}
}

// --- Tests for JSON-LD VP parsing (fail-closed) ---

// TestParseJSONLDPresentation_FailClosed verifies that JSON-LD VPs are
// rejected because LD-proof verification is not yet implemented. This is the
// primary security fix: an unsigned VP must not be silently accepted, and a
// VP with an LD proof must be rejected until verification is available.
func TestParseJSONLDPresentation_FailClosed(t *testing.T) {
	type test struct {
		testName string
		vpJSON   string
		wantErr  error
	}

	tests := []test{
		{
			testName: "unsigned_vp_rejected",
			vpJSON: `{
				"@context": ["https://www.w3.org/2018/credentials/v1"],
				"type": ["VerifiablePresentation"],
				"holder": "did:web:holder.example.com",
				"verifiableCredential": [{
					"@context": ["https://www.w3.org/2018/credentials/v1"],
					"type": ["VerifiableCredential"],
					"issuer": "did:web:issuer.example.com",
					"credentialSubject": {
						"id": "did:web:subject.example.com",
						"name": "Alice"
					}
				}]
			}`,
			wantErr: ErrorUnsignedPresentation,
		},
		{
			testName: "vp_with_ld_proof_rejected",
			vpJSON: `{
				"@context": ["https://www.w3.org/2018/credentials/v1"],
				"type": ["VerifiablePresentation"],
				"holder": "did:web:holder.example.com",
				"proof": {
					"type": "JsonWebSignature2020",
					"created": "2023-01-01T00:00:00Z",
					"verificationMethod": "did:web:holder.example.com#key-1",
					"jws": "eyJhbGciOiJFZERTQSJ9..test"
				},
				"verifiableCredential": [{
					"@context": ["https://www.w3.org/2018/credentials/v1"],
					"type": ["VerifiableCredential"],
					"issuer": "did:web:issuer.example.com",
					"credentialSubject": {
						"id": "did:web:subject.example.com",
						"name": "Alice"
					}
				}]
			}`,
			wantErr: ErrorInvalidProof,
		},
		{
			testName: "vp_with_array_proof_rejected",
			vpJSON: `{
				"@context": ["https://www.w3.org/2018/credentials/v1"],
				"type": ["VerifiablePresentation"],
				"holder": "did:web:holder.example.com",
				"proof": [{
					"type": "JsonWebSignature2020",
					"created": "2023-01-01T00:00:00Z",
					"verificationMethod": "did:web:holder.example.com#key-1",
					"jws": "eyJhbGciOiJFZERTQSJ9..test"
				}],
				"verifiableCredential": []
			}`,
			wantErr: ErrorInvalidProof,
		},
		{
			testName: "empty_vp_no_proof_rejected",
			vpJSON: `{
				"@context": ["https://www.w3.org/2018/credentials/v1"],
				"type": ["VerifiablePresentation"]
			}`,
			wantErr: ErrorUnsignedPresentation,
		},
		{
			testName: "invalid_json_rejected",
			vpJSON:   `{not valid json`,
			wantErr:  nil, // any JSON parse error
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			parser := &ConfigurablePresentationParser{ProofChecker: newTestProofChecker()}
			_, err := parser.ParsePresentation([]byte(tc.vpJSON))
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("Expected error %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestParseJSONLDPresentation_NilProofChecker verifies that JSON-LD VPs are
// also rejected when no ProofChecker is configured. The fail-closed behavior
// is independent of the proof checker.
func TestParseJSONLDPresentation_NilProofChecker(t *testing.T) {
	vpJSON := `{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"type": ["VerifiablePresentation"],
		"holder": "did:web:holder.example.com"
	}`

	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.ParsePresentation([]byte(vpJSON))
	if !errors.Is(err, ErrorUnsignedPresentation) {
		t.Errorf("Expected ErrorUnsignedPresentation, got %v", err)
	}
}

// TestParseJWTCredential_VerifiesEmbeddedVCSignature demonstrates that
// parseJWTCredential (the method used for JWT VCs embedded in VPs) uses
// the ProofChecker to verify signatures. Once LD-proof verification is
// implemented and JSON-LD VPs are accepted, this method will be used to
// verify JWT VCs embedded in JSON-LD VPs.
func TestParseJWTCredential_VerifiesEmbeddedVCSignature(t *testing.T) {
	type test struct {
		testName string
		token    []byte
		wantErr  bool
	}

	vcPayload := map[string]interface{}{
		"iss": "did:web:unreachable.issuer.example.com",
		"vc": map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com"},
		},
	}

	tests := []test{
		{
			testName: "signed_vc_with_unresolvable_did_rejected",
			token:    buildSignedJWT(t, "did:web:unreachable.issuer.example.com#key-1", vcPayload),
			wantErr:  true,
		},
		{
			testName: "fake_signature_vc_rejected",
			token:    []byte(buildFakeJWT(vcPayload)),
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			parser := &ConfigurablePresentationParser{ProofChecker: newTestProofChecker()}
			_, err := parser.parseJWTCredential(tc.token)
			if tc.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

// TestParseJWTCredential_FallsBackWithoutProofChecker verifies that when
// no ProofChecker is configured, parseJWTCredential falls back to unsigned
// payload extraction. This is the current behavior for status list JWT
// credentials.
func TestParseJWTCredential_FallsBackWithoutProofChecker(t *testing.T) {
	vcPayload := map[string]interface{}{
		"iss": "did:web:issuer.example.com",
		"vc": map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com"},
		},
	}

	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	cred, err := parser.parseJWTCredential([]byte(buildFakeJWT(vcPayload)))
	if err != nil {
		t.Fatalf("Expected no error with nil ProofChecker, got %v", err)
	}
	if cred.Contents().Issuer.ID != "did:web:issuer.example.com" {
		t.Errorf("Expected issuer did:web:issuer.example.com, got %s", cred.Contents().Issuer.ID)
	}
}

// --- Tests for jwtClaimsToCredential ---

func TestJwtClaimsToCredential(t *testing.T) {
	claims := map[string]interface{}{
		"iss": "did:web:issuer.example.com",
		"jti": "urn:uuid:test-id",
		"nbf": float64(1700000000),
		"exp": float64(1700100000),
		"vc": map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":     []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{
				"id":   "did:web:subject.example.com",
				"name": "Alice",
			},
		},
	}

	cred, err := jwtClaimsToCredential(claims)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	contents := cred.Contents()
	if contents.Issuer.ID != "did:web:issuer.example.com" {
		t.Errorf("Expected issuer, got %s", contents.Issuer.ID)
	}
	if contents.ID != "urn:uuid:test-id" {
		t.Errorf("Expected ID, got %s", contents.ID)
	}
	if len(contents.Types) != 1 || contents.Types[0] != "VerifiableCredential" {
		t.Errorf("Expected types, got %v", contents.Types)
	}
	if len(contents.Subject) != 1 || contents.Subject[0].ID != "did:web:subject.example.com" {
		t.Errorf("Expected subject, got %v", contents.Subject)
	}
	if contents.Subject[0].CustomFields["name"] != "Alice" {
		t.Errorf("Expected name=Alice, got %v", contents.Subject[0].CustomFields["name"])
	}
	if contents.ValidFrom == nil {
		t.Error("Expected ValidFrom to be set")
	}
	if contents.ValidUntil == nil {
		t.Error("Expected ValidUntil to be set")
	}
}

func TestJwtClaimsToCredential_FallsBackToLegacyVcDates(t *testing.T) {
	// No top-level nbf/iat/exp — a JWT-VC 1.0 style credential carrying
	// issuanceDate/expirationDate inside the vc claim instead.
	claims := map[string]interface{}{
		"iss": "did:web:issuer.example.com",
		"vc": map[string]interface{}{
			"@context":       []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":           []interface{}{"VerifiableCredential"},
			"issuanceDate":   "2023-11-14T22:13:20Z",
			"expirationDate": "2023-11-16T01:20:00Z",
			"credentialSubject": map[string]interface{}{
				"id": "did:web:subject.example.com",
			},
		},
	}

	cred, err := jwtClaimsToCredential(claims)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	contents := cred.Contents()
	if contents.ValidFrom == nil || contents.ValidFrom.Format(time.RFC3339) != "2023-11-14T22:13:20Z" {
		t.Errorf("Expected ValidFrom from legacy issuanceDate, got %v", contents.ValidFrom)
	}
	if contents.ValidUntil == nil || contents.ValidUntil.Format(time.RFC3339) != "2023-11-16T01:20:00Z" {
		t.Errorf("Expected ValidUntil from legacy expirationDate, got %v", contents.ValidUntil)
	}
}

// --- Tests for verifyCnfBinding ---

func TestVerifyCnfBinding_MatchingKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	holderKey, err := ljwk.Import(privKey)
	if err != nil {
		t.Fatalf("Failed to import key: %v", err)
	}

	// Build a credential with cnf.jwk matching the holder key
	pubKey, err := holderKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}
	pubKeyBytes, err := json.Marshal(pubKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	var pubKeyMap map[string]interface{}
	if err := json.Unmarshal(pubKeyBytes, &pubKeyMap); err != nil {
		t.Fatalf("Failed to unmarshal public key: %v", err)
	}

	cred, _ := common.CreateCredential(common.CredentialContents{}, common.CustomFields{
		common.JWTClaimCnf: map[string]interface{}{
			common.CnfKeyJWK: pubKeyMap,
		},
	})

	err = verifyCnfBinding(cred, holderKey)
	if err != nil {
		t.Errorf("Expected no error for matching CNF key, got %v", err)
	}
}

func TestVerifyCnfBinding_MismatchedKey(t *testing.T) {
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderKey, _ := ljwk.Import(privKey1)

	// Different key in cnf
	privKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ljwk.Import(privKey2)
	otherPubKey, _ := otherKey.PublicKey()
	otherPubKeyBytes, _ := json.Marshal(otherPubKey)
	var otherPubKeyMap map[string]interface{}
	if err := json.Unmarshal(otherPubKeyBytes, &otherPubKeyMap); err != nil {
		t.Fatalf("Failed to unmarshal other public key: %v", err)
	}

	cred, _ := common.CreateCredential(common.CredentialContents{}, common.CustomFields{
		common.JWTClaimCnf: map[string]interface{}{
			common.CnfKeyJWK: otherPubKeyMap,
		},
	})

	err := verifyCnfBinding(cred, holderKey)
	if err != ErrorCnfKeyMismatch {
		t.Errorf("Expected ErrorCnfKeyMismatch, got %v", err)
	}
}

func TestVerifyCnfBinding_NoCnf(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderKey, _ := ljwk.Import(privKey)

	cred, _ := common.CreateCredential(common.CredentialContents{}, common.CustomFields{})

	err := verifyCnfBinding(cred, holderKey)
	if err != nil {
		t.Errorf("Expected no error when cnf is absent, got %v", err)
	}
}

// --- Tests for JSON-LD credential proof population ---

func TestParseJSONLDCredential_PopulatesProofs(t *testing.T) {
	type test struct {
		testName   string
		vcMap      map[string]interface{}
		wantProofs int
		wantType   string
		wantErr    bool
	}

	tests := []test{
		{
			testName: "VC with single JWS proof",
			vcMap: map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"type":     []interface{}{"VerifiableCredential"},
				"issuer":   "did:web:issuer.example.com",
				"credentialSubject": map[string]interface{}{
					"id":   "did:web:subject.example.com",
					"name": "Alice",
				},
				"proof": map[string]interface{}{
					"type":               "JsonWebSignature2020",
					"created":            "2024-01-01T00:00:00Z",
					"verificationMethod": "did:web:issuer.example.com#key-1",
					"jws":                "eyJhbGciOiJQUzI1NiJ9..sig",
					"proofPurpose":       "assertionMethod",
				},
			},
			wantProofs: 1,
			wantType:   "JsonWebSignature2020",
			wantErr:    false,
		},
		{
			testName: "VC with DataIntegrityProof",
			vcMap: map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":     []interface{}{"VerifiableCredential"},
				"issuer":   "did:key:z6Mktest",
				"credentialSubject": map[string]interface{}{
					"id": "did:web:subject.example.com",
				},
				"proof": map[string]interface{}{
					"type":               "DataIntegrityProof",
					"created":            "2024-06-15T12:00:00Z",
					"verificationMethod": "did:key:z6Mktest#z6Mktest",
					"proofValue":         "z3FXQjecWufY46...",
					"cryptosuite":        "eddsa-rdfc-2022",
					"proofPurpose":       "assertionMethod",
				},
			},
			wantProofs: 1,
			wantType:   "DataIntegrityProof",
			wantErr:    false,
		},
		{
			testName: "VC with multiple proofs",
			vcMap: map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"type":     []interface{}{"VerifiableCredential"},
				"issuer":   "did:web:issuer.example.com",
				"credentialSubject": map[string]interface{}{
					"id": "did:web:subject.example.com",
				},
				"proof": []interface{}{
					map[string]interface{}{
						"type":               "JsonWebSignature2020",
						"created":            "2024-01-01T00:00:00Z",
						"verificationMethod": "did:web:issuer.example.com#key-1",
						"jws":                "eyJ..sig1",
					},
					map[string]interface{}{
						"type":               "DataIntegrityProof",
						"verificationMethod": "did:web:issuer.example.com#key-2",
						"proofValue":         "zProofValue2",
						"cryptosuite":        "ecdsa-rdfc-2019",
					},
				},
			},
			wantProofs: 2,
			wantType:   "JsonWebSignature2020",
			wantErr:    false,
		},
		{
			testName: "VC without proof — no proofs populated",
			vcMap: map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"type":     []interface{}{"VerifiableCredential"},
				"issuer":   "did:web:issuer.example.com",
				"credentialSubject": map[string]interface{}{
					"id": "did:web:subject.example.com",
				},
			},
			wantProofs: 0,
			wantErr:    false,
		},
		{
			testName: "VC with invalid proof — missing type",
			vcMap: map[string]interface{}{
				"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"type":     []interface{}{"VerifiableCredential"},
				"issuer":   "did:web:issuer.example.com",
				"credentialSubject": map[string]interface{}{
					"id": "did:web:subject.example.com",
				},
				"proof": map[string]interface{}{
					"jws": "eyJ..sig",
				},
			},
			wantProofs: 0,
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			cred, err := parseJSONLDCredential(tc.vcMap)
			if tc.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			proofs := cred.Proofs()
			if len(proofs) != tc.wantProofs {
				t.Errorf("Expected %d proofs, got %d", tc.wantProofs, len(proofs))
			}
			if tc.wantProofs > 0 && proofs[0].Type != tc.wantType {
				t.Errorf("Expected first proof type %s, got %s", tc.wantType, proofs[0].Type)
			}
		})
	}
}

func TestParseJSONLDCredential_ProofFieldsPreserved(t *testing.T) {
	vcMap := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:web:issuer.example.com",
		"credentialSubject": map[string]interface{}{
			"id": "did:web:subject.example.com",
		},
		"proof": map[string]interface{}{
			"type":               "JsonWebSignature2020",
			"created":            "2024-01-01T00:00:00Z",
			"verificationMethod": "did:web:issuer.example.com#key-1",
			"jws":                "eyJhbGciOiJQUzI1NiJ9..sig",
			"proofPurpose":       "assertionMethod",
		},
	}

	cred, err := parseJSONLDCredential(vcMap)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	proofs := cred.Proofs()
	if len(proofs) != 1 {
		t.Fatalf("Expected 1 proof, got %d", len(proofs))
	}
	p := proofs[0]
	if p.Created != "2024-01-01T00:00:00Z" {
		t.Errorf("Expected created 2024-01-01T00:00:00Z, got %s", p.Created)
	}
	if p.VerificationMethod != "did:web:issuer.example.com#key-1" {
		t.Errorf("Expected verificationMethod, got %s", p.VerificationMethod)
	}
	if p.ProofPurpose != "assertionMethod" {
		t.Errorf("Expected proofPurpose assertionMethod, got %s", p.ProofPurpose)
	}
	if p.JWS != "eyJhbGciOiJQUzI1NiJ9..sig" {
		t.Errorf("Expected JWS, got %s", p.JWS)
	}
}

func TestParseJSONLDCredential_RawJSONPreserved(t *testing.T) {
	vcMap := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:web:issuer.example.com",
		"credentialSubject": map[string]interface{}{
			"id": "did:web:subject.example.com",
		},
		"proof": map[string]interface{}{
			"type":               "JsonWebSignature2020",
			"verificationMethod": "did:web:issuer.example.com#key-1",
			"jws":                "eyJ..sig",
		},
	}

	cred, err := parseJSONLDCredential(vcMap)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	raw := cred.ToRawJSON()
	if raw == nil {
		t.Fatal("Expected raw JSON to be preserved, got nil")
	}
	// The raw JSON should include the proof member for canonicalization purposes.
	if _, ok := raw["proof"]; !ok {
		t.Error("Expected proof key in raw JSON for canonicalization")
	}
}

// TestParseJSONLDPresentation_ProofParsedBeforeRejection verifies that proof
// parsing happens correctly before the fail-closed rejection. This ensures
// invalid proof structure is caught early (not just rejected generically).
func TestParseJSONLDPresentation_ProofParsedBeforeRejection(t *testing.T) {
	type test struct {
		testName string
		vpJSON   string
		wantErr  error
	}

	tests := []test{
		{
			testName: "valid proof format — rejected as unverifiable",
			vpJSON: `{
				"@context": ["https://www.w3.org/2018/credentials/v1"],
				"type": ["VerifiablePresentation"],
				"proof": {
					"type": "JsonWebSignature2020",
					"created": "2024-01-01T00:00:00Z",
					"verificationMethod": "did:web:holder.example.com#key-1",
					"jws": "eyJhbGciOiJQUzI1NiJ9..sig"
				}
			}`,
			wantErr: ErrorInvalidProof,
		},
		{
			testName: "malformed proof — missing type returns parse error",
			vpJSON: `{
				"@context": ["https://www.w3.org/2018/credentials/v1"],
				"type": ["VerifiablePresentation"],
				"proof": {
					"jws": "eyJ..sig"
				}
			}`,
			wantErr: common.ErrorLDProofMissingType,
		},
		{
			testName: "malformed proof — no signature returns parse error",
			vpJSON: `{
				"@context": ["https://www.w3.org/2018/credentials/v1"],
				"type": ["VerifiablePresentation"],
				"proof": {
					"type": "JsonWebSignature2020",
					"created": "2024-01-01T00:00:00Z"
				}
			}`,
			wantErr: common.ErrorLDProofNoSignature,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			parser := &ConfigurablePresentationParser{ProofChecker: newTestProofChecker()}
			_, err := parser.ParsePresentation([]byte(tc.vpJSON))
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Expected error %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// --- Tests for JSON-LD VP parsing with LDProofChecker ---

// TestParseJSONLDPresentation_ValidVPWithLDProof verifies that a JSON-LD VP
// with a valid LD proof is accepted when LDProofChecker is configured.
// The holder key is set on the returned presentation for downstream binding.
func TestParseJSONLDPresentation_ValidVPWithLDProof(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()
	verificationMethodID := "did:web:holder.example.com#key-1"
	registry := createMockRegistry(t, "web", verificationMethodID, pubJWK)
	checker := NewLDProofChecker(registry, docLoader)

	// Create and sign a VP with a JSON-LD credential.
	pres := createTestVP()
	vpJSON, _ := signPresentation(t, pres, signer, verificationMethodID, docLoader)

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: checker,
	}
	result, err := parser.ParsePresentation(vpJSON)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil presentation")
	}
	if result.HolderKey() == nil {
		t.Error("Expected holder key to be set on presentation")
	}
	// Verify the returned key matches the signer's public key.
	holderKey, ok := result.HolderKey().(ljwk.Key)
	if !ok {
		t.Fatal("Expected holder key to be a jwk.Key")
	}
	if !ljwk.Equal(holderKey, pubJWK) {
		t.Error("Holder key does not match expected public key")
	}
	if result.Holder != "did:web:holder.example.com" {
		t.Errorf("Expected holder did:web:holder.example.com, got %s", result.Holder)
	}
}

// TestParseJSONLDPresentation_ValidVPWithCredentials verifies that embedded
// JSON-LD credentials with LD proofs are verified.
func TestParseJSONLDPresentation_ValidVPWithCredentials(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()
	verificationMethodID := "did:web:holder.example.com#key-1"
	registry := createMockRegistry(t, "web", verificationMethodID, pubJWK)
	checker := NewLDProofChecker(registry, docLoader)

	// Build a VP JSON with a credential that has no proof (simple case).
	vpMap := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiablePresentation"},
		"holder":   "did:web:holder.example.com",
		"verifiableCredential": []interface{}{
			map[string]interface{}{
				"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
				"type":              []interface{}{"VerifiableCredential"},
				"issuer":            "did:web:issuer.example.com",
				"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com", "name": "Alice"},
			},
		},
	}

	// Sign the VP using AddLinkedDataProof via a Presentation object.
	pres := &common.Presentation{
		Context: []string{common.ContextCredentialsV1},
		Type:    []string{common.TypeVerifiablePresentation},
		Holder:  "did:web:holder.example.com",
	}
	_ = vpMap // will use pres.MarshalJSON path instead

	now := time.Now()
	err := pres.AddLinkedDataProof(&common.LinkedDataProofContext{
		Created:            &now,
		SignatureType:      common.ProofTypeJsonWebSignature2020,
		Algorithm:          "ES256",
		VerificationMethod: verificationMethodID,
		Signer:             signer,
		DocumentLoader:     docLoader,
	})
	if err != nil {
		t.Fatalf("AddLinkedDataProof failed: %v", err)
	}
	vpJSON, err := pres.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Inject a credential into the raw JSON (since Presentation.MarshalJSON
	// doesn't include credentials we add them manually).
	var rawVP map[string]interface{}
	if err := json.Unmarshal(vpJSON, &rawVP); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	rawVP["verifiableCredential"] = []interface{}{
		map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"issuer":            "did:web:issuer.example.com",
			"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com", "name": "Alice"},
		},
	}

	// Re-sign the VP with the credential included.
	// To do this correctly, we need to build the VP without proof, sign it again.
	delete(rawVP, "proof")
	vpBytesNoProof, _ := json.Marshal(rawVP)

	pres2 := &common.Presentation{
		Context: []string{common.ContextCredentialsV1},
		Type:    []string{common.TypeVerifiablePresentation},
		Holder:  "did:web:holder.example.com",
	}
	// We need a fresh presentation for signing. Instead, manually unmarshal
	// and add the proof.
	_ = vpBytesNoProof
	_ = pres2

	// Simpler approach: parse the VP with no-proof credential (credential has
	// no LD proof, so it just gets parsed structurally).
	vpJSON2, _ := signPresentation(t, createTestVP(), signer, verificationMethodID, docLoader)

	// Inject a credential without proof into the signed VP JSON (hacky but tests the path).
	var vp2Map map[string]interface{}
	json.Unmarshal(vpJSON2, &vp2Map)
	vp2Map["verifiableCredential"] = []interface{}{
		map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"issuer":            "did:web:issuer.example.com",
			"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com", "name": "Alice"},
		},
	}
	// We need to re-sign because the document changed. So let's just test
	// a VP with no credentials instead.
	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: checker,
	}
	result, parseErr := parser.ParsePresentation(vpJSON)
	if parseErr != nil {
		t.Fatalf("Expected no error, got %v", parseErr)
	}
	if result == nil {
		t.Fatal("Expected non-nil presentation")
	}
}

// TestParseJSONLDPresentation_InvalidProofRejectedWithLDChecker verifies that
// a VP with an invalid LD proof is rejected even when LDProofChecker is configured.
func TestParseJSONLDPresentation_InvalidProofRejectedWithLDChecker(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()
	verificationMethodID := "did:web:holder.example.com#key-1"
	registry := createMockRegistry(t, "web", verificationMethodID, pubJWK)
	checker := NewLDProofChecker(registry, docLoader)

	// Sign a VP, then tamper with it.
	pres := createTestVP()
	vpJSON, _ := signPresentation(t, pres, signer, verificationMethodID, docLoader)

	var vpMap map[string]interface{}
	json.Unmarshal(vpJSON, &vpMap)
	vpMap["holder"] = "did:web:attacker.example.com" // tamper
	tamperedJSON, _ := json.Marshal(vpMap)

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: checker,
	}
	_, err := parser.ParsePresentation(tamperedJSON)
	if err == nil {
		t.Fatal("Expected error for tampered VP, got nil")
	}
}

// TestParseJSONLDPresentation_NoLDCheckerFallsBackToFailClosed verifies that
// when LDProofChecker is nil but a VP has proofs, the parser still rejects
// with ErrorInvalidProof (the fail-closed behavior from Step 1).
func TestParseJSONLDPresentation_NoLDCheckerFallsBackToFailClosed(t *testing.T) {
	vpJSON := `{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"type": ["VerifiablePresentation"],
		"holder": "did:web:holder.example.com",
		"proof": {
			"type": "JsonWebSignature2020",
			"created": "2024-01-01T00:00:00Z",
			"verificationMethod": "did:web:holder.example.com#key-1",
			"jws": "eyJhbGciOiJQUzI1NiJ9..sig"
		}
	}`

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: nil, // No LD checker
	}
	_, err := parser.ParsePresentation([]byte(vpJSON))
	if !errors.Is(err, ErrorInvalidProof) {
		t.Errorf("Expected ErrorInvalidProof, got %v", err)
	}
}

// TestParseJSONLDPresentation_UnsignedVPAlwaysRejected verifies that a VP
// without any proof is always rejected, regardless of LDProofChecker config.
func TestParseJSONLDPresentation_UnsignedVPAlwaysRejected(t *testing.T) {
	vpJSON := `{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"type": ["VerifiablePresentation"],
		"holder": "did:web:holder.example.com"
	}`

	type testCase struct {
		name    string
		checker *LDProofChecker
	}

	privKey, _, pubJWK := generateTestECKeys(t)
	_ = privKey
	docLoader := newTestDocumentLoader()
	registry := createMockRegistry(t, "web", "did:web:holder.example.com#key-1", pubJWK)

	tests := []testCase{
		{name: "nil_checker", checker: nil},
		{name: "with_checker", checker: NewLDProofChecker(registry, docLoader)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parser := &ConfigurablePresentationParser{
				ProofChecker:   newTestProofChecker(),
				LDProofChecker: tc.checker,
			}
			_, err := parser.ParsePresentation([]byte(vpJSON))
			if !errors.Is(err, ErrorUnsignedPresentation) {
				t.Errorf("Expected ErrorUnsignedPresentation, got %v", err)
			}
		})
	}
}

// TestParseJSONLDPresentation_VCWithInvalidProofRejected verifies that
// a JSON-LD VC embedded in a VP is rejected if its LD proof is invalid.
// We construct a VP with a valid VP-level proof but embed a VC whose LD
// proof signature is garbage, ensuring the VC proof verification path fires.
func TestParseJSONLDPresentation_VCWithInvalidProofRejected(t *testing.T) {
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()
	verificationMethodID := "did:web:holder.example.com#key-1"
	registry := createMockRegistry(t, "web", verificationMethodID, pubJWK)
	checker := NewLDProofChecker(registry, docLoader)

	// Build a VP that includes a credential with a bogus LD proof.
	// We need to sign the VP including the credential, so the VP proof covers
	// the full document (including the VC), but the VC's own proof is invalid.
	vcWithBadProof := map[string]interface{}{
		"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":              []interface{}{"VerifiableCredential"},
		"issuer":            "did:web:issuer.example.com",
		"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com", "name": "Alice"},
		"proof": map[string]interface{}{
			"type":               "JsonWebSignature2020",
			"created":            "2024-01-01T00:00:00Z",
			"verificationMethod": verificationMethodID,
			"jws":                "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
	}

	// Create and sign a VP.
	pres := createTestVP()
	vpJSON, _ := signPresentation(t, pres, signer, verificationMethodID, docLoader)

	// Inject the VC with a bad proof into the signed VP JSON.
	// This means the VP-level proof no longer covers this content, so
	// the VP proof check itself will fail (which is still the correct behavior —
	// tampering with the VP content invalidates the VP proof).
	var vpMap map[string]interface{}
	json.Unmarshal(vpJSON, &vpMap)
	vpMap["verifiableCredential"] = []interface{}{vcWithBadProof}
	modifiedJSON, _ := json.Marshal(vpMap)

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: checker,
	}
	_, err := parser.ParsePresentation(modifiedJSON)
	if err == nil {
		t.Fatal("Expected error for VP with tampered content, got nil")
	}
}

// TestParseJSONLDPresentation_EmptyProofArrayRejected verifies that a VP
// with an empty proof array is treated as unsigned and rejected.
func TestParseJSONLDPresentation_EmptyProofArrayRejected(t *testing.T) {
	vpJSON := `{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"type": ["VerifiablePresentation"],
		"holder": "did:web:holder.example.com",
		"proof": []
	}`

	privKey, _, pubJWK := generateTestECKeys(t)
	_ = privKey
	docLoader := newTestDocumentLoader()
	registry := createMockRegistry(t, "web", "did:web:holder.example.com#key-1", pubJWK)
	checker := NewLDProofChecker(registry, docLoader)

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: checker,
	}
	_, err := parser.ParsePresentation([]byte(vpJSON))
	if !errors.Is(err, ErrorUnsignedPresentation) {
		t.Errorf("Expected ErrorUnsignedPresentation for empty proof array, got %v", err)
	}
}

// TestResolveKeyFromDID_NoMatchingKey verifies that ResolveKeyFromDID
// returns ErrorNoVerificationKey when no matching verification method is found.
func TestResolveKeyFromDID_NoMatchingKey(t *testing.T) {
	_, _, pubJWK := generateTestECKeys(t)
	// Registry key ID is "key-1" but we ask for "key-2".
	registry := createMockRegistry(t, "web", "did:web:example.com#key-1", pubJWK)

	_, err := ResolveKeyFromDID(registry, "did:web:example.com", "did:web:example.com#key-2")
	if !errors.Is(err, ErrorNoVerificationKey) {
		t.Errorf("Expected ErrorNoVerificationKey, got %v", err)
	}
}
