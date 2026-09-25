package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/lestrrat-go/jwx/v3/jwa"
	ljwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	return NewJWTProofChecker(registry)
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

// TestParseJSONLDPresentation_ValidVPWithCredentials verifies that a JSON-LD
// VP carrying a signed JSON-LD credential is accepted and that the embedded
// credential's own Linked Data Proof is verified.
func TestParseJSONLDPresentation_ValidVPWithCredentials(t *testing.T) {
	docLoader := newTestDocumentLoader()

	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)
	holderSigner := &testES256Signer{key: holderPrivKey}

	issuerPrivKey, _, issuerPubJWK := generateTestECKeys(t)
	issuerSigner := &testES256Signer{key: issuerPrivKey}

	registry := createMultiKeyRegistry(t, map[string]ljwk.Key{
		testHolderKeyID: holderPubJWK,
		testIssuerKeyID: issuerPubJWK,
	})
	checker := NewLDProofChecker(registry, docLoader)

	signedVC := signTestCredential(t, testIssuerDID, issuerSigner, testIssuerKeyID, docLoader)
	vpJSON := signVPWithCredentials(t, holderSigner, testHolderKeyID, docLoader,
		[]interface{}{signedVC}, ldProofTestOptions{proofPurpose: common.ProofPurposeAuthentication})

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: checker,
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err, "a VP with a correctly signed credential must be accepted")
	require.NotNil(t, result)
	require.Len(t, result.Credentials(), 1, "the embedded credential must be part of the presentation")
	assert.Equal(t, testIssuerDID, result.Credentials()[0].Contents().Issuer.ID)
	assert.NotNil(t, result.HolderKey(), "holder key must be populated from the VP proof")
}

// TestParseJSONLDPresentation_CredentialProofsAreEnforced covers the negative
// cases around embedded JSON-LD credentials: an unsigned credential, a
// credential whose proof was made by somebody other than the claimed issuer,
// and a credential whose content was changed after signing.
func TestParseJSONLDPresentation_CredentialProofsAreEnforced(t *testing.T) {
	docLoader := newTestDocumentLoader()

	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)
	holderSigner := &testES256Signer{key: holderPrivKey}

	issuerPrivKey, _, issuerPubJWK := generateTestECKeys(t)
	issuerSigner := &testES256Signer{key: issuerPrivKey}

	const attackerDID = "did:web:attacker.example.com"
	const attackerKeyID = attackerDID + "#key-1"
	attackerPrivKey, _, attackerPubJWK := generateTestECKeys(t)
	attackerSigner := &testES256Signer{key: attackerPrivKey}

	registry := createMultiKeyRegistry(t, map[string]ljwk.Key{
		testHolderKeyID: holderPubJWK,
		testIssuerKeyID: issuerPubJWK,
		attackerKeyID:   attackerPubJWK,
	})
	checker := NewLDProofChecker(registry, docLoader)

	// A credential signed by the attacker but claiming the trusted issuer.
	forgedVC := createTestVC(testIssuerDID)
	forgedVC[common.VPKeyProof] = signDocument(t, forgedVC, attackerSigner, attackerKeyID, docLoader,
		ldProofTestOptions{proofPurpose: common.ProofPurposeAssertionMethod})

	// A properly signed credential whose subject was swapped afterwards.
	tamperedVC := signTestCredential(t, testIssuerDID, issuerSigner, testIssuerKeyID, docLoader)
	tamperedVC[common.VCKeyCredentialSubject] = map[string]interface{}{
		common.JSONLDKeyID: "did:web:somebody-else.example.com",
	}

	// A correctly signed credential that was issued to somebody other than
	// the holder of the presentation — a replay of another subject's
	// credential inside a VP the attacker signed themselves.
	foreignSubjectVC := createTestVCForSubject(testIssuerDID, testForeignSubjectDID)
	foreignSubjectVC[common.VPKeyProof] = signDocument(t, foreignSubjectVC, issuerSigner, testIssuerKeyID, docLoader,
		ldProofTestOptions{proofPurpose: common.ProofPurposeAssertionMethod})

	tests := []struct {
		name       string
		credential map[string]interface{}
		wantErrIs  error
	}{
		{
			name:       "unsigned_credential_rejected",
			credential: createTestVC(testIssuerDID),
			wantErrIs:  ErrorUnsignedCredential,
		},
		{
			name:       "credential_signed_by_other_than_issuer_rejected",
			credential: forgedVC,
			wantErrIs:  ErrorProofIssuerMismatch,
		},
		{
			name:       "tampered_credential_rejected",
			credential: tamperedVC,
			wantErrIs:  common.ErrorLDProofVerifySignature,
		},
		{
			name:       "credential_issued_to_another_subject_rejected",
			credential: foreignSubjectVC,
			wantErrIs:  ErrorHolderSubjectMismatch,
		},
	}

	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: checker,
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vpJSON := signVPWithCredentials(t, holderSigner, testHolderKeyID, docLoader,
				[]interface{}{tc.credential}, ldProofTestOptions{proofPurpose: common.ProofPurposeAuthentication})

			_, err := parser.ParsePresentation(vpJSON)
			require.Error(t, err, "the credential must not be accepted")
			assert.True(t, errors.Is(err, tc.wantErrIs), "expected %v, got %v", tc.wantErrIs, err)
		})
	}
}

// TestParseJWTPresentation_EmbeddedJSONLDCredentialIsVerified closes the
// bypass where JSON-LD credentials were only proof-checked inside JSON-LD
// VPs: wrapping them in a JWT VP — which any holder can mint — must not skip
// credential verification.
func TestParseJWTPresentation_EmbeddedJSONLDCredentialIsVerified(t *testing.T) {
	docLoader := newTestDocumentLoader()

	issuerPrivKey, _, issuerPubJWK := generateTestECKeys(t)
	issuerSigner := &testES256Signer{key: issuerPrivKey}

	const attackerDID = "did:web:attacker.example.com"
	const attackerKeyID = attackerDID + "#key-1"
	attackerPrivKey, _, attackerPubJWK := generateTestECKeys(t)
	attackerSigner := &testES256Signer{key: attackerPrivKey}

	registry := createMultiKeyRegistry(t, map[string]ljwk.Key{
		testIssuerKeyID: issuerPubJWK,
		attackerKeyID:   attackerPubJWK,
	})

	forgedVC := createTestVC(testIssuerDID)
	forgedVC[common.VPKeyProof] = signDocument(t, forgedVC, attackerSigner, attackerKeyID, docLoader,
		ldProofTestOptions{proofPurpose: common.ProofPurposeAssertionMethod})

	tests := []struct {
		name       string
		credential map[string]interface{}
		wantErrIs  error
	}{
		{
			name:       "signed_credential_accepted",
			credential: signTestCredential(t, testIssuerDID, issuerSigner, testIssuerKeyID, docLoader),
		},
		{
			name:       "unsigned_credential_rejected",
			credential: createTestVC(testIssuerDID),
			wantErrIs:  ErrorUnsignedCredential,
		},
		{
			name:       "credential_signed_by_other_than_issuer_rejected",
			credential: forgedVC,
			wantErrIs:  ErrorProofIssuerMismatch,
		},
	}

	// No JWT proof checker: the JWT VP envelope is not the subject here, the
	// embedded JSON-LD credential is.
	parser := &ConfigurablePresentationParser{
		LDProofChecker: NewLDProofChecker(registry, docLoader),
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jwtVP := buildFakeJWT(map[string]interface{}{
				common.JWTClaimIss: testHolderDID,
				common.JWTClaimVP: map[string]interface{}{
					common.JSONLDKeyContext:          []string{common.ContextCredentialsV1},
					common.JSONLDKeyType:             []string{common.TypeVerifiablePresentation},
					common.VPKeyVerifiableCredential: []interface{}{tc.credential},
				},
			})

			result, err := parser.ParsePresentation([]byte(jwtVP))
			if tc.wantErrIs != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.wantErrIs), "expected %v, got %v", tc.wantErrIs, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, result.Credentials(), 1)
		})
	}
}

// createMultiKeyRegistry builds a did.Registry that resolves several DIDs,
// keyed by verification method ID. Each key is declared for both the
// authentication and the assertionMethod relationship.
func createMultiKeyRegistry(t *testing.T, keysByVerificationMethod map[string]ljwk.Key) *did.Registry {
	t.Helper()

	docsByDID := make(map[string]*did.DocResolution, len(keysByVerificationMethod))
	for keyID, pubJWK := range keysByVerificationMethod {
		didStr, _ := ExtractDIDAndFragment(keyID)
		vm, err := did.NewVerificationMethodFromJWK(keyID, "JsonWebKey2020", didStr, pubJWK)
		require.NoError(t, err)
		docsByDID[didStr] = &did.DocResolution{
			DIDDocument: &did.Doc{
				ID:                 didStr,
				VerificationMethod: []did.VerificationMethod{*vm},
				Authentication:     []string{keyID},
				AssertionMethod:    []string{keyID},
			},
		}
	}

	return did.NewRegistry(did.WithVDR(&mockVDR{
		readFunc: func(didStr string) (*did.DocResolution, error) {
			doc, ok := docsByDID[didStr]
			if !ok {
				return nil, errors.New("test: unknown did " + didStr)
			}
			return doc, nil
		},
	}))
}

// signVPWithCredentials builds a JSON-LD VP around the given credentials and
// signs it, returning the full signed VP JSON. The credentials are part of
// the signed document, so the VP proof covers them.
func signVPWithCredentials(t *testing.T, signer common.LDSigner, verificationMethod string, docLoader ld.DocumentLoader, credentials []interface{}, opts ldProofTestOptions) []byte {
	t.Helper()

	vpMap := map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{
			common.ContextCredentialsV1,
			common.ContextSecuritySuiteJWS2020,
		},
		common.JSONLDKeyType:             []interface{}{common.TypeVerifiablePresentation},
		common.VPKeyHolder:               testHolderDID,
		common.VPKeyVerifiableCredential: credentials,
	}
	vpMap[common.VPKeyProof] = signDocument(t, vpMap, signer, verificationMethod, docLoader, opts)

	return marshal(t, vpMap)
}

// signVPWithCredentialsV2 builds a JSON-LD VP around the given credentials
// using the VC Data Model 2.0 context and signs it, returning the full signed
// VP JSON. Use this instead of signVPWithCredentials when the credentials
// include EnvelopedVerifiableCredential objects that carry their own V2
// context — the V1 and V2 contexts cannot coexist in the same document
// because V2 redefines terms V1 declares as protected.
func signVPWithCredentialsV2(t *testing.T, signer common.LDSigner, verificationMethod string, docLoader ld.DocumentLoader, credentials []interface{}, opts ldProofTestOptions) []byte {
	t.Helper()

	vpMap := map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{
			common.ContextCredentialsV2,
			common.ContextSecuritySuiteJWS2020,
		},
		common.JSONLDKeyType:             []interface{}{common.TypeVerifiablePresentation},
		common.VPKeyHolder:               testHolderDID,
		common.VPKeyVerifiableCredential: credentials,
	}
	vpMap[common.VPKeyProof] = signDocument(t, vpMap, signer, verificationMethod, docLoader, opts)

	return marshal(t, vpMap)
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
	require.NoError(t, json.Unmarshal(vpJSON, &vpMap))
	vpMap["holder"] = "did:web:attacker.example.com" // tamper
	tamperedJSON, marshalErr := json.Marshal(vpMap)
	require.NoError(t, marshalErr)

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
	require.NoError(t, json.Unmarshal(vpJSON, &vpMap))
	vpMap["verifiableCredential"] = []interface{}{vcWithBadProof}
	modifiedJSON, marshalErr := json.Marshal(vpMap)
	require.NoError(t, marshalErr)

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

// --- VerifyLDVPProofBinding tests ---

// TestVerifyLDVPProofBinding verifies challenge and domain binding for
// JSON-LD VP proofs using table-driven tests.
func TestVerifyLDVPProofBinding(t *testing.T) {
	expectedChallenge := "session-nonce-abc123"
	expectedDomain := "did:key:verifier"

	type bindingTest struct {
		name              string
		proofs            []*common.LDProof
		expectedChallenge string
		expectedDomain    string
		expectedErr       error
	}

	tests := []bindingTest{
		{
			name:              "correct challenge and domain",
			proofs:            []*common.LDProof{{Type: "JsonWebSignature2020", Challenge: expectedChallenge, Domain: expectedDomain}},
			expectedChallenge: expectedChallenge,
			expectedDomain:    expectedDomain,
			expectedErr:       nil,
		},
		{
			// Omitting the domain must not be a way to opt out of the
			// audience binding.
			name:              "correct challenge, no domain in proof",
			proofs:            []*common.LDProof{{Type: "JsonWebSignature2020", Challenge: expectedChallenge}},
			expectedChallenge: expectedChallenge,
			expectedDomain:    expectedDomain,
			expectedErr:       ErrorProofDomainMismatch,
		},
		{
			name:              "wrong challenge",
			proofs:            []*common.LDProof{{Type: "JsonWebSignature2020", Challenge: "wrong-nonce"}},
			expectedChallenge: expectedChallenge,
			expectedDomain:    "",
			expectedErr:       ErrorProofChallengeMismatch,
		},
		{
			name:              "missing challenge when expected",
			proofs:            []*common.LDProof{{Type: "JsonWebSignature2020"}},
			expectedChallenge: expectedChallenge,
			expectedDomain:    "",
			expectedErr:       ErrorProofChallengeMismatch,
		},
		{
			name:              "wrong domain",
			proofs:            []*common.LDProof{{Type: "JsonWebSignature2020", Challenge: expectedChallenge, Domain: "did:key:attacker"}},
			expectedChallenge: expectedChallenge,
			expectedDomain:    expectedDomain,
			expectedErr:       ErrorProofDomainMismatch,
		},
		{
			name:              "no challenge expected, skip check",
			proofs:            []*common.LDProof{{Type: "JsonWebSignature2020", Challenge: "any-value"}},
			expectedChallenge: "",
			expectedDomain:    "",
			expectedErr:       nil,
		},
		{
			name:              "no domain expected, skip domain check",
			proofs:            []*common.LDProof{{Type: "JsonWebSignature2020", Domain: "any-domain"}},
			expectedChallenge: "",
			expectedDomain:    "",
			expectedErr:       nil,
		},
		{
			name:              "no proofs, no-op",
			proofs:            nil,
			expectedChallenge: expectedChallenge,
			expectedDomain:    expectedDomain,
			expectedErr:       nil,
		},
		{
			name:              "empty proofs slice, no-op",
			proofs:            []*common.LDProof{},
			expectedChallenge: expectedChallenge,
			expectedDomain:    expectedDomain,
			expectedErr:       nil,
		},
		{
			name: "multiple proofs, first has correct challenge",
			proofs: []*common.LDProof{
				{Type: "JsonWebSignature2020", Challenge: expectedChallenge},
				{Type: "JsonWebSignature2020"},
			},
			expectedChallenge: expectedChallenge,
			expectedDomain:    "",
			expectedErr:       nil,
		},
		{
			name: "multiple proofs, second has wrong challenge",
			proofs: []*common.LDProof{
				{Type: "JsonWebSignature2020", Challenge: expectedChallenge},
				{Type: "JsonWebSignature2020", Challenge: "wrong-nonce"},
			},
			expectedChallenge: expectedChallenge,
			expectedDomain:    "",
			expectedErr:       ErrorProofChallengeMismatch,
		},
		{
			name: "multiple proofs, one has wrong domain",
			proofs: []*common.LDProof{
				{Type: "JsonWebSignature2020", Challenge: expectedChallenge, Domain: expectedDomain},
				{Type: "JsonWebSignature2020", Domain: "did:key:attacker"},
			},
			expectedChallenge: expectedChallenge,
			expectedDomain:    expectedDomain,
			expectedErr:       ErrorProofDomainMismatch,
		},
		{
			name:              "correct domain, no challenge expected",
			proofs:            []*common.LDProof{{Type: "JsonWebSignature2020", Domain: expectedDomain}},
			expectedChallenge: "",
			expectedDomain:    expectedDomain,
			expectedErr:       nil,
		},
		{
			// Neither proof binds the session to this verifier on its own,
			// so the split must not be accepted just because both values
			// appear somewhere in the list.
			name: "challenge and domain split across two proofs",
			proofs: []*common.LDProof{
				{Type: "JsonWebSignature2020", Challenge: expectedChallenge},
				{Type: "JsonWebSignature2020", Domain: expectedDomain},
			},
			expectedChallenge: expectedChallenge,
			expectedDomain:    expectedDomain,
			expectedErr:       ErrorProofChallengeMismatch,
		},
		{
			name: "one proof carries both bindings alongside an unbound proof",
			proofs: []*common.LDProof{
				{Type: "JsonWebSignature2020"},
				{Type: "JsonWebSignature2020", Challenge: expectedChallenge, Domain: expectedDomain},
			},
			expectedChallenge: expectedChallenge,
			expectedDomain:    expectedDomain,
			expectedErr:       nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pres, _ := common.NewPresentation()
			pres.Proofs = tc.proofs

			err := VerifyLDVPProofBinding(pres, tc.expectedChallenge, tc.expectedDomain)
			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr, "expected error %v, got %v", tc.expectedErr, err)
			} else {
				assert.NoError(t, err, "expected no error, got %v", err)
			}
		})
	}
}

// TestVerifyLDVPProofBinding_HolderKeyPropagation verifies that after parsing a
// JSON-LD VP with a valid LD proof, the presentation's HolderKey is set to the
// LD-proof signer key.
func TestVerifyLDVPProofBinding_HolderKeyPropagation(t *testing.T) {
	// Generate a key pair for signing and set up test infrastructure.
	privKey, _, pubJWK := generateTestECKeys(t)
	signer := &testES256Signer{key: privKey}
	docLoader := newTestDocumentLoader()
	verificationMethodID := "did:web:holder.example.com#key-1"
	registry := createMockRegistry(t, "web", verificationMethodID, pubJWK)

	// Create and sign a VP using the shared test helpers.
	pres := createTestVP()
	vpJSON, _ := signPresentation(t, pres, signer, verificationMethodID, docLoader)

	// Set up a parser with the real LDProofChecker and mock JWTProofChecker.
	ldChecker := NewLDProofChecker(registry, docLoader)
	parser := &ConfigurablePresentationParser{
		ProofChecker:   newTestProofChecker(),
		LDProofChecker: ldChecker,
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Holder key should be set from the LD-proof verification.
	holderKey := result.HolderKey()
	assert.NotNil(t, holderKey, "HolderKey should be set after LD-proof verification")

	// The proof should be populated.
	require.Len(t, result.Proofs, 1)
	assert.Equal(t, common.ProofTypeJsonWebSignature2020, result.Proofs[0].Type)

	// Since AddLinkedDataProof doesn't add challenge/domain, the parsed proof
	// won't have them. Simulate a VP from a wallet that included challenge/domain
	// by setting them on the parsed proofs and then testing VerifyLDVPProofBinding.
	challenge := "test-nonce-123"
	domain := "did:web:verifier"
	result.Proofs[0].Challenge = challenge
	result.Proofs[0].Domain = domain

	// VerifyLDVPProofBinding should accept with matching challenge/domain.
	err = VerifyLDVPProofBinding(result, challenge, domain)
	assert.NoError(t, err)

	// VerifyLDVPProofBinding should reject with wrong challenge.
	err = VerifyLDVPProofBinding(result, "wrong-nonce", domain)
	assert.ErrorIs(t, err, ErrorProofChallengeMismatch)

	// VerifyLDVPProofBinding should reject with wrong domain.
	err = VerifyLDVPProofBinding(result, challenge, "wrong-domain")
	assert.ErrorIs(t, err, ErrorProofDomainMismatch)
}

// TestCredentialParsers_ContextAndTypeSpellings verifies that both credential parsers
// accept every JSON-LD spelling of `@context` and `type`. JSON-LD allows a single string
// where an array is also valid, and a dropped `@context` would leave the credential
// without a detectable VC Data Model version.
func TestCredentialParsers_ContextAndTypeSpellings(t *testing.T) {
	tests := []struct {
		name        string
		context     interface{}
		types       interface{}
		wantContext []string
		wantTypes   []string
	}{
		{
			name:        "array context and array type",
			context:     []interface{}{common.ContextCredentialsV2, "https://w3id.org/security/suites/jws-2020/v1"},
			types:       []interface{}{"VerifiableCredential", "TestCredential"},
			wantContext: []string{common.ContextCredentialsV2, "https://w3id.org/security/suites/jws-2020/v1"},
			wantTypes:   []string{"VerifiableCredential", "TestCredential"},
		},
		{
			name:        "string context and string type",
			context:     common.ContextCredentialsV1,
			types:       "VerifiableCredential",
			wantContext: []string{common.ContextCredentialsV1},
			wantTypes:   []string{"VerifiableCredential"},
		},
		{
			name:        "string context with array type",
			context:     common.ContextCredentialsV2,
			types:       []interface{}{"VerifiableCredential"},
			wantContext: []string{common.ContextCredentialsV2},
			wantTypes:   []string{"VerifiableCredential"},
		},
		{
			name:        "non-string entries are skipped",
			context:     []interface{}{common.ContextCredentialsV2, 42},
			types:       []interface{}{"VerifiableCredential", nil},
			wantContext: []string{common.ContextCredentialsV2},
			wantTypes:   []string{"VerifiableCredential"},
		},
		{
			name:        "absent context and type yield nothing",
			context:     nil,
			types:       nil,
			wantContext: nil,
			wantTypes:   nil,
		},
	}

	for _, tc := range tests {
		vcBody := func() map[string]interface{} {
			body := map[string]interface{}{
				"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com"},
			}
			if tc.context != nil {
				body[common.JSONLDKeyContext] = tc.context
			}
			if tc.types != nil {
				body[common.JSONLDKeyType] = tc.types
			}
			return body
		}

		t.Run("jwt_vc/"+tc.name, func(t *testing.T) {
			cred, err := jwtClaimsToCredential(map[string]interface{}{
				common.JWTClaimIss: "did:web:issuer.example.com",
				common.JWTClaimVC:  vcBody(),
			})
			require.NoError(t, err)
			assert.Equal(t, tc.wantContext, cred.Contents().Context)
			assert.Equal(t, tc.wantTypes, cred.Contents().Types)
		})

		t.Run("ldp_vc/"+tc.name, func(t *testing.T) {
			cred, err := parseJSONLDCredential(vcBody())
			require.NoError(t, err)
			assert.Equal(t, tc.wantContext, cred.Contents().Context)
			assert.Equal(t, tc.wantTypes, cred.Contents().Types)
		})
	}
}

// TestValidateVC_StringContextIsGated is the regression test for the version gate being
// bypassable via a string-valued `@context`: such a context used to be dropped by the
// parsers, leaving the credential without a version and exempting it from the gate.
func TestValidateVC_StringContextIsGated(t *testing.T) {
	cred, err := parseJSONLDCredential(map[string]interface{}{
		common.JSONLDKeyContext: common.ContextCredentialsV1,
		common.JSONLDKeyType:    "VerifiableCredential",
		common.VCKeyIssuer:      "did:web:issuer.example.com",
	})
	require.NoError(t, err)

	validator := CredentialValidator{
		validationMode:      ValidationModeNone,
		vcDataModelVersions: []string{common.VCDataModelVersion20},
	}
	result, err := validator.ValidateVC(cred, nil)

	assert.False(t, result, "a v1.1 credential must not pass a 2.0-only allowlist")
	assert.ErrorIs(t, err, ErrorVCDataModelVersionNotAccepted)
}

// TestParseJWTCredential_RejectsIssuerSubstitution is the end-to-end regression
// test for credential forgery via a kid/iss mismatch.
//
// The credential is signed with a key the presenter generated themselves and
// names an unrelated issuer in the iss claim. Before the kid/iss binding check,
// the signature verified against the presenter's own DID while the resulting
// credential carried the claimed issuer — which is what the trusted-issuer
// registry lookups key off, so a credential could be attributed to any trusted
// issuer.
func TestParseJWTCredential_RejectsIssuerSubstitution(t *testing.T) {
	signerKey, signerDID := generateTestKeyAndDIDJWK(t)

	payload := map[string]interface{}{
		common.JWTClaimIss: "did:web:trusted.issuer.example.com",
		common.JWTClaimVC: map[string]interface{}{
			common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV1},
			common.JSONLDKeyType:    []interface{}{"VerifiableCredential"},
			"credentialSubject":     map[string]interface{}{"id": "did:web:subject.example.com"},
		},
	}
	token := signTestJWT(t, signerKey, signerDID+"#0", payload)

	parser := &ConfigurablePresentationParser{
		ProofChecker: NewJWTProofChecker(did.NewRegistry(did.WithVDR(did.NewJWKVDR()))),
	}
	cred, err := parser.parseJWTCredential(token)

	assert.ErrorIs(t, err, ErrorIssuerKeyMismatch,
		"a credential signed by a key unrelated to its claimed issuer must be rejected")
	assert.Nil(t, cred)
}

// --- Tests for jwtMediaType and VC-JOSE-COSE predicates ---

// buildTestJWTWithTyp creates a compact-serialization JWT with a custom typ
// header. The payload is arbitrary — these tests only need the header segment.
func buildTestJWTWithTyp(t *testing.T, typ string) []byte {
	t.Helper()
	header := map[string]interface{}{
		"alg": "ES256",
	}
	if typ != "" {
		header["typ"] = typ
	}
	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]interface{}{"iss": "test"})
	require.NoError(t, err)

	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	p := base64.RawURLEncoding.EncodeToString(payload)
	return []byte(h + "." + p + ".fakesig")
}

func TestJwtMediaType(t *testing.T) {
	tests := []struct {
		name    string
		token   []byte
		wantTyp string
	}{
		{
			name:    "vc+jwt typ header",
			token:   buildTestJWTWithTyp(t, "vc+jwt"),
			wantTyp: "vc+jwt",
		},
		{
			name:    "vp+jwt typ header",
			token:   buildTestJWTWithTyp(t, "vp+jwt"),
			wantTyp: "vp+jwt",
		},
		{
			name:    "classic JWT typ header",
			token:   buildTestJWTWithTyp(t, "JWT"),
			wantTyp: "JWT",
		},
		{
			name:    "no typ header",
			token:   buildTestJWTWithTyp(t, ""),
			wantTyp: "",
		},
		{
			name:    "empty token",
			token:   []byte(""),
			wantTyp: "",
		},
		{
			name:    "not a JWT (no dots)",
			token:   []byte("notajwt"),
			wantTyp: "",
		},
		{
			name:    "invalid base64 header segment",
			token:   []byte("!!!invalid!!!.payload.sig"),
			wantTyp: "",
		},
		{
			name:    "non-JSON header segment",
			token:   []byte(base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".payload.sig"),
			wantTyp: "",
		},
		{
			name: "two-segment token (no signature)",
			token: func() []byte {
				full := buildTestJWTWithTyp(t, "vc+jwt")
				// Remove the last ".fakesig" segment to get a header.payload token.
				idx := bytes.LastIndex(full, []byte("."))
				return full[:idx]
			}(),
			wantTyp: "vc+jwt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := jwtMediaType(tc.token)
			assert.Equal(t, tc.wantTyp, got)
		})
	}
}

func TestIsVCJoseJWT(t *testing.T) {
	tests := []struct {
		name string
		typ  string
		want bool
	}{
		{"vc+jwt lowercase", "vc+jwt", true},
		{"vc+jwt uppercase", "VC+JWT", true},
		{"vc+jwt mixed case", "Vc+Jwt", true},
		{"vp+jwt is not vc+jwt", "vp+jwt", false},
		{"JWT is not vc+jwt", "JWT", false},
		{"empty is not vc+jwt", "", false},
		{"arbitrary string", "something", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isVCJoseJWT(tc.typ))
		})
	}
}

func TestIsVPJoseJWT(t *testing.T) {
	tests := []struct {
		name string
		typ  string
		want bool
	}{
		{"vp+jwt lowercase", "vp+jwt", true},
		{"vp+jwt uppercase", "VP+JWT", true},
		{"vp+jwt mixed case", "Vp+Jwt", true},
		{"vc+jwt is not vp+jwt", "vc+jwt", false},
		{"JWT is not vp+jwt", "JWT", false},
		{"empty is not vp+jwt", "", false},
		{"arbitrary string", "something", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isVPJoseJWT(tc.typ))
		})
	}
}

// --- Tests for vcJwtClaimsToCredential ---

// buildFakeVCJoseJWT constructs a fake compact JWT with a custom typ header
// and the given payload. It is NOT cryptographically signed — it uses a
// dummy signature, which is sufficient for unit tests that parse claims
// without verifying the JWS.
func buildFakeVCJoseJWT(t *testing.T, typ string, payload map[string]interface{}) []byte {
	t.Helper()
	header := map[string]interface{}{
		"alg": "ES256",
	}
	if typ != "" {
		header["typ"] = typ
	}
	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)
	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	p := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return []byte(h + "." + p + ".fakesig")
}

func TestVcJwtClaimsToCredential_FullClaims(t *testing.T) {
	nbf := float64(1700000000)
	exp := float64(1700100000)
	claims := map[string]interface{}{
		"iss": "did:web:issuer.example.com",
		"sub": "did:web:subject.example.com",
		"jti": "urn:uuid:test-vc-jwt-id",
		"nbf": nbf,
		"exp": exp,
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		"type":   []interface{}{"VerifiableCredential"},
		"issuer": "did:web:issuer.example.com",
		"credentialSubject": map[string]interface{}{
			"id":   "did:web:subject.example.com",
			"name": "Alice",
		},
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)

	contents := cred.Contents()
	assert.Equal(t, "did:web:issuer.example.com", contents.Issuer.ID)
	assert.Equal(t, "urn:uuid:test-vc-jwt-id", contents.ID)
	assert.Equal(t, []string{"https://www.w3.org/ns/credentials/v2"}, contents.Context)
	assert.Equal(t, []string{"VerifiableCredential"}, contents.Types)

	require.Len(t, contents.Subject, 1)
	// sub takes precedence over credentialSubject[0].id
	assert.Equal(t, "did:web:subject.example.com", contents.Subject[0].ID)
	assert.Equal(t, "Alice", contents.Subject[0].CustomFields["name"])

	require.NotNil(t, contents.ValidFrom)
	assert.Equal(t, time.Unix(int64(nbf), 0), *contents.ValidFrom)
	require.NotNil(t, contents.ValidUntil)
	assert.Equal(t, time.Unix(int64(exp), 0), *contents.ValidUntil)

	// rawJSON should be the full claims map, not a sub-object
	raw := cred.ToRawJSON()
	assert.NotNil(t, raw)
	assert.Equal(t, "did:web:issuer.example.com", raw["iss"])
	assert.NotNil(t, raw["@context"])
}

func TestVcJwtClaimsToCredential_IssuerAsObject(t *testing.T) {
	claims := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer": map[string]interface{}{
			"id":   "did:web:issuer-object.example.com",
			"name": "Issuer Corp",
		},
		"credentialSubject": map[string]interface{}{
			"id": "did:web:subject.example.com",
		},
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)
	// No iss claim, should fall back to issuer object's id
	assert.Equal(t, "did:web:issuer-object.example.com", cred.Contents().Issuer.ID)
}

func TestVcJwtClaimsToCredential_IssClaimMatchesIssuerField(t *testing.T) {
	// When iss and issuer agree, the credential is accepted with iss as the issuer.
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:web:issuer.example.com",
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)
	assert.Equal(t, "did:web:issuer.example.com", cred.Contents().Issuer.ID)
}

func TestVcJwtClaimsToCredential_IssClaimMismatchIssuerFieldRejectsCredential(t *testing.T) {
	// VC-JOSE-COSE §3.3.1: iss and issuer MUST be equal when both present.
	// A mismatch is a malformed credential.
	claims := map[string]interface{}{
		"iss":      "did:web:iss-claim-issuer.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:web:payload-issuer.example.com",
	}

	_, err := vcJwtClaimsToCredential(claims)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorIssClaimIssuerMismatch)
}

func TestVcJwtClaimsToCredential_IssClaimMismatchIssuerObjectRejectsCredential(t *testing.T) {
	// Same as above, but issuer is an object with an id field.
	claims := map[string]interface{}{
		"iss":      "did:web:iss-claim-issuer.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer": map[string]interface{}{
			"id":   "did:web:object-issuer.example.com",
			"name": "Acme Corp",
		},
	}

	_, err := vcJwtClaimsToCredential(claims)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorIssClaimIssuerMismatch)
}

// TestVcJwtClaimsToCredential_SubMustAgreeWithSubjectID checks that `sub` is
// reconciled with credentialSubject.id rather than overriding it. It used to
// win silently, which let it rewrite the subject that holder binding and the
// holder policies compare against.
func TestVcJwtClaimsToCredential_SubMustAgreeWithSubjectID(t *testing.T) {
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"sub":      "did:web:sub-claim-subject.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   "did:web:payload-subject.example.com",
			"name": "Bob",
		},
	}

	_, err := vcJwtClaimsToCredential(claims)
	assert.ErrorIs(t, err, ErrorSubClaimSubjectMismatch)
}

// TestVcJwtClaimsToCredential_SubAgreeingWithSubjectID checks the other half of
// the rule: a redundant copy that agrees is accepted, and the subject keeps its
// other fields.
func TestVcJwtClaimsToCredential_SubAgreeingWithSubjectID(t *testing.T) {
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"sub":      "did:web:payload-subject.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   "did:web:payload-subject.example.com",
			"name": "Bob",
		},
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)

	require.Len(t, cred.Contents().Subject, 1)
	assert.Equal(t, "did:web:payload-subject.example.com", cred.Contents().Subject[0].ID)
	assert.Equal(t, "Bob", cred.Contents().Subject[0].CustomFields["name"])
}

func TestVcJwtClaimsToCredential_SubWithoutCredentialSubject(t *testing.T) {
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"sub":      "did:web:subject-only.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)

	require.Len(t, cred.Contents().Subject, 1)
	assert.Equal(t, "did:web:subject-only.example.com", cred.Contents().Subject[0].ID)
}

// TestVcJwtClaimsToCredential_NoIssuer checks that a vc+jwt naming no issuer is
// rejected rather than parsed with a nil issuer. There is no identity to bind
// the signing key to, so accepting it would leave a credential that verified
// against nobody in particular.
func TestVcJwtClaimsToCredential_NoIssuer(t *testing.T) {
	claims := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
	}

	_, err := vcJwtClaimsToCredential(claims)
	assert.ErrorIs(t, err, ErrorVCJWTNoIssuer)
}

func TestVcJwtClaimsToCredential_CredentialStatus(t *testing.T) {
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialStatus": map[string]interface{}{
			"id":   "https://example.com/status/1#42",
			"type": "BitstringStatusListEntry",
		},
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)
	require.NotNil(t, cred.Contents().Status)
	assert.Equal(t, "https://example.com/status/1#42", cred.Contents().Status.ID)
	assert.Equal(t, "BitstringStatusListEntry", cred.Contents().Status.Type)
}

func TestVcJwtClaimsToCredential_CredentialStatusAsArray(t *testing.T) {
	// VCDM 2.0 allows credentialStatus to be an array of objects.
	// The first entry should be extracted for contents.Status.
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialStatus": []interface{}{
			map[string]interface{}{
				"id":   "https://example.com/status/1#42",
				"type": "BitstringStatusListEntry",
			},
			map[string]interface{}{
				"id":   "https://example.com/status/2#99",
				"type": "BitstringStatusListEntry",
			},
		},
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)
	require.NotNil(t, cred.Contents().Status)
	assert.Equal(t, "https://example.com/status/1#42", cred.Contents().Status.ID)
	assert.Equal(t, "BitstringStatusListEntry", cred.Contents().Status.Type)
}

func TestVcJwtClaimsToCredential_DateFallbackToPayloadStrings(t *testing.T) {
	// No JWT numeric claims — should fall back to VCDM 2.0 validFrom/validUntil
	claims := map[string]interface{}{
		"iss":        "did:web:issuer.example.com",
		"@context":   []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":       []interface{}{"VerifiableCredential"},
		"validFrom":  "2024-01-01T00:00:00Z",
		"validUntil": "2025-01-01T00:00:00Z",
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)

	expectedFrom, _ := time.Parse(time.RFC3339, "2024-01-01T00:00:00Z")
	expectedUntil, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	require.NotNil(t, cred.Contents().ValidFrom)
	assert.Equal(t, expectedFrom, *cred.Contents().ValidFrom)
	require.NotNil(t, cred.Contents().ValidUntil)
	assert.Equal(t, expectedUntil, *cred.Contents().ValidUntil)
}

// TestVcJwtClaimsToCredential_ValidityWindow covers the rule VC-JOSE-COSE
// §3.1.3 states: iat and exp are the issuance and expiration time of the
// *signature*, not of the credential, and nbf is NOT RECOMMENDED. The payload's
// validFrom/validUntil state the credential's validity, and a registered claim
// present anyway may only narrow that window.
func TestVcJwtClaimsToCredential_ValidityWindow(t *testing.T) {
	const (
		hour       = int64(3600)
		base       = int64(1700000000)
		baseRFC    = "2023-11-14T22:13:20Z"
		laterRFC   = "2023-11-14T23:13:20Z"
		earlierRFC = "2023-11-14T21:13:20Z"
	)

	tests := []struct {
		name           string
		claims         map[string]interface{}
		wantValidFrom  *int64
		wantValidUntil *int64
	}{
		{
			// The bypass: a signing timestamp used to become the start of
			// validity, so a credential that is not valid yet was usable now.
			name: "iat does not start the validity window",
			claims: map[string]interface{}{
				"iat":       float64(base),
				"validFrom": laterRFC,
			},
			wantValidFrom: ptrInt64(base + hour),
		},
		{
			name: "iat alone leaves the window open",
			claims: map[string]interface{}{
				"iat": float64(base),
			},
		},
		{
			name: "exp may shorten a longer validUntil",
			claims: map[string]interface{}{
				"exp":        float64(base),
				"validUntil": laterRFC,
			},
			wantValidUntil: ptrInt64(base),
		},
		{
			name: "exp may not extend a shorter validUntil",
			claims: map[string]interface{}{
				"exp":        float64(base + hour),
				"validUntil": baseRFC,
			},
			wantValidUntil: ptrInt64(base),
		},
		{
			name: "nbf may delay an earlier validFrom",
			claims: map[string]interface{}{
				"nbf":       float64(base),
				"validFrom": earlierRFC,
			},
			wantValidFrom: ptrInt64(base),
		},
		{
			name: "nbf may not bring forward a later validFrom",
			claims: map[string]interface{}{
				"nbf":       float64(base - hour),
				"validFrom": baseRFC,
			},
			wantValidFrom: ptrInt64(base),
		},
		{
			name: "payload dates alone",
			claims: map[string]interface{}{
				"validFrom":  baseRFC,
				"validUntil": laterRFC,
			},
			wantValidFrom:  ptrInt64(base),
			wantValidUntil: ptrInt64(base + hour),
		},
		{
			name: "claims alone still bound the window",
			claims: map[string]interface{}{
				"nbf": float64(base),
				"exp": float64(base + hour),
			},
			wantValidFrom:  ptrInt64(base),
			wantValidUntil: ptrInt64(base + hour),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"iss":      "did:web:issuer.example.com",
				"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":     []interface{}{"VerifiableCredential"},
			}
			for k, v := range tc.claims {
				claims[k] = v
			}

			cred, err := vcJwtClaimsToCredential(claims)
			require.NoError(t, err)

			contents := cred.Contents()
			if tc.wantValidFrom == nil {
				assert.Nil(t, contents.ValidFrom)
			} else {
				require.NotNil(t, contents.ValidFrom)
				assert.Equal(t, *tc.wantValidFrom, contents.ValidFrom.Unix())
			}
			if tc.wantValidUntil == nil {
				assert.Nil(t, contents.ValidUntil)
			} else {
				require.NotNil(t, contents.ValidUntil)
				assert.Equal(t, *tc.wantValidUntil, contents.ValidUntil.Unix())
			}
		})
	}
}

func ptrInt64(v int64) *int64 { return &v }

func TestVcJwtClaimsToCredential_CnfPreserved(t *testing.T) {
	cnf := map[string]interface{}{
		"jwk": map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   "base64x",
			"y":   "base64y",
		},
	}
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"cnf":      cnf,
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)

	cf := cred.CustomFields()
	assert.NotNil(t, cf["cnf"])
}

func TestVcJwtClaimsToCredential_MultipleSubjects(t *testing.T) {
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": []interface{}{
			map[string]interface{}{"id": "did:web:alice.example.com", "name": "Alice"},
			map[string]interface{}{"id": "did:web:bob.example.com", "name": "Bob"},
		},
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)

	require.Len(t, cred.Contents().Subject, 2)
	assert.Equal(t, "did:web:alice.example.com", cred.Contents().Subject[0].ID)
	assert.Equal(t, "did:web:bob.example.com", cred.Contents().Subject[1].ID)
}

// TestVcJwtClaimsToCredential_SubRejectedWithMultipleSubjects checks that a
// `sub` alongside several subjects is rejected rather than dropped. §3.1.3
// permits it only for a single subject, so there is no property for it to be a
// redundant copy of - and silently ignoring a claim the signature covers hides
// the same disagreement that silently applying it would.
func TestVcJwtClaimsToCredential_SubRejectedWithMultipleSubjects(t *testing.T) {
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"sub":      "did:web:should-not-be-ignored.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": []interface{}{
			map[string]interface{}{"id": "did:web:alice.example.com", "name": "Alice"},
			map[string]interface{}{"id": "did:web:bob.example.com", "name": "Bob"},
		},
	}

	_, err := vcJwtClaimsToCredential(claims)
	assert.ErrorIs(t, err, ErrorSubClaimMultipleSubjects)
}

// TestVcJwtClaimsToCredential_MultipleSubjectsWithoutSub checks that several
// subjects are fine on their own - the rejection above is about `sub`, not
// about multi-subject credentials.
func TestVcJwtClaimsToCredential_MultipleSubjectsWithoutSub(t *testing.T) {
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": []interface{}{
			map[string]interface{}{"id": "did:web:alice.example.com", "name": "Alice"},
			map[string]interface{}{"id": "did:web:bob.example.com", "name": "Bob"},
		},
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)

	require.Len(t, cred.Contents().Subject, 2)
	assert.Equal(t, "did:web:alice.example.com", cred.Contents().Subject[0].ID)
	assert.Equal(t, "did:web:bob.example.com", cred.Contents().Subject[1].ID)
}

func TestVcJwtClaimsToCredential_IDFromPayload(t *testing.T) {
	// When jti is absent, fall back to payload-level "id"
	claims := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"id":       "urn:uuid:payload-level-id",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)
	assert.Equal(t, "urn:uuid:payload-level-id", cred.Contents().ID)
}

// TestVcJwtClaimsToCredential_JtiMustAgreeWithID applies the same rule to the
// third pair §3.1.3 names: jti is a redundant copy of the payload id.
func TestVcJwtClaimsToCredential_JtiMustAgreeWithID(t *testing.T) {
	tests := []struct {
		name    string
		jti     string
		id      string
		wantID  string
		wantErr error
	}{
		{name: "agreeing", jti: "urn:uuid:same", id: "urn:uuid:same", wantID: "urn:uuid:same"},
		{name: "jti only", jti: "urn:uuid:jti-id", wantID: "urn:uuid:jti-id"},
		{name: "id only", id: "urn:uuid:payload-id", wantID: "urn:uuid:payload-id"},
		{name: "neither", wantID: ""},
		{name: "disagreeing", jti: "urn:uuid:jti-id", id: "urn:uuid:payload-id", wantErr: ErrorJtiClaimIDMismatch},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"iss":      "did:web:issuer.example.com",
				"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":     []interface{}{"VerifiableCredential"},
			}
			if tc.jti != "" {
				claims["jti"] = tc.jti
			}
			if tc.id != "" {
				claims["id"] = tc.id
			}

			cred, err := vcJwtClaimsToCredential(claims)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantID, cred.Contents().ID)
		})
	}
}

func TestVcJwtClaimsToCredential_IssuerStringFallback(t *testing.T) {
	// No iss claim — fall back to payload "issuer" as a string
	claims := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:web:string-issuer.example.com",
	}

	cred, err := vcJwtClaimsToCredential(claims)
	require.NoError(t, err)
	assert.Equal(t, "did:web:string-issuer.example.com", cred.Contents().Issuer.ID)
}

// --- Tests for parseJWTCredential typ dispatch ---

func TestParseJWTCredential_VCJoseJWTDispatch(t *testing.T) {
	payload := map[string]interface{}{
		"iss": "did:web:issuer.example.com",
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
		},
		"type": []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   "did:web:subject.example.com",
			"name": "Alice",
		},
	}

	token := buildFakeVCJoseJWT(t, "vc+jwt", payload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	cred, err := parser.parseJWTCredential(token)
	require.NoError(t, err)

	assert.Equal(t, common.FormatVCJWT, cred.Format())
	assert.Equal(t, "did:web:issuer.example.com", cred.Contents().Issuer.ID)
	assert.Equal(t, []string{"https://www.w3.org/ns/credentials/v2"}, cred.Contents().Context)
	assert.Equal(t, []string{"VerifiableCredential"}, cred.Contents().Types)
	require.Len(t, cred.Contents().Subject, 1)
	assert.Equal(t, "did:web:subject.example.com", cred.Contents().Subject[0].ID)
}

func TestParseJWTCredential_ClassicJWTVCStillWorks(t *testing.T) {
	// Classic JWT-VC with typ: JWT (not vc+jwt) — should go through the
	// old jwtClaimsToCredential path.
	payload := map[string]interface{}{
		"iss": "did:web:classic-issuer.example.com",
		"vc": map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com"},
		},
	}

	// buildFakeJWT uses typ: "JWT"
	token := []byte(buildFakeJWT(payload))
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	cred, err := parser.parseJWTCredential(token)
	require.NoError(t, err)

	assert.Equal(t, common.FormatJWTVC, cred.Format())
	assert.Equal(t, "did:web:classic-issuer.example.com", cred.Contents().Issuer.ID)
}

func TestParseJWTCredential_NoTypHeaderUsesClassicPath(t *testing.T) {
	// JWT without any typ header — should be treated as classic JWT-VC.
	payload := map[string]interface{}{
		"iss": "did:web:no-typ-issuer.example.com",
		"vc": map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com"},
		},
	}

	token := buildFakeVCJoseJWT(t, "", payload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	cred, err := parser.parseJWTCredential(token)
	require.NoError(t, err)

	assert.Equal(t, common.FormatJWTVC, cred.Format())
	assert.Equal(t, "did:web:no-typ-issuer.example.com", cred.Contents().Issuer.ID)
}

func TestParseJWTCredential_VCJoseJWT_CaseInsensitive(t *testing.T) {
	// vc+jwt typ header should be case-insensitive
	payload := map[string]interface{}{
		"iss":      "did:web:issuer.example.com",
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
	}

	token := buildFakeVCJoseJWT(t, "VC+JWT", payload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	cred, err := parser.parseJWTCredential(token)
	require.NoError(t, err)

	assert.Equal(t, common.FormatVCJWT, cred.Format())
}

// --- Tests for vp+jwt presentation parsing ---

// buildFakeVPJWT constructs a fake compact JWT with a custom typ header and
// the given payload. NOT cryptographically signed — uses a dummy signature.
// Sufficient for unit tests that parse claims without verifying the JWS.
func buildFakeVPJWT(t *testing.T, typ string, payload map[string]interface{}) []byte {
	t.Helper()
	return buildFakeVCJoseJWT(t, typ, payload)
}

// buildEmbeddedVCJWT constructs a vc+jwt compact JWT string suitable for
// embedding inside a vp+jwt's verifiableCredential array.
func buildEmbeddedVCJWT(t *testing.T, issuer string, subjectID string) string {
	t.Helper()
	payload := map[string]interface{}{
		"iss":      issuer,
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"credentialSubject": map[string]interface{}{
			"id":   subjectID,
			"name": "Alice",
		},
	}
	return string(buildFakeVCJoseJWT(t, "vc+jwt", payload))
}

// buildEnvelopedCredential constructs an EnvelopedVerifiableCredential map
// wrapping the given compact JWT string in a data:application/vc+jwt, URI.
func buildEnvelopedCredential(jwtString string) map[string]interface{} {
	return map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "EnvelopedVerifiableCredential",
		"id":       common.DataURISchemeVCJWT + jwtString,
	}
}

func TestParseVPJWT_WithVCJWTCredentials(t *testing.T) {
	vcJWT := buildEmbeddedVCJWT(t, "did:web:issuer.example.com", "did:web:subject.example.com")
	vpPayload := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{vcJWT},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, "did:web:holder.example.com", pres.Holder)
	assert.Equal(t, []string{"https://www.w3.org/ns/credentials/v2"}, pres.Context)
	assert.Equal(t, []string{"VerifiablePresentation"}, pres.Type)
	require.Len(t, pres.Credentials(), 1)
	assert.Equal(t, common.FormatVCJWT, pres.Credentials()[0].Format())
	assert.Equal(t, "did:web:issuer.example.com", pres.Credentials()[0].Contents().Issuer.ID)
}

func TestParseVPJWT_WithClassicJWTVCCredentials(t *testing.T) {
	// Classic jwt_vc embedded in a vp+jwt presentation.
	classicPayload := map[string]interface{}{
		"iss": "did:web:classic-issuer.example.com",
		"vc": map[string]interface{}{
			"@context":          []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":              []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{"id": "did:web:subject.example.com"},
		},
	}
	classicJWT := buildFakeJWT(classicPayload)

	vpPayload := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{classicJWT},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	require.Len(t, pres.Credentials(), 1)
	assert.Equal(t, common.FormatJWTVC, pres.Credentials()[0].Format())
	assert.Equal(t, "did:web:classic-issuer.example.com", pres.Credentials()[0].Contents().Issuer.ID)
}

func TestParseVPJWT_WithEnvelopedCredential(t *testing.T) {
	vcJWT := buildEmbeddedVCJWT(t, "did:web:issuer.example.com", "did:web:subject.example.com")
	envelope := buildEnvelopedCredential(vcJWT)

	vpPayload := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{envelope},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	require.Len(t, pres.Credentials(), 1)
	assert.Equal(t, common.FormatVCJWT, pres.Credentials()[0].Format())
	assert.Equal(t, "did:web:issuer.example.com", pres.Credentials()[0].Contents().Issuer.ID)
}

func TestParseVPJWT_HolderFromIss(t *testing.T) {
	// When "holder" is not in the payload, "iss" is used as the holder.
	vpPayload := map[string]interface{}{
		"iss":                  "did:web:iss-holder.example.com",
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"verifiableCredential": []interface{}{},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, "did:web:iss-holder.example.com", pres.Holder)
}

func TestParseVPJWT_HolderAndIssAgree(t *testing.T) {
	// When both "holder" and "iss" are present and equal, parsing succeeds.
	vpPayload := map[string]interface{}{
		"iss":                  "did:web:holder.example.com",
		"holder":               "did:web:holder.example.com",
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"verifiableCredential": []interface{}{},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, "did:web:holder.example.com", pres.Holder)
}

func TestParseVPJWT_HolderIssDisagreementReturnsError(t *testing.T) {
	// When both "holder" and "iss" are present but disagree,
	// VC-JOSE-COSE §3.3.2 requires them to match.
	vpPayload := map[string]interface{}{
		"iss":                  "did:web:iss-holder.example.com",
		"holder":               "did:web:holder-field.example.com",
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"verifiableCredential": []interface{}{},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseJWTPresentation(token)
	require.Error(t, err)

	assert.ErrorIs(t, err, ErrorIssClaimHolderMismatch)
	assert.Contains(t, err.Error(), "did:web:iss-holder.example.com")
	assert.Contains(t, err.Error(), "did:web:holder-field.example.com")
}

func TestParseVPJWT_IDFromJti(t *testing.T) {
	vpPayload := map[string]interface{}{
		"jti":                  "urn:uuid:vp-id-from-jti",
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, "urn:uuid:vp-id-from-jti", pres.ID)
}

func TestParseVPJWT_IDFallbackToPayloadID(t *testing.T) {
	vpPayload := map[string]interface{}{
		"id":                   "urn:uuid:vp-id-from-payload",
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, "urn:uuid:vp-id-from-payload", pres.ID)
}

// TestParseVPJWT_JtiMustAgreeWithPayloadID applies the jti/id rule on the
// presentation side too: a disagreeing redundant copy is malformed, not a
// value that overrules the document.
func TestParseVPJWT_JtiMustAgreeWithPayloadID(t *testing.T) {
	vpPayload := map[string]interface{}{
		"jti":                  "urn:uuid:from-jti",
		"id":                   "urn:uuid:from-payload",
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseJWTPresentation(token)

	assert.ErrorIs(t, err, ErrorJtiClaimIDMismatch)
}

func TestParseVPJWT_MissingVerifiableCredentialIsOK(t *testing.T) {
	// A vp+jwt without verifiableCredential is valid (zero credentials).
	vpPayload := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiablePresentation"},
		"holder":   "did:web:holder.example.com",
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, "did:web:holder.example.com", pres.Holder)
	assert.Empty(t, pres.Credentials())
}

func TestParseVPJWT_VerifiableCredentialNotArrayReturnsError(t *testing.T) {
	vpPayload := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": "not-an-array",
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseJWTPresentation(token)

	assert.ErrorIs(t, err, ErrorVCNotArray)
}

func TestParseVPJWT_MultipleCredentials(t *testing.T) {
	vc1 := buildEmbeddedVCJWT(t, "did:web:issuer1.example.com", "did:web:subject1.example.com")
	vc2 := buildEmbeddedVCJWT(t, "did:web:issuer2.example.com", "did:web:subject2.example.com")

	vpPayload := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{vc1, vc2},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	require.Len(t, pres.Credentials(), 2)
	assert.Equal(t, "did:web:issuer1.example.com", pres.Credentials()[0].Contents().Issuer.ID)
	assert.Equal(t, "did:web:issuer2.example.com", pres.Credentials()[1].Contents().Issuer.ID)
}

func TestParseVPJWT_MixedCredentialTypes(t *testing.T) {
	// Mix of vc+jwt string and EnvelopedVerifiableCredential in one VP.
	vcJWT := buildEmbeddedVCJWT(t, "did:web:issuer1.example.com", "did:web:subject1.example.com")
	envelopedJWT := buildEmbeddedVCJWT(t, "did:web:issuer2.example.com", "did:web:subject2.example.com")
	envelope := buildEnvelopedCredential(envelopedJWT)

	vpPayload := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{vcJWT, envelope},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	require.Len(t, pres.Credentials(), 2)
	assert.Equal(t, "did:web:issuer1.example.com", pres.Credentials()[0].Contents().Issuer.ID)
	assert.Equal(t, "did:web:issuer2.example.com", pres.Credentials()[1].Contents().Issuer.ID)
}

func TestParseVPJWT_CaseInsensitiveTypHeader(t *testing.T) {
	vpPayload := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{},
	}

	// VP+JWT in uppercase — must still be recognized as vp+jwt.
	token := buildFakeVPJWT(t, "VP+JWT", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, "did:web:holder.example.com", pres.Holder)
}

func TestParseVPJWT_ClassicJWTVPStillWorks(t *testing.T) {
	// Classic JWT VP with typ: "JWT" — must NOT go through vp+jwt path.
	classicPayload := map[string]interface{}{
		"iss": "did:web:classic-holder.example.com",
		"vp": map[string]interface{}{
			"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []interface{}{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{},
		},
	}

	token := []byte(buildFakeJWT(classicPayload))
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, "did:web:classic-holder.example.com", pres.Holder)
}

func TestParseVPJWT_NoTypHeaderUsesClassicPath(t *testing.T) {
	// JWT with no typ header and a vp claim — must use the classic path.
	payload := map[string]interface{}{
		"iss": "did:web:no-typ-holder.example.com",
		"vp": map[string]interface{}{
			"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []interface{}{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{},
		},
	}

	token := buildFakeVCJoseJWT(t, "", payload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, "did:web:no-typ-holder.example.com", pres.Holder)
}

func TestParseVPJWT_ContextAndTypeFromPayload(t *testing.T) {
	vpPayload := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/credentials/v2",
			"https://example.com/custom-context",
		},
		"type":                 []interface{}{"VerifiablePresentation", "CustomType"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, []string{"https://www.w3.org/ns/credentials/v2", "https://example.com/custom-context"}, pres.Context)
	assert.Equal(t, []string{"VerifiablePresentation", "CustomType"}, pres.Type)
}

// --- Tests for isEnvelopedVerifiableCredential ---

func TestIsEnvelopedVerifiableCredential(t *testing.T) {
	tests := []struct {
		name string
		vc   map[string]interface{}
		want bool
	}{
		{
			name: "standard EnvelopedVerifiableCredential",
			vc: map[string]interface{}{
				"type": "EnvelopedVerifiableCredential",
				"id":   "data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.payload.sig",
			},
			want: true,
		},
		{
			name: "array type with EnvelopedVerifiableCredential",
			vc: map[string]interface{}{
				"type": []interface{}{"EnvelopedVerifiableCredential"},
			},
			want: true,
		},
		{
			name: "regular VerifiableCredential",
			vc: map[string]interface{}{
				"type": []interface{}{"VerifiableCredential"},
			},
			want: false,
		},
		{
			name: "empty type",
			vc:   map[string]interface{}{},
			want: false,
		},
		{
			name: "mixed type array including EnvelopedVerifiableCredential",
			vc: map[string]interface{}{
				"type": []interface{}{"VerifiableCredential", "EnvelopedVerifiableCredential"},
			},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isEnvelopedVerifiableCredential(tc.vc))
		})
	}
}

// --- Tests for parseEnvelopedCredential ---

func TestParseEnvelopedCredential_Success(t *testing.T) {
	vcJWT := buildEmbeddedVCJWT(t, "did:web:issuer.example.com", "did:web:subject.example.com")
	envelope := buildEnvelopedCredential(vcJWT)

	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	cred, err := parser.parseEnvelopedCredential(envelope, nil)
	require.NoError(t, err)

	assert.Equal(t, common.FormatVCJWT, cred.Format())
	assert.Equal(t, "did:web:issuer.example.com", cred.Contents().Issuer.ID)
	require.Len(t, cred.Contents().Subject, 1)
	assert.Equal(t, "did:web:subject.example.com", cred.Contents().Subject[0].ID)
}

func TestParseEnvelopedCredential_MissingID(t *testing.T) {
	envelope := map[string]interface{}{
		"type": "EnvelopedVerifiableCredential",
		// no "id" field
	}

	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseEnvelopedCredential(envelope, nil)
	assert.ErrorIs(t, err, ErrorEnvelopedCredentialMissingID)
}

func TestParseEnvelopedCredential_EmptyID(t *testing.T) {
	envelope := map[string]interface{}{
		"type": "EnvelopedVerifiableCredential",
		"id":   "",
	}

	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseEnvelopedCredential(envelope, nil)
	assert.ErrorIs(t, err, ErrorEnvelopedCredentialMissingID)
}

func TestParseEnvelopedCredential_NonStringID(t *testing.T) {
	envelope := map[string]interface{}{
		"type": "EnvelopedVerifiableCredential",
		"id":   12345,
	}

	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseEnvelopedCredential(envelope, nil)
	assert.ErrorIs(t, err, ErrorEnvelopedCredentialMissingID)
}

func TestParseEnvelopedCredential_InvalidDataURIPrefix(t *testing.T) {
	envelope := map[string]interface{}{
		"type": "EnvelopedVerifiableCredential",
		"id":   "data:application/json,{\"not\":\"vc+jwt\"}",
	}

	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseEnvelopedCredential(envelope, nil)
	assert.ErrorIs(t, err, ErrorEnvelopedCredentialInvalidDataURI)
}

func TestParseEnvelopedCredential_EmptyJWSAfterPrefix(t *testing.T) {
	envelope := map[string]interface{}{
		"type": "EnvelopedVerifiableCredential",
		"id":   common.DataURISchemeVCJWT, // prefix only, no JWS
	}

	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseEnvelopedCredential(envelope, nil)
	assert.ErrorIs(t, err, ErrorEnvelopedCredentialInvalidDataURI)
}

func TestParseEnvelopedCredential_DataURIWithParameters(t *testing.T) {
	// data: URI with parameters (;base64,...) should not match the prefix.
	envelope := map[string]interface{}{
		"type": "EnvelopedVerifiableCredential",
		"id":   "data:application/vc+jwt;base64,eyJhbGciOiJFUzI1NiJ9.payload.sig",
	}

	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseEnvelopedCredential(envelope, nil)
	assert.ErrorIs(t, err, ErrorEnvelopedCredentialInvalidDataURI)
}

// --- Tests for ParsePresentation dispatching with vp+jwt ---

func TestParsePresentation_VPJWTGoesToJWTPresentationPath(t *testing.T) {
	vcJWT := buildEmbeddedVCJWT(t, "did:web:issuer.example.com", "did:web:subject.example.com")
	vpPayload := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{vcJWT},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurablePresentationParser{ProofChecker: nil}

	// ParsePresentation should see it as non-JSON (no leading '{'), route to parseJWTPresentation,
	// which should detect vp+jwt and route to parseVPJWTPresentation.
	pres, err := parser.ParsePresentation(token)
	require.NoError(t, err)

	assert.Equal(t, "did:web:holder.example.com", pres.Holder)
	require.Len(t, pres.Credentials(), 1)
}

// --- Tests for ParseWithSdJwt fallthrough for vp+jwt ---

func TestParseWithSdJwt_VPJWTFallsThrough(t *testing.T) {
	// A vp+jwt has no "vp" claim, so ParseWithSdJwt should return
	// ErrorPresentationNoCredentials — allowing tokenToPresentation to
	// fall through to ParsePresentation.
	vpPayload := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               "did:web:holder.example.com",
		"verifiableCredential": []interface{}{},
	}

	token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
	parser := &ConfigurableSdJwtParser{}
	_, err := parser.ParseWithSdJwt(token)

	assert.ErrorIs(t, err, ErrorPresentationNoCredentials,
		"vp+jwt tokens have no vp claim, so ParseWithSdJwt must return ErrorPresentationNoCredentials")
}

// --- Parameterized tests for vp+jwt edge cases ---

func TestParseVPJWT_VariousPayloads(t *testing.T) {
	tests := []struct {
		name           string
		payload        map[string]interface{}
		wantHolder     string
		wantID         string
		wantNumCreds   int
		wantContextLen int
	}{
		{
			name: "empty verifiableCredential array",
			payload: map[string]interface{}{
				"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":                 []interface{}{"VerifiablePresentation"},
				"holder":               "did:web:holder.example.com",
				"verifiableCredential": []interface{}{},
			},
			wantHolder:     "did:web:holder.example.com",
			wantNumCreds:   0,
			wantContextLen: 1,
		},
		{
			name: "single string context",
			payload: map[string]interface{}{
				"@context":             "https://www.w3.org/ns/credentials/v2",
				"type":                 "VerifiablePresentation",
				"holder":               "did:web:holder.example.com",
				"verifiableCredential": []interface{}{},
			},
			wantHolder:     "did:web:holder.example.com",
			wantNumCreds:   0,
			wantContextLen: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := buildFakeVPJWT(t, "vp+jwt", tc.payload)
			parser := &ConfigurablePresentationParser{ProofChecker: nil}
			pres, err := parser.parseJWTPresentation(token)
			require.NoError(t, err)

			assert.Equal(t, tc.wantHolder, pres.Holder)
			assert.Equal(t, tc.wantID, pres.ID)
			assert.Len(t, pres.Credentials(), tc.wantNumCreds)
			assert.Len(t, pres.Context, tc.wantContextLen)
		})
	}
}

func TestParseVPJWT_UnexpectedCredentialEntryType(t *testing.T) {
	tests := []struct {
		name  string
		entry interface{}
	}{
		{name: "null entry", entry: nil},
		{name: "number entry", entry: float64(42)},
		{name: "boolean entry", entry: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vpPayload := map[string]interface{}{
				"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
				"type":                 []interface{}{"VerifiablePresentation"},
				"holder":               "did:web:holder.example.com",
				"verifiableCredential": []interface{}{tc.entry},
			}

			token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
			parser := &ConfigurablePresentationParser{ProofChecker: nil}
			_, err := parser.parseJWTPresentation(token)

			require.Error(t, err)
			assert.ErrorIs(t, err, ErrorUnexpectedCredentialEntryType)
		})
	}
}

// --- Tests for EnvelopedVerifiableCredential in classic JWT VP ---

func TestParseJWTPresentation_WithEnvelopedCredential(t *testing.T) {
	// Classic JWT VP (typ: JWT / vp claim) carrying an EnvelopedVerifiableCredential.
	issuerDID := "did:web:issuer.example.com"
	subjectDID := "did:web:subject.example.com"
	holderDID := "did:web:holder.example.com"
	embeddedVC := buildEmbeddedVCJWT(t, issuerDID, subjectDID)

	vpPayload := map[string]interface{}{
		"iss": holderDID,
		"vp": map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":     []interface{}{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{
				buildEnvelopedCredential(embeddedVC),
			},
		},
	}

	token := []byte(buildFakeJWT(vpPayload))
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	assert.Equal(t, holderDID, pres.Holder)
	require.Len(t, pres.Credentials(), 1, "enveloped credential must be parsed")
	cred := pres.Credentials()[0]
	assert.Equal(t, issuerDID, cred.Contents().Issuer.ID)
	assert.Equal(t, common.FormatVCJWT, cred.Format())
}

func TestParseJWTPresentation_WithEnvelopedAndJWTCredentials(t *testing.T) {
	// Classic JWT VP with mixed credential types: an enveloped credential and a
	// regular JWT VC string.
	issuerDID := "did:web:issuer.example.com"
	subjectDID := "did:web:subject.example.com"
	holderDID := "did:web:holder.example.com"

	envelopedVC := buildEmbeddedVCJWT(t, issuerDID, subjectDID)
	regularVC := buildFakeJWT(map[string]interface{}{
		"iss": "did:web:other-issuer.example.com",
		"vc": map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":     []interface{}{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{
				"id":   subjectDID,
				"name": "Bob",
			},
		},
	})

	vpPayload := map[string]interface{}{
		"iss": holderDID,
		"vp": map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":     []interface{}{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{
				buildEnvelopedCredential(envelopedVC),
				regularVC,
			},
		},
	}

	token := []byte(buildFakeJWT(vpPayload))
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.parseJWTPresentation(token)
	require.NoError(t, err)

	require.Len(t, pres.Credentials(), 2, "both credentials must be parsed")
	assert.Equal(t, common.FormatVCJWT, pres.Credentials()[0].Format(), "enveloped must be vc+jwt")
	assert.Equal(t, common.FormatJWTVC, pres.Credentials()[1].Format(), "regular must be jwt_vc")
	assert.Equal(t, issuerDID, pres.Credentials()[0].Contents().Issuer.ID)
	assert.Equal(t, "did:web:other-issuer.example.com", pres.Credentials()[1].Contents().Issuer.ID)
}

func TestParseJWTPresentation_EnvelopedCredentialInvalidDataURI(t *testing.T) {
	// Classic JWT VP carrying an EnvelopedVerifiableCredential with an invalid
	// data URI — must fail with ErrorEnvelopedCredentialInvalidDataURI.
	holderDID := "did:web:holder.example.com"

	envelope := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "EnvelopedVerifiableCredential",
		"id":       "data:application/vc+jwt;base64,invalid",
	}

	vpPayload := map[string]interface{}{
		"iss": holderDID,
		"vp": map[string]interface{}{
			"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []interface{}{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{envelope},
		},
	}

	token := []byte(buildFakeJWT(vpPayload))
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseJWTPresentation(token)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorEnvelopedCredentialInvalidDataURI)
}

func TestParseJWTPresentation_EnvelopedCredentialMissingID(t *testing.T) {
	// Classic JWT VP carrying an EnvelopedVerifiableCredential without an "id"
	// field — must fail with ErrorEnvelopedCredentialMissingID.
	holderDID := "did:web:holder.example.com"

	envelope := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "EnvelopedVerifiableCredential",
		// No "id" field.
	}

	vpPayload := map[string]interface{}{
		"iss": holderDID,
		"vp": map[string]interface{}{
			"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []interface{}{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{envelope},
		},
	}

	token := []byte(buildFakeJWT(vpPayload))
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	_, err := parser.parseJWTPresentation(token)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorEnvelopedCredentialMissingID)
}

func TestParseJWTPresentation_NonEnvelopedMapStillFallsThrough(t *testing.T) {
	// Classic JWT VP with a map credential that is NOT an EnvelopedVerifiableCredential
	// — must fall through to the JSON-LD credential parsing path.
	// Without a configured LDProofChecker, an unsigned JSON-LD VC is rejected.
	holderDID := "did:web:holder.example.com"

	jsonldVC := map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:web:issuer.example.com",
		"credentialSubject": map[string]interface{}{
			"id":   "did:web:subject.example.com",
			"name": "Alice",
		},
	}

	vpPayload := map[string]interface{}{
		"iss": holderDID,
		"vp": map[string]interface{}{
			"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []interface{}{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{jsonldVC},
		},
	}

	token := []byte(buildFakeJWT(vpPayload))
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	// Without LDProofChecker configured, the unsigned JSON-LD credential must
	// be rejected — proving the non-enveloped path is still used.
	_, err := parser.parseJWTPresentation(token)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorUnsignedCredential)
}

// --- Tests for EnvelopedVerifiableCredential in JSON-LD VP ---

func TestParseJSONLDPresentation_WithEnvelopedCredential(t *testing.T) {
	// JSON-LD VP (V2 context) with an EnvelopedVerifiableCredential inside the
	// verifiableCredential array. The VP is properly signed with an LD proof,
	// and the enveloped credential is a fake vc+jwt (unsigned, no ProofChecker).
	// The VP must use V2 context because EnvelopedVerifiableCredential is a V2
	// type and V1+V2 contexts cannot coexist (protected term redefinition).
	docLoader := newTestDocumentLoader()

	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)
	holderSigner := &testES256Signer{key: holderPrivKey}

	registry := createMultiKeyRegistry(t, map[string]ljwk.Key{
		testHolderKeyID: holderPubJWK,
	})
	checker := NewLDProofChecker(registry, docLoader)

	issuerDID := "did:web:issuer.example.com"
	subjectDID := testHolderDID // subject == holder for holder binding
	envelopedVC := buildEnvelopedCredential(buildEmbeddedVCJWT(t, issuerDID, subjectDID))

	vpJSON := signVPWithCredentialsV2(t, holderSigner, testHolderKeyID, docLoader,
		[]interface{}{envelopedVC},
		ldProofTestOptions{proofPurpose: common.ProofPurposeAuthentication})

	parser := &ConfigurablePresentationParser{
		ProofChecker:   nil, // No JWT proof checker — enveloped JWT is unsigned for this test.
		LDProofChecker: checker,
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err, "JSON-LD VP with enveloped credential must parse successfully")
	require.NotNil(t, result)
	require.Len(t, result.Credentials(), 1, "the enveloped credential must be extracted")
	assert.Equal(t, issuerDID, result.Credentials()[0].Contents().Issuer.ID)
	assert.Equal(t, common.FormatVCJWT, result.Credentials()[0].Format())
	assert.NotNil(t, result.HolderKey(), "holder key must be populated from the VP LD proof")
}

func TestParseJSONLDPresentation_EnvelopedAndSignedLDCredentials(t *testing.T) {
	// JSON-LD VP (V2 context) with mixed credential types: one enveloped
	// vc+jwt credential and one properly signed JSON-LD credential. The VP
	// uses V2 context because EnvelopedVerifiableCredential requires V2.
	docLoader := newTestDocumentLoader()

	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)
	holderSigner := &testES256Signer{key: holderPrivKey}

	issuerPrivKey, _, issuerPubJWK := generateTestECKeys(t)
	issuerSigner := &testES256Signer{key: issuerPrivKey}

	registry := createMultiKeyRegistry(t, map[string]ljwk.Key{
		testHolderKeyID: holderPubJWK,
		testIssuerKeyID: issuerPubJWK,
	})
	checker := NewLDProofChecker(registry, docLoader)

	// A properly signed JSON-LD credential (uses V1 context internally, but
	// that's fine — credential contexts are independent of the VP context).
	signedVC := signTestCredential(t, testIssuerDID, issuerSigner, testIssuerKeyID, docLoader)

	// An enveloped vc+jwt credential from a different issuer.
	envelopedIssuer := "did:web:enveloped-issuer.example.com"
	envelopedVC := buildEnvelopedCredential(buildEmbeddedVCJWT(t, envelopedIssuer, testHolderDID))

	vpJSON := signVPWithCredentialsV2(t, holderSigner, testHolderKeyID, docLoader,
		[]interface{}{signedVC, envelopedVC},
		ldProofTestOptions{proofPurpose: common.ProofPurposeAuthentication})

	parser := &ConfigurablePresentationParser{
		ProofChecker:   nil,
		LDProofChecker: checker,
	}

	result, err := parser.ParsePresentation(vpJSON)
	require.NoError(t, err, "JSON-LD VP with mixed credential types must parse")
	require.Len(t, result.Credentials(), 2)

	// First credential is the signed JSON-LD VC.
	assert.Equal(t, common.FormatLDPVC, result.Credentials()[0].Format())
	assert.Equal(t, testIssuerDID, result.Credentials()[0].Contents().Issuer.ID)

	// Second credential is the enveloped vc+jwt.
	assert.Equal(t, common.FormatVCJWT, result.Credentials()[1].Format())
	assert.Equal(t, envelopedIssuer, result.Credentials()[1].Contents().Issuer.ID)
}

func TestParseJSONLDPresentation_EnvelopedCredentialInvalidDataURI(t *testing.T) {
	// JSON-LD VP (V2 context) with an EnvelopedVerifiableCredential whose data
	// URI has parameters (;base64,...) — must fail with
	// ErrorEnvelopedCredentialInvalidDataURI.
	docLoader := newTestDocumentLoader()

	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)
	holderSigner := &testES256Signer{key: holderPrivKey}

	registry := createMultiKeyRegistry(t, map[string]ljwk.Key{
		testHolderKeyID: holderPubJWK,
	})
	checker := NewLDProofChecker(registry, docLoader)

	invalidEnvelope := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "EnvelopedVerifiableCredential",
		"id":       "data:application/vc+jwt;base64,invalid-encoding",
	}

	vpJSON := signVPWithCredentialsV2(t, holderSigner, testHolderKeyID, docLoader,
		[]interface{}{invalidEnvelope},
		ldProofTestOptions{proofPurpose: common.ProofPurposeAuthentication})

	parser := &ConfigurablePresentationParser{
		ProofChecker:   nil,
		LDProofChecker: checker,
	}

	_, err := parser.ParsePresentation(vpJSON)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorEnvelopedCredentialInvalidDataURI)
}

func TestParseJSONLDPresentation_EnvelopedCredentialMissingID(t *testing.T) {
	// JSON-LD VP (V2 context) with an EnvelopedVerifiableCredential without an
	// "id" field — must fail with ErrorEnvelopedCredentialMissingID.
	docLoader := newTestDocumentLoader()

	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)
	holderSigner := &testES256Signer{key: holderPrivKey}

	registry := createMultiKeyRegistry(t, map[string]ljwk.Key{
		testHolderKeyID: holderPubJWK,
	})
	checker := NewLDProofChecker(registry, docLoader)

	invalidEnvelope := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "EnvelopedVerifiableCredential",
		// No "id" field.
	}

	vpJSON := signVPWithCredentialsV2(t, holderSigner, testHolderKeyID, docLoader,
		[]interface{}{invalidEnvelope},
		ldProofTestOptions{proofPurpose: common.ProofPurposeAuthentication})

	parser := &ConfigurablePresentationParser{
		ProofChecker:   nil,
		LDProofChecker: checker,
	}

	_, err := parser.ParsePresentation(vpJSON)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorEnvelopedCredentialMissingID)
}

func TestParseJSONLDPresentation_NonEnvelopedUnsignedVCStillRejected(t *testing.T) {
	// JSON-LD VP with a non-enveloped, unsigned JSON-LD credential must still
	// be rejected — proving the regular JSON-LD path is not bypassed.
	docLoader := newTestDocumentLoader()

	holderPrivKey, _, holderPubJWK := generateTestECKeys(t)
	holderSigner := &testES256Signer{key: holderPrivKey}

	registry := createMultiKeyRegistry(t, map[string]ljwk.Key{
		testHolderKeyID: holderPubJWK,
	})
	checker := NewLDProofChecker(registry, docLoader)

	unsignedVC := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/2018/credentials/v1",
			common.ContextSecuritySuiteJWS2020,
		},
		"type":   []interface{}{"VerifiableCredential"},
		"issuer": testIssuerDID,
		"credentialSubject": map[string]interface{}{
			"id":   testHolderDID,
			"name": "Alice",
		},
	}

	vpJSON := signVPWithCredentials(t, holderSigner, testHolderKeyID, docLoader,
		[]interface{}{unsignedVC},
		ldProofTestOptions{proofPurpose: common.ProofPurposeAuthentication})

	parser := &ConfigurablePresentationParser{
		ProofChecker:   nil,
		LDProofChecker: checker,
	}

	_, err := parser.ParsePresentation(vpJSON)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorUnsignedCredential,
		"non-enveloped unsigned credentials must still be rejected via the JSON-LD path")
}

// --- Tests for ParsePresentation dispatch with enveloped credentials ---

func TestParsePresentation_DispatchesEnvelopedInClassicJWTVP(t *testing.T) {
	// Verify the top-level ParsePresentation correctly handles a classic JWT VP
	// with an enveloped credential via the parseJWTPresentation path.
	issuerDID := "did:web:issuer.example.com"
	subjectDID := "did:web:subject.example.com"
	holderDID := "did:web:holder.example.com"
	envelopedVC := buildEnvelopedCredential(buildEmbeddedVCJWT(t, issuerDID, subjectDID))

	vpPayload := map[string]interface{}{
		"iss": holderDID,
		"vp": map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/2018/credentials/v1"},
			"type":     []interface{}{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{
				envelopedVC,
			},
		},
	}

	token := []byte(buildFakeJWT(vpPayload))
	parser := &ConfigurablePresentationParser{ProofChecker: nil}
	pres, err := parser.ParsePresentation(token)
	require.NoError(t, err)

	require.Len(t, pres.Credentials(), 1)
	assert.Equal(t, common.FormatVCJWT, pres.Credentials()[0].Format())
	assert.Equal(t, issuerDID, pres.Credentials()[0].Contents().Issuer.ID)
}

// --- Parameterized test for enveloped credentials across JWT-based VP types ---

func TestEnvelopedCredential_InJWTVPTypes(t *testing.T) {
	issuerDID := "did:web:issuer.example.com"
	subjectDID := "did:web:subject.example.com"
	holderDID := "did:web:holder.example.com"
	embeddedVC := buildEmbeddedVCJWT(t, issuerDID, subjectDID)
	envelope := buildEnvelopedCredential(embeddedVC)

	tests := []struct {
		name    string
		builder func(t *testing.T) []byte
	}{
		{
			name: "classic JWT VP",
			builder: func(t *testing.T) []byte {
				vpPayload := map[string]interface{}{
					"iss": holderDID,
					"vp": map[string]interface{}{
						"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1"},
						"type":                 []interface{}{"VerifiablePresentation"},
						"verifiableCredential": []interface{}{envelope},
					},
				}
				return []byte(buildFakeJWT(vpPayload))
			},
		},
		{
			name: "vp+jwt VP",
			builder: func(t *testing.T) []byte {
				vpPayload := map[string]interface{}{
					"@context":             []interface{}{"https://www.w3.org/ns/credentials/v2"},
					"type":                 []interface{}{"VerifiablePresentation"},
					"holder":               holderDID,
					"verifiableCredential": []interface{}{envelope},
				}
				return buildFakeVPJWT(t, "vp+jwt", vpPayload)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := tc.builder(t)
			parser := &ConfigurablePresentationParser{ProofChecker: nil}
			pres, err := parser.ParsePresentation(token)
			require.NoError(t, err)

			assert.Equal(t, holderDID, pres.Holder)
			require.Len(t, pres.Credentials(), 1)
			assert.Equal(t, common.FormatVCJWT, pres.Credentials()[0].Format())
			assert.Equal(t, issuerDID, pres.Credentials()[0].Contents().Issuer.ID)
		})
	}
}

// --- VC-JOSE-COSE issuer/holder binding regression tests ---

// signVCJoseJWT signs a compact JWT carrying the given JOSE typ header. Unlike
// buildFakeVCJoseJWT the signature is real, so the token can be put through a
// parser with a live ProofChecker.
func signVCJoseJWT(t *testing.T, privKey ljwk.Key, typ string, kid string, payload map[string]interface{}) []byte {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	headers := jws.NewHeaders()
	if typ != "" {
		require.NoError(t, headers.Set("typ", typ))
	}
	if kid != "" {
		require.NoError(t, headers.Set(jws.KeyIDKey, kid))
	}

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), privKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

// vcJoseTestParser builds a parser with a live proof checker that resolves
// did:jwk without any network access.
func vcJoseTestParser() *ConfigurablePresentationParser {
	return &ConfigurablePresentationParser{
		ProofChecker: NewJWTProofChecker(did.NewRegistry(did.WithVDR(did.NewJWKVDR()))),
	}
}

// TestParseVCJoseCredential_IssuerBinding is the regression test for the
// vc+jwt issuer forgery.
//
// A vc+jwt has no iss claim: the issuer is the credential's own `issuer`
// property. While the key was resolved from the kid, a credential signed with a
// self-generated did:jwk key could name any trusted issuer in `issuer` and be
// accepted — and `issuer` is exactly what the trusted-issuer registry lookups
// key off, so that was full issuer impersonation.
func TestParseVCJoseCredential_IssuerBinding(t *testing.T) {
	signerKey, signerDID := generateTestKeyAndDIDJWK(t)
	_, otherDID := generateTestKeyAndDIDJWK(t)

	tests := []struct {
		name    string
		kid     string
		iss     string
		issuer  interface{}
		wantErr error
		// anyErr marks a case that must fail without naming which check catches
		// it: with no kid the forgery is caught by signature verification against
		// the claimed issuer's key, whose error is the jwx library's.
		anyErr bool
	}{
		{
			// The forgery: signed by the attacker, attributed to somebody else.
			name:    "issuer property names a DID the signer does not control",
			kid:     signerDID + "#0",
			issuer:  otherDID,
			wantErr: ErrorIssuerKeyMismatch,
		},
		{
			// The same forgery without a kid to give it away: resolution now
			// follows the claimed issuer, whose key cannot verify this signature.
			name:   "issuer property names another DID, no kid",
			kid:    "",
			issuer: otherDID,
			anyErr: true,
		},
		{
			name:   "issuer property names the signer",
			kid:    signerDID + "#0",
			issuer: signerDID,
		},
		{
			name:   "issuer property names the signer, no kid",
			kid:    "",
			issuer: signerDID,
		},
		{
			name:   "issuer as an object with an id",
			kid:    signerDID + "#0",
			issuer: map[string]interface{}{"id": signerDID, "name": "Test Issuer"},
		},
		{
			name:   "iss claim agreeing with the issuer property",
			kid:    signerDID + "#0",
			iss:    signerDID,
			issuer: signerDID,
		},
		{
			name:    "iss claim disagreeing with the issuer property",
			kid:     signerDID + "#0",
			iss:     signerDID,
			issuer:  otherDID,
			wantErr: ErrorIssClaimIssuerMismatch,
		},
		{
			name:    "no issuer at all",
			kid:     signerDID + "#0",
			wantErr: ErrorVCJWTNoIssuer,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]interface{}{
				common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
				common.JSONLDKeyType:    []interface{}{"VerifiableCredential"},
				"credentialSubject":     map[string]interface{}{"id": "did:web:subject.example.com"},
			}
			if tc.iss != "" {
				payload[common.JWTClaimIss] = tc.iss
			}
			if tc.issuer != nil {
				payload[common.VCKeyIssuer] = tc.issuer
			}

			token := signVCJoseJWT(t, signerKey, common.JWTTypVCJWT, tc.kid, payload)
			cred, err := vcJoseTestParser().parseJWTCredential(token)

			if tc.anyErr {
				assert.Error(t, err)
				assert.Nil(t, cred)
				return
			}
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, cred)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cred.Contents().Issuer)
			assert.Equal(t, signerDID, cred.Contents().Issuer.ID,
				"the parsed issuer must be the identity the signature was checked against")
			assert.Equal(t, common.FormatVCJWT, cred.Format())
		})
	}
}

// TestParseVCJoseCredential_TamperedPayloadRejected checks that the credential
// is read from the verified payload and not from the unverified first pass: a
// token whose payload was edited after signing must not parse at all.
func TestParseVCJoseCredential_TamperedPayloadRejected(t *testing.T) {
	signerKey, signerDID := generateTestKeyAndDIDJWK(t)

	token := signVCJoseJWT(t, signerKey, common.JWTTypVCJWT, signerDID+"#0", map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
		common.JSONLDKeyType:    []interface{}{"VerifiableCredential"},
		common.VCKeyIssuer:      signerDID,
		"credentialSubject":     map[string]interface{}{"id": "did:web:subject.example.com"},
	})

	// Swap the payload segment for one claiming a different subject, keeping the
	// issuer so the first pass still resolves the signer's key.
	parts := strings.SplitN(string(token), ".", 3)
	require.Len(t, parts, 3)
	tamperedPayload, err := json.Marshal(map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
		common.JSONLDKeyType:    []interface{}{"VerifiableCredential"},
		common.VCKeyIssuer:      signerDID,
		"credentialSubject":     map[string]interface{}{"id": "did:web:attacker.example.com"},
	})
	require.NoError(t, err)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tamperedPayload) + "." + parts[2]

	cred, err := vcJoseTestParser().parseJWTCredential([]byte(tampered))
	assert.Error(t, err, "a payload edited after signing must not verify")
	assert.Nil(t, cred)
}

// TestParseVPJosePresentation_HolderBinding is the regression test for the
// vp+jwt holder spoof.
//
// Presentation.Holder becomes the subject of the issued access token and drives
// holder policy validation. While it came from the unverified payload, a
// presentation signed with a self-generated key could claim any holder DID.
func TestParseVPJosePresentation_HolderBinding(t *testing.T) {
	signerKey, signerDID := generateTestKeyAndDIDJWK(t)
	_, otherDID := generateTestKeyAndDIDJWK(t)

	tests := []struct {
		name       string
		kid        string
		holder     string
		iss        string
		wantErr    error
		anyErr     bool
		wantHolder string
	}{
		{
			// The spoof: signed by the attacker, presented as somebody else.
			name:    "holder names a DID the signer does not control",
			kid:     signerDID + "#0",
			holder:  otherDID,
			wantErr: ErrorIssuerKeyMismatch,
		},
		{
			name:   "holder names another DID, no kid",
			kid:    "",
			holder: otherDID,
			anyErr: true,
		},
		{
			name:       "holder names the signer",
			kid:        signerDID + "#0",
			holder:     signerDID,
			wantHolder: signerDID,
		},
		{
			name:       "holder names the signer, no kid",
			kid:        "",
			holder:     signerDID,
			wantHolder: signerDID,
		},
		{
			name:       "iss alone stands in for an absent holder",
			kid:        signerDID + "#0",
			iss:        signerDID,
			wantHolder: signerDID,
		},
		{
			name:    "iss disagreeing with holder",
			kid:     signerDID + "#0",
			holder:  signerDID,
			iss:     otherDID,
			wantErr: ErrorIssClaimHolderMismatch,
		},
		{
			name:    "no holder and no iss",
			kid:     signerDID + "#0",
			wantErr: ErrorVPJWTNoHolder,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]interface{}{
				common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
				common.JSONLDKeyType:    []interface{}{"VerifiablePresentation"},
			}
			if tc.holder != "" {
				payload[common.VPKeyHolder] = tc.holder
			}
			if tc.iss != "" {
				payload[common.JWTClaimIss] = tc.iss
			}

			token := signVCJoseJWT(t, signerKey, common.JWTTypVPJWT, tc.kid, payload)
			pres, err := vcJoseTestParser().parsePresentationForTest(token)

			if tc.anyErr {
				assert.Error(t, err)
				assert.Nil(t, pres)
				return
			}
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, pres)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantHolder, pres.Holder,
				"the parsed holder must be the identity the signature was checked against")
			assert.NotNil(t, pres.HolderKey())
		})
	}
}

// parsePresentationForTest exposes the JWT presentation path under a stable
// name for the binding tests.
func (cpp *ConfigurablePresentationParser) parsePresentationForTest(token []byte) (*common.Presentation, error) {
	return cpp.parseJWTPresentation(token)
}

// --- Exhaustive JOSE typ dispatch ---

// TestNormalizeJOSEType covers the spellings RFC 7515 §4.1.9 makes equivalent.
func TestNormalizeJOSEType(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "plain", value: "vc+jwt", want: "vc+jwt"},
		{name: "with the application prefix", value: "application/vc+jwt", want: "vc+jwt"},
		{name: "upper case", value: "VC+JWT", want: "vc+jwt"},
		{name: "upper case with prefix", value: "Application/VC+JWT", want: "vc+jwt"},
		{name: "surrounding whitespace", value: "  vp+jwt  ", want: "vp+jwt"},
		{name: "empty", value: "", want: ""},
		{name: "unrelated type is left alone", value: "at+jwt", want: "at+jwt"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeJOSEType(tc.value))
		})
	}
}

// TestJWTTypeDispatchIsExhaustive checks that a token is parsed as the format
// its typ header declares, in every spelling of it, and rejected when the type
// does not belong in the position it was found in.
//
// The failure this prevents is not a missed rejection but a silent
// reinterpretation: dispatch used to fall through to the classic parser, so a
// vp+jwt in a credential position parsed as a legacy JWT-VC with no "vc" claim
// — no error and an all-but-empty credential — and any spelling of vc+jwt that
// the comparison missed was quietly downgraded to the legacy format.
func TestJWTTypeDispatchIsExhaustive(t *testing.T) {
	signerKey, signerDID := generateTestKeyAndDIDJWK(t)

	credentialPayload := map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
		common.JSONLDKeyType:    []interface{}{"VerifiableCredential"},
		common.VCKeyIssuer:      signerDID,
		"credentialSubject":     map[string]interface{}{"id": "did:web:subject.example.com"},
	}
	classicPayload := map[string]interface{}{
		common.JWTClaimIss: signerDID,
		common.JWTClaimVC: map[string]interface{}{
			common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV1},
			common.JSONLDKeyType:    []interface{}{"VerifiableCredential"},
			"credentialSubject":     map[string]interface{}{"id": "did:web:subject.example.com"},
		},
	}
	presentationPayload := map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
		common.JSONLDKeyType:    []interface{}{"VerifiablePresentation"},
		common.VPKeyHolder:      signerDID,
	}
	classicVPPayload := map[string]interface{}{
		common.JWTClaimIss: signerDID,
		common.JWTClaimVP: map[string]interface{}{
			common.JSONLDKeyType: []interface{}{"VerifiablePresentation"},
		},
	}

	t.Run("credential position", func(t *testing.T) {
		tests := []struct {
			name       string
			typ        string
			payload    map[string]interface{}
			wantFormat string
			wantErr    error
		}{
			{name: "vc+jwt", typ: "vc+jwt", payload: credentialPayload, wantFormat: common.FormatVCJWT},
			{name: "application/vc+jwt", typ: "application/vc+jwt", payload: credentialPayload, wantFormat: common.FormatVCJWT},
			{name: "VC+JWT", typ: "VC+JWT", payload: credentialPayload, wantFormat: common.FormatVCJWT},
			{name: "Application/VC+JWT", typ: "Application/VC+JWT", payload: credentialPayload, wantFormat: common.FormatVCJWT},
			{name: "no typ is the classic format", typ: "", payload: classicPayload, wantFormat: common.FormatJWTVC},
			{name: "JWT is the classic format", typ: "JWT", payload: classicPayload, wantFormat: common.FormatJWTVC},
			{name: "a presentation is not a credential", typ: "vp+jwt", payload: presentationPayload, wantErr: ErrorUnexpectedJWTType},
			{name: "an unknown type is rejected", typ: "at+jwt", payload: classicPayload, wantErr: ErrorUnexpectedJWTType},
			{name: "an SD-JWT type is rejected", typ: "sd-jwt", payload: classicPayload, wantErr: ErrorUnexpectedJWTType},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				token := signVCJoseJWT(t, signerKey, tc.typ, signerDID+"#0", tc.payload)
				cred, err := vcJoseTestParser().parseJWTCredential(token)

				if tc.wantErr != nil {
					assert.ErrorIs(t, err, tc.wantErr)
					assert.Nil(t, cred)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tc.wantFormat, cred.Format())
			})
		}
	})

	t.Run("presentation position", func(t *testing.T) {
		tests := []struct {
			name    string
			typ     string
			payload map[string]interface{}
			wantErr error
		}{
			{name: "vp+jwt", typ: "vp+jwt", payload: presentationPayload},
			{name: "application/vp+jwt", typ: "application/vp+jwt", payload: presentationPayload},
			{name: "VP+JWT", typ: "VP+JWT", payload: presentationPayload},
			{name: "no typ is the classic format", typ: "", payload: classicVPPayload},
			{name: "JWT is the classic format", typ: "JWT", payload: classicVPPayload},
			{name: "a credential is not a presentation", typ: "vc+jwt", payload: credentialPayload, wantErr: ErrorUnexpectedJWTType},
			{name: "an unknown type is rejected", typ: "at+jwt", payload: classicVPPayload, wantErr: ErrorUnexpectedJWTType},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				token := signVCJoseJWT(t, signerKey, tc.typ, signerDID+"#0", tc.payload)
				pres, err := vcJoseTestParser().parsePresentationForTest(token)

				if tc.wantErr != nil {
					assert.ErrorIs(t, err, tc.wantErr)
					assert.Nil(t, pres)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, signerDID, pres.Holder)
			})
		}
	})
}

// TestJWTContentTypeMustAgreeWithType checks the optional cty header: a token
// whose own headers disagree about what it contains is rejected rather than
// resolved in favour of one of them.
func TestJWTContentTypeMustAgreeWithType(t *testing.T) {
	signerKey, signerDID := generateTestKeyAndDIDJWK(t)

	tests := []struct {
		name    string
		cty     string
		wantErr error
	}{
		{name: "cty absent", cty: ""},
		{name: "cty vc", cty: "vc"},
		{name: "cty application/vc", cty: "application/vc"},
		{name: "cty VC", cty: "VC"},
		{name: "cty vp on a credential", cty: "vp", wantErr: ErrorUnexpectedJWTType},
		{name: "cty of an unrelated type", cty: "json", wantErr: ErrorUnexpectedJWTType},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]interface{}{
				common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
				common.JSONLDKeyType:    []interface{}{"VerifiableCredential"},
				common.VCKeyIssuer:      signerDID,
			}
			token := signVCJoseJWTWithCty(t, signerKey, common.JWTTypVCJWT, tc.cty, signerDID+"#0", payload)
			cred, err := vcJoseTestParser().parseJWTCredential(token)

			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, cred)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, common.FormatVCJWT, cred.Format())
		})
	}
}

// signVCJoseJWTWithCty signs a compact JWT carrying both a typ and a cty header.
func signVCJoseJWTWithCty(t *testing.T, privKey ljwk.Key, typ, cty, kid string, payload map[string]interface{}) []byte {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set("typ", typ))
	if cty != "" {
		require.NoError(t, headers.Set("cty", cty))
	}
	require.NoError(t, headers.Set(jws.KeyIDKey, kid))

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), privKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

// TestParseEnvelopedCredential_MediaTypeBinding checks that the envelope's
// declared media type constrains what is inside it and that the data: URI is
// matched on RFC 2397's terms.
func TestParseEnvelopedCredential_MediaTypeBinding(t *testing.T) {
	signerKey, signerDID := generateTestKeyAndDIDJWK(t)

	vcJose := string(signVCJoseJWT(t, signerKey, common.JWTTypVCJWT, signerDID+"#0", map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
		common.JSONLDKeyType:    []interface{}{"VerifiableCredential"},
		common.VCKeyIssuer:      signerDID,
	}))
	classic := string(signVCJoseJWT(t, signerKey, "", signerDID+"#0", map[string]interface{}{
		common.JWTClaimIss: signerDID,
		common.JWTClaimVC: map[string]interface{}{
			common.JSONLDKeyType: []interface{}{"VerifiableCredential"},
		},
	}))

	tests := []struct {
		name    string
		id      string
		wantErr error
	}{
		{
			name: "a vc+jwt under the vc+jwt media type",
			id:   "data:application/vc+jwt," + vcJose,
		},
		{
			// RFC 2397 makes the scheme and media type case-insensitive.
			name: "the media type spelled in mixed case",
			id:   "Data:Application/VC+JWT," + vcJose,
		},
		{
			// The envelope says vc+jwt; parseJWTCredential re-dispatches on the
			// inner typ, so without this check the label meant nothing.
			name:    "a legacy JWT-VC under the vc+jwt media type",
			id:      "data:application/vc+jwt," + classic,
			wantErr: ErrorEnvelopedCredentialInvalidDataURI,
		},
		{
			name:    "a base64 data URI variant",
			id:      "data:application/vc+jwt;base64," + vcJose,
			wantErr: ErrorEnvelopedCredentialInvalidDataURI,
		},
		{
			name:    "an unexpected media type",
			id:      "data:application/json," + vcJose,
			wantErr: ErrorEnvelopedCredentialInvalidDataURI,
		},
		{
			name:    "an empty payload after the media type",
			id:      "data:application/vc+jwt,",
			wantErr: ErrorEnvelopedCredentialInvalidDataURI,
		},
		{
			name:    "not a data URI at all",
			id:      "https://example.com/credentials/1",
			wantErr: ErrorEnvelopedCredentialInvalidDataURI,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			envelope := map[string]interface{}{
				common.JSONLDKeyContext: common.ContextCredentialsV2,
				common.JSONLDKeyType:    common.TypeEnvelopedVerifiableCredential,
				"id":                    tc.id,
			}

			cred, err := vcJoseTestParser().parseEnvelopedCredential(envelope, nil)

			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, cred)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, common.FormatVCJWT, cred.Format())
		})
	}
}

// --- VC-JOSE-COSE well-formedness ---

// TestVCJoseReservedClaimsRejected covers VC-JOSE-COSE §1.1.2.1: "The JWT Claim
// Names `vc` and `vp` MUST NOT be present in any JWT Claims Set that comprises
// a verifiable credential or presentation."
//
// The mapping used to ignore such a claim, which is worse than accepting it:
// the token then describes two documents at once and which one a verifier reads
// depends on how it dispatches.
func TestVCJoseReservedClaimsRejected(t *testing.T) {
	tests := []struct {
		name     string
		reserved string
	}{
		{name: "vc claim", reserved: common.JWTClaimVC},
		{name: "vp claim", reserved: common.JWTClaimVP},
	}

	for _, tc := range tests {
		t.Run("credential with a "+tc.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"iss":                   "did:web:issuer.example.com",
				common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
				common.JSONLDKeyType:    []interface{}{"VerifiableCredential"},
				tc.reserved:             map[string]interface{}{"type": []interface{}{"VerifiableCredential"}},
			}

			_, err := vcJwtClaimsToCredential(claims)
			assert.ErrorIs(t, err, ErrorVCJoseReservedClaim)
		})

		t.Run("presentation with a "+tc.name, func(t *testing.T) {
			vpPayload := map[string]interface{}{
				common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
				common.JSONLDKeyType:    []interface{}{"VerifiablePresentation"},
				common.VPKeyHolder:      "did:web:holder.example.com",
				tc.reserved:             map[string]interface{}{"type": []interface{}{"VerifiablePresentation"}},
			}

			token := buildFakeVPJWT(t, "vp+jwt", vpPayload)
			parser := &ConfigurablePresentationParser{ProofChecker: nil}
			_, err := parser.parseJWTPresentation(token)
			assert.ErrorIs(t, err, ErrorVCJoseReservedClaim)
		})
	}
}

// TestVCJoseCredentialMustBeDataModel2 covers VC-JOSE-COSE §3.1.1: a vc+jwt
// secures a VCDM 2.0 document.
//
// The check lives in the parser rather than in the configurable version gate:
// verifier.vcDataModelVersions selects which data models are acceptable, and
// its default accepts 1.1, so leaving it to the gate meant a v1.1 payload could
// be presented as a vc+jwt out of the box.
func TestVCJoseCredentialMustBeDataModel2(t *testing.T) {
	tests := []struct {
		name    string
		context interface{}
		wantErr error
	}{
		{
			name:    "VCDM 2.0 base context",
			context: []interface{}{common.ContextCredentialsV2},
		},
		{
			name:    "VCDM 2.0 base context with an extension",
			context: []interface{}{common.ContextCredentialsV2, "https://example.com/vocab/v1"},
		},
		{
			name:    "VCDM 1.1 base context",
			context: []interface{}{common.ContextCredentialsV1},
			wantErr: ErrorVCJWTNotDataModel2,
		},
		{
			name:    "both base contexts declare no version",
			context: []interface{}{common.ContextCredentialsV2, common.ContextCredentialsV1},
			wantErr: ErrorVCJWTNotDataModel2,
		},
		{
			name:    "an unrecognized first context",
			context: []interface{}{"https://example.com/vocab/v1", common.ContextCredentialsV2},
			wantErr: ErrorVCJWTNotDataModel2,
		},
		{
			name:    "no context at all",
			context: nil,
			wantErr: ErrorVCJWTNotDataModel2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"iss":                "did:web:issuer.example.com",
				common.JSONLDKeyType: []interface{}{"VerifiableCredential"},
			}
			if tc.context != nil {
				claims[common.JSONLDKeyContext] = tc.context
			}

			cred, err := vcJwtClaimsToCredential(claims)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, cred)
		})
	}
}

// TestVCJoseCredentialDataModelGateIgnoresConfig checks that the vc+jwt version
// requirement holds even when the configurable gate would accept 1.1 — the two
// answer different questions.
func TestVCJoseCredentialDataModelGateIgnoresConfig(t *testing.T) {
	signerKey, signerDID := generateTestKeyAndDIDJWK(t)

	token := signVCJoseJWT(t, signerKey, common.JWTTypVCJWT, signerDID+"#0", map[string]interface{}{
		common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV1},
		common.JSONLDKeyType:    []interface{}{"VerifiableCredential"},
		common.VCKeyIssuer:      signerDID,
	})

	cred, err := vcJoseTestParser().parseJWTCredential(token)
	assert.ErrorIs(t, err, ErrorVCJWTNotDataModel2)
	assert.Nil(t, cred)
}
