package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testStatusListCredentialJSONLD is a valid JSON-LD Bitstring Status List
// credential used to exercise successful fetch + parse paths. The encoded
// bitstring itself is arbitrary — this test only cares that the body parses
// as a VC; bitstring decoding is covered separately in common/.
const testStatusListCredentialJSONLD = `{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "id": "https://example.com/status/1",
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "did:example:issuer",
  "credentialSubject": {
    "id": "https://example.com/status/1#list",
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "H4sIAAAAAAAA_2NgAAMAAAAEAAEAAAAA"
  }
}`

// testStatusListIssuer is the issuer of both status-list fixtures above. A
// status list is only accepted when it was issued by the issuer of the
// credential that referenced it, so the tests have to name it explicitly.
const testStatusListIssuer = "did:example:issuer"

// testStatusListCacheExpiry is long enough to keep entries cached for the
// entire test run but still short enough to make an accidental stale cache
// visible if the test is re-run in a persistent process.
const testStatusListCacheExpiry = time.Minute

// testStatusListHTTPTimeout is deliberately small — the tests exchange
// fixture payloads with an in-process httptest server so any request taking
// longer than this indicates a hang.
const testStatusListHTTPTimeout = 2 * time.Second

// TestCachingStatusListClientFetch covers Fetch's response-handling branches:
// successful fetch, non-2xx status propagation, and unparseable-body failure.
// Parameterising the HTTP response keeps the success and failure paths in one
// table and matches the repository's existing testing style.
func TestCachingStatusListClientFetch(t *testing.T) {
	type serverResp struct {
		status int
		body   string
	}
	tests := []struct {
		name     string
		response serverResp
		wantErr  error
	}{
		{name: "jsonld_rejected", response: serverResp{http.StatusOK, testStatusListCredentialJSONLD}, wantErr: ErrorStatusListJSONLDProofUnsupported},
		{name: "http_5xx", response: serverResp{http.StatusInternalServerError, "boom"}, wantErr: ErrorStatusListHttpFailure},
		{name: "http_4xx", response: serverResp{http.StatusNotFound, "missing"}, wantErr: ErrorStatusListHttpFailure},
		{name: "unparseable_body", response: serverResp{http.StatusOK, "not json at all"}, wantErr: ErrorStatusListUnparseable},
		{name: "unparseable_json_fragment", response: serverResp{http.StatusOK, "{not:valid"}, wantErr: ErrorStatusListJSONLDProofUnsupported},
		{name: "empty_body", response: serverResp{http.StatusOK, ""}, wantErr: ErrorStatusListUnparseable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.response.status)
				_, _ = w.Write([]byte(tc.response.body))
			}))
			defer srv.Close()

			client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry, nil, nil)
			cred, err := client.Fetch(srv.URL, testStatusListIssuer)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, cred)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cred)
		})
	}
}

// TestCachingStatusListClientCache verifies that a second call to Fetch for
// the same URL is served from the cache and does not hit the origin again.
// Uses a JWT body since JSON-LD status list credentials are now rejected
// (LD-proof verification is not yet supported).
func TestCachingStatusListClientCache(t *testing.T) {
	var hits int32
	jwtBody := testStatusListVCJWT
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", ContentTypeCredentialJWT)
		_, _ = w.Write([]byte(jwtBody))
	}))
	defer srv.Close()

	client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry, nil, nil)

	first, err := client.Fetch(srv.URL, testStatusListIssuer)
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := client.Fetch(srv.URL, testStatusListIssuer)
	require.NoError(t, err)
	require.NotNil(t, second)

	// Cache hit: same pointer, single origin request.
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits))
	assert.Same(t, first, second)
}

// TestCachingStatusListClientTransportError ensures Fetch wraps network
// failures (connection refused, DNS, etc.) with ErrorStatusListHttpFailure.
// We simulate a transport failure by pointing the client at a closed server's
// URL.
func TestCachingStatusListClientTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry, nil, nil)
	cred, err := client.Fetch(url, testStatusListIssuer)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorStatusListHttpFailure)
	assert.Nil(t, cred)
}

// TestCachingStatusListClientAcceptHeader verifies that the client sends both
// the JSON-LD and JWT VC media types when fetching status-list credentials.
// This keeps the client compatible with issuers that perform strict content
// negotiation and may serve either representation.
func TestCachingStatusListClientAcceptHeader(t *testing.T) {
	var received string
	jwtBody := testStatusListVCJWT
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Accept")
		w.Header().Set("Content-Type", ContentTypeCredentialJWT)
		_, _ = w.Write([]byte(jwtBody))
	}))
	defer srv.Close()

	client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry, nil, nil)
	_, err := client.Fetch(srv.URL, testStatusListIssuer)
	require.NoError(t, err)
	assert.Equal(t, AcceptHeaderStatusListCredential, received)
	assert.Contains(t, received, ContentTypeCredentialJson)
	assert.Contains(t, received, ContentTypeCredentialJWT)
}

// TestCachingStatusListClientFetchUnknownIssuer verifies that a status list
// is rejected when the credential that referenced it carries no issuer. The
// binding is the only check that anchors the list to a known party, so
// skipping it would fail open on exactly the credentials that name nobody.
func TestCachingStatusListClientFetchUnknownIssuer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentTypeCredentialJWT)
		_, _ = w.Write([]byte(testStatusListVCJWT))
	}))
	defer srv.Close()

	client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry, nil, nil)
	cred, err := client.Fetch(srv.URL, "")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorStatusListIssuerUnknown)
	assert.Nil(t, cred)
}

// ensureInterfaceSatisfied asserts at test compile time that the concrete
// client satisfies the exported interface. This mirrors the compile-time
// assertion in the implementation file but also surfaces a dependency on
// common.Credential here so static analysis doesn't drop the import.
var _ StatusListCredentialClient = (*CachingStatusListClient)(nil)
var _ = (*common.Credential)(nil)

// ---------------------------------------------------------------------------
// JWT signature verification tests
// ---------------------------------------------------------------------------

// mockJWTVerifier is a test double for StatusListJWTVerifier. It records
// whether it was called, which issuer it was asked to bind to, and returns the
// configured error along with the token payload it was handed.
type mockJWTVerifier struct {
	called       bool
	calledIssuer string
	err          error
}

func (m *mockJWTVerifier) VerifyStatusListJWT(_ []byte) ([]byte, error) {
	m.called = true
	return nil, m.err
}

func (m *mockJWTVerifier) VerifyStatusListJWTForIssuer(jwtBytes []byte, issuer string) ([]byte, error) {
	m.called = true
	m.calledIssuer = issuer
	if m.err != nil {
		return nil, m.err
	}
	// The issuer-bound path parses what verification returned, so hand back the
	// token's own payload rather than nil.
	return extractJWTPayload(jwtBytes)
}

// testStatusListVCJWT is a minimal JWT-encoded BitstringStatusListCredential
// built with the shared buildFakeJWT helper (defined in presentation_parser_test.go).
// The signature segment is a static placeholder — format checks pass without a
// real key pair, which is sufficient for unit tests of the verifier wiring.
var testStatusListVCJWT = buildFakeJWT(map[string]interface{}{
	"iss": "did:example:issuer",
	"jti": "https://example.com/status/1",
	"vc": map[string]interface{}{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"type":     []string{"VerifiableCredential", "BitstringStatusListCredential"},
		"credentialSubject": map[string]interface{}{
			"id":            "https://example.com/status/1#list",
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   "H4sIAAAAAAAA_2NgAAMAAAAEAAEAAAAA",
		},
	},
})

// TestParseStatusListCredentialBodyJWTVerification confirms that
// parseStatusListCredentialBody calls the JWT verifier for non-JSON-LD
// responses and respects its outcome.
func TestParseStatusListCredentialBodyJWTVerification(t *testing.T) {
	jwtBody := testStatusListVCJWT

	tests := []struct {
		name            string
		body            string
		verifier        *mockJWTVerifier
		wantErr         error
		wantVerifierHit bool
	}{
		{
			name:            "verifier_failure_rejects_jwt",
			body:            jwtBody,
			verifier:        &mockJWTVerifier{err: ErrorStatusListUnparseable},
			wantErr:         ErrorStatusListUnparseable,
			wantVerifierHit: true,
		},
		{
			name:            "verifier_success_proceeds_to_parse",
			body:            jwtBody,
			verifier:        &mockJWTVerifier{err: nil},
			wantErr:         nil,
			wantVerifierHit: true,
		},
		{
			name:            "nil_verifier_skips_verification",
			body:            jwtBody,
			verifier:        nil,
			wantErr:         nil,
			wantVerifierHit: false,
		},
		{
			name:            "jsonld_body_rejected_without_ld_proof_support",
			body:            testStatusListCredentialJSONLD,
			verifier:        &mockJWTVerifier{err: ErrorStatusListUnparseable},
			wantErr:         ErrorStatusListJSONLDProofUnsupported,
			wantVerifierHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var verifier StatusListJWTVerifier
			if tc.verifier != nil {
				verifier = tc.verifier
			}

			cred, err := parseStatusListCredentialBody([]byte(tc.body), verifier, nil)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, cred)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cred)
			}

			if tc.verifier != nil {
				assert.Equal(t, tc.wantVerifierHit, tc.verifier.called, "verifier.called mismatch")
			}
		})
	}
}

// TestCachingStatusListClientFetchJWTVerification exercises the Fetch path
// end-to-end: the httptest server returns a JWT body, and the configured
// verifier is consulted before the credential is accepted.
func TestCachingStatusListClientFetchJWTVerification(t *testing.T) {
	jwtBody := testStatusListVCJWT

	tests := []struct {
		name     string
		verifier *mockJWTVerifier
		wantErr  error
	}{
		{
			name:     "verifier_rejects_jwt_body",
			verifier: &mockJWTVerifier{err: ErrorStatusListUnparseable},
			wantErr:  ErrorStatusListUnparseable,
		},
		{
			name:     "verifier_accepts_jwt_body",
			verifier: &mockJWTVerifier{err: nil},
			wantErr:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ContentTypeCredentialJWT)
				_, _ = w.Write([]byte(jwtBody))
			}))
			defer srv.Close()

			client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry, tc.verifier, nil)
			cred, err := client.Fetch(srv.URL, testStatusListIssuer)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, cred)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cred)
			}

			assert.True(t, tc.verifier.called, "verifier should have been called for JWT body")
		})
	}
}

// TestParseStatusListCredentialBody_RejectsJSONLD verifies that JSON-LD
// status list credentials are rejected because LD-proof verification is not
// yet supported. This prevents MITM attacks where an attacker could serve a
// forged JSON-LD status list credential to suppress revocation status.
func TestParseStatusListCredentialBody_RejectsJSONLD(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "standard_jsonld_status_list",
			body: testStatusListCredentialJSONLD,
		},
		{
			name: "minimal_jsonld_object",
			body: `{"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential"]}`,
		},
		{
			name: "jsonld_with_proof",
			body: `{
				"@context": ["https://www.w3.org/ns/credentials/v2"],
				"type": ["VerifiableCredential", "BitstringStatusListCredential"],
				"proof": {
					"type": "JsonWebSignature2020",
					"jws": "eyJhbGciOiJFZERTQSJ9..test"
				}
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := parseStatusListCredentialBody([]byte(tc.body), nil, nil)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrorStatusListJSONLDProofUnsupported)
			assert.Nil(t, cred)
		})
	}
}

// --- vc+jwt status list credential parsing tests ---

// testStatusListVCJWT_VCJOSE is a minimal vc+jwt-encoded BitstringStatusListCredential.
// In a vc+jwt token the payload IS the credential (no "vc" wrapper).
var testStatusListVCJWT_VCJOSE string // initialized in init()

func init() {
	// Build a vc+jwt status list credential. We cannot use buildFakeVCJoseJWT
	// because it requires *testing.T; instead we build it inline. The typ
	// header must be "vc+jwt" so parseUnsignedJWTCredential dispatches to
	// vcJwtClaimsToCredential.
	payload := map[string]interface{}{
		"@context": []string{"https://www.w3.org/ns/credentials/v2"},
		"type":     []string{"VerifiableCredential", "BitstringStatusListCredential"},
		"issuer":   testStatusListIssuer,
		"credentialSubject": map[string]interface{}{
			"id":            "https://example.com/status/1#list",
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   "H4sIAAAAAAAA_2NgAAMAAAAEAAEAAAAA",
		},
	}
	testStatusListVCJWT_VCJOSE = buildFakeJWTWithTyp("vc+jwt", payload)
}

// buildFakeJWTWithTyp constructs a fake compact JWT with a custom typ header
// and the given payload. Unlike buildFakeVCJoseJWT it does not require
// *testing.T, making it suitable for package-level var initialization.
func buildFakeJWTWithTyp(typ string, payload map[string]interface{}) string {
	header := map[string]interface{}{"alg": "ES256"}
	if typ != "" {
		header["typ"] = typ
	}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + ".fakesig"
}

// TestParseStatusListCredentialBody_VCJoseJWT verifies that a vc+jwt-encoded
// status list credential is parsed from its top-level claims (no "vc" wrapper)
// and, crucially, that the signature is checked against the issuer the payload
// names rather than through the envelope.
func TestParseStatusListCredentialBody_VCJoseJWT(t *testing.T) {
	verifier := &mockJWTVerifier{}
	cred, err := parseStatusListCredentialBody(
		[]byte(testStatusListVCJWT_VCJOSE), verifier, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.True(t, verifier.called, "a vc+jwt status list must have its signature verified")
	assert.Equal(t, testStatusListIssuer, verifier.calledIssuer,
		"verification must be bound to the issuer the status list itself names")

	contents := cred.Contents()
	assert.Equal(t, testStatusListIssuer, contents.Issuer.ID,
		"issuer must come from the top-level payload 'issuer' field")
	assert.Contains(t, contents.Types, "BitstringStatusListCredential")
	assert.Contains(t, contents.Context, common.ContextCredentialsV2)
	assert.Len(t, contents.Subject, 1)
	assert.Equal(t, "https://example.com/status/1#list", contents.Subject[0].ID)
}

// TestParseStatusListCredentialBody_VCJoseJWTFailsClosed is the regression test
// for the vc+jwt status-list forgery.
//
// A vc+jwt names its issuer in the payload and carries no iss claim, so the
// envelope-driven verifier took its x5c fallback - which lifts a key out of
// whatever certificate the token carries without validating a chain. Anyone who
// could answer the status-list URL could therefore serve a self-signed list
// attributed to the credential's real issuer, with every revocation bit clear.
// The vc+jwt path now has no fallback at all: no verifier, no acceptance.
func TestParseStatusListCredentialBody_VCJoseJWTFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		verifier StatusListJWTVerifier
		wantErr  error
	}{
		{
			name:     "no verifier configured",
			verifier: nil,
			wantErr:  ErrorStatusListVCJoseUnverifiable,
		},
		{
			name:     "signature does not verify against the named issuer",
			verifier: &mockJWTVerifier{err: errors.New("signature mismatch")},
			wantErr:  ErrorStatusListUnparseable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := parseStatusListCredentialBody(
				[]byte(testStatusListVCJWT_VCJOSE), tc.verifier, nil,
			)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Nil(t, cred)
		})
	}
}

// TestParseStatusListCredentialBody_VCJoseJWTNoIssuer checks that a vc+jwt
// status list naming no issuer is rejected before any key lookup: there is
// nothing to bind the signing key to.
func TestParseStatusListCredentialBody_VCJoseJWTNoIssuer(t *testing.T) {
	token := buildFakeJWTWithTyp("vc+jwt", map[string]interface{}{
		"@context": []interface{}{common.ContextCredentialsV2},
		"type":     []interface{}{"VerifiableCredential", "BitstringStatusListCredential"},
	})

	verifier := &mockJWTVerifier{}
	cred, err := parseStatusListCredentialBody([]byte(token), verifier, nil)

	assert.ErrorIs(t, err, ErrorStatusListUnparseable)
	assert.ErrorIs(t, err, ErrorVCJWTNoIssuer)
	assert.Nil(t, cred)
	assert.False(t, verifier.called, "the issuer must be settled before a key is resolved")
}

// TestParseStatusListCredentialBody_ClassicJWTRegression ensures that a classic
// jwt_vc status list credential (with a "vc" wrapper) is still correctly parsed
// after the vc+jwt dispatch was added to parseUnsignedJWTCredential.
func TestParseStatusListCredentialBody_ClassicJWTRegression(t *testing.T) {
	cred, err := parseStatusListCredentialBody(
		[]byte(testStatusListVCJWT), nil, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, cred)

	contents := cred.Contents()
	assert.Equal(t, testStatusListIssuer, contents.Issuer.ID)
	assert.Contains(t, contents.Types, "BitstringStatusListCredential")
}

// TestCachingStatusListClientFetch_VCJoseJWT exercises the Fetch path
// end-to-end with a vc+jwt status list credential served by an httptest
// server. This confirms the wiring from HTTP fetch → parse → credential.
func TestCachingStatusListClientFetch_VCJoseJWT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentTypeCredentialJWT)
		_, _ = w.Write([]byte(testStatusListVCJWT_VCJOSE))
	}))
	defer srv.Close()

	client := NewCachingStatusListClient(
		testStatusListCacheExpiry, testStatusListHTTPTimeout,
		&mockJWTVerifier{}, nil,
	)
	cred, err := client.Fetch(srv.URL+"/status/1", testStatusListIssuer)
	require.NoError(t, err)
	require.NotNil(t, cred)

	contents := cred.Contents()
	assert.Equal(t, testStatusListIssuer, contents.Issuer.ID)
	assert.Contains(t, contents.Types, "BitstringStatusListCredential")
	assert.Contains(t, contents.Context, common.ContextCredentialsV2)
}

// TestParseUnsignedJWTCredential_VCJoseJWT directly tests that
// parseUnsignedJWTCredential dispatches to vcJwtClaimsToCredential when
// the typ header is "vc+jwt".
func TestParseUnsignedJWTCredential_VCJoseJWT(t *testing.T) {
	token := string(buildFakeVCJoseJWT(t, "vc+jwt", map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/ns/credentials/v2"},
		"type":     []interface{}{"VerifiableCredential"},
		"issuer":   "did:web:issuer.example.com",
		"credentialSubject": map[string]interface{}{
			"id":   "did:web:subject.example.com",
			"name": "Alice",
		},
	}))

	cred, err := parseUnsignedJWTCredential(token)
	require.NoError(t, err)
	require.NotNil(t, cred)

	contents := cred.Contents()
	assert.Equal(t, "did:web:issuer.example.com", contents.Issuer.ID,
		"issuer should come from the top-level payload, not a nested vc claim")
	assert.Contains(t, contents.Types, "VerifiableCredential")
	assert.Contains(t, contents.Context, common.ContextCredentialsV2)
}

// TestParseUnsignedJWTCredential_ClassicJWTRegression verifies that classic
// jwt_vc tokens (with a "vc" wrapper and typ absent or "JWT") continue to
// be parsed correctly via jwtClaimsToCredential.
func TestParseUnsignedJWTCredential_ClassicJWTRegression(t *testing.T) {
	token := buildFakeJWT(map[string]interface{}{
		"iss": "did:web:issuer.example.com",
		"vc": map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiableCredential"},
			"credentialSubject": map[string]interface{}{
				"id":   "did:web:subject.example.com",
				"name": "Alice",
			},
		},
	})

	cred, err := parseUnsignedJWTCredential(token)
	require.NoError(t, err)
	require.NotNil(t, cred)

	contents := cred.Contents()
	assert.Equal(t, "did:web:issuer.example.com", contents.Issuer.ID)
	assert.Contains(t, contents.Types, "VerifiableCredential")
	assert.Contains(t, contents.Context, common.ContextCredentialsV1)
}

// TestParseStatusListCredentialBody_VCJoseIssuerBinding is the end-to-end
// regression test for the vc+jwt status-list forgery, with a real verifier and
// real signatures rather than a test double.
//
// A status list decides whether a credential is revoked. Before the issuer was
// bound to the signing key, a list signed with a self-generated did:jwk key
// could name the victim's DID in `issuer`, satisfy the issuer check that
// assertStatusListIssuer performs, and report every credential as valid.
func TestParseStatusListCredentialBody_VCJoseIssuerBinding(t *testing.T) {
	signerKey, signerDID := generateTestKeyAndDIDJWK(t)
	_, victimDID := generateTestKeyAndDIDJWK(t)

	statusListVerifier := NewStatusListJWTVerifier(did.NewRegistry(did.WithVDR(did.NewJWKVDR())))

	tests := []struct {
		name    string
		kid     string
		issuer  string
		wantErr bool
	}{
		{
			name:    "list attributed to a DID the signer does not control",
			kid:     signerDID + "#0",
			issuer:  victimDID,
			wantErr: true,
		},
		{
			name:    "same forgery without a kid to give it away",
			kid:     "",
			issuer:  victimDID,
			wantErr: true,
		},
		{
			name:   "list signed by the issuer it names",
			kid:    signerDID + "#0",
			issuer: signerDID,
		},
		{
			name:   "list signed by the issuer it names, no kid",
			kid:    "",
			issuer: signerDID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := signVCJoseJWT(t, signerKey, common.JWTTypVCJWT, tc.kid, map[string]interface{}{
				common.JSONLDKeyContext: []interface{}{common.ContextCredentialsV2},
				common.JSONLDKeyType:    []interface{}{"VerifiableCredential", "BitstringStatusListCredential"},
				common.VCKeyIssuer:      tc.issuer,
				"credentialSubject": map[string]interface{}{
					"id":            "https://example.com/status/1#list",
					"type":          "BitstringStatusList",
					"statusPurpose": "revocation",
					"encodedList":   "H4sIAAAAAAAA_2NgAAMAAAAEAAEAAAAA",
				},
			})

			cred, err := parseStatusListCredentialBody(token, statusListVerifier, nil)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cred)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cred.Contents().Issuer)
			assert.Equal(t, signerDID, cred.Contents().Issuer.ID)
		})
	}
}
