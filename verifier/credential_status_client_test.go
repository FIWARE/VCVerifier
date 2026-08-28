package verifier

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
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
// whether it was called and returns the configured error.
type mockJWTVerifier struct {
	called bool
	err    error
}

func (m *mockJWTVerifier) VerifyStatusListJWT(_ []byte) ([]byte, error) {
	m.called = true
	return nil, m.err
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
