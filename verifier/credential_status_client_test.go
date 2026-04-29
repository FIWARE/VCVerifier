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
		{name: "ok_jsonld", response: serverResp{http.StatusOK, testStatusListCredentialJSONLD}, wantErr: nil},
		{name: "http_5xx", response: serverResp{http.StatusInternalServerError, "boom"}, wantErr: ErrorStatusListHttpFailure},
		{name: "http_4xx", response: serverResp{http.StatusNotFound, "missing"}, wantErr: ErrorStatusListHttpFailure},
		{name: "unparseable_body", response: serverResp{http.StatusOK, "not json at all"}, wantErr: ErrorStatusListUnparseable},
		{name: "unparseable_json_fragment", response: serverResp{http.StatusOK, "{not:valid"}, wantErr: ErrorStatusListUnparseable},
		{name: "empty_body", response: serverResp{http.StatusOK, ""}, wantErr: ErrorStatusListUnparseable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.response.status)
				_, _ = w.Write([]byte(tc.response.body))
			}))
			defer srv.Close()

			client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry)
			cred, err := client.Fetch(srv.URL)

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
func TestCachingStatusListClientCache(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", ContentTypeCredentialJson)
		_, _ = w.Write([]byte(testStatusListCredentialJSONLD))
	}))
	defer srv.Close()

	client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry)

	first, err := client.Fetch(srv.URL)
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := client.Fetch(srv.URL)
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

	client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry)
	cred, err := client.Fetch(url)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorStatusListHttpFailure)
	assert.Nil(t, cred)
}

// TestCachingStatusListClientAcceptHeader confirms the client advertises the
// JSON-LD VC media type when fetching status-list credentials. This keeps
// the client compatible with origins that serve different representations
// based on content negotiation.
func TestCachingStatusListClientAcceptHeader(t *testing.T) {
	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Accept")
		_, _ = w.Write([]byte(testStatusListCredentialJSONLD))
	}))
	defer srv.Close()

	client := NewCachingStatusListClient(testStatusListHTTPTimeout, testStatusListCacheExpiry)
	_, err := client.Fetch(srv.URL)
	require.NoError(t, err)
	assert.Equal(t, ContentTypeCredentialJson, received)
}

// ensureInterfaceSatisfied asserts at test compile time that the concrete
// client satisfies the exported interface. This mirrors the compile-time
// assertion in the implementation file but also surfaces a dependency on
// common.Credential here so static analysis doesn't drop the import.
var _ StatusListCredentialClient = (*CachingStatusListClient)(nil)
var _ = (*common.Credential)(nil)
