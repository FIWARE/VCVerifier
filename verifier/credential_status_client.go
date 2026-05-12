package verifier

// credential_status_client.go implements the cached HTTP client responsible
// for fetching W3C Bitstring Status List / StatusList2021 credentials
// referenced from a Verifiable Credential's `credentialStatus` entry.
//
// The client keeps parsed status-list credentials in an in-memory cache so
// the verifier does not re-fetch the same list on every presentation. TTL
// and HTTP timeout are parametrised through config.Verifier
// (StatusListCacheExpiry / StatusListHttpTimeout) — see config/config.go.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
)

// Named constants consumed by the status-list client. The values are kept in
// one place so reviewers can audit the Accept header and the cache cleanup
// cadence without hunting through the implementation.
const (
	// ContentTypeCredentialJson is the default Accept header sent when
	// fetching a status-list credential. It follows the W3C VC Data Model 2.0
	// recommendation for JSON-LD encoded Verifiable Credentials.
	ContentTypeCredentialJson = "application/vc+ld+json"

	// StatusListCacheCleanupMultiplier scales the configured cache expiry to
	// obtain the go-cache janitor cleanup interval. A value of 2 matches the
	// 2×expiry pattern used by the existing caches in common/cache.go and
	// verifier/caching_client.go.
	StatusListCacheCleanupMultiplier = 2

	// statusListHTTPOKMin and statusListHTTPOKMaxExclusive define the
	// accepted success-status range for a status-list fetch. They are
	// module-private because no caller outside this file needs to inspect
	// the raw HTTP contract.
	statusListHTTPOKMin          = 200
	statusListHTTPOKMaxExclusive = 300
)

// Typed errors returned by the status-list client. Exported so callers can
// match them with errors.Is when the verifier's validation service needs to
// distinguish a network failure from a parse failure.
var (
	// ErrorStatusListHttpFailure is returned when the HTTP request to fetch
	// a status-list credential cannot be executed or returns a non-2xx
	// status code.
	ErrorStatusListHttpFailure = errors.New("status_list_http_failure")
	// ErrorStatusListUnparseable is returned when the fetched response body
	// is not a recognisable Verifiable Credential (neither a JSON-LD object
	// nor a decodable JWT).
	ErrorStatusListUnparseable = errors.New("status_list_unparseable")
)

// StatusListCredentialClient fetches and returns W3C Bitstring / StatusList2021
// credentials referenced from a VC's `credentialStatus` entry.
//
// Implementations are expected to be safe for concurrent use so the verifier
// can share a single client across requests.
type StatusListCredentialClient interface {
	// Fetch returns the status-list credential found at the given URL. It is
	// free to serve previously fetched responses from an internal cache.
	Fetch(url string) (*common.Credential, error)
}

// CachingStatusListClient is the default StatusListCredentialClient
// implementation. It uses patrickmn/go-cache to avoid repeated network calls
// for the same URL and a configurable http.Client timeout to protect the
// verifier from slow status-list issuers.
type CachingStatusListClient struct {
	httpClient *http.Client
	cache      common.Cache
	expiry     time.Duration
}

// NewCachingStatusListClient constructs a CachingStatusListClient using the
// supplied HTTP timeout and cache TTL. Both values are typically taken from
// config.Verifier.StatusListHttpTimeout / config.Verifier.StatusListCacheExpiry.
//
// The cache janitor's cleanup interval is derived from cacheExpiry via
// StatusListCacheCleanupMultiplier so evicted entries are reaped on a cadence
// that matches the rest of the codebase.
func NewCachingStatusListClient(timeout time.Duration, cacheExpiry time.Duration) *CachingStatusListClient {
	return &CachingStatusListClient{
		httpClient: &http.Client{Timeout: timeout},
		cache:      cache.New(cacheExpiry, StatusListCacheCleanupMultiplier*cacheExpiry),
		expiry:     cacheExpiry,
	}
}

// Fetch retrieves the status-list credential at url. A cached copy is
// returned when available; otherwise the credential is fetched, parsed with
// the existing VC parser, stored in the cache and returned.
//
// The returned error is wrapped with ErrorStatusListHttpFailure for transport
// or non-2xx responses, and with ErrorStatusListUnparseable when the body
// does not parse as a Verifiable Credential.
func (c *CachingStatusListClient) Fetch(url string) (*common.Credential, error) {
	if cached, hit := c.cache.Get(url); hit {
		logging.Log().Debugf("Status-list cache hit for %s", url)
		return cached.(*common.Credential), nil
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrorStatusListHttpFailure, err)
	}
	req.Header.Set("Accept", ContentTypeCredentialJson)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrorStatusListHttpFailure, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < statusListHTTPOKMin || resp.StatusCode >= statusListHTTPOKMaxExclusive {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrorStatusListHttpFailure, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrorStatusListHttpFailure, err)
	}

	cred, err := parseStatusListCredentialBody(body)
	if err != nil {
		return nil, err
	}

	c.cache.Set(url, cred, c.expiry)
	logging.Log().Debugf("Cached status-list credential for %s", url)
	return cred, nil
}

// parseStatusListCredentialBody decodes a status-list credential response
// body into a *common.Credential.
//
// Two transport encodings are accepted:
//   - JSON-LD: a response body starting with `{` is unmarshalled and handed
//     to parseJSONLDCredential (the existing VC parser helper).
//   - JWT: any other non-empty body is treated as a JWS and parsed via
//     parseUnsignedJWTCredential — status-list credentials are public by
//     nature so signature verification is intentionally deferred to higher
//     layers that enforce trust registry lookups.
//
// A non-nil error is always wrapped with ErrorStatusListUnparseable so
// callers can distinguish parse failures from transport failures with
// errors.Is.
func parseStatusListCredentialBody(body []byte) (*common.Credential, error) {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty response body", ErrorStatusListUnparseable)
	}

	if trimmed[0] == '{' {
		var vcMap map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &vcMap); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, err)
		}
		cred, err := parseJSONLDCredential(vcMap)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, err)
		}
		return cred, nil
	}

	cred, err := parseUnsignedJWTCredential(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, err)
	}
	return cred, nil
}

// Compile-time assertion that CachingStatusListClient satisfies the public
// interface. This protects callers who type against StatusListCredentialClient
// from accidental signature drift.
var _ StatusListCredentialClient = (*CachingStatusListClient)(nil)
