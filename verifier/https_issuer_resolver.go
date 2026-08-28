package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Well-known endpoint paths for HTTPS-based issuer metadata discovery.
const (
	// WellKnownJwtVcIssuer is the path for SD-JWT VC Issuer Metadata
	// (draft-ietf-oauth-sd-jwt-vc, Section 5.2). Like RFC 8414, the segment is
	// inserted between the host and the issuer's path component.
	WellKnownJwtVcIssuer = "/.well-known/jwt-vc-issuer"

	// WellKnownOIDCCredentialIssuer is the path for OpenID4VCI Credential Issuer Metadata
	// (openid-4-verifiable-credential-issuance-1_0, Section 12.2.4). Unlike the two
	// well-known paths above, OpenID4VCI *appends* the segment to the issuer's path.
	WellKnownOIDCCredentialIssuer = "/.well-known/openid-credential-issuer"

	// WellKnownOAuthAuthzServer is the path for OAuth 2.0 Authorization Server Metadata
	// (RFC 8414). Section 3.1 requires the segment to be inserted between the host and
	// the issuer's path component.
	WellKnownOAuthAuthzServer = "/.well-known/oauth-authorization-server"

	// DefaultJwksCacheTTL is the default time-to-live for cached JWKS entries.
	DefaultJwksCacheTTL = 15 * time.Minute

	// DefaultJwksFailureCacheTTL is the time-to-live for cached resolution
	// failures. Failures are cached so that a flood of tokens naming an
	// unresolvable issuer cannot be turned into a flood of outbound requests.
	// It is deliberately much shorter than the success TTL so a temporarily
	// unreachable issuer recovers quickly.
	DefaultJwksFailureCacheTTL = 30 * time.Second

	// MinJwksRefetchInterval is the minimum time between two JWKS fetches for
	// the same issuer triggered by an unknown `kid`. It bounds the cost of the
	// key-rotation refetch so an attacker cannot force a fetch per token by
	// naming random key ids.
	MinJwksRefetchInterval = 1 * time.Minute

	// httpClientTimeout is the maximum duration of a single HTTP request made
	// by the resolver.
	httpClientTimeout = 10 * time.Second

	// resolutionTimeout is the maximum duration of one issuer resolution as a
	// whole. Discovery can involve several requests — metadata, authorization
	// server metadata, JWKS — and how many is decided by documents the issuer
	// serves, so the per-request timeout alone leaves the total unbounded.
	resolutionTimeout = 30 * time.Second

	// maxAuthorizationServers caps how many entries of a credential issuer's
	// `authorization_servers` are tried. RFC 8414 deployments name one; the
	// list comes from the issuer itself, so an unbounded walk would let a
	// hostile document turn one token into thousands of outbound requests.
	maxAuthorizationServers = 5

	// maxMetadataResponseBytes bounds the size of a metadata or JWKS response body.
	// The endpoints are attacker-reachable, so an unbounded read would let a hostile
	// host stream until the verifier runs out of memory.
	maxMetadataResponseBytes = 1 << 20 // 1 MiB

	// maxMetadataRedirects is the maximum number of redirects followed while
	// fetching issuer metadata.
	maxMetadataRedirects = 5

	// schemeHttps / schemeHttp are the only URL schemes the resolver will fetch from.
	schemeHttps = "https"
	schemeHttp  = "http"

	// keyOpVerify is the `key_ops` value marking a key as usable for signature verification.
	keyOpVerify = "verify"

	// keyUseSignature is the `use` value marking a key as a signature key.
	keyUseSignature = "sig"

	// cacheControlMaxAge is the Cache-Control directive naming a response's
	// freshness lifetime.
	cacheControlMaxAge = "max-age="
)

// Sentinel errors for HTTPS issuer key resolution.
var (
	// ErrorIssuerMetadataNotFound indicates that neither well-known endpoint returned valid metadata.
	ErrorIssuerMetadataNotFound = errors.New("issuer_metadata_not_found")

	// ErrorIssuerJwksNotFound indicates that metadata has no jwks_uri and no inline jwks,
	// and no authorization_servers could provide a JWKS.
	ErrorIssuerJwksNotFound = errors.New("issuer_jwks_not_found")

	// ErrorIssuerKeyNotFound indicates that the JWKS did not contain a key matching
	// the requested kid.
	ErrorIssuerKeyNotFound = errors.New("issuer_key_not_found")

	// ErrorIssuerMismatch indicates that the issuer field in the metadata does not match
	// the expected issuer URL (security check per RFC 8414 Section 3.3).
	ErrorIssuerMismatch = errors.New("issuer_mismatch")

	// ErrorInvalidIssuerURL indicates that the issuer identifier is not a usable
	// absolute http(s) URL.
	ErrorInvalidIssuerURL = errors.New("invalid_issuer_url")

	// ErrorMetadataURLNotAllowed indicates that a URL taken from a metadata document
	// (jwks_uri, authorization_servers) points somewhere the resolver refuses to go:
	// a different scheme or a host that is neither the issuer's own nor explicitly
	// allowed by configuration. Without this check the metadata response — which is
	// under the control of whoever the token names as issuer — would pick the next
	// hop, turning verification into a server-side request forgery primitive.
	ErrorMetadataURLNotAllowed = errors.New("metadata_url_not_allowed")

	// ErrorResponseTooLarge indicates that a metadata or JWKS response exceeded
	// maxMetadataResponseBytes.
	ErrorResponseTooLarge = errors.New("metadata_response_too_large")
)

// HttpsIssuerResolver resolves signing keys for HTTPS-based credential issuer identifiers.
// It discovers issuer metadata via well-known endpoints and retrieves keys from JWKS.
type HttpsIssuerResolver interface {
	// ResolveIssuerKeys fetches issuer metadata from well-known endpoints, resolves the
	// JWKS and returns the candidate verification keys. When kid is non-empty exactly the
	// keys carrying that key id are returned; when it is empty every signature-capable key
	// of the set is returned and the caller has to pick the one the signature verifies
	// with. Returns ErrorIssuerKeyNotFound when no candidate remains.
	ResolveIssuerKeys(ctx context.Context, issuerURL string, kid string) ([]jwk.Key, error)
}

// JwtVcIssuerMetadata represents the SD-JWT VC issuer metadata response
// from the /.well-known/jwt-vc-issuer endpoint.
type JwtVcIssuerMetadata struct {
	// Issuer is the issuer identifier, which MUST match the iss value in the JWT.
	Issuer string `json:"issuer"`
	// JwksUri is a URL referencing the issuer's JSON Web Key Set document.
	JwksUri string `json:"jwks_uri,omitempty"`
	// Jwks is an inline JSON Web Key Set document, represented as raw JSON
	// for deferred parsing via jwk.Parse.
	Jwks json.RawMessage `json:"jwks,omitempty"`
}

// OidcCredentialIssuerMetadata represents the OpenID4VCI credential issuer metadata
// from the /.well-known/openid-credential-issuer endpoint.
type OidcCredentialIssuerMetadata struct {
	// Issuer is the credential issuer identifier.
	Issuer string `json:"issuer"`
	// CredentialIssuer is the credential issuer identifier as named by OpenID4VCI.
	// Deployments differ in which of the two they populate, so both are accepted
	// and either one has to match the URL the lookup started from.
	CredentialIssuer string `json:"credential_issuer,omitempty"`
	// AuthorizationServers is an array of OAuth 2.0 Authorization Server identifiers
	// whose metadata contains jwks_uri.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
}

// OAuthServerMetadata represents an OAuth 2.0 Authorization Server metadata response
// from the /.well-known/oauth-authorization-server endpoint.
type OAuthServerMetadata struct {
	// Issuer is the authorization server identifier.
	Issuer string `json:"issuer"`
	// JwksUri is a URL referencing the authorization server's JSON Web Key Set.
	JwksUri string `json:"jwks_uri,omitempty"`
}

// jwksCacheEntry is what the resolver stores per issuer: either a resolved key
// set or the failure that resolution ended in. Caching the failure keeps a
// stream of tokens naming an unresolvable issuer from becoming a stream of
// outbound requests.
type jwksCacheEntry struct {
	// keySet is the resolved JWKS; nil for a negative entry.
	keySet jwk.Set
	// err is the failure resolution ended in; nil for a positive entry.
	err error
	// nextRefetchAt is the earliest time at which an unknown kid may trigger a
	// refetch for this issuer. It is stored rather than derived from the time
	// of the fetch, so that a refetch which fails can push the window out
	// without pretending the cached key set is newer than it is.
	nextRefetchAt time.Time
}

// CachingHttpsIssuerResolver implements HttpsIssuerResolver with a caching layer
// that avoids redundant HTTP requests for previously resolved issuer JWKS.
//
// Everything it fetches is chosen, directly or indirectly, by whoever presented
// the token: the issuer URL comes from the token itself and the next hops come
// from the metadata that URL serves. The resolver therefore restricts the hosts
// it will talk to (see ErrorMetadataURLNotAllowed), bounds response sizes and
// redirects, and caches failures as well as successes.
type CachingHttpsIssuerResolver struct {
	httpClient *http.Client
	cache      common.Cache
	cacheTTL   time.Duration
	// failureCacheTTL is the TTL for negative cache entries.
	failureCacheTTL time.Duration
	// allowedHosts holds additional hosts (in `host` or `host:port` form) that
	// metadata documents may point to. The issuer's own host is always allowed.
	allowedHosts map[string]bool
	// clock supplies the current time, injectable for tests.
	clock common.Clock
}

// NewCachingHttpsIssuerResolver creates a new CachingHttpsIssuerResolver with the given
// cache and TTL. If cacheTTL is zero, DefaultJwksCacheTTL is used.
func NewCachingHttpsIssuerResolver(cache common.Cache, cacheTTL time.Duration) *CachingHttpsIssuerResolver {
	if cacheTTL == 0 {
		cacheTTL = DefaultJwksCacheTTL
	}
	return &CachingHttpsIssuerResolver{
		// The per-request timeout is applied through the request context in
		// fetchJSON, so that it is bounded by the overall resolution deadline
		// as well; a client-level Timeout would duplicate the shorter of the two.
		httpClient: &http.Client{
			CheckRedirect: restrictRedirects,
		},
		cache:           cache,
		cacheTTL:        cacheTTL,
		failureCacheTTL: DefaultJwksFailureCacheTTL,
		allowedHosts:    map[string]bool{},
		clock:           common.RealClock{},
	}
}

// WithAllowedMetadataHosts allows metadata documents to point at the given hosts
// in addition to the issuer's own host. Each entry is a `host` or `host:port`
// value, matched against the URL host exactly.
//
// It exists for deployments whose authorization server or JWKS lives on a
// different host than the credential issuer. Leaving it empty — the default —
// confines every request the resolver makes to the issuer's own origin.
// Returns the resolver to allow method chaining.
func (r *CachingHttpsIssuerResolver) WithAllowedMetadataHosts(hosts []string) *CachingHttpsIssuerResolver {
	for _, host := range hosts {
		if trimmed := strings.TrimSpace(host); trimmed != "" {
			r.allowedHosts[trimmed] = true
		}
	}
	return r
}

// WithClock sets the clock used for cache bookkeeping. Returns the resolver to
// allow method chaining.
func (r *CachingHttpsIssuerResolver) WithClock(clock common.Clock) *CachingHttpsIssuerResolver {
	if clock != nil {
		r.clock = clock
	}
	return r
}

// ResolveIssuerKeys fetches issuer metadata from well-known endpoints, resolves the JWKS
// and returns the candidate verification keys for the given kid.
//
// Resolution flow:
//  1. Check the cache — a cached failure is returned as-is, a cached key set is
//     used unless the requested kid is absent from it (see below).
//  2. Primary path: /.well-known/jwt-vc-issuer for a direct jwks_uri or inline jwks.
//  3. Fallback path: /.well-known/openid-credential-issuer, then the
//     authorization_servers' OAuth metadata for a jwks_uri.
//  4. Fetch the JWKS, cache it, and select the candidate keys.
//
// A cached key set that does not contain the requested kid triggers at most one
// refetch per MinJwksRefetchInterval, so a key rotation is picked up without
// waiting out the cache TTL and without letting unknown key ids drive the
// outbound request rate.
func (r *CachingHttpsIssuerResolver) ResolveIssuerKeys(ctx context.Context, issuerURL string, kid string) ([]jwk.Key, error) {
	issuerBase, err := parseIssuerURL(issuerURL)
	if err != nil {
		return nil, err
	}
	cacheKey := issuerCacheKey(issuerBase)

	// Set when a usable key set is already cached and only the requested kid is
	// missing from it, so a failing rotation refetch does not discard it.
	var cachedKeySet jwk.Set
	var cachedExpiration time.Time

	if entry, expiration, found := r.cachedEntry(cacheKey); found {
		if entry.err != nil {
			logging.Log().Debugf("Using cached resolution failure for issuer %s: %v", issuerURL, entry.err)
			return nil, entry.err
		}
		keys, selectErr := selectCandidateKeys(entry.keySet, kid)
		if selectErr == nil {
			logging.Log().Debugf("Using cached JWKS for issuer %s", issuerURL)
			return keys, nil
		}
		if !r.mayRefetch(entry) {
			return nil, selectErr
		}
		logging.Log().Debugf("Cached JWKS for issuer %s does not contain kid %q, refetching", issuerURL, kid)
		cachedKeySet = entry.keySet
		cachedExpiration = expiration
	}

	// One deadline for the whole discovery, however many hops the issuer's
	// documents ask for.
	resolutionCtx, cancel := context.WithTimeout(ctx, resolutionTimeout)
	defer cancel()

	keySet, declaredMaxAge, err := r.resolveKeySet(resolutionCtx, issuerURL, issuerBase)
	if err != nil {
		if cachedKeySet != nil {
			// The issuer was reachable a moment ago; keep what it served then
			// rather than replacing it with a failure the next token would hit.
			// The refetch window still has to move, otherwise every following
			// token naming an unknown kid would retry immediately.
			logging.Log().Warnf("Refetch for issuer %s failed, keeping the cached JWKS: %v", issuerURL, err)
			r.postponeRefetch(cacheKey, cachedKeySet, cachedExpiration)
			return nil, ErrorIssuerKeyNotFound
		}
		r.cache.Set(cacheKey, jwksCacheEntry{err: err, nextRefetchAt: r.nextRefetchAt()}, r.failureCacheTTL)
		return nil, err
	}

	ttl := r.jwksTTL(declaredMaxAge)
	r.cache.Set(cacheKey, jwksCacheEntry{keySet: keySet, nextRefetchAt: r.nextRefetchAt()}, ttl)
	logging.Log().Debugf("Cached JWKS for issuer %s for %s (keys: %d)", issuerURL, ttl, keySet.Len())

	return selectCandidateKeys(keySet, kid)
}

// resolveKeySet runs the two discovery paths for the given issuer.
//
// An issuer mismatch on the primary path is not a "try the next endpoint"
// condition: the endpoint answered and claimed to be somebody else. It is
// surfaced directly instead of being retried through the fallback path, which
// would follow a further hop chosen by the same host and report the failure as
// a plain "no metadata".
func (r *CachingHttpsIssuerResolver) resolveKeySet(ctx context.Context, issuerURL string, issuerBase *url.URL) (jwk.Set, time.Duration, error) {
	keySet, maxAge, err := r.resolveViaPrimaryPath(ctx, issuerURL, issuerBase)
	if err == nil {
		return keySet, maxAge, nil
	}
	if errors.Is(err, ErrorIssuerMismatch) {
		logging.Log().Warnf("Aborting resolution for issuer %s: %v", issuerURL, err)
		return nil, 0, err
	}
	logging.Log().Debugf("Primary path (jwt-vc-issuer) failed for %s: %v", issuerURL, err)

	keySet, maxAge, fallbackErr := r.resolveViaFallbackPath(ctx, issuerURL, issuerBase)
	if fallbackErr != nil {
		if errors.Is(fallbackErr, ErrorIssuerMismatch) {
			logging.Log().Warnf("Aborting resolution for issuer %s: %v", issuerURL, fallbackErr)
			return nil, 0, fallbackErr
		}
		logging.Log().Warnf("Both metadata paths failed for issuer %s: %v", issuerURL, fallbackErr)
		return nil, 0, ErrorIssuerMetadataNotFound
	}
	return keySet, maxAge, nil
}

// resolveViaPrimaryPath attempts to resolve the JWKS via the SD-JWT VC issuer metadata
// endpoint (/.well-known/jwt-vc-issuer).
func (r *CachingHttpsIssuerResolver) resolveViaPrimaryPath(ctx context.Context, issuerURL string, issuerBase *url.URL) (jwk.Set, time.Duration, error) {
	metadataURL := wellKnownURLInserted(issuerBase, WellKnownJwtVcIssuer)

	body, maxAge, err := r.fetchJSON(ctx, metadataURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch jwt-vc-issuer metadata: %w", err)
	}

	var metadata JwtVcIssuerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, 0, fmt.Errorf("failed to parse jwt-vc-issuer metadata: %w", err)
	}

	if err := assertIssuerMatches(issuerURL, metadata.Issuer, "jwt-vc-issuer"); err != nil {
		return nil, 0, err
	}

	// Try inline JWKS first, then jwks_uri
	if len(metadata.Jwks) > 0 {
		keySet, err := jwk.Parse(metadata.Jwks)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse inline JWKS: %w", err)
		}
		return keySet, maxAge, nil
	}

	if metadata.JwksUri != "" {
		jwksURL, err := r.allowedMetadataURL(issuerBase, metadata.JwksUri)
		if err != nil {
			return nil, 0, err
		}
		return r.fetchJWKS(ctx, jwksURL)
	}

	return nil, 0, ErrorIssuerJwksNotFound
}

// resolveViaFallbackPath attempts to resolve the JWKS via the OpenID4VCI credential issuer
// metadata endpoint (/.well-known/openid-credential-issuer), then resolves
// authorization_servers' OAuth metadata for jwks_uri.
func (r *CachingHttpsIssuerResolver) resolveViaFallbackPath(ctx context.Context, issuerURL string, issuerBase *url.URL) (jwk.Set, time.Duration, error) {
	// OpenID4VCI appends its well-known segment to the issuer path instead of
	// inserting it after the host, unlike SD-JWT VC and RFC 8414.
	metadataURL := wellKnownURLAppended(issuerBase, WellKnownOIDCCredentialIssuer)

	body, _, err := r.fetchJSON(ctx, metadataURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch openid-credential-issuer metadata: %w", err)
	}

	var metadata OidcCredentialIssuerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, 0, fmt.Errorf("failed to parse openid-credential-issuer metadata: %w", err)
	}

	// OpenID4VCI names the identifier `credential_issuer`; accept either field,
	// but require the one that is present to be the issuer we asked.
	claimedIssuer := metadata.Issuer
	if claimedIssuer == "" {
		claimedIssuer = metadata.CredentialIssuer
	}
	if err := assertIssuerMatches(issuerURL, claimedIssuer, "openid-credential-issuer"); err != nil {
		return nil, 0, err
	}

	if len(metadata.AuthorizationServers) == 0 {
		return nil, 0, ErrorIssuerJwksNotFound
	}

	authorizationServers := metadata.AuthorizationServers
	if len(authorizationServers) > maxAuthorizationServers {
		logging.Log().Warnf("Issuer %s lists %d authorization servers, only the first %d are tried",
			issuerURL, len(authorizationServers), maxAuthorizationServers)
		authorizationServers = authorizationServers[:maxAuthorizationServers]
	}

	// Try each authorization server until we find one with a valid JWKS
	for _, authServerURL := range authorizationServers {
		allowedAuthServerURL, err := r.allowedMetadataURL(issuerBase, authServerURL)
		if err != nil {
			logging.Log().Warnf("Ignoring authorization server %s of issuer %s: %v", authServerURL, issuerURL, err)
			continue
		}
		keySet, maxAge, err := r.resolveViaAuthorizationServer(ctx, allowedAuthServerURL)
		if err != nil {
			logging.Log().Debugf("Authorization server %s failed: %v", allowedAuthServerURL, err)
			continue
		}
		return keySet, maxAge, nil
	}

	return nil, 0, ErrorIssuerJwksNotFound
}

// resolveViaAuthorizationServer fetches OAuth 2.0 Authorization Server metadata
// from /.well-known/oauth-authorization-server and retrieves the JWKS. RFC 8414
// Section 3.3 requires the `issuer` of the response to be the authorization
// server identifier the request was built from, so it is checked here too.
func (r *CachingHttpsIssuerResolver) resolveViaAuthorizationServer(ctx context.Context, authServerURL string) (jwk.Set, time.Duration, error) {
	authServerBase, err := parseIssuerURL(authServerURL)
	if err != nil {
		return nil, 0, err
	}
	oauthMetadataURL := wellKnownURLInserted(authServerBase, WellKnownOAuthAuthzServer)

	body, _, err := r.fetchJSON(ctx, oauthMetadataURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch oauth-authorization-server metadata: %w", err)
	}

	var oauthMeta OAuthServerMetadata
	if err := json.Unmarshal(body, &oauthMeta); err != nil {
		return nil, 0, fmt.Errorf("failed to parse oauth-authorization-server metadata: %w", err)
	}

	if err := assertIssuerMatches(authServerURL, oauthMeta.Issuer, "oauth-authorization-server"); err != nil {
		return nil, 0, err
	}

	if oauthMeta.JwksUri == "" {
		return nil, 0, ErrorIssuerJwksNotFound
	}

	jwksURL, err := r.allowedMetadataURL(authServerBase, oauthMeta.JwksUri)
	if err != nil {
		return nil, 0, err
	}

	return r.fetchJWKS(ctx, jwksURL)
}

// fetchJWKS fetches and parses a JSON Web Key Set from the given URL.
func (r *CachingHttpsIssuerResolver) fetchJWKS(ctx context.Context, jwksURL string) (jwk.Set, time.Duration, error) {
	body, maxAge, err := r.fetchJSON(ctx, jwksURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}

	keySet, err := jwk.Parse(body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse JWKS from %s: %w", jwksURL, err)
	}

	return keySet, maxAge, nil
}

// fetchJSON performs an HTTP GET request and returns the response body, bounded
// to maxMetadataResponseBytes, together with the freshness lifetime the response
// declares. Returns an error for non-2xx status codes.
func (r *CachingHttpsIssuerResolver) fetchJSON(ctx context.Context, url string) ([]byte, time.Duration, error) {
	requestCtx, cancel := context.WithTimeout(ctx, httpClientTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request for %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("http request to %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("http request to %s returned status %d", url, resp.StatusCode)
	}

	// Read one byte beyond the limit so an oversized body is detected rather
	// than silently truncated into unparseable JSON.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataResponseBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body from %s: %w", url, err)
	}
	if len(body) > maxMetadataResponseBytes {
		return nil, 0, fmt.Errorf("%w: %s returned more than %d bytes", ErrorResponseTooLarge, url, maxMetadataResponseBytes)
	}

	return body, maxAgeOf(resp.Header), nil
}

// maxAgeOf extracts the `max-age` directive of a Cache-Control response header.
// Returns 0 when the header is absent, unparseable or does not carry max-age.
func maxAgeOf(header http.Header) time.Duration {
	for _, directive := range strings.Split(header.Get("Cache-Control"), ",") {
		directive = strings.TrimSpace(directive)
		if !strings.HasPrefix(directive, cacheControlMaxAge) {
			continue
		}
		seconds, err := strconv.Atoi(strings.TrimPrefix(directive, cacheControlMaxAge))
		if err != nil || seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	return 0
}

// jwksTTL is the time-to-live for a fetched key set: the configured TTL, or the
// shorter lifetime the origin declared. An origin may shorten its own keys'
// lifetime — that is how a frequently rotating issuer stays verifiable — but it
// may not extend caching beyond what the operator configured.
func (r *CachingHttpsIssuerResolver) jwksTTL(declaredMaxAge time.Duration) time.Duration {
	if declaredMaxAge > 0 && declaredMaxAge < r.cacheTTL {
		return declaredMaxAge
	}
	return r.cacheTTL
}

// cachedEntry returns the cache entry for the given issuer, if one is present
// and of the expected type, together with the time it expires. A zero
// expiration means the entry does not expire.
func (r *CachingHttpsIssuerResolver) cachedEntry(cacheKey string) (jwksCacheEntry, time.Time, bool) {
	cached, expiration, found := r.cache.GetWithExpiration(cacheKey)
	if !found {
		return jwksCacheEntry{}, time.Time{}, false
	}
	entry, ok := cached.(jwksCacheEntry)
	if !ok {
		return jwksCacheEntry{}, time.Time{}, false
	}
	return entry, expiration, true
}

// mayRefetch reports whether the refetch window of a cached entry has opened.
func (r *CachingHttpsIssuerResolver) mayRefetch(entry jwksCacheEntry) bool {
	return !r.clock.Now().Before(entry.nextRefetchAt)
}

// nextRefetchAt is the point from which the next rotation refetch is allowed.
func (r *CachingHttpsIssuerResolver) nextRefetchAt() time.Time {
	return r.clock.Now().Add(MinJwksRefetchInterval)
}

// postponeRefetch re-arms the refetch window of an existing key set after a
// refetch failed, keeping the keys and what is left of their cache lifetime.
//
// The remaining lifetime has to be carried over explicitly: writing the entry
// back restarts the TTL, which would keep a key set alive indefinitely as long
// as unknown key ids keep arriving. An entry that is at (or past) its
// expiration is left to expire instead.
func (r *CachingHttpsIssuerResolver) postponeRefetch(cacheKey string, keySet jwk.Set, expiration time.Time) {
	remaining := r.cacheTTL
	if !expiration.IsZero() {
		remaining = time.Until(expiration)
		if remaining <= 0 {
			return
		}
	}
	r.cache.Set(cacheKey, jwksCacheEntry{keySet: keySet, nextRefetchAt: r.nextRefetchAt()}, remaining)
}

// allowedMetadataURL validates a URL taken from a metadata document against the
// document's own origin and returns it unchanged when it is acceptable.
//
// The scheme has to be the one the issuer itself was reached over — so an
// https issuer can never be downgraded to http — and the host has to be the
// issuer's own or one the operator explicitly allowed.
func (r *CachingHttpsIssuerResolver) allowedMetadataURL(base *url.URL, rawURL string) (string, error) {
	target, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("%w: %s is not a valid URL: %v", ErrorMetadataURLNotAllowed, rawURL, err)
	}
	if target.Scheme != base.Scheme {
		return "", fmt.Errorf("%w: %s does not use the issuer's scheme %s", ErrorMetadataURLNotAllowed, rawURL, base.Scheme)
	}
	if target.Host == "" {
		return "", fmt.Errorf("%w: %s has no host", ErrorMetadataURLNotAllowed, rawURL)
	}
	if target.Host != base.Host && !r.allowedHosts[target.Host] {
		return "", fmt.Errorf("%w: host %s is neither the issuer's host %s nor allowed by configuration", ErrorMetadataURLNotAllowed, target.Host, base.Host)
	}
	return target.String(), nil
}

// restrictRedirects is the redirect policy for metadata requests: a redirect may
// not leave the origin of the original request, so a metadata host cannot bounce
// the verifier onto another scheme or host.
func restrictRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= maxMetadataRedirects {
		return fmt.Errorf("stopped after %d redirects", maxMetadataRedirects)
	}
	origin := via[0].URL
	if req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
		return fmt.Errorf("%w: redirect from %s to %s leaves the origin", ErrorMetadataURLNotAllowed, origin.Redacted(), req.URL.Redacted())
	}
	return nil
}

// parseIssuerURL parses an issuer identifier into a URL usable for metadata
// discovery. Only absolute http(s) URLs with a host are accepted; https is what
// production identifiers use, http is accepted so tests can run against a local
// server.
func parseIssuerURL(issuerURL string) (*url.URL, error) {
	parsed, err := url.Parse(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrorInvalidIssuerURL, issuerURL, err)
	}
	if parsed.Scheme != schemeHttps && parsed.Scheme != schemeHttp {
		return nil, fmt.Errorf("%w: %s is not an http(s) URL", ErrorInvalidIssuerURL, issuerURL)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: %s has no host", ErrorInvalidIssuerURL, issuerURL)
	}
	// An identifier carrying userinfo would have those credentials sent to the
	// well-known endpoint, and it is not an identifier any issuer legitimately
	// publishes.
	if parsed.User != nil {
		return nil, fmt.Errorf("%w: %s carries userinfo", ErrorInvalidIssuerURL, parsed.Redacted())
	}
	return parsed, nil
}

// wellKnownURLInserted builds a well-known URL the way RFC 8414 Section 3.1 and
// SD-JWT VC Section 5.2 prescribe: the well-known segment goes between the host
// and the issuer's path component. For issuer `https://example.com/tenant1` and
// segment `/.well-known/jwt-vc-issuer` the result is
// `https://example.com/.well-known/jwt-vc-issuer/tenant1`.
func wellKnownURLInserted(base *url.URL, wellKnownPath string) string {
	metadataURL := *base
	metadataURL.Path = wellKnownPath + strings.TrimSuffix(base.Path, "/")
	metadataURL.RawPath = ""
	metadataURL.RawQuery = ""
	metadataURL.Fragment = ""
	return metadataURL.String()
}

// wellKnownURLAppended builds a well-known URL by appending the segment to the
// issuer's path, which is what OpenID4VCI Section 12.2.4 prescribes for the
// credential issuer metadata. For issuer `https://example.com/tenant1` the
// result is `https://example.com/tenant1/.well-known/openid-credential-issuer`.
func wellKnownURLAppended(base *url.URL, wellKnownPath string) string {
	metadataURL := *base
	metadataURL.Path = strings.TrimSuffix(base.Path, "/") + wellKnownPath
	metadataURL.RawPath = ""
	metadataURL.RawQuery = ""
	metadataURL.Fragment = ""
	return metadataURL.String()
}

// assertIssuerMatches enforces the RFC 8414 Section 3.3 check that the issuer
// identifier in a metadata document is the identifier the lookup started from.
// Both sides are canonicalized identically, so an issuer whose identifier ends
// in a slash is neither rejected against its own metadata nor able to pass as a
// different one.
func assertIssuerMatches(expectedIssuer, metadataIssuer, endpoint string) error {
	if canonicalIssuerID(metadataIssuer) != canonicalIssuerID(expectedIssuer) {
		logging.Log().Warnf("Issuer mismatch in %s metadata: expected %s, got %s", endpoint, expectedIssuer, metadataIssuer)
		return fmt.Errorf("%w: %s metadata claims issuer %q, expected %q", ErrorIssuerMismatch, endpoint, metadataIssuer, expectedIssuer)
	}
	return nil
}

// canonicalIssuerID normalizes an issuer identifier for the RFC 8414 Section
// 3.3 comparison. Only a trailing slash is removed — `https://example.com` and
// `https://example.com/` denote the same issuer — everything else is left
// untouched, because that comparison is otherwise an exact string match.
func canonicalIssuerID(issuerID string) string {
	return strings.TrimSuffix(issuerID, "/")
}

// issuerCacheKey is the key an issuer's resolved keys are cached under. Scheme
// and host are case-insensitive per RFC 3986, so they are lowercased to keep
// `https://Example.com` and `https://example.com` from occupying two entries
// and costing two resolutions. The path keeps its case — it is case-sensitive
// — and only a trailing slash is dropped, matching canonicalIssuerID.
//
// This is deliberately a different function from canonicalIssuerID: relaxing
// the identity comparison the same way would go beyond what RFC 8414 allows.
func issuerCacheKey(issuerBase *url.URL) string {
	normalized := *issuerBase
	normalized.Scheme = strings.ToLower(issuerBase.Scheme)
	normalized.Host = strings.ToLower(issuerBase.Host)
	normalized.Path = strings.TrimSuffix(issuerBase.Path, "/")
	normalized.RawPath = ""
	return normalized.String()
}

// selectCandidateKeys returns the keys of a JWKS that may verify a signature.
//
// Keys marked for encryption use, or whose key_ops exclude verification, are
// never returned. When a kid is given only the keys carrying it qualify; when
// none is given every remaining key is a candidate, because a JWS without a kid
// carries no information about which key of a multi-key set signed it and
// picking the first one would make verification depend on JWKS ordering.
func selectCandidateKeys(keySet jwk.Set, kid string) ([]jwk.Key, error) {
	candidates := []jwk.Key{}
	for i := 0; i < keySet.Len(); i++ {
		key, ok := keySet.Key(i)
		if !ok {
			continue
		}
		if !isSignatureKey(key) {
			continue
		}
		if kid != "" {
			keyID, hasKeyID := key.KeyID()
			if !hasKeyID || keyID != kid {
				continue
			}
		}
		candidates = append(candidates, key)
	}

	if len(candidates) == 0 {
		return nil, ErrorIssuerKeyNotFound
	}
	return candidates, nil
}

// isSignatureKey reports whether a JWKS entry may be used to verify signatures,
// according to its `use` and `key_ops` members (RFC 7517 Sections 4.2 and 4.3).
// A key that declares neither is usable, as those members are optional.
func isSignatureKey(key jwk.Key) bool {
	if use, ok := key.KeyUsage(); ok && use != "" && use != keyUseSignature {
		return false
	}
	if keyOps, ok := key.KeyOps(); ok && len(keyOps) > 0 {
		for _, op := range keyOps {
			if string(op) == keyOpVerify {
				return true
			}
		}
		return false
	}
	return true
}
