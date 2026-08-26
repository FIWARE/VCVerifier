package verifier

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
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Well-known endpoint paths for HTTPS-based issuer metadata discovery.
const (
	// WellKnownJwtVcIssuer is the path for SD-JWT VC Issuer Metadata
	// (draft-ietf-oauth-sd-jwt-vc, Section 5.2).
	WellKnownJwtVcIssuer = "/.well-known/jwt-vc-issuer"

	// WellKnownOIDCCredentialIssuer is the path for OpenID4VCI Credential Issuer Metadata
	// (openid-4-verifiable-credential-issuance-1_0, Section 12.2.4).
	WellKnownOIDCCredentialIssuer = "/.well-known/openid-credential-issuer"

	// WellKnownOAuthAuthzServer is the path for OAuth 2.0 Authorization Server Metadata
	// (RFC 8414).
	WellKnownOAuthAuthzServer = "/.well-known/oauth-authorization-server"

	// DefaultJwksCacheTTL is the default time-to-live for cached JWKS entries.
	DefaultJwksCacheTTL = 15 * time.Minute

	// httpClientTimeout is the maximum duration for HTTP requests made by the resolver.
	httpClientTimeout = 10 * time.Second
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
)

// HttpsIssuerResolver resolves signing keys for HTTPS-based credential issuer identifiers.
// It discovers issuer metadata via well-known endpoints and retrieves keys from JWKS.
type HttpsIssuerResolver interface {
	// ResolveIssuerKey fetches issuer metadata from well-known endpoints, resolves the JWKS,
	// and returns the key matching the given kid. If kid is empty, returns the first key in the set.
	ResolveIssuerKey(issuerURL string, kid string) (jwk.Key, error)
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

// CachingHttpsIssuerResolver implements HttpsIssuerResolver with a caching layer
// that avoids redundant HTTP requests for previously resolved issuer JWKS.
type CachingHttpsIssuerResolver struct {
	httpClient *http.Client
	cache      common.Cache
	cacheTTL   time.Duration
}

// NewCachingHttpsIssuerResolver creates a new CachingHttpsIssuerResolver with the given
// cache and TTL. If cacheTTL is zero, DefaultJwksCacheTTL is used.
func NewCachingHttpsIssuerResolver(cache common.Cache, cacheTTL time.Duration) *CachingHttpsIssuerResolver {
	if cacheTTL == 0 {
		cacheTTL = DefaultJwksCacheTTL
	}
	return &CachingHttpsIssuerResolver{
		httpClient: &http.Client{Timeout: httpClientTimeout},
		cache:      cache,
		cacheTTL:   cacheTTL,
	}
}

// ResolveIssuerKey fetches issuer metadata from well-known endpoints, resolves the JWKS,
// and returns the key matching the given kid. If kid is empty, returns the first key.
//
// Resolution flow:
//  1. Check cache for previously resolved JWKS.
//  2. Primary path: try /.well-known/jwt-vc-issuer for direct jwks_uri or inline jwks.
//  3. Fallback path: try /.well-known/openid-credential-issuer, then resolve
//     authorization_servers' OAuth metadata for jwks_uri.
//  4. Fetch the JWKS, cache it, and find the key matching kid.
func (r *CachingHttpsIssuerResolver) ResolveIssuerKey(issuerURL string, kid string) (jwk.Key, error) {
	issuerURL = strings.TrimSuffix(issuerURL, "/")

	// Step 1: Check cache
	if cached, found := r.cache.Get(issuerURL); found {
		if keySet, ok := cached.(jwk.Set); ok {
			logging.Log().Debugf("Using cached JWKS for issuer %s", issuerURL)
			return findKeyInSet(keySet, kid)
		}
	}

	// Step 2: Primary path — SD-JWT VC issuer metadata
	keySet, err := r.resolveViaPrimaryPath(issuerURL)
	if err != nil {
		logging.Log().Debugf("Primary path (jwt-vc-issuer) failed for %s: %v", issuerURL, err)

		// Step 3: Fallback path — OpenID4VCI credential issuer metadata
		keySet, err = r.resolveViaFallbackPath(issuerURL)
		if err != nil {
			logging.Log().Warnf("Both metadata paths failed for issuer %s: %v", issuerURL, err)
			return nil, ErrorIssuerMetadataNotFound
		}
	}

	// Step 4: Cache the resolved JWKS
	r.cache.Set(issuerURL, keySet, r.cacheTTL)
	logging.Log().Debugf("Cached JWKS for issuer %s (keys: %d)", issuerURL, keySet.Len())

	return findKeyInSet(keySet, kid)
}

// resolveViaPrimaryPath attempts to resolve the JWKS via the SD-JWT VC issuer metadata
// endpoint (/.well-known/jwt-vc-issuer).
func (r *CachingHttpsIssuerResolver) resolveViaPrimaryPath(issuerURL string) (jwk.Set, error) {
	metadataURL := issuerURL + WellKnownJwtVcIssuer

	body, err := r.fetchJSON(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwt-vc-issuer metadata: %w", err)
	}

	var metadata JwtVcIssuerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse jwt-vc-issuer metadata: %w", err)
	}

	// Security check: verify issuer field matches expected URL
	if metadata.Issuer != issuerURL {
		logging.Log().Warnf("Issuer mismatch in jwt-vc-issuer metadata: expected %s, got %s", issuerURL, metadata.Issuer)
		return nil, ErrorIssuerMismatch
	}

	// Try inline JWKS first, then jwks_uri
	if len(metadata.Jwks) > 0 {
		keySet, err := jwk.Parse(metadata.Jwks)
		if err != nil {
			return nil, fmt.Errorf("failed to parse inline JWKS: %w", err)
		}
		return keySet, nil
	}

	if metadata.JwksUri != "" {
		return r.fetchJWKS(metadata.JwksUri)
	}

	return nil, ErrorIssuerJwksNotFound
}

// resolveViaFallbackPath attempts to resolve the JWKS via the OpenID4VCI credential issuer
// metadata endpoint (/.well-known/openid-credential-issuer), then resolves
// authorization_servers' OAuth metadata for jwks_uri.
func (r *CachingHttpsIssuerResolver) resolveViaFallbackPath(issuerURL string) (jwk.Set, error) {
	metadataURL := issuerURL + WellKnownOIDCCredentialIssuer

	body, err := r.fetchJSON(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch openid-credential-issuer metadata: %w", err)
	}

	var metadata OidcCredentialIssuerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse openid-credential-issuer metadata: %w", err)
	}

	if len(metadata.AuthorizationServers) == 0 {
		return nil, ErrorIssuerJwksNotFound
	}

	// Try each authorization server until we find one with a valid JWKS
	for _, authServerURL := range metadata.AuthorizationServers {
		keySet, err := r.resolveViaAuthorizationServer(authServerURL)
		if err != nil {
			logging.Log().Debugf("Authorization server %s failed: %v", authServerURL, err)
			continue
		}
		return keySet, nil
	}

	return nil, ErrorIssuerJwksNotFound
}

// resolveViaAuthorizationServer fetches OAuth 2.0 Authorization Server metadata
// from /.well-known/oauth-authorization-server and retrieves the JWKS.
func (r *CachingHttpsIssuerResolver) resolveViaAuthorizationServer(authServerURL string) (jwk.Set, error) {
	authServerURL = strings.TrimSuffix(authServerURL, "/")
	oauthMetadataURL := authServerURL + WellKnownOAuthAuthzServer

	body, err := r.fetchJSON(oauthMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch oauth-authorization-server metadata: %w", err)
	}

	var oauthMeta OAuthServerMetadata
	if err := json.Unmarshal(body, &oauthMeta); err != nil {
		return nil, fmt.Errorf("failed to parse oauth-authorization-server metadata: %w", err)
	}

	if oauthMeta.JwksUri == "" {
		return nil, ErrorIssuerJwksNotFound
	}

	return r.fetchJWKS(oauthMeta.JwksUri)
}

// fetchJWKS fetches and parses a JSON Web Key Set from the given URL.
func (r *CachingHttpsIssuerResolver) fetchJWKS(jwksURL string) (jwk.Set, error) {
	body, err := r.fetchJSON(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}

	keySet, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS from %s: %w", jwksURL, err)
	}

	return keySet, nil
}

// fetchJSON performs an HTTP GET request and returns the response body.
// Returns an error for non-2xx status codes.
func (r *CachingHttpsIssuerResolver) fetchJSON(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request to %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http request to %s returned status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from %s: %w", url, err)
	}

	return body, nil
}

// findKeyInSet looks up a key by kid in the given JWKS. If kid is empty,
// returns the first key in the set (for single-key issuers).
func findKeyInSet(keySet jwk.Set, kid string) (jwk.Key, error) {
	if keySet.Len() == 0 {
		return nil, ErrorIssuerKeyNotFound
	}

	// If no kid specified, return the first key
	if kid == "" {
		key, ok := keySet.Key(0)
		if !ok {
			return nil, ErrorIssuerKeyNotFound
		}
		return key, nil
	}

	// Search by kid
	for i := 0; i < keySet.Len(); i++ {
		key, ok := keySet.Key(i)
		if !ok {
			continue
		}
		keyID, ok := key.KeyID()
		if ok && keyID == kid {
			return key, nil
		}
	}

	return nil, ErrorIssuerKeyNotFound
}
