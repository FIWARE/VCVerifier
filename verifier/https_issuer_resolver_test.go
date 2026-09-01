package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLoggingConfig initializes logging for tests in this file.
var testLoggingConfig = logging.LoggingConfig{
	Level:         "DEBUG",
	JsonLogging:   true,
	LogRequests:   true,
	PathsToSkip:   []string{},
	DisableCaller: false,
}

// newTestIssuerResolver builds a resolver for the tests in this file. The
// metadata servers are httptest listeners on loopback, which the address guard
// refuses by default, so the tests opt into private addresses the same way a
// deployment with in-network issuers would.
func newTestIssuerResolver(c common.Cache, cacheTTL time.Duration) *CachingHttpsIssuerResolver {
	return NewCachingHttpsIssuerResolver(c, cacheTTL).WithAllowPrivateAddresses(true)
}

// generateTestJWKSet creates a JWKS containing an ECDSA P-256 key pair for testing.
// Returns both the jwk.Set and the private key for signing.
func generateTestJWKSet(t *testing.T, kid string) (jwk.Set, *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "failed to generate ECDSA key")

	pubJWK, err := jwk.Import(privateKey.PublicKey)
	require.NoError(t, err, "failed to import public key to JWK")

	if kid != "" {
		err = pubJWK.Set(jwk.KeyIDKey, kid)
		require.NoError(t, err, "failed to set kid on JWK")
	}

	keySet := jwk.NewSet()
	err = keySet.AddKey(pubJWK)
	require.NoError(t, err, "failed to add key to set")

	return keySet, privateKey
}

// generateMultiKeyJWKSet creates a JWKS containing multiple keys with different kids.
func generateMultiKeyJWKSet(t *testing.T, kids []string) jwk.Set {
	t.Helper()

	keySet := jwk.NewSet()
	for _, kid := range kids {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubJWK, err := jwk.Import(privateKey.PublicKey)
		require.NoError(t, err)

		err = pubJWK.Set(jwk.KeyIDKey, kid)
		require.NoError(t, err)

		err = keySet.AddKey(pubJWK)
		require.NoError(t, err)
	}

	return keySet
}

// marshalJWKSet serializes a jwk.Set to JSON bytes.
func marshalJWKSet(t *testing.T, keySet jwk.Set) []byte {
	t.Helper()

	jwksBytes, err := json.Marshal(keySet)
	require.NoError(t, err, "failed to marshal JWKS")
	return jwksBytes
}

// resolveFirstIssuerKey resolves the candidate keys for an issuer and returns
// the first one, so tests that expect a single key stay readable.
func resolveFirstIssuerKey(r HttpsIssuerResolver, issuerURL, kid string) (jwk.Key, error) {
	keys, err := r.ResolveIssuerKeys(context.Background(), issuerURL, kid)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

// startWellKnownJwksServer starts a metadata server serving SD-JWT VC issuer
// metadata and a JWKS holding one key with the given kid. It returns the server
// and the key set, and closes the server when the test ends.
func startWellKnownJwksServer(t *testing.T, kid string) (*httptest.Server, jwk.Set) {
	t.Helper()

	keySet, _ := generateTestJWKSet(t, kid)
	jwksBytes := marshalJWKSet(t, keySet)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s/jwks"}`, serverURL, serverURL)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL

	return server, keySet
}

// hostOf returns the `host:port` part of a URL, for use with
// WithAllowedMetadataHosts.
func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	return parsed.Host
}

func TestResolveIssuerKey_PrimaryPath_JwksUri(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "key-1")
	jwksBytes := marshalJWKSet(t, keySet)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"jwks_uri": "%s/jwks"
			}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL)

	key, err := resolveFirstIssuerKey(resolver, serverURL, "key-1")

	assert.NoError(t, err)
	assert.NotNil(t, key)
	keyID, ok := key.KeyID()
	assert.True(t, ok)
	assert.Equal(t, "key-1", keyID)
}

func TestResolveIssuerKey_PrimaryPath_InlineJwks(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "inline-key")
	jwksBytes := marshalJWKSet(t, keySet)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"jwks": %s
			}`, serverURL, string(jwksBytes))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL)

	key, err := resolveFirstIssuerKey(resolver, serverURL, "inline-key")

	assert.NoError(t, err)
	assert.NotNil(t, key)
	keyID, ok := key.KeyID()
	assert.True(t, ok)
	assert.Equal(t, "inline-key", keyID)
}

func TestResolveIssuerKey_FallbackPath_OpenID4VCI(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "oidc-key")
	jwksBytes := marshalJWKSet(t, keySet)

	// Auth server that serves OAuth metadata and JWKS
	var authServerURL string
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownOAuthAuthzServer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"jwks_uri": "%s/jwks"
			}`, authServerURL, authServerURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer authServer.Close()
	authServerURL = authServer.URL

	// Issuer server: primary path fails (404), fallback returns OpenID4VCI metadata
	var issuerServerURL string
	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownOIDCCredentialIssuer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"authorization_servers": ["%s"]
			}`, issuerServerURL, authServerURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuerServer.Close()
	issuerServerURL = issuerServer.URL

	c := cache.New(5*time.Minute, 10*time.Minute)
	// The authorization server lives on its own host, which the resolver only
	// follows when the operator allowed it.
	resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL).
		WithAllowedMetadataHosts([]string{hostOf(t, authServerURL)})

	key, err := resolveFirstIssuerKey(resolver, issuerServerURL, "oidc-key")

	assert.NoError(t, err)
	assert.NotNil(t, key)
	keyID, ok := key.KeyID()
	assert.True(t, ok)
	assert.Equal(t, "oidc-key", keyID)
}

func TestResolveIssuerKey_MultiKeyJWKS_SelectByKid(t *testing.T) {
	logging.Configure(testLoggingConfig)

	kids := []string{"key-alpha", "key-beta", "key-gamma"}
	keySet := generateMultiKeyJWKSet(t, kids)
	jwksBytes := marshalJWKSet(t, keySet)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"jwks_uri": "%s/jwks"
			}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL)

	tests := []struct {
		testName    string
		kid         string
		expectError error
	}{
		{"select first key by kid", "key-alpha", nil},
		{"select middle key by kid", "key-beta", nil},
		{"select last key by kid", "key-gamma", nil},
		{"non-existent kid returns error", "key-missing", ErrorIssuerKeyNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			key, err := resolveFirstIssuerKey(resolver, serverURL, tc.kid)
			if tc.expectError != nil {
				assert.ErrorIs(t, err, tc.expectError)
				assert.Nil(t, key)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
				keyID, ok := key.KeyID()
				assert.True(t, ok)
				assert.Equal(t, tc.kid, keyID)
			}
		})
	}
}

func TestResolveIssuerKey_SingleKeyJWKS_NoKid(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "only-key")
	jwksBytes := marshalJWKSet(t, keySet)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"jwks_uri": "%s/jwks"
			}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL)

	// Empty kid should return the only key of the set
	key, err := resolveFirstIssuerKey(resolver, serverURL, "")

	assert.NoError(t, err)
	assert.NotNil(t, key)
	keyID, ok := key.KeyID()
	assert.True(t, ok)
	assert.Equal(t, "only-key", keyID)
}

func TestResolveIssuerKey_Caching(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "cached-key")
	jwksBytes := marshalJWKSet(t, keySet)

	var requestCount atomic.Int32
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"jwks_uri": "%s/jwks"
			}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL)

	// First call — should make HTTP requests
	key1, err := resolveFirstIssuerKey(resolver, serverURL, "cached-key")
	assert.NoError(t, err)
	assert.NotNil(t, key1)
	firstCallRequests := requestCount.Load()
	assert.Greater(t, firstCallRequests, int32(0), "first call should make HTTP requests")

	// Second call — should use cache, no additional HTTP requests
	key2, err := resolveFirstIssuerKey(resolver, serverURL, "cached-key")
	assert.NoError(t, err)
	assert.NotNil(t, key2)
	assert.Equal(t, firstCallRequests, requestCount.Load(), "second call should not make additional HTTP requests")
}

func TestResolveIssuerKey_ErrorCases(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "good-key")
	jwksBytes := marshalJWKSet(t, keySet)

	tests := []struct {
		testName      string
		setupHandler  func(serverURL string) http.Handler
		kid           string
		expectedError error
	}{
		{
			testName: "both endpoints return 404",
			setupHandler: func(serverURL string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.NotFound(w, r)
				})
			},
			kid:           "key-1",
			expectedError: ErrorIssuerMetadataNotFound,
		},
		{
			testName: "issuer mismatch in metadata",
			setupHandler: func(serverURL string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case WellKnownJwtVcIssuer:
						metadata := `{
							"issuer": "https://wrong-issuer.example.com",
							"jwks_uri": "https://wrong-issuer.example.com/jwks"
						}`
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(metadata))
					default:
						http.NotFound(w, r)
					}
				})
			},
			kid:           "key-1",
			expectedError: ErrorIssuerMismatch,
		},
		{
			testName: "no matching kid in JWKS",
			setupHandler: func(serverURL string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case WellKnownJwtVcIssuer:
						metadata := fmt.Sprintf(`{
							"issuer": "%s",
							"jwks_uri": "%s/jwks"
						}`, serverURL, serverURL)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(metadata))
					case "/jwks":
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(jwksBytes)
					default:
						http.NotFound(w, r)
					}
				})
			},
			kid:           "non-existent-key",
			expectedError: ErrorIssuerKeyNotFound,
		},
		{
			testName: "JWKS fetch failure — server error",
			setupHandler: func(serverURL string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case WellKnownJwtVcIssuer:
						metadata := fmt.Sprintf(`{
							"issuer": "%s",
							"jwks_uri": "%s/jwks"
						}`, serverURL, serverURL)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(metadata))
					case "/jwks":
						w.WriteHeader(http.StatusInternalServerError)
					default:
						http.NotFound(w, r)
					}
				})
			},
			kid:           "key-1",
			expectedError: ErrorIssuerMetadataNotFound,
		},
		{
			testName: "metadata has no jwks_uri and no inline jwks",
			setupHandler: func(serverURL string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case WellKnownJwtVcIssuer:
						metadata := fmt.Sprintf(`{
							"issuer": "%s"
						}`, serverURL)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(metadata))
					default:
						http.NotFound(w, r)
					}
				})
			},
			kid:           "key-1",
			expectedError: ErrorIssuerMetadataNotFound,
		},
		{
			testName: "authorization server metadata fetch failure",
			setupHandler: func(serverURL string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case WellKnownOIDCCredentialIssuer:
						metadata := fmt.Sprintf(`{
							"issuer": "%s",
							"authorization_servers": ["https://nonexistent.example.com"]
						}`, serverURL)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(metadata))
					default:
						http.NotFound(w, r)
					}
				})
			},
			kid:           "key-1",
			expectedError: ErrorIssuerMetadataNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			var serverURL string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.setupHandler(serverURL).ServeHTTP(w, r)
			}))
			defer server.Close()
			serverURL = server.URL

			c := cache.New(5*time.Minute, 10*time.Minute)
			resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL)

			key, err := resolveFirstIssuerKey(resolver, serverURL, tc.kid)
			assert.ErrorIs(t, err, tc.expectedError)
			assert.Nil(t, key)
		})
	}
}

func TestResolveIssuerKey_TrailingSlashNormalized(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "slash-key")
	jwksBytes := marshalJWKSet(t, keySet)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"jwks_uri": "%s/jwks"
			}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL)

	// Call with trailing slash — should be normalized
	key, err := resolveFirstIssuerKey(resolver, serverURL+"/", "slash-key")

	assert.NoError(t, err)
	assert.NotNil(t, key)
}

func TestResolveIssuerKey_DefaultCacheTTL(t *testing.T) {
	// Verify that zero cacheTTL defaults to DefaultJwksCacheTTL
	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := newTestIssuerResolver(c, 0)
	assert.Equal(t, DefaultJwksCacheTTL, resolver.cacheTTL)
}

func TestSelectCandidateKeys(t *testing.T) {
	logging.Configure(testLoggingConfig)

	tests := []struct {
		testName     string
		keySet       func(t *testing.T) jwk.Set
		kid          string
		expectError  error
		expectedKids []string
	}{
		{
			testName: "empty keyset returns error",
			keySet: func(t *testing.T) jwk.Set {
				return jwk.NewSet()
			},
			kid:         "any",
			expectError: ErrorIssuerKeyNotFound,
		},
		{
			testName: "find key by kid",
			keySet: func(t *testing.T) jwk.Set {
				return generateMultiKeyJWKSet(t, []string{"a", "b", "c"})
			},
			kid:          "b",
			expectedKids: []string{"b"},
		},
		{
			testName: "empty kid returns every key of the set",
			keySet: func(t *testing.T) jwk.Set {
				return generateMultiKeyJWKSet(t, []string{"first", "second"})
			},
			kid:          "",
			expectedKids: []string{"first", "second"},
		},
		{
			testName: "non-existent kid returns error",
			keySet: func(t *testing.T) jwk.Set {
				return generateMultiKeyJWKSet(t, []string{"a", "b"})
			},
			kid:         "z",
			expectError: ErrorIssuerKeyNotFound,
		},
		{
			testName: "an unlabelled key is a candidate for any kid",
			keySet: func(t *testing.T) jwk.Set {
				keySet, _ := generateTestJWKSet(t, "")
				return keySet
			},
			kid:          "signed-with-a-kid",
			expectedKids: []string{""},
		},
		{
			testName: "a matching kid wins over an unlabelled key",
			keySet: func(t *testing.T) jwk.Set {
				keySet := generateMultiKeyJWKSet(t, []string{"a", ""})
				return keySet
			},
			kid:          "a",
			expectedKids: []string{"a"},
		},
		{
			testName: "encryption keys are never candidates",
			keySet: func(t *testing.T) jwk.Set {
				keySet := generateMultiKeyJWKSet(t, []string{"enc-key", "sig-key"})
				encKey, _ := keySet.Key(0)
				require.NoError(t, encKey.Set(jwk.KeyUsageKey, "enc"))
				return keySet
			},
			kid:          "",
			expectedKids: []string{"sig-key"},
		},
		{
			testName: "key_ops without verify excludes the key",
			keySet: func(t *testing.T) jwk.Set {
				keySet := generateMultiKeyJWKSet(t, []string{"wrap-only"})
				key, _ := keySet.Key(0)
				require.NoError(t, key.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpWrapKey}))
				return keySet
			},
			kid:         "wrap-only",
			expectError: ErrorIssuerKeyNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			keys, err := selectCandidateKeys(tc.keySet(t), tc.kid)

			if tc.expectError != nil {
				assert.ErrorIs(t, err, tc.expectError)
				assert.Nil(t, keys)
				return
			}
			require.NoError(t, err)
			require.Len(t, keys, len(tc.expectedKids))
			for i, expectedKid := range tc.expectedKids {
				keyID, _ := keys[i].KeyID()
				assert.Equal(t, expectedKid, keyID)
			}
		})
	}
}

func TestResolveIssuerKey_FallbackPath_MultipleAuthServers(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "multi-auth-key")
	jwksBytes := marshalJWKSet(t, keySet)

	// First auth server — returns 500 (fails)
	failingAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failingAuthServer.Close()

	// Second auth server — returns valid OAuth metadata with JWKS
	var workingAuthServerURL string
	workingAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownOAuthAuthzServer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"jwks_uri": "%s/jwks"
			}`, workingAuthServerURL, workingAuthServerURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer workingAuthServer.Close()
	workingAuthServerURL = workingAuthServer.URL

	// Issuer server: primary path fails, fallback has two authorization servers
	var issuerServerURL string
	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownOIDCCredentialIssuer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"authorization_servers": ["%s", "%s"]
			}`, issuerServerURL, failingAuthServer.URL, workingAuthServerURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuerServer.Close()
	issuerServerURL = issuerServer.URL

	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL).
		WithAllowedMetadataHosts([]string{hostOf(t, failingAuthServer.URL), hostOf(t, workingAuthServerURL)})

	// Should succeed via the second authorization server
	key, err := resolveFirstIssuerKey(resolver, issuerServerURL, "multi-auth-key")

	assert.NoError(t, err)
	assert.NotNil(t, key)
	keyID, ok := key.KeyID()
	assert.True(t, ok)
	assert.Equal(t, "multi-auth-key", keyID)
}

func TestResolveIssuerKey_FallbackPath_NoAuthorizationServers(t *testing.T) {
	logging.Configure(testLoggingConfig)

	var issuerServerURL string
	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownOIDCCredentialIssuer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"authorization_servers": []
			}`, issuerServerURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuerServer.Close()
	issuerServerURL = issuerServer.URL

	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL)

	key, err := resolveFirstIssuerKey(resolver, issuerServerURL, "some-key")
	assert.ErrorIs(t, err, ErrorIssuerMetadataNotFound)
	assert.Nil(t, key)
}

func TestResolveIssuerKey_InvalidJWKSContent(t *testing.T) {
	logging.Configure(testLoggingConfig)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			metadata := fmt.Sprintf(`{
				"issuer": "%s",
				"jwks_uri": "%s/jwks"
			}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"not_valid_jwks": true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := newTestIssuerResolver(c, DefaultJwksCacheTTL)

	// Invalid JWKS content in primary path leads to fallback, which also fails → metadata not found
	key, err := resolveFirstIssuerKey(resolver, serverURL, "key-1")
	assert.Error(t, err)
	assert.Nil(t, key)
}

// advanceableClock is a common.Clock whose time can be moved forward, for
// testing the cache and refetch bookkeeping without sleeping.
type advanceableClock struct {
	now time.Time
}

// Now returns the clock's current time.
func (c *advanceableClock) Now() time.Time {
	return c.now
}

// advance moves the clock forward.
func (c *advanceableClock) advance(d time.Duration) {
	c.now = c.now.Add(d)
}

// TestResolveIssuerKeys_WellKnownPathPlacement verifies that the well-known
// segment is inserted between host and path for SD-JWT VC / RFC 8414 and
// appended for OpenID4VCI, as the respective specs prescribe.
func TestResolveIssuerKeys_WellKnownPathPlacement(t *testing.T) {
	logging.Configure(testLoggingConfig)

	tests := []struct {
		testName    string
		issuerPath  string
		expectedVC  string
		expectedVCI string
	}{
		{
			testName:    "issuer without a path",
			issuerPath:  "",
			expectedVC:  "/.well-known/jwt-vc-issuer",
			expectedVCI: "/.well-known/openid-credential-issuer",
		},
		{
			testName:    "issuer with a tenant path",
			issuerPath:  "/tenant1",
			expectedVC:  "/.well-known/jwt-vc-issuer/tenant1",
			expectedVCI: "/tenant1/.well-known/openid-credential-issuer",
		},
		{
			testName:    "issuer with a trailing slash",
			issuerPath:  "/tenant1/",
			expectedVC:  "/.well-known/jwt-vc-issuer/tenant1",
			expectedVCI: "/tenant1/.well-known/openid-credential-issuer",
		},
		{
			// An encoded slash stays inside its segment; decoding it would
			// address a different issuer's well-known location.
			testName:    "issuer with an encoded slash in its path",
			issuerPath:  "/a%2Fb",
			expectedVC:  "/.well-known/jwt-vc-issuer/a%2Fb",
			expectedVCI: "/a%2Fb/.well-known/openid-credential-issuer",
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			base, err := url.Parse("https://example.com" + tc.issuerPath)
			require.NoError(t, err)

			assert.Equal(t, "https://example.com"+tc.expectedVC, wellKnownURLInserted(base, WellKnownJwtVcIssuer))
			assert.Equal(t, "https://example.com"+tc.expectedVCI, wellKnownURLAppended(base, WellKnownOIDCCredentialIssuer))
		})
	}
}

// TestResolveIssuerKeys_MultiTenantIssuer verifies that an issuer with a path
// component is resolved through the inserted well-known path.
func TestResolveIssuerKeys_MultiTenantIssuer(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "tenant-key")
	jwksBytes := marshalJWKSet(t, keySet)

	var issuerURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer + "/tenant1":
			metadata := fmt.Sprintf(`{"issuer": "%s", "jwks_uri": "%s/jwks"}`, issuerURL, issuerURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/tenant1/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuerURL = server.URL + "/tenant1"

	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

	key, err := resolveFirstIssuerKey(resolver, issuerURL, "tenant-key")
	require.NoError(t, err)
	require.NotNil(t, key)
}

// TestResolveIssuerKeys_MetadataURLRestrictions verifies that URLs taken from a
// metadata document may not leave the issuer's origin unless the host was
// explicitly allowed.
func TestResolveIssuerKeys_MetadataURLRestrictions(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "off-host-key")
	jwksBytes := marshalJWKSet(t, keySet)

	// A separate host serving the JWKS.
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer jwksServer.Close()

	tests := []struct {
		testName     string
		jwksURI      func(issuerURL string) string
		allowedHosts []string
		expectError  bool
	}{
		{
			testName:    "jwks_uri on the issuer's own host is followed",
			jwksURI:     func(issuerURL string) string { return issuerURL + "/jwks" },
			expectError: false,
		},
		{
			testName:    "jwks_uri on a foreign host is refused",
			jwksURI:     func(string) string { return jwksServer.URL + "/jwks" },
			expectError: true,
		},
		{
			testName:     "jwks_uri on an explicitly allowed host is followed",
			jwksURI:      func(string) string { return jwksServer.URL + "/jwks" },
			allowedHosts: []string{hostOf(t, jwksServer.URL)},
			expectError:  false,
		},
		{
			testName:    "jwks_uri pointing at the link-local metadata service is refused",
			jwksURI:     func(string) string { return "http://169.254.169.254/latest/meta-data/" },
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			var issuerURL string
			issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case WellKnownJwtVcIssuer:
					metadata := fmt.Sprintf(`{"issuer": "%s", "jwks_uri": "%s"}`, issuerURL, tc.jwksURI(issuerURL))
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(metadata))
				case "/jwks":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(jwksBytes)
				default:
					http.NotFound(w, r)
				}
			}))
			defer issuerServer.Close()
			issuerURL = issuerServer.URL

			resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL).
				WithAllowedMetadataHosts(tc.allowedHosts)

			key, err := resolveFirstIssuerKey(resolver, issuerURL, "off-host-key")
			if tc.expectError {
				assert.ErrorIs(t, err, ErrorIssuerMetadataNotFound)
				assert.Nil(t, key)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, key)
		})
	}
}

// TestResolveIssuerKeys_RedirectsMayNotLeaveTheOrigin verifies that a metadata
// endpoint cannot bounce the resolver onto another host.
func TestResolveIssuerKeys_RedirectsMayNotLeaveTheOrigin(t *testing.T) {
	logging.Configure(testLoggingConfig)

	internalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secret": "internal"}`))
	}))
	defer internalServer.Close()

	issuerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internalServer.URL+"/internal", http.StatusFound)
	}))
	defer issuerServer.Close()

	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

	key, err := resolveFirstIssuerKey(resolver, issuerServer.URL, "any-key")
	assert.ErrorIs(t, err, ErrorIssuerMetadataNotFound)
	assert.Nil(t, key)
}

// TestResolveIssuerKeys_OversizedResponseIsRejected verifies that a hostile
// endpoint cannot stream an unbounded body into the verifier.
func TestResolveIssuerKeys_OversizedResponseIsRejected(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "padded-key")
	jwksBytes := marshalJWKSet(t, keySet)

	// Otherwise valid metadata, padded past the size limit: without the limit
	// the resolution would succeed, so the test really exercises the bound.
	padding := strings.Repeat("a", maxMetadataResponseBytes)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s/jwks", "padding": "%s"}`,
				serverURL, serverURL, padding)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

	key, err := resolveFirstIssuerKey(resolver, serverURL, "padded-key")
	assert.ErrorIs(t, err, ErrorIssuerMetadataNotFound)
	assert.Nil(t, key)
}

// TestResolveIssuerKeys_FailuresAreCached verifies that a failing issuer is not
// contacted again for every token naming it.
func TestResolveIssuerKeys_FailuresAreCached(t *testing.T) {
	logging.Configure(testLoggingConfig)

	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

	_, firstErr := resolver.ResolveIssuerKeys(context.Background(), server.URL, "key-1")
	assert.ErrorIs(t, firstErr, ErrorIssuerMetadataNotFound)
	requestsAfterFirst := requestCount.Load()
	assert.Greater(t, requestsAfterFirst, int32(0))

	_, secondErr := resolver.ResolveIssuerKeys(context.Background(), server.URL, "key-1")
	assert.ErrorIs(t, secondErr, ErrorIssuerMetadataNotFound)
	assert.Equal(t, requestsAfterFirst, requestCount.Load(),
		"a cached failure must not trigger further outbound requests")
}

// TestResolveIssuerKeys_KeyRotation verifies that an unknown kid triggers a
// refetch once the rate limit has passed, and does not before.
func TestResolveIssuerKeys_KeyRotation(t *testing.T) {
	logging.Configure(testLoggingConfig)

	oldKeySet, _ := generateTestJWKSet(t, "old-key")
	newKeySet, _ := generateTestJWKSet(t, "new-key")
	servedJwks := marshalJWKSet(t, oldKeySet)

	var jwksRequests atomic.Int32
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			metadata := fmt.Sprintf(`{"issuer": "%s", "jwks_uri": "%s/jwks"}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			jwksRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(servedJwks)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	clock := &advanceableClock{now: time.Now()}
	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL).
		WithClock(clock)

	key, err := resolveFirstIssuerKey(resolver, serverURL, "old-key")
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, int32(1), jwksRequests.Load())

	// The issuer rotates its key.
	servedJwks = marshalJWKSet(t, newKeySet)

	// Immediately after the first fetch the unknown kid must not trigger a refetch.
	_, err = resolver.ResolveIssuerKeys(context.Background(), serverURL, "new-key")
	assert.ErrorIs(t, err, ErrorIssuerKeyNotFound)
	assert.Equal(t, int32(1), jwksRequests.Load(), "refetch must be rate-limited")

	// Once the minimum interval has passed, the rotated key is picked up
	// without waiting for the cache TTL to expire.
	clock.advance(MinJwksRefetchInterval)
	rotatedKey, err := resolveFirstIssuerKey(resolver, serverURL, "new-key")
	require.NoError(t, err)
	keyID, ok := rotatedKey.KeyID()
	assert.True(t, ok)
	assert.Equal(t, "new-key", keyID)
	assert.Equal(t, int32(2), jwksRequests.Load())
}

// TestResolveIssuerKeys_FallbackPathIssuerMismatch verifies that the RFC 8414
// issuer check is enforced on the fallback path too — for the credential issuer
// metadata as well as for the authorization server metadata.
func TestResolveIssuerKeys_FallbackPathIssuerMismatch(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "fallback-key")
	jwksBytes := marshalJWKSet(t, keySet)

	tests := []struct {
		testName        string
		oidcIssuer      func(issuerURL string) string
		authIssuer      func(issuerURL string) string
		expectedError   error
		expectResolvedK bool
	}{
		{
			testName:        "matching issuers resolve",
			oidcIssuer:      func(issuerURL string) string { return issuerURL },
			authIssuer:      func(issuerURL string) string { return issuerURL },
			expectResolvedK: true,
		},
		{
			testName:      "credential issuer metadata claiming another identity is refused",
			oidcIssuer:    func(string) string { return "https://somebody-else.example.com" },
			authIssuer:    func(issuerURL string) string { return issuerURL },
			expectedError: ErrorIssuerMismatch,
		},
		{
			testName:      "authorization server metadata claiming another identity is refused",
			oidcIssuer:    func(issuerURL string) string { return issuerURL },
			authIssuer:    func(string) string { return "https://somebody-else.example.com" },
			expectedError: ErrorIssuerMetadataNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			var issuerURL string
			// The authorization server is hosted by the issuer itself, so no
			// extra allowed host is needed.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case WellKnownOIDCCredentialIssuer:
					_, _ = fmt.Fprintf(w, `{"issuer": "%s", "authorization_servers": ["%s"]}`,
						tc.oidcIssuer(issuerURL), issuerURL)
				case WellKnownOAuthAuthzServer:
					_, _ = fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s/jwks"}`,
						tc.authIssuer(issuerURL), issuerURL)
				case "/jwks":
					_, _ = w.Write(jwksBytes)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			issuerURL = server.URL

			resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

			key, err := resolveFirstIssuerKey(resolver, issuerURL, "fallback-key")
			if tc.expectResolvedK {
				assert.NoError(t, err)
				assert.NotNil(t, key)
				return
			}
			assert.ErrorIs(t, err, tc.expectedError)
			assert.Nil(t, key)
		})
	}
}

// TestResolveIssuerKeys_IssuerIdentifierWithTrailingSlash verifies that an
// issuer whose canonical identifier ends in a slash is accepted: both sides of
// the RFC 8414 comparison are canonicalized the same way.
func TestResolveIssuerKeys_IssuerIdentifierWithTrailingSlash(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "slash-key")
	jwksBytes := marshalJWKSet(t, keySet)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			// The issuer publishes its identifier WITH a trailing slash.
			metadata := fmt.Sprintf(`{"issuer": "%s/", "jwks_uri": "%s/jwks"}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

	for _, requestedIssuer := range []string{serverURL, serverURL + "/"} {
		key, err := resolveFirstIssuerKey(resolver, requestedIssuer, "slash-key")
		assert.NoError(t, err, "issuer %s should resolve", requestedIssuer)
		assert.NotNil(t, key)
	}
}

// TestResolveIssuerKeys_InvalidIssuerURL verifies that identifiers that are not
// usable http(s) URLs are rejected before any request is made.
func TestResolveIssuerKeys_InvalidIssuerURL(t *testing.T) {
	logging.Configure(testLoggingConfig)

	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

	invalidIssuers := []string{
		"", "not-a-url", "ftp://example.com", "https://",
		// RFC 8414 Section 2: an issuer identifier carries no query and no
		// fragment. Accepting them would make one endpoint addressable under
		// unboundedly many cache keys.
		"https://example.com?tenant=1", "https://example.com?", "https://example.com#one",
	}
	for _, issuer := range invalidIssuers {
		keys, err := resolver.ResolveIssuerKeys(context.Background(), issuer, "")
		assert.ErrorIs(t, err, ErrorInvalidIssuerURL, "issuer %q should be rejected", issuer)
		assert.Nil(t, keys)
	}
}

// TestJwksTTL verifies that an origin may shorten, but not extend, the lifetime
// of its cached key set, and that a declared lifetime of zero suppresses the
// cache write instead of falling back to the configured TTL.
func TestJwksTTL(t *testing.T) {
	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), 10*time.Minute)

	tests := []struct {
		testName         string
		caching          responseCaching
		expectedTTL      time.Duration
		expectedStorable bool
	}{
		{"no declaration falls back to the configured TTL", responseCaching{}, 10 * time.Minute, true},
		{"a shorter max-age is honoured", responseCaching{maxAge: 2 * time.Minute, declared: true}, 2 * time.Minute, true},
		{"a longer max-age is capped at the configured TTL", responseCaching{maxAge: time.Hour, declared: true}, 10 * time.Minute, true},
		{"a declared zero lifetime is not cached", responseCaching{declared: true}, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			ttl, storable := resolver.jwksTTL(tc.caching)
			assert.Equal(t, tc.expectedStorable, storable)
			assert.Equal(t, tc.expectedTTL, ttl)
		})
	}
}

// TestCachingOf verifies the reading of the Cache-Control directives that
// decide how long — and whether — a fetched key set is kept.
func TestCachingOf(t *testing.T) {
	tests := []struct {
		testName     string
		cacheControl string
		expected     responseCaching
	}{
		{"absent header", "", responseCaching{}},
		{"plain max-age", "max-age=120", responseCaching{maxAge: 2 * time.Minute, declared: true}},
		{"max-age among other directives", "public, max-age=60, must-revalidate", responseCaching{maxAge: time.Minute, declared: true}},
		{"unparseable max-age", "max-age=soon", responseCaching{}},
		{"zero max-age forbids caching", "max-age=0", responseCaching{declared: true}},
		{"no-store forbids caching", "no-store", responseCaching{declared: true}},
		{"no-cache forbids caching", "no-cache", responseCaching{declared: true}},
		{"directives are case-insensitive", "No-Store", responseCaching{declared: true}},
		{"no-store wins over a max-age behind it", "no-store, max-age=600", responseCaching{declared: true}},
		{"an unrelated directive is no declaration", "public", responseCaching{}},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			header := http.Header{}
			if tc.cacheControl != "" {
				header.Set("Cache-Control", tc.cacheControl)
			}
			assert.Equal(t, tc.expected, cachingOf(header))
		})
	}
}

// TestResolveIssuerKeys_UncacheableJwksIsNotCached verifies that a JWKS whose
// origin declares it uncacheable is fetched again on the next resolution
// instead of being kept for the configured TTL — go-cache reads a zero TTL as
// "default expiration", so honouring the directive means not storing at all.
func TestResolveIssuerKeys_UncacheableJwksIsNotCached(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "short-lived")
	jwksBytes := marshalJWKSet(t, keySet)

	tests := []struct {
		testName     string
		cacheControl string
		expectedJwks int32
	}{
		{"no-store is not cached", cacheControlNoStore, 2},
		{"no-cache is not cached", cacheControlNoCache, 2},
		{"max-age=0 is not cached", "max-age=0", 2},
		{"a positive max-age is cached", "max-age=600", 1},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			var jwksRequests atomic.Int32
			var serverURL string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case WellKnownJwtVcIssuer:
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s/jwks"}`, serverURL, serverURL)
				case "/jwks":
					jwksRequests.Add(1)
					w.Header().Set("Cache-Control", tc.cacheControl)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(jwksBytes)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			serverURL = server.URL

			resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)
			for i := 0; i < 2; i++ {
				keys, err := resolver.ResolveIssuerKeys(context.Background(), serverURL, "short-lived")
				require.NoError(t, err)
				require.Len(t, keys, 1)
			}

			assert.Equal(t, tc.expectedJwks, jwksRequests.Load())
		})
	}
}

// TestResolveIssuerKeys_UncacheableJwksClearsAnEarlierEntry verifies that a
// response declared uncacheable also removes what an earlier fetch left in the
// cache — otherwise the keys the issuer just declared uncacheable would keep
// being served from there. The second resolution is a rotation refetch, which
// is the only way a fresh response is fetched while an entry exists.
func TestResolveIssuerKeys_UncacheableJwksClearsAnEarlierEntry(t *testing.T) {
	logging.Configure(testLoggingConfig)

	oldKeySet, _ := generateTestJWKSet(t, "cached-key")
	rotatedKeySet, _ := generateTestJWKSet(t, "rotated-key")
	servedJwks := marshalJWKSet(t, oldKeySet)
	cacheable := true

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s/jwks"}`, serverURL, serverURL)
		case "/jwks":
			if !cacheable {
				w.Header().Set("Cache-Control", cacheControlNoStore)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(servedJwks)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	issuerCache := cache.New(5*time.Minute, 10*time.Minute)
	clock := &advanceableClock{now: time.Now()}
	resolver := newTestIssuerResolver(issuerCache, DefaultJwksCacheTTL).WithClock(clock)

	_, err := resolver.ResolveIssuerKeys(context.Background(), serverURL, "cached-key")
	require.NoError(t, err)
	issuerBase, err := parseIssuerURL(serverURL)
	require.NoError(t, err)
	_, found := issuerCache.Get(issuerCacheKey(issuerBase))
	require.True(t, found, "the first, cacheable response should have been cached")

	// The issuer rotates its key and now declares the key set uncacheable.
	servedJwks = marshalJWKSet(t, rotatedKeySet)
	cacheable = false
	clock.advance(MinJwksRefetchInterval)

	keys, err := resolver.ResolveIssuerKeys(context.Background(), serverURL, "rotated-key")
	require.NoError(t, err)
	require.Len(t, keys, 1)

	_, found = issuerCache.Get(issuerCacheKey(issuerBase))
	assert.False(t, found, "the stale cached entry should have been dropped")
}

// TestResolveIssuerKeys_FailedRefetchKeepsCachedKeys verifies that a rotation
// refetch that fails does not replace a working cached key set with a failure.
func TestResolveIssuerKeys_FailedRefetchKeepsCachedKeys(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "known-key")
	jwksBytes := marshalJWKSet(t, keySet)

	metadataAvailable := true
	var requestCount atomic.Int32
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if !metadataAvailable {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch r.URL.Path {
		case WellKnownJwtVcIssuer:
			metadata := fmt.Sprintf(`{"issuer": "%s", "jwks_uri": "%s/jwks"}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	clock := &advanceableClock{now: time.Now()}
	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL).
		WithClock(clock)

	_, err := resolveFirstIssuerKey(resolver, serverURL, "known-key")
	require.NoError(t, err)

	// The issuer goes down, and a token names a key id that is not cached.
	metadataAvailable = false
	clock.advance(MinJwksRefetchInterval)

	_, err = resolver.ResolveIssuerKeys(context.Background(), serverURL, "unknown-key")
	assert.ErrorIs(t, err, ErrorIssuerKeyNotFound)
	requestsAfterFailedRefetch := requestCount.Load()

	// A further unknown kid within the interval must not trigger another
	// resolution: a failed refetch has to re-arm the rate limit, otherwise
	// every token naming a random kid becomes an outbound request.
	_, err = resolver.ResolveIssuerKeys(context.Background(), serverURL, "another-unknown-key")
	assert.ErrorIs(t, err, ErrorIssuerKeyNotFound)
	assert.Equal(t, requestsAfterFailedRefetch, requestCount.Load(),
		"a failed refetch must not open the refetch window for every following token")

	// The known key must still verify — the failed refetch may not have
	// replaced the cached set with a negative entry.
	key, err := resolveFirstIssuerKey(resolver, serverURL, "known-key")
	assert.NoError(t, err)
	assert.NotNil(t, key)

	// Once the interval has passed again, a refetch is attempted anew.
	clock.advance(MinJwksRefetchInterval)
	_, err = resolver.ResolveIssuerKeys(context.Background(), serverURL, "unknown-key")
	assert.ErrorIs(t, err, ErrorIssuerKeyNotFound)
	assert.Greater(t, requestCount.Load(), requestsAfterFailedRefetch,
		"the refetch window must open again after the interval")
}

// TestResolveIssuerKeys_CapsAuthorizationServers verifies that only the first
// maxAuthorizationServers entries of a credential issuer's metadata are tried,
// so a hostile document cannot turn one token into an unbounded series of
// outbound requests.
func TestResolveIssuerKeys_CapsAuthorizationServers(t *testing.T) {
	logging.Configure(testLoggingConfig)

	const advertisedAuthServers = 50

	var authServerRequests atomic.Int32
	var issuerURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == WellKnownOIDCCredentialIssuer:
			authServers := make([]string, 0, advertisedAuthServers)
			for i := 0; i < advertisedAuthServers; i++ {
				authServers = append(authServers, fmt.Sprintf("%s/as-%d", issuerURL, i))
			}
			list, err := json.Marshal(authServers)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer": %q, "authorization_servers": %s}`, issuerURL, list)
		case strings.HasPrefix(r.URL.Path, WellKnownOAuthAuthzServer):
			// Every authorization server is reachable but useless.
			authServerRequests.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuerURL = server.URL

	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

	keys, err := resolver.ResolveIssuerKeys(context.Background(), issuerURL, "any-key")
	assert.ErrorIs(t, err, ErrorIssuerMetadataNotFound)
	assert.Nil(t, keys)
	assert.Equal(t, int32(maxAuthorizationServers), authServerRequests.Load(),
		"at most %d authorization servers may be tried", maxAuthorizationServers)
}

// TestResolveIssuerKeys_HonoursCallerContext verifies that the caller's context
// bounds the resolution: a context that is already done stops the work instead
// of running through the discovery hops.
func TestResolveIssuerKeys_HonoursCallerContext(t *testing.T) {
	logging.Configure(testLoggingConfig)

	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	keys, err := resolver.ResolveIssuerKeys(ctx, server.URL, "any-key")
	assert.ErrorIs(t, err, ErrorIssuerMetadataNotFound)
	assert.Nil(t, keys)
	assert.Equal(t, int32(0), requestCount.Load(), "a cancelled context must not reach the issuer")
}

// TestIssuerCacheKey verifies which issuer identifiers share a cache entry.
// Only differences that cannot denote a different issuer may collapse: the
// case of scheme and host, and a trailing slash. Everything else — the case of
// the path, its percent-encoding, a query or a fragment — has to keep the
// identifiers apart, because a shared entry hands one issuer's keys to
// another without the metadata identity check ever running.
func TestIssuerCacheKey(t *testing.T) {
	tests := []struct {
		testName string
		issuer   string
		other    string
		sameKey  bool
	}{
		{"a trailing slash is not a difference", "https://example.com", "https://example.com/", true},
		{"the host is case-insensitive", "https://Example.COM", "https://example.com", true},
		{"the scheme is case-insensitive", "HTTPS://example.com", "https://example.com", true},
		{"a trailing slash on a path is not a difference", "https://example.com/tenant1/", "https://example.com/tenant1", true},
		{"an encoded slash is not a path separator", "https://example.com/a%2Fb", "https://example.com/a/b", false},
		{"the path is case-sensitive", "https://example.com/Tenant1", "https://example.com/tenant1", false},
		{"different tenants stay apart", "https://example.com/tenant1", "https://example.com/tenant2", false},
		{"the port is part of the host", "https://example.com:8443", "https://example.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			issuerBase, err := parseIssuerURL(tc.issuer)
			require.NoError(t, err)
			otherBase, err := parseIssuerURL(tc.other)
			require.NoError(t, err)

			if tc.sameKey {
				assert.Equal(t, issuerCacheKey(otherBase), issuerCacheKey(issuerBase),
					"%s and %s should share a cache entry", tc.issuer, tc.other)
				return
			}
			assert.NotEqual(t, issuerCacheKey(otherBase), issuerCacheKey(issuerBase),
				"%s and %s must not share a cache entry", tc.issuer, tc.other)
		})
	}
}

// TestResolveIssuerKeys_EncodedPathDoesNotShareCache verifies the same at the
// resolver level: resolving an issuer must not serve its keys to an identifier
// that only decodes to the same path.
func TestResolveIssuerKeys_EncodedPathDoesNotShareCache(t *testing.T) {
	logging.Configure(testLoggingConfig)

	keySet, _ := generateTestJWKSet(t, "tenant-key")
	jwksBytes := marshalJWKSet(t, keySet)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Match on the escaped path: r.URL.Path decodes %2F back into a
		// separator, which is exactly the conflation under test.
		switch r.URL.EscapedPath() {
		case WellKnownJwtVcIssuer + "/a/b":
			metadata := fmt.Sprintf(`{"issuer": "%s/a/b", "jwks_uri": "%s/jwks"}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(metadata))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	resolver := newTestIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

	key, err := resolveFirstIssuerKey(resolver, serverURL+"/a/b", "tenant-key")
	require.NoError(t, err)
	require.NotNil(t, key)

	// The encoded form names a different issuer — one whose metadata this
	// server does not serve — so it must be resolved on its own and fail.
	keys, err := resolver.ResolveIssuerKeys(context.Background(), serverURL+"/a%2Fb", "tenant-key")
	assert.ErrorIs(t, err, ErrorIssuerMetadataNotFound)
	assert.Nil(t, keys)
}
