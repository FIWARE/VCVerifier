package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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
	resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

	key, err := resolver.ResolveIssuerKey(serverURL, "key-1")

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
	resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

	key, err := resolver.ResolveIssuerKey(serverURL, "inline-key")

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
	resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

	key, err := resolver.ResolveIssuerKey(issuerServerURL, "oidc-key")

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
	resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

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
			key, err := resolver.ResolveIssuerKey(serverURL, tc.kid)
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

func TestResolveIssuerKey_DefaultToFirstKey_NoKid(t *testing.T) {
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
	resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

	// Empty kid should return the first (only) key
	key, err := resolver.ResolveIssuerKey(serverURL, "")

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
	resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

	// First call — should make HTTP requests
	key1, err := resolver.ResolveIssuerKey(serverURL, "cached-key")
	assert.NoError(t, err)
	assert.NotNil(t, key1)
	firstCallRequests := requestCount.Load()
	assert.Greater(t, firstCallRequests, int32(0), "first call should make HTTP requests")

	// Second call — should use cache, no additional HTTP requests
	key2, err := resolver.ResolveIssuerKey(serverURL, "cached-key")
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
			expectedError: ErrorIssuerMetadataNotFound,
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
			resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

			key, err := resolver.ResolveIssuerKey(serverURL, tc.kid)
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
	resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

	// Call with trailing slash — should be normalized
	key, err := resolver.ResolveIssuerKey(serverURL+"/", "slash-key")

	assert.NoError(t, err)
	assert.NotNil(t, key)
}

func TestResolveIssuerKey_DefaultCacheTTL(t *testing.T) {
	// Verify that zero cacheTTL defaults to DefaultJwksCacheTTL
	c := cache.New(5*time.Minute, 10*time.Minute)
	resolver := NewCachingHttpsIssuerResolver(c, 0)
	assert.Equal(t, DefaultJwksCacheTTL, resolver.cacheTTL)
}

func TestFindKeyInSet(t *testing.T) {
	logging.Configure(testLoggingConfig)

	tests := []struct {
		testName    string
		keySet      func(t *testing.T) jwk.Set
		kid         string
		expectError error
		expectedKid string
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
			kid:         "b",
			expectedKid: "b",
		},
		{
			testName: "empty kid returns first key",
			keySet: func(t *testing.T) jwk.Set {
				return generateMultiKeyJWKSet(t, []string{"first", "second"})
			},
			kid:         "",
			expectedKid: "first",
		},
		{
			testName: "non-existent kid returns error",
			keySet: func(t *testing.T) jwk.Set {
				return generateMultiKeyJWKSet(t, []string{"a", "b"})
			},
			kid:         "z",
			expectError: ErrorIssuerKeyNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			keySet := tc.keySet(t)
			key, err := findKeyInSet(keySet, tc.kid)

			if tc.expectError != nil {
				assert.ErrorIs(t, err, tc.expectError)
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				require.NotNil(t, key)
				keyID, ok := key.KeyID()
				assert.True(t, ok)
				assert.Equal(t, tc.expectedKid, keyID)
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
	resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

	// Should succeed via the second authorization server
	key, err := resolver.ResolveIssuerKey(issuerServerURL, "multi-auth-key")

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
	resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

	key, err := resolver.ResolveIssuerKey(issuerServerURL, "some-key")
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
	resolver := NewCachingHttpsIssuerResolver(c, DefaultJwksCacheTTL)

	// Invalid JWKS content in primary path leads to fallback, which also fails → metadata not found
	key, err := resolver.ResolveIssuerKey(serverURL, "key-1")
	assert.Error(t, err)
	assert.Nil(t, key)
}
