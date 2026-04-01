//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/fiware/VCVerifier/integration_test/helpers"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// endpointFixture holds a running verifier for endpoint tests.
type endpointFixture struct {
	verifier *helpers.VerifierProcess
	cleanup  func()
}

// setupEndpointTests creates a verifier with a basic DEEPLINK config for endpoint testing.
func setupEndpointTests(t *testing.T) *endpointFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	tirServer := helpers.NewMockTIR(map[string]helpers.TrustedIssuer{
		issuer.DID: {
			Did: issuer.DID,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute("VerifiableCredential", nil),
				helpers.BuildIssuerAttribute("CustomerCredential", nil),
			},
		},
	})

	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	keyPath, err := helpers.GenerateSigningKeyPEM(t.TempDir())
	require.NoError(t, err)

	config := helpers.NewConfigBuilder(port, tirServer.URL).
		WithSigningKey(keyPath).
		WithService(serviceID, scopeName, "DEEPLINK").
		WithCredential(serviceID, scopeName, "VerifiableCredential", "*").
		WithCredential(serviceID, scopeName, "CustomerCredential", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "CustomerCredential", true).
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-1", "CustomerCredential"),
			},
		}).
		Build()

	vp, err := helpers.StartVerifier(config, projectRoot, binaryPath)
	require.NoError(t, err)

	return &endpointFixture{
		verifier: vp,
		cleanup: func() {
			vp.Stop()
			tirServer.Close()
		},
	}
}

// TestEndpoints runs parameterized tests for cross-cutting endpoint concerns and edge cases.
func TestEndpoints(t *testing.T) {
	fixture := setupEndpointTests(t)
	defer fixture.cleanup()

	baseURL := fixture.verifier.BaseURL

	t.Run("JWKS", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/.well-known/jwks", baseURL))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		keySet, err := jwk.Parse(body)
		require.NoError(t, err, "response must be valid JWKS JSON")
		assert.True(t, keySet.Len() > 0, "JWKS should contain at least one key")
	})

	t.Run("OpenIDConfiguration", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/services/%s/.well-known/openid-configuration", baseURL, serviceID))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var config map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&config)
		require.NoError(t, err, "response must be valid JSON")

		assert.NotEmpty(t, config["issuer"], "openid-configuration must contain issuer")
		assert.NotEmpty(t, config["token_endpoint"], "openid-configuration must contain token_endpoint")
		assert.NotEmpty(t, config["jwks_uri"], "openid-configuration must contain jwks_uri")
	})

	t.Run("Health", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/health", baseURL))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("TokenWithoutGrantType", func(t *testing.T) {
		resp, err := http.PostForm(fmt.Sprintf("%s/token", baseURL), url.Values{
			"code": {"some-code"},
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("TokenWithUnsupportedGrantType", func(t *testing.T) {
		resp, err := http.PostForm(fmt.Sprintf("%s/token", baseURL), url.Values{
			"grant_type": {"unsupported_type"},
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("AuthorizationWithoutClientID", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/api/v1/authorization?scope=%s&state=test-state&redirect_uri=http://example.com",
			baseURL, scopeName))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("AuthorizationWithoutScope", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/api/v1/authorization?client_id=%s&state=test-state&redirect_uri=http://example.com",
			baseURL, serviceID))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("AuthorizationWithoutState", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("%s/api/v1/authorization?client_id=%s&scope=%s&redirect_uri=http://example.com",
			baseURL, serviceID, scopeName))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}
