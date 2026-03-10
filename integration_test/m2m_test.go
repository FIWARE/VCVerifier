//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/fiware/VCVerifier/integration_test/helpers"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// serviceID is the service identifier used in all M2M test configurations.
	serviceID = "test-svc"
	// scopeName is the OIDC scope used in all M2M test configurations.
	scopeName = "test-scope"
)

var (
	// binaryPath holds the path to the compiled verifier binary, built once per test run.
	binaryPath string
	// projectRoot holds the absolute path to the VCVerifier project root.
	projectRoot string
)

func TestMain(m *testing.M) {
	// Determine project root (parent of integration_test/).
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get working directory: %v\n", err)
		os.Exit(1)
	}
	projectRoot = filepath.Dir(wd)

	// Build the verifier binary once for all tests.
	binaryPath, err = helpers.BuildVerifier(projectRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build verifier: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(filepath.Dir(binaryPath))

	os.Exit(m.Run())
}

// m2mTestCase defines a parameterized M2M success test case.
type m2mTestCase struct {
	name string
	// setup prepares all infrastructure (mocks, identities, config, credentials)
	// and returns what's needed to execute the test.
	setup func(t *testing.T) *m2mTestFixture
}

// m2mTestFixture holds all objects needed to execute an M2M test case.
type m2mTestFixture struct {
	configYAML   string
	extraEnv     []string
	dcqlResponse map[string]string
	cleanup      func()
}

// TestM2MSuccess runs parameterized success tests for the M2M VP-token-to-JWT exchange
// via POST /services/:service_id/token with grant_type=vp_token.
func TestM2MSuccess(t *testing.T) {
	tests := []m2mTestCase{
		{
			name:  "OneJWTVC_DidKeyIssuer",
			setup: setupOneJWTVCDidKey,
		},
		{
			name:  "MultipleJWTVCs_DidKeyIssuer",
			setup: setupMultipleJWTVCsDidKey,
		},
		{
			name:  "OneSDJWT_DidKeyIssuer",
			setup: setupOneSDJWTDidKey,
		},
		{
			name:  "MultipleSDJWTs_DidKeyIssuer",
			setup: setupMultipleSDJWTsDidKey,
		},
		{
			name:  "JWTVC_DidWebIssuer",
			setup: setupJWTVCDidWeb,
		},
		{
			name:  "JWTVC_CnfHolderBinding",
			setup: setupJWTVCCnfHolder,
		},
		{
			name:  "JWTVC_ClaimBasedHolderBinding",
			setup: setupJWTVCClaimHolder,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := tc.setup(t)
			defer fixture.cleanup()

			vp, err := helpers.StartVerifier(fixture.configYAML, projectRoot, binaryPath, fixture.extraEnv...)
			require.NoError(t, err, "verifier should start successfully")
			defer vp.Stop()

			vpToken, err := helpers.CreateDCQLResponse(fixture.dcqlResponse)
			require.NoError(t, err)

			resp, err := http.PostForm(
				fmt.Sprintf("%s/services/%s/token", vp.BaseURL, serviceID),
				url.Values{
					"grant_type": {"vp_token"},
					"vp_token":   {vpToken},
					"scope":      {scopeName},
				},
			)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "expected 200 OK, got %d: %s", resp.StatusCode, string(body))

			var tokenResp tokenResponse
			err = json.Unmarshal(body, &tokenResp)
			require.NoError(t, err)

			assert.Equal(t, "Bearer", tokenResp.TokenType)
			assert.NotEmpty(t, tokenResp.AccessToken, "access_token should not be empty")
			assert.NotEmpty(t, tokenResp.IDToken, "id_token should not be empty")

			// Verify the returned JWT against the verifier's JWKS.
			verifyAccessToken(t, vp.BaseURL, tokenResp.AccessToken)
		})
	}
}

// tokenResponse mirrors the verifier's token endpoint JSON response.
type tokenResponse struct {
	TokenType       string  `json:"token_type"`
	IssuedTokenType string  `json:"issued_token_type"`
	ExpiresIn       float64 `json:"expires_in"`
	AccessToken     string  `json:"access_token"`
	IDToken         string  `json:"id_token"`
	Scope           string  `json:"scope"`
}

// verifyAccessToken fetches the verifier's JWKS and verifies that the access token JWT
// has a valid signature and contains expected standard claims.
func verifyAccessToken(t *testing.T, baseURL string, accessToken string) {
	t.Helper()

	// Fetch JWKS from the verifier.
	resp, err := http.Get(baseURL + "/.well-known/jwks")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	jwksBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	keySet, err := jwk.Parse(jwksBytes)
	require.NoError(t, err)

	// Parse and verify the JWT signature using the JWKS.
	token, err := jwt.Parse([]byte(accessToken), jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)))
	require.NoError(t, err, "access token JWT should be verifiable with verifier's JWKS")

	// The token should have an issuer and an expiration.
	iss, issOk := token.Issuer()
	assert.True(t, issOk, "JWT should have an issuer claim")
	assert.NotEmpty(t, iss, "JWT issuer should not be empty")
	exp, expOk := token.Expiration()
	assert.True(t, expOk, "JWT should have an expiration claim")
	assert.False(t, exp.IsZero(), "JWT expiration should not be zero")
}

// --- Setup functions for each test case ---

// setupOneJWTVCDidKey creates a single JWT-VC with a did:key issuer.
func setupOneJWTVCDidKey(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
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

	vc, err := helpers.CreateJWTVC(issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
		"name": "Test User",
	})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(holder, "", serviceID, vc)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML:   config,
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup:      func() { tirServer.Close() },
	}
}

// setupMultipleJWTVCsDidKey creates two JWT-VCs of different types with a did:key issuer.
func setupMultipleJWTVCsDidKey(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	tirServer := helpers.NewMockTIR(map[string]helpers.TrustedIssuer{
		issuer.DID: {
			Did: issuer.DID,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute("VerifiableCredential", nil),
				helpers.BuildIssuerAttribute("TypeA", nil),
				helpers.BuildIssuerAttribute("TypeB", nil),
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
		WithCredential(serviceID, scopeName, "TypeA", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "TypeA", true).
		WithCredential(serviceID, scopeName, "TypeB", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "TypeB", true).
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-1", "TypeA"),
				helpers.NewJWTVCQuery("cred-2", "TypeB"),
			},
		}).
		Build()

	vcA, err := helpers.CreateJWTVC(issuer, "TypeA", map[string]interface{}{"type": "TypeA"})
	require.NoError(t, err)
	vcB, err := helpers.CreateJWTVC(issuer, "TypeB", map[string]interface{}{"type": "TypeB"})
	require.NoError(t, err)

	// Each DCQL query gets its own VP wrapping the matching VC.
	vpA, err := helpers.CreateVPToken(holder, "", serviceID, vcA)
	require.NoError(t, err)
	vpB, err := helpers.CreateVPToken(holder, "", serviceID, vcB)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML: config,
		dcqlResponse: map[string]string{
			"cred-1": vpA,
			"cred-2": vpB,
		},
		cleanup: func() { tirServer.Close() },
	}
}

// setupOneSDJWTDidKey creates a single SD-JWT with a did:key issuer.
func setupOneSDJWTDidKey(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	tirServer := helpers.NewMockTIR(map[string]helpers.TrustedIssuer{
		issuer.DID: {
			Did: issuer.DID,
			Attributes: []helpers.IssuerAttribute{
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
		WithCredential(serviceID, scopeName, "CustomerCredential", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "CustomerCredential", true).
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewSDJWTQuery("cred-1", "CustomerCredential"),
			},
		}).
		Build()

	sdJWT, err := helpers.CreateSDJWT(issuer, "CustomerCredential", map[string]interface{}{
		"familyName": "Doe",
		"givenName":  "John",
	})
	require.NoError(t, err)

	// SD-JWT is placed directly in the DCQL response (not wrapped in a VP).
	return &m2mTestFixture{
		configYAML:   config,
		dcqlResponse: map[string]string{"cred-1": sdJWT},
		cleanup:      func() { tirServer.Close() },
	}
}

// setupMultipleSDJWTsDidKey creates two SD-JWTs of different types from the same did:key issuer.
func setupMultipleSDJWTsDidKey(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	tirServer := helpers.NewMockTIR(map[string]helpers.TrustedIssuer{
		issuer.DID: {
			Did: issuer.DID,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute("TypeA", nil),
				helpers.BuildIssuerAttribute("TypeB", nil),
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
		WithCredential(serviceID, scopeName, "TypeA", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "TypeA", true).
		WithCredential(serviceID, scopeName, "TypeB", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "TypeB", true).
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewSDJWTQuery("cred-1", "TypeA"),
				helpers.NewSDJWTQuery("cred-2", "TypeB"),
			},
		}).
		Build()

	sdJWTA, err := helpers.CreateSDJWT(issuer, "TypeA", map[string]interface{}{"familyName": "Doe"})
	require.NoError(t, err)
	sdJWTB, err := helpers.CreateSDJWT(issuer, "TypeB", map[string]interface{}{"givenName": "John"})
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML: config,
		dcqlResponse: map[string]string{
			"cred-1": sdJWTA,
			"cred-2": sdJWTB,
		},
		cleanup: func() { tirServer.Close() },
	}
}

// setupJWTVCDidWeb creates a JWT-VC with a did:web issuer backed by a TLS mock server.
// Uses SetupDidWebTLSIdentity to handle the chicken-and-egg problem of needing
// the server URL for the DID while needing the identity for the DID document.
func setupJWTVCDidWeb(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, didWebServer := helpers.SetupDidWebTLSIdentity()

	holder, err := helpers.GenerateDidKeyIdentity()
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

	vc, err := helpers.CreateJWTVC(issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
		"name": "Test User",
	})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(holder, "", serviceID, vc)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML:   config,
		extraEnv:     []string{"SSL_CERT_FILE=" + didWebServer.CACertPath},
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup: func() {
			tirServer.Close()
			didWebServer.Close()
		},
	}
}

// setupJWTVCCnfHolder creates a JWT-VC with cnf (confirmation) holder binding.
// The verifier does not enforce cnf validation, so this test verifies that
// VCs with cnf claims are accepted without error.
func setupJWTVCCnfHolder(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
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

	vc, err := helpers.CreateJWTVCWithCnf(issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
		"name": "Test User",
	}, holder.PublicKeyJWK)
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(holder, "", serviceID, vc)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML:   config,
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup:      func() { tirServer.Close() },
	}
}

// setupJWTVCClaimHolder creates a JWT-VC with claim-based holder binding.
// The VC's credentialSubject contains a "holder" field matching the VP signer's DID.
// The verifier validates that credentialSubject.holder == VP holder DID.
func setupJWTVCClaimHolder(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
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
		WithHolderVerification(serviceID, scopeName, "CustomerCredential", "holder").
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-1", "CustomerCredential"),
			},
		}).
		Build()

	vc, err := helpers.CreateJWTVCWithHolder(issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
		"name": "Test User",
	}, holder.DID)
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(holder, "", serviceID, vc)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML:   config,
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup:      func() { tirServer.Close() },
	}
}
