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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// httpsCredentialType is the credential type used across the HTTPS issuer tests.
	httpsCredentialType = "CustomerCredential"
	// wildcardTil accepts any issuer for a credential type without querying a registry.
	wildcardTil = "*"
)

// httpsIssuerFixture holds everything needed to run one HTTPS-issuer test case.
type httpsIssuerFixture struct {
	configYAML   string
	extraEnv     []string
	dcqlResponse map[string]string
	cleanup      func()
}

// httpsIssuerCase parameterizes the HTTPS-issuer exchange test.
type httpsIssuerCase struct {
	name string
	// inlineJwks serves the key set inside the metadata document instead of
	// from a jwks_uri.
	inlineJwks bool
	// registerAtTir controls whether the registry knows the issuer.
	registerAtTir bool
	// useWildcardTil configures "*" as the trusted issuers list instead of the
	// registry endpoint, which accepts the issuer without a lookup.
	useWildcardTil bool
	// expectedStatus is the HTTP status the token exchange must answer with.
	expectedStatus int
}

// setupHttpsIssuer builds a verifier configuration for one HTTPS-issuer case:
// a TLS metadata server standing in for the issuer, a credential signed by it,
// and a registry that may or may not know the issuer.
func setupHttpsIssuer(t *testing.T, tc httpsIssuerCase) *httpsIssuerFixture {
	t.Helper()

	identity, err := helpers.GenerateHttpsIssuerIdentity()
	require.NoError(t, err)

	var issuerServer *helpers.HttpsIssuerServer
	if tc.inlineJwks {
		issuerServer = helpers.NewHttpsIssuerTLSServerWithInlineJWKS(identity)
	} else {
		issuerServer = helpers.NewHttpsIssuerTLSServer(identity)
	}

	holder, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	// The issuer is looked up in the registry by its HTTPS identifier, exactly
	// like a DID-based issuer would be.
	registeredIssuers := map[string]helpers.TrustedIssuer{}
	if tc.registerAtTir {
		registeredIssuers[issuerServer.Identity.IssuerURL] = helpers.TrustedIssuer{
			Did: issuerServer.Identity.IssuerURL,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute(httpsCredentialType, nil),
			},
		}
	}
	tirServer := helpers.NewMockTIR(registeredIssuers)

	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	keyPath, err := helpers.GenerateSigningKeyPEM(t.TempDir())
	require.NoError(t, err)

	trustedIssuersURL := tirServer.URL
	if tc.useWildcardTil {
		trustedIssuersURL = wildcardTil
	}

	config := helpers.NewConfigBuilder(port, tirServer.URL).
		WithSigningKey(keyPath).
		WithService(serviceID, scopeName, "DEEPLINK").
		WithCredential(serviceID, scopeName, httpsCredentialType, trustedIssuersURL).
		WithTrustedParticipantsList(serviceID, scopeName, httpsCredentialType, "ebsi", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, httpsCredentialType, true).
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-1", httpsCredentialType),
			},
		}).
		Build()

	vc, err := helpers.CreateJWTVCWithHttpsIssuer(identity, httpsCredentialType, map[string]interface{}{
		"type": httpsCredentialType,
		"name": "Test User",
	})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(holder, "", serviceID, vc)
	require.NoError(t, err)

	return &httpsIssuerFixture{
		configYAML:   config,
		extraEnv:     []string{"SSL_CERT_FILE=" + issuerServer.CACertPath},
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup: func() {
			tirServer.Close()
			issuerServer.Close()
		},
	}
}

// TestHttpsIssuerVPExchange exercises the full VP-token-to-JWT exchange with a
// credential issued by an issuer identified by an HTTPS URL. The signing key is
// discovered through the issuer's well-known metadata and JWKS, and the issuer
// itself is resolved in the configured trusted-issuers registry — a trust-list
// entry is an endpoint to query, never an issuer identity.
func TestHttpsIssuerVPExchange(t *testing.T) {
	tests := []httpsIssuerCase{
		{
			name:           "JwksUri_RegisteredAtRegistry",
			registerAtTir:  true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "InlineJwks_RegisteredAtRegistry",
			inlineJwks:     true,
			registerAtTir:  true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "WildcardTil_SkipsTheRegistryLookup",
			registerAtTir:  true,
			useWildcardTil: true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "UnknownToTheRegistry",
			registerAtTir:  false,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := setupHttpsIssuer(t, tc)
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
			require.Equal(t, tc.expectedStatus, resp.StatusCode,
				"unexpected status, body: %s", string(body))

			if tc.expectedStatus != http.StatusOK {
				return
			}

			var tokenResp tokenResponse
			require.NoError(t, json.Unmarshal(body, &tokenResp))
			assert.Equal(t, "Bearer", tokenResp.TokenType)
			assert.NotEmpty(t, tokenResp.AccessToken, "access_token should not be empty")

			verifyAccessToken(t, vp.BaseURL, tokenResp.AccessToken)
		})
	}
}
