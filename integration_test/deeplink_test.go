//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/fiware/VCVerifier/integration_test/helpers"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// deeplinkState is the session state parameter used in deeplink tests.
	deeplinkState = "deeplink-state-42"
)

// deeplinkFixture holds all infrastructure for a deeplink test.
type deeplinkFixture struct {
	verifier *helpers.VerifierProcess
	issuer   *helpers.TestIdentity
	holder   *helpers.TestIdentity
	cleanup  func()
}

// setupDeeplink creates a verifier configured for DEEPLINK with a simple JWT-VC credential.
func setupDeeplink(t *testing.T) *deeplinkFixture {
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

	vp, err := helpers.StartVerifier(config, projectRoot, binaryPath)
	require.NoError(t, err)

	return &deeplinkFixture{
		verifier: vp,
		issuer:   issuer,
		holder:   holder,
		cleanup: func() {
			vp.Stop()
			tirServer.Close()
		},
	}
}

// TestDeeplinkByReference tests the deeplink same-device flow using byReference mode.
// The authorization endpoint redirects directly to openid4vp:// with a request_uri.
func TestDeeplinkByReference(t *testing.T) {
	fixture := setupDeeplink(t)
	defer fixture.cleanup()

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Initiate authorization → expect redirect to openid4vp://
	authURL := fmt.Sprintf("%s/api/v1/authorization?client_id=%s&response_type=code&scope=%s&state=%s&redirect_uri=%s&nonce=test-nonce",
		fixture.verifier.BaseURL, serviceID, scopeName, deeplinkState, url.QueryEscape(redirectURI))

	resp, err := noRedirectClient.Get(authURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode, "authorization should redirect")

	// Step 2: Parse the openid4vp:// redirect Location header
	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "redirect Location header must be set")
	assert.True(t, strings.HasPrefix(location, "openid4vp://"), "should redirect to openid4vp:// URL, got: %s", location)

	// Step 3: Extract request_uri from the openid4vp URL
	parsedAuth, err := url.Parse(location)
	require.NoError(t, err)
	requestURI := parsedAuth.Query().Get("request_uri")
	require.NotEmpty(t, requestURI, "request_uri must be present in openid4vp URL")

	// Step 4: Fetch the request object JWT
	requestObjResp, err := http.Get(requestURI)
	require.NoError(t, err)
	defer requestObjResp.Body.Close()
	assert.Equal(t, http.StatusOK, requestObjResp.StatusCode, "request object endpoint should return 200")

	requestObjBody, err := io.ReadAll(requestObjResp.Body)
	require.NoError(t, err)

	// Step 5: Decode request object JWT to extract claims
	requestToken, err := jwt.Parse([]byte(requestObjBody), jwt.WithVerify(false))
	require.NoError(t, err, "request object should be valid JWT")

	responseURIRaw := getStringClaim(t, requestToken, "response_uri")
	require.NotEmpty(t, responseURIRaw, "response_uri must be in request object")

	stateClaim := getStringClaim(t, requestToken, "state")
	require.NotEmpty(t, stateClaim, "state must be in request object")

	// Step 6: Verify dcql_query is present
	assertHasClaim(t, requestToken, "dcql_query")

	// Step 7: Create valid credentials and DCQL response
	vc, err := helpers.CreateJWTVC(fixture.issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
	})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(fixture.holder, "", serviceID, vc)
	require.NoError(t, err)

	vpToken, err := helpers.CreateDCQLResponse(map[string]string{"cred-1": vpJWT})
	require.NoError(t, err)

	// Step 8: POST authentication response → expect 302 redirect with code
	authResp, err := noRedirectClient.PostForm(responseURIRaw, url.Values{
		"state":    {stateClaim},
		"vp_token": {vpToken},
	})
	require.NoError(t, err)
	defer authResp.Body.Close()
	assert.Equal(t, http.StatusFound, authResp.StatusCode, "authentication response should redirect (same-device)")

	// Step 9: Extract authorization code from redirect Location
	authRedirect := authResp.Header.Get("Location")
	require.NotEmpty(t, authRedirect, "redirect Location must be set after authentication")

	parsedRedirect, err := url.Parse(authRedirect)
	require.NoError(t, err)
	code := parsedRedirect.Query().Get("code")
	require.NotEmpty(t, code, "authorization code must be in redirect URL")

	// Step 10: Exchange authorization code for JWT
	// For DEEPLINK same-device flow, the stored callback is the verifier's own base URL
	// (since redirectPath is empty in the authorization endpoint call).
	// The redirect_uri in the token exchange must match the stored callback.
	tokenResp, err := http.PostForm(fmt.Sprintf("%s/token", fixture.verifier.BaseURL), url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {fixture.verifier.BaseURL},
	})
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	assert.Equal(t, http.StatusOK, tokenResp.StatusCode, "token exchange should return 200")

	var tokenBody map[string]interface{}
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenBody)
	require.NoError(t, err)
	assert.Equal(t, "Bearer", tokenBody["token_type"])
	accessToken, ok := tokenBody["access_token"].(string)
	require.True(t, ok && accessToken != "", "access_token must be a non-empty string")

	// Step 11: Verify the returned JWT
	verifyAccessToken(t, fixture.verifier.BaseURL, accessToken)
}

// TestDeeplinkByValue tests the deeplink same-device flow using byValue mode.
// The openid4vp:// URL contains the request object JWT directly in a "request" parameter.
func TestDeeplinkByValue(t *testing.T) {
	fixture := setupDeeplink(t)
	defer fixture.cleanup()

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Use /api/v1/samedevice with request_mode=byValue to get the openid4vp:// URL
	// The authorization endpoint always forces byReference, so we use the samedevice endpoint directly.
	sameDeviceURL := fmt.Sprintf("%s/api/v1/samedevice?state=%s&client_id=%s&scope=%s&request_mode=byValue",
		fixture.verifier.BaseURL, deeplinkState, serviceID, scopeName)

	resp, err := noRedirectClient.Get(sameDeviceURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode, "samedevice should redirect")

	// Step 2: Parse the openid4vp:// redirect with embedded request JWT
	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "redirect Location header must be set")
	assert.True(t, strings.HasPrefix(location, "openid4vp://"), "should redirect to openid4vp:// URL")

	parsedAuth, err := url.Parse(location)
	require.NoError(t, err)
	requestJWTStr := parsedAuth.Query().Get("request")
	require.NotEmpty(t, requestJWTStr, "request parameter must be present in openid4vp URL (byValue mode)")

	// Step 3: Decode the embedded request object JWT
	requestToken, err := jwt.Parse([]byte(requestJWTStr), jwt.WithVerify(false))
	require.NoError(t, err, "embedded request object should be valid JWT")

	responseURIRaw := getStringClaim(t, requestToken, "response_uri")
	require.NotEmpty(t, responseURIRaw, "response_uri must be in request object")

	stateClaim := getStringClaim(t, requestToken, "state")
	require.NotEmpty(t, stateClaim, "state must be in request object")

	// Verify dcql_query is present
	assertHasClaim(t, requestToken, "dcql_query")

	// Step 4: Create valid credentials and DCQL response
	vc, err := helpers.CreateJWTVC(fixture.issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
	})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(fixture.holder, "", serviceID, vc)
	require.NoError(t, err)

	vpToken, err := helpers.CreateDCQLResponse(map[string]string{"cred-1": vpJWT})
	require.NoError(t, err)

	// Step 5: POST authentication response → expect 302 redirect with code
	authResp, err := noRedirectClient.PostForm(responseURIRaw, url.Values{
		"state":    {stateClaim},
		"vp_token": {vpToken},
	})
	require.NoError(t, err)
	defer authResp.Body.Close()
	assert.Equal(t, http.StatusFound, authResp.StatusCode, "authentication response should redirect (same-device)")

	// Step 6: Extract authorization code from redirect
	authRedirect := authResp.Header.Get("Location")
	require.NotEmpty(t, authRedirect, "redirect Location must be set after authentication")

	parsedRedirect, err := url.Parse(authRedirect)
	require.NoError(t, err)
	code := parsedRedirect.Query().Get("code")
	require.NotEmpty(t, code, "authorization code must be in redirect URL")

	// Step 7: Exchange authorization code for JWT
	// The stored callback for same-device flow is the verifier's own base URL.
	tokenResp, err := http.PostForm(fmt.Sprintf("%s/token", fixture.verifier.BaseURL), url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {fixture.verifier.BaseURL},
	})
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	assert.Equal(t, http.StatusOK, tokenResp.StatusCode, "token exchange should return 200")

	var tokenBody map[string]interface{}
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenBody)
	require.NoError(t, err)
	assert.Equal(t, "Bearer", tokenBody["token_type"])
	accessToken, ok := tokenBody["access_token"].(string)
	require.True(t, ok && accessToken != "", "access_token must be a non-empty string")

	verifyAccessToken(t, fixture.verifier.BaseURL, accessToken)
}
