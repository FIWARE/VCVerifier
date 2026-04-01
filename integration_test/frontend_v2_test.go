//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/integration_test/helpers"
	"github.com/gorilla/websocket"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// redirectURI is the simulated callback URI for the frontend application.
	redirectURI = "http://localhost:9999/callback"
	// testState is the session state parameter used in frontend v2 tests.
	testState = "test-state-12345"
)

// frontendV2Fixture holds all infrastructure for a frontend v2 test.
type frontendV2Fixture struct {
	verifier *helpers.VerifierProcess
	issuer   *helpers.TestIdentity
	holder   *helpers.TestIdentity
	cleanup  func()
}

// setupFrontendV2 creates a verifier configured for FRONTEND_V2 with a simple JWT-VC credential.
func setupFrontendV2(t *testing.T) *frontendV2Fixture {
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
		WithService(serviceID, scopeName, "FRONTEND_V2").
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

	return &frontendV2Fixture{
		verifier: vp,
		issuer:   issuer,
		holder:   holder,
		cleanup: func() {
			vp.Stop()
			tirServer.Close()
		},
	}
}

// TestFrontendV2ByReference tests the complete frontend v2 cross-device flow using byReference mode.
func TestFrontendV2ByReference(t *testing.T) {
	fixture := setupFrontendV2(t)
	defer fixture.cleanup()

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Initiate authorization → expect redirect to /api/v2/loginQR
	authURL := fmt.Sprintf("%s/api/v1/authorization?client_id=%s&response_type=code&scope=%s&state=%s&redirect_uri=%s&nonce=test-nonce",
		fixture.verifier.BaseURL, serviceID, scopeName, testState, url.QueryEscape(redirectURI))

	resp, err := noRedirectClient.Get(authURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode, "authorization should redirect")

	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "redirect Location header must be set")
	assert.Contains(t, location, "/api/v2/loginQR", "should redirect to loginQR v2")
	assert.Contains(t, location, "request_mode=byReference", "should use byReference mode")

	// Step 2: Follow redirect to /api/v2/loginQR → get HTML with openid4vp:// URL
	loginQRURL := location
	// The redirect URL may be relative or absolute; handle both.
	if !strings.HasPrefix(loginQRURL, "http") {
		loginQRURL = fixture.verifier.BaseURL + loginQRURL
	}

	qrResp, err := http.Get(loginQRURL)
	require.NoError(t, err)
	defer qrResp.Body.Close()
	assert.Equal(t, http.StatusOK, qrResp.StatusCode, "loginQR should return 200")

	htmlBody, err := io.ReadAll(qrResp.Body)
	require.NoError(t, err)
	htmlStr := string(htmlBody)

	// Step 3: Extract openid4vp:// URL from the HTML (it's in the href of the "Open in Wallet" link)
	authRequestURL := extractOpenID4VPURL(t, htmlStr)
	require.NotEmpty(t, authRequestURL, "openid4vp URL must be present in HTML")

	// Step 4: Parse the openid4vp:// URL and extract request_uri
	// The HTML template may encode ampersands as &amp; in href attributes.
	authRequestURL = strings.ReplaceAll(authRequestURL, "&amp;", "&")
	parsedAuth, err := url.Parse(authRequestURL)
	require.NoError(t, err)
	requestURI := parsedAuth.Query().Get("request_uri")
	require.NotEmpty(t, requestURI, "request_uri must be present in openid4vp URL")

	// Step 5: Fetch the request object JWT
	requestObjResp, err := http.Get(requestURI)
	require.NoError(t, err)
	defer requestObjResp.Body.Close()
	assert.Equal(t, http.StatusOK, requestObjResp.StatusCode, "request object endpoint should return 200")

	requestObjBody, err := io.ReadAll(requestObjResp.Body)
	require.NoError(t, err)
	requestJWT := string(requestObjBody)

	// Step 6: Decode request object JWT (without verification) to extract claims
	requestToken, err := jwt.Parse([]byte(requestJWT), jwt.WithVerify(false))
	require.NoError(t, err, "request object should be valid JWT")

	responseURIRaw := getStringClaim(t, requestToken, "response_uri")
	require.NotEmpty(t, responseURIRaw, "response_uri must be in request object")
	// The loginQR handler hardcodes "https" as protocol, but our test verifier runs plain HTTP.
	responseURI := strings.Replace(responseURIRaw, "https://", "http://", 1)

	stateClaim := getStringClaim(t, requestToken, "state")
	require.NotEmpty(t, stateClaim, "state must be in request object")

	// Verify dcql_query is present
	assertHasClaim(t, requestToken, "dcql_query")

	// Step 7: Create valid credentials matching the DCQL query
	vc, err := helpers.CreateJWTVC(fixture.issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
	})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(fixture.holder, "", serviceID, vc)
	require.NoError(t, err)

	vpToken, err := helpers.CreateDCQLResponse(map[string]string{"cred-1": vpJWT})
	require.NoError(t, err)

	// Step 8: Open WebSocket connection BEFORE posting the authentication response
	wsURL := fmt.Sprintf("ws://localhost:%d/ws?state=%s", fixture.verifier.Port, stateClaim)
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err, "WebSocket connection should succeed")
	defer wsConn.Close()

	// Read the initial "session" message
	var sessionMsg map[string]interface{}
	err = wsConn.ReadJSON(&sessionMsg)
	require.NoError(t, err, "should receive session message")
	assert.Equal(t, "session", sessionMsg["type"], "first message should be type=session")

	// Step 9: POST authentication response
	authResp, err := http.PostForm(responseURI, url.Values{
		"state":    {stateClaim},
		"vp_token": {vpToken},
	})
	require.NoError(t, err)
	defer authResp.Body.Close()
	assert.Equal(t, http.StatusOK, authResp.StatusCode, "authentication response should return 200")

	// Step 10: Read WebSocket "authenticated" message with redirect URL
	wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var authMsg map[string]interface{}
	err = wsConn.ReadJSON(&authMsg)
	require.NoError(t, err, "should receive authenticated message")
	assert.Equal(t, "authenticated", authMsg["type"], "message should be type=authenticated")

	wsRedirectURL, ok := authMsg["redirectUrl"].(string)
	require.True(t, ok, "redirectUrl must be a string")
	require.NotEmpty(t, wsRedirectURL, "redirectUrl must not be empty")

	// Step 11: Extract authorization code from the redirect URL
	parsedRedirect, err := url.Parse(wsRedirectURL)
	require.NoError(t, err)
	code := parsedRedirect.Query().Get("code")
	require.NotEmpty(t, code, "authorization code must be in redirect URL")

	// Step 12: Exchange authorization code for JWT at /token endpoint
	tokenResp, err := http.PostForm(fmt.Sprintf("%s/token", fixture.verifier.BaseURL), url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
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

	// Step 13: Verify the returned JWT
	verifyAccessToken(t, fixture.verifier.BaseURL, accessToken)
}

// TestFrontendV2ByValue tests the complete frontend v2 cross-device flow using byValue mode.
// In byValue mode, the request object JWT is embedded directly in the openid4vp:// URL.
func TestFrontendV2ByValue(t *testing.T) {
	fixture := setupFrontendV2(t)
	defer fixture.cleanup()

	// For byValue, call /api/v2/loginQR directly with request_mode=byValue
	loginQRURL := fmt.Sprintf("%s/api/v2/loginQR?state=%s&client_id=%s&redirect_uri=%s&scope=%s&nonce=test-nonce&request_mode=byValue",
		fixture.verifier.BaseURL, testState, serviceID, url.QueryEscape(redirectURI), scopeName)

	qrResp, err := http.Get(loginQRURL)
	require.NoError(t, err)
	defer qrResp.Body.Close()
	assert.Equal(t, http.StatusOK, qrResp.StatusCode, "loginQR should return 200")

	htmlBody, err := io.ReadAll(qrResp.Body)
	require.NoError(t, err)

	// Step 1: Extract openid4vp:// URL from HTML
	authRequestURL := extractOpenID4VPURL(t, string(htmlBody))
	require.NotEmpty(t, authRequestURL, "openid4vp URL must be present in HTML")

	// Step 2: In byValue mode, the request JWT is embedded in the "request" query parameter
	// The HTML template may encode ampersands as &amp; in href attributes.
	authRequestURL = strings.ReplaceAll(authRequestURL, "&amp;", "&")
	parsedAuth, err := url.Parse(authRequestURL)
	require.NoError(t, err)
	requestJWTStr := parsedAuth.Query().Get("request")
	require.NotEmpty(t, requestJWTStr, "request parameter must be present in openid4vp URL (byValue mode)")

	// Step 3: Decode the request object JWT (without verification)
	requestToken, err := jwt.Parse([]byte(requestJWTStr), jwt.WithVerify(false))
	require.NoError(t, err, "embedded request object should be valid JWT")

	responseURIRaw := getStringClaim(t, requestToken, "response_uri")
	require.NotEmpty(t, responseURIRaw, "response_uri must be in request object")
	// The loginQR handler hardcodes "https" as protocol, but our test verifier runs plain HTTP.
	responseURI := strings.Replace(responseURIRaw, "https://", "http://", 1)

	stateClaim := getStringClaim(t, requestToken, "state")
	require.NotEmpty(t, stateClaim, "state must be in request object")

	// Verify dcql_query is present
	assertHasClaim(t, requestToken, "dcql_query")

	// Step 4: Create valid credentials
	vc, err := helpers.CreateJWTVC(fixture.issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
	})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(fixture.holder, "", serviceID, vc)
	require.NoError(t, err)

	vpToken, err := helpers.CreateDCQLResponse(map[string]string{"cred-1": vpJWT})
	require.NoError(t, err)

	// Step 5: Open WebSocket connection
	wsURL := fmt.Sprintf("ws://localhost:%d/ws?state=%s", fixture.verifier.Port, stateClaim)
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err, "WebSocket connection should succeed")
	defer wsConn.Close()

	// Read initial session message
	var sessionMsg map[string]interface{}
	err = wsConn.ReadJSON(&sessionMsg)
	require.NoError(t, err, "should receive session message")
	assert.Equal(t, "session", sessionMsg["type"])

	// Step 6: POST authentication response
	authResp, err := http.PostForm(responseURI, url.Values{
		"state":    {stateClaim},
		"vp_token": {vpToken},
	})
	require.NoError(t, err)
	defer authResp.Body.Close()
	assert.Equal(t, http.StatusOK, authResp.StatusCode)

	// Step 7: Read WebSocket authenticated message
	wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var authMsg map[string]interface{}
	err = wsConn.ReadJSON(&authMsg)
	require.NoError(t, err, "should receive authenticated message")
	assert.Equal(t, "authenticated", authMsg["type"])

	wsRedirectURL, ok := authMsg["redirectUrl"].(string)
	require.True(t, ok && wsRedirectURL != "", "redirectUrl must be a non-empty string")

	// Step 8: Extract code and exchange for JWT
	parsedRedirect, err := url.Parse(wsRedirectURL)
	require.NoError(t, err)
	code := parsedRedirect.Query().Get("code")
	require.NotEmpty(t, code)

	tokenResp, err := http.PostForm(fmt.Sprintf("%s/token", fixture.verifier.BaseURL), url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	})
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	assert.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenBody map[string]interface{}
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenBody)
	require.NoError(t, err)
	assert.Equal(t, "Bearer", tokenBody["token_type"])
	accessToken, ok := tokenBody["access_token"].(string)
	require.True(t, ok && accessToken != "", "access_token must be a non-empty string")

	verifyAccessToken(t, fixture.verifier.BaseURL, accessToken)
}

// --- Helper functions ---

// openid4vpHrefPattern matches href="openid4vp://..." in the HTML template.
var openid4vpHrefPattern = regexp.MustCompile(`href="(openid4vp://[^"]+)"`)

// extractOpenID4VPURL extracts the openid4vp:// URL from the loginQR HTML page.
func extractOpenID4VPURL(t *testing.T, html string) string {
	t.Helper()
	matches := openid4vpHrefPattern.FindStringSubmatch(html)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// getStringClaim extracts a string claim from a JWT token.
func getStringClaim(t *testing.T, token jwt.Token, key string) string {
	t.Helper()
	var val string
	err := token.Get(key, &val)
	if err != nil {
		return ""
	}
	return val
}

// assertHasClaim asserts that a JWT token contains the given claim.
func assertHasClaim(t *testing.T, token jwt.Token, key string) {
	t.Helper()
	var val interface{}
	err := token.Get(key, &val)
	require.NoError(t, err, "claim %q must be present in JWT", key)
	require.NotNil(t, val, "claim %q must not be nil", key)
}

