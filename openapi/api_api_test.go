package openapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	verifier "github.com/fiware/VCVerifier/verifier"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
)

var LOGGING_CONFIG = logging.LoggingConfig{
	Level:         "DEBUG",
	JsonLogging:   true,
	LogRequests:   true,
	PathsToSkip:   []string{},
	DisableCaller: false,
}

type mockVerifier struct {
	mockJWTString            string
	mockQR                   string
	mockConnectionString     string
	mockAuthRequest          string
	mockStartedScope         string
	mockReceivedCodeVerifier string
	mockReceivedPKCE         verifier.PKCEChallenge
	mockJWKS                 jwk.Set
	mockOpenIDConfig         common.OpenIDProviderMetadata
	mockSameDevice           verifier.Response
	mockExpiration           int64
	mockError                error
	mockAuthorizationType    string
	mockRefreshTokenEnabled  bool
	mockRefreshToken         string
	mockRefreshTokenError    error
	mockExchangeJWT          string
	mockExchangeExpiration   int64
	mockExchangeRefresh      string
	mockExchangeError        error
	mockPathPrefix           string
	mockRequestMode          string
	mockDefaultScope         string
	mockDefaultScopeError    error
	mockHost                 string
	// sessions HasLoginSession reports as gone; every other session exists
	mockMissingSessions map[string]bool
	// guards mockMissingSessions once WebSocket handlers may read it (see endSession)
	sessionsMu sync.Mutex
	// the secret CheckLoginPageSecret accepts for every open session
	mockPageSecret string
	// what ReturnLoginQRV2 returns, if set
	mockQRInfo *verifier.QRLoginInfo
	// called by HasLoginSession before it answers
	mockOnHasLoginSession func(sessionId string)
	// codes passed to ReleaseUndeliveredCode, by session id
	releasedCodes map[string]string
	// what CheckRedirectUri returns
	mockRedirectUriError error
	// completed logins whose page did not get the result yet, by session id; guarded by sessionsMu
	mockPendingLogins map[string]verifier.PendingLogin
	// called by PendingLogin before it answers
	mockOnPendingLogin func(sessionId string)
}

func (mV *mockVerifier) HasLoginSession(sessionId string) bool {
	if mV.mockOnHasLoginSession != nil {
		mV.mockOnHasLoginSession(sessionId)
	}
	return !mV.isSessionMissing(sessionId)
}

func (mV *mockVerifier) isSessionMissing(sessionId string) bool {
	mV.sessionsMu.Lock()
	defer mV.sessionsMu.Unlock()
	return mV.mockMissingSessions[sessionId]
}

// endSession makes the session gone, like a completed or expired login, while handlers may run.
func (mV *mockVerifier) endSession(sessionId string) {
	mV.sessionsMu.Lock()
	defer mV.sessionsMu.Unlock()
	if mV.mockMissingSessions == nil {
		mV.mockMissingSessions = map[string]bool{}
	}
	mV.mockMissingSessions[sessionId] = true
}

func (mV *mockVerifier) CheckLoginPageSecret(sessionId string, secret string) error {
	// not via AwaitsLoginPage: mockOnHasLoginSession is about the check after registration
	if _, pending := mV.pendingLogin(sessionId); mV.isSessionMissing(sessionId) && !pending {
		return verifier.ErrorNoSuchSession
	}
	if secret != mV.mockPageSecret {
		return verifier.ErrorLoginPageSecretMismatch
	}
	return nil
}

func (mV *mockVerifier) AwaitsLoginPage(sessionId string) bool {
	if mV.HasLoginSession(sessionId) {
		return true
	}
	_, pending := mV.pendingLogin(sessionId)
	return pending
}

func (mV *mockVerifier) PendingLogin(sessionId string) (verifier.PendingLogin, bool) {
	if mV.mockOnPendingLogin != nil {
		mV.mockOnPendingLogin(sessionId)
	}
	return mV.pendingLogin(sessionId)
}

func (mV *mockVerifier) pendingLogin(sessionId string) (verifier.PendingLogin, bool) {
	mV.sessionsMu.Lock()
	defer mV.sessionsMu.Unlock()
	pending, found := mV.mockPendingLogins[sessionId]
	return pending, found
}

// completeSession ends the session like a completed login whose result its page did not get yet.
func (mV *mockVerifier) completeSession(sessionId string, pending verifier.PendingLogin) {
	mV.endSession(sessionId)
	mV.sessionsMu.Lock()
	defer mV.sessionsMu.Unlock()
	if mV.mockPendingLogins == nil {
		mV.mockPendingLogins = map[string]verifier.PendingLogin{}
	}
	mV.mockPendingLogins[sessionId] = pending
}

// exchangeCode drops the pending login of the session, like its code being exchanged at /token.
func (mV *mockVerifier) exchangeCode(sessionId string) {
	mV.sessionsMu.Lock()
	defer mV.sessionsMu.Unlock()
	delete(mV.mockPendingLogins, sessionId)
}

func (mV *mockVerifier) CheckRedirectUri(clientId string, redirectUri string) error {
	return mV.mockRedirectUriError
}

func (mV *mockVerifier) ReleaseUndeliveredCode(sessionId string, authorizationCode string) bool {
	if mV.releasedCodes == nil {
		mV.releasedCodes = map[string]string{}
	}
	mV.releasedCodes[sessionId] = authorizationCode
	return true
}

func (mV *mockVerifier) ReturnLoginQR(host string, protocol string, callback string, state string, clientId string, nonce string, requestType string) (qr string, err error) {
	return mV.mockQR, mV.mockError
}
func (mV *mockVerifier) ReturnLoginQRWithPKCE(host string, protocol string, callback string, state string, clientId string, nonce string, requestType string, pkce verifier.PKCEChallenge) (qr string, err error) {
	mV.mockReceivedPKCE = pkce
	return mV.mockQR, mV.mockError
}
func (mV *mockVerifier) ReturnLoginQRV2(host string, protocol string, callback string, state string, clientId string, scope string, nonce string, requestMode string) (qrInfo verifier.QRLoginInfo, err error) {
	if mV.mockQRInfo != nil {
		return *mV.mockQRInfo, mV.mockError
	}
	return verifier.QRLoginInfo{QR: mV.mockQR}, mV.mockError
}
func (mV *mockVerifier) StartSiopFlow(host string, protocol string, callback string, sessionId string, clientId string, nonce string, requestType string) (connectionString string, err error) {
	return mV.mockConnectionString, mV.mockError
}
func (mV *mockVerifier) StartSiopFlowWithPKCE(host string, protocol string, callback string, sessionId string, clientId string, nonce string, requestType string, pkce verifier.PKCEChallenge) (connectionString string, err error) {
	mV.mockReceivedPKCE = pkce
	return mV.mockConnectionString, mV.mockError
}
func (mV *mockVerifier) StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string, clientId string, nonce string, requestType string, scope string, requestProtocol string) (authenticationRequest string, err error) {
	mV.mockStartedScope = scope
	return mV.mockAuthRequest, mV.mockError
}
func (mV *mockVerifier) GetToken(authorizationCode string, redirectUri string, validated bool) (jwtString string, expiration int64, refreshToken string, err error) {
	return mV.mockJWTString, mV.mockExpiration, mV.mockRefreshToken, mV.mockError
}
func (mV *mockVerifier) GetTokenWithCodeVerifier(authorizationCode string, redirectUri string, validated bool, codeVerifier string) (jwtString string, expiration int64, refreshToken string, err error) {
	mV.mockReceivedCodeVerifier = codeVerifier
	return mV.mockJWTString, mV.mockExpiration, mV.mockRefreshToken, mV.mockError
}
func (mV *mockVerifier) StartSameDeviceFlowWithPKCE(host string, protocol string, sessionId string, redirectPath string, clientId string, nonce string, requestMode string, scope string, requestProtocol string, pkce verifier.PKCEChallenge) (authenticationRequest string, err error) {
	mV.mockStartedScope = scope
	mV.mockReceivedPKCE = pkce
	return mV.mockAuthRequest, mV.mockError
}
func (mV *mockVerifier) ReturnLoginQRV2WithPKCE(host string, protocol string, callback string, state string, clientId string, scope string, nonce string, requestMode string, pkce verifier.PKCEChallenge) (qrLoginInfo verifier.QRLoginInfo, err error) {
	mV.mockReceivedPKCE = pkce
	if mV.mockQRInfo != nil {
		return *mV.mockQRInfo, mV.mockError
	}
	return verifier.QRLoginInfo{QR: mV.mockQR}, mV.mockError
}
func (mV *mockVerifier) GetJWKS() jwk.Set {
	return mV.mockJWKS
}
func (mV *mockVerifier) GetDefaultScope(clientId string) (string, error) {
	if mV.mockDefaultScopeError != nil {
		return "", mV.mockDefaultScopeError
	}
	if mV.mockDefaultScope != "" {
		return mV.mockDefaultScope, nil
	}
	return "openid", nil
}

func (mV *mockVerifier) GetAuthorizationType(clientId string) string {
	return mV.mockAuthorizationType
}

func (mV *mockVerifier) AuthenticationResponse(state string, presentation *common.Presentation) (sameDevice verifier.Response, err error) {
	return mV.mockSameDevice, mV.mockError
}
func (mV *mockVerifier) GetOpenIDConfiguration(serviceIdentifier string) (metadata common.OpenIDProviderMetadata, err error) {
	return mV.mockOpenIDConfig, err
}
func (mV *mockVerifier) GetHost() string {
	return mV.mockHost
}

func (mV *mockVerifier) GetPathPrefix() string {
	return mV.mockPathPrefix
}

func (mV *mockVerifier) GetRequestMode() string {
	return mV.mockRequestMode
}

// TODO
func (mV *mockVerifier) GetRequestObject(state string) (jwt string, err error) {
	return jwt, err
}

func (mV *mockVerifier) GenerateToken(clientId, subject, audience string, scope []string, presentation *common.Presentation) (int64, string, error) {
	return mV.mockExpiration, mV.mockJWTString, mV.mockError
}

func (mV *mockVerifier) ExchangeRefreshToken(refreshToken string) (string, int64, string, error) {
	return mV.mockExchangeJWT, mV.mockExchangeExpiration, mV.mockExchangeRefresh, mV.mockExchangeError
}

func (mV *mockVerifier) IsRefreshTokenEnabled() bool {
	return mV.mockRefreshTokenEnabled
}

func (mV *mockVerifier) RefreshTokenExpiresIn() int64 {
	return 0
}

func (mV *mockVerifier) CreateRefreshToken(clientId string, signedJWT string) (string, error) {
	return mV.mockRefreshToken, mV.mockRefreshTokenError
}

func TestGetToken(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName               string
		proofCheck             bool
		testGrantType          string
		testCode               string
		testRedirectUri        string
		testCodeVerifier       string
		testRefreshToken       string
		testVPToken            string
		testScope              string
		testResource           string
		testSubjectTokenType   string
		testRequestedTokenType string
		mockJWTString          string
		mockExpiration         int64
		mockError              error
		mockRefreshEnabled     bool
		mockRefreshToken       string
		mockRefreshTokenError  error
		mockExchangeJWT        string
		mockExchangeExpiration int64
		mockExchangeRefresh    string
		mockExchangeError      error
		expectedStatusCode     int
		expectedResponse       TokenResponse
		expectedError          ErrorMessage
	}
	tests := []test{
		{testName: "If a valid authorization_code request is received a token should be responded.", proofCheck: false, testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockJWTString: "theJWT", mockExpiration: 10, mockError: nil, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT"}, expectedError: ErrorMessage{}},
		{testName: "authorization_code requests forward the PKCE verifier.", testGrantType: "authorization_code", testCode: "my-auth-code", testCodeVerifier: "the-pkce-verifier", testRedirectUri: "http://my-redirect.org", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200},
		{testName: "If no grant type is provided, the request should fail.", proofCheck: false, testGrantType: "", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessagNoGrantType},
		{testName: "If an invalid grant type is provided, the request should fail.", proofCheck: false, testGrantType: "my_special_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessageUnsupportedGrantType},
		{testName: "If no auth code is provided, the request should fail.", proofCheck: false, testGrantType: "authorization_code", testCode: "", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessageNoCode},
		{testName: "If no redirect uri is provided, the request should fail.", proofCheck: false, testGrantType: "authorization_code", testCode: "my-auth-code", expectedStatusCode: 400, expectedError: ErrorMessageInvalidTokenRequest},
		{testName: "If the verify returns an error, a 403 should be answerd.", proofCheck: false, testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockError: errors.New("invalid"), expectedStatusCode: 403, expectedError: ErrorMessage{}},
		{testName: "If no valid scope is provided, the request should be executed in the default scope.", proofCheck: false, testVPToken: getValidVPTokenJWT(), testGrantType: "vp_token", expectedStatusCode: 200},

		{testName: "If a valid vp_token request is received a token should be responded.", proofCheck: false, testGrantType: "vp_token", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, IdToken: "theJWT"}},
		{testName: "If a valid signed vp_token request is received a token should be responded.", proofCheck: true, testGrantType: "vp_token", testVPToken: buildSignedVPToken(t), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, IdToken: "theJWT"}},
		{testName: "If no valid vp_token is provided, the request should fail.", proofCheck: false, testGrantType: "vp_token", testScope: "tir_read", expectedStatusCode: 400, expectedError: ErrorMessageNoToken},
		// token-exchange
		{testName: "If a valid token-exchange request is received a token should be responded.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN}},
		{testName: "If a token-exchange request is received without resource, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", testSubjectTokenType: "urn:eu:oidf:vp_token", expectedStatusCode: 400, expectedError: ErrorMessageNoResource},
		{testName: "If a token-exchange request is received with invalid subject_token_type, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "invalid_type", expectedStatusCode: 400, expectedError: ErrorMessageInvalidSubjectTokenType},
		{testName: "If a token-exchange request is received with invalid requested_token_type, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", testRequestedTokenType: "invalid_type", expectedStatusCode: 400, expectedError: ErrorMessageInvalidRequestedTokenType},
		{testName: "If a token-exchange request is received without subject_token, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", expectedStatusCode: 400, expectedError: ErrorMessageNoToken},
		{testName: "If a token-exchange request is received without scope, the default scope should be used.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPTokenJWT(), testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", expectedStatusCode: 200},
		// refresh_token grant type
		{testName: "If a valid refresh_token request is received, new tokens should be returned.", testGrantType: "refresh_token", testRefreshToken: "valid-refresh-token", mockExchangeJWT: "newJWT", mockExchangeExpiration: 300, mockExchangeRefresh: "rotated-refresh-token", expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 300, AccessToken: "newJWT", IdToken: "newJWT", RefreshToken: "rotated-refresh-token"}},
		{testName: "If no refresh_token is provided in a refresh_token request, a 400 should be returned.", testGrantType: "refresh_token", expectedStatusCode: 400, expectedError: ErrorMessageNoRefreshToken},
		{testName: "If an invalid refresh_token is provided, a 403 should be returned.", testGrantType: "refresh_token", testRefreshToken: "invalid-token", mockExchangeError: errors.New("token not found"), expectedStatusCode: 403, expectedError: ErrorMessageInvalidRefreshToken},
		// authorization_code with refresh token enabled
		{testName: "If refresh tokens are enabled, authorization_code response includes refresh_token.", testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: true, mockRefreshToken: "new-refresh-token", expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT", RefreshToken: "new-refresh-token"}},
		// vp_token with refresh token enabled
		{testName: "If refresh tokens are enabled, vp_token response includes refresh_token.", testGrantType: "vp_token", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: true, mockRefreshToken: "new-refresh-token", expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, IdToken: "theJWT", RefreshToken: "new-refresh-token"}},
		// token-exchange with refresh token enabled
		{testName: "If refresh tokens are enabled, token-exchange response includes refresh_token.", testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: true, mockRefreshToken: "new-refresh-token", expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, RefreshToken: "new-refresh-token"}},
		// refresh token disabled — verify no refresh_token in existing grant type responses
		{testName: "If refresh tokens are disabled, authorization_code response omits refresh_token.", testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: false, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT"}},
		{testName: "If refresh tokens are disabled, vp_token response omits refresh_token.", testGrantType: "vp_token", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: false, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, IdToken: "theJWT"}},
		{testName: "If refresh tokens are disabled, token-exchange response omits refresh_token.", testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: false, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN}},
		// non-fatal CreateRefreshToken error — access token returned without refresh_token
		{testName: "If CreateRefreshToken fails for vp_token, access token is still returned.", testGrantType: "vp_token", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: true, mockRefreshTokenError: errors.New("db write failed"), expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, IdToken: "theJWT"}},
		{testName: "If CreateRefreshToken fails for token-exchange, access token is still returned.", testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPTokenJWT(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: true, mockRefreshTokenError: errors.New("db write failed"), expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN}},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			if tc.proofCheck {
				presentationParser = &verifier.ConfigurablePresentationParser{
					ProofChecker: newTestProofChecker()}
			} else {
				presentationParser = &verifier.ConfigurablePresentationParser{}
			}

			sdJwtParser = &verifier.ConfigurableSdJwtParser{
				ProofChecker: newTestProofChecker()}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)
			apiVerifier = &mockVerifier{
				mockJWTString:           tc.mockJWTString,
				mockExpiration:          tc.mockExpiration,
				mockError:               tc.mockError,
				mockRefreshTokenEnabled: tc.mockRefreshEnabled,
				mockRefreshToken:        tc.mockRefreshToken,
				mockRefreshTokenError:   tc.mockRefreshTokenError,
				mockExchangeJWT:         tc.mockExchangeJWT,
				mockExchangeExpiration:  tc.mockExchangeExpiration,
				mockExchangeRefresh:     tc.mockExchangeRefresh,
				mockExchangeError:       tc.mockExchangeError,
			}

			formArray := []string{}

			if tc.testGrantType != "" {
				formArray = append(formArray, "grant_type="+tc.testGrantType)
			}
			if tc.testCode != "" {
				formArray = append(formArray, "code="+tc.testCode)
			}
			if tc.testCodeVerifier != "" {
				formArray = append(formArray, "code_verifier="+tc.testCodeVerifier)
			}
			if tc.testRedirectUri != "" {
				formArray = append(formArray, "redirect_uri="+tc.testRedirectUri)
			}

			if tc.testRefreshToken != "" {
				formArray = append(formArray, "refresh_token="+tc.testRefreshToken)
			}
			if tc.testScope != "" {
				formArray = append(formArray, "scope="+tc.testScope)
			}

			if tc.testVPToken != "" {
				switch tc.testGrantType {
				case "vp_token":
					formArray = append(formArray, "vp_token="+tc.testVPToken)
				case "urn:ietf:params:oauth:grant-type:token-exchange":
					formArray = append(formArray, "subject_token="+tc.testVPToken)
				}
			}

			if tc.testResource != "" {
				formArray = append(formArray, "resource="+tc.testResource)
			}
			if tc.testSubjectTokenType != "" {
				formArray = append(formArray, "subject_token_type="+tc.testSubjectTokenType)
			}
			if tc.testRequestedTokenType != "" {
				formArray = append(formArray, "requested_token_type="+tc.testRequestedTokenType)
			}

			body := bytes.NewBufferString(strings.Join(formArray, "&"))
			testContext.Request, _ = http.NewRequest("POST", "/", body)
			testContext.Request.Header.Add("Content-Type", gin.MIMEPOSTForm)

			GetToken(testContext)
			if tc.testCodeVerifier != "" && apiVerifier.(*mockVerifier).mockReceivedCodeVerifier != tc.testCodeVerifier {
				t.Errorf("Expected code_verifier %q to be forwarded, got %q", tc.testCodeVerifier, apiVerifier.(*mockVerifier).mockReceivedCodeVerifier)
			}

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
			}

			if tc.expectedStatusCode == 400 || (tc.expectedStatusCode == 403 && tc.expectedError != (ErrorMessage{})) {
				errorBody, _ := io.ReadAll(recorder.Body)
				errorMessage := ErrorMessage{}
				if err := json.Unmarshal(errorBody, &errorMessage); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if errorMessage != tc.expectedError {
					t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
					return
				}
				return
			}

			tokenResponse := TokenResponse{}
			if tc.expectedResponse != tokenResponse {
				body, _ := io.ReadAll(recorder.Body)
				err := json.Unmarshal(body, &tokenResponse)
				if err != nil {
					t.Errorf("%s - Was not able to unmarshal the token response. Err: %v.", tc.testName, err)
					return
				}
				if tokenResponse != tc.expectedResponse {
					t.Errorf("%s - Expected token response %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedResponse), logging.PrettyPrintObject(tokenResponse))
					return
				}
			}
		})

	}
}

func TestStartSIOPSameDevice(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName           string
		testState          string
		testRedirectPath   string
		testRequestAddress string
		testScope          string
		scopePresent       bool
		defaultScope       string
		defaultScopeError  error
		expectedScope      string
		mockRedirect       string
		mockError          error
		expectedStatusCode int
		expectedLocation   string
		expectedResponse   string
	}

	tests := []test{
		{testName: "If all neccessary parameters provided, a valid redirect should be returned.", testState: "my-state", testRedirectPath: "/my-redirect", testRequestAddress: "http://host.org", mockRedirect: "http://host.org/api/v1/authentication_response", mockError: nil, expectedStatusCode: 302, expectedLocation: "http://host.org/api/v1/authentication_response"},
		{testName: "If the scope is omitted, use the client's default scope.", testState: "my-state", testRequestAddress: "http://host.org", defaultScope: "default-scope", expectedScope: "default-scope", mockRedirect: "http://host.org/api/v1/authentication_response", expectedStatusCode: 302, expectedLocation: "http://host.org/api/v1/authentication_response"},
		{testName: "If the scope is provided, keep the requested scope.", testState: "my-state", testRequestAddress: "http://host.org", testScope: "requested-scope", expectedScope: "requested-scope", mockRedirect: "http://host.org/api/v1/authentication_response", expectedStatusCode: 302, expectedLocation: "http://host.org/api/v1/authentication_response"},
		{testName: "If no default scope is configured, reject the request.", testState: "my-state", testRequestAddress: "http://host.org", defaultScopeError: errors.New("no default scope"), expectedStatusCode: 400},
		{testName: "If the client or scope is not configured, reject the request without exposing configuration details.", testState: "my-state", testRedirectPath: "/", testRequestAddress: "http://host.org", mockError: verifier.ErrorUnknownClientOrScope, expectedStatusCode: 400},
		{testName: "If an empty scope is explicitly provided, reject the request.", testState: "my-state", testRequestAddress: "http://host.org", scopePresent: true, expectedStatusCode: 400},
		{testName: "If no state is provided, a 400 should be returned.", testState: "", testRedirectPath: "", testRequestAddress: "http://host.org", mockRedirect: "http://host.org/api/v1/authentication_response", mockError: nil, expectedStatusCode: 400, expectedLocation: ""},
		{testName: "If the verifier returns an error, a 500 should be returned.", testState: "my-state", testRedirectPath: "/", testRequestAddress: "http://host.org", mockRedirect: "http://host.org/api/v1/authentication_response", mockError: errors.New("verifier_failure"), expectedStatusCode: 500, expectedLocation: ""},
		{testName: "If no path is provided, a deeplink should be returned.", testState: "my-state", testRedirectPath: "", testRequestAddress: "http://host.org", mockRedirect: "http://host.org/api/v1/authentication_response", mockError: nil, expectedStatusCode: 302, expectedLocation: "http://host.org/api/v1/authentication_response", expectedResponse: ""},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {
			presentationParser = &verifier.ConfigurablePresentationParser{}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)
			apiVerifier = &mockVerifier{
				mockAuthRequest:       tc.mockRedirect,
				mockError:             tc.mockError,
				mockDefaultScope:      tc.defaultScope,
				mockDefaultScopeError: tc.defaultScopeError,
			}

			testParameters := []string{}
			if tc.testState != "" {
				testParameters = append(testParameters, "state="+tc.testState)
			}
			if tc.testRedirectPath != "" {
				testParameters = append(testParameters, "redirect_path="+tc.testRedirectPath)
			}
			if tc.scopePresent || tc.testScope != "" {
				testParameters = append(testParameters, "scope="+tc.testScope)
			}

			testContext.Request, _ = http.NewRequest("GET", tc.testRequestAddress+"/?"+strings.Join(testParameters, "&"), nil)
			StartSIOPSameDevice(testContext)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
			}
			if tc.mockError == verifier.ErrorUnknownClientOrScope && strings.Contains(recorder.Body.String(), tc.mockError.Error()) {
				t.Errorf("%s - The response must not expose the internal configuration error.", tc.testName)
			}
			if tc.expectedScope != "" && apiVerifier.(*mockVerifier).mockStartedScope != tc.expectedScope {
				t.Errorf("%s - Expected scope %q but got %q.", tc.testName, tc.expectedScope, apiVerifier.(*mockVerifier).mockStartedScope)
			}
			if tc.expectedStatusCode == 200 {
				responseString := recorder.Body.String()
				if tc.expectedResponse != responseString {
					t.Errorf("%s - Expected response %v but was %v.", tc.testName, tc.expectedResponse, responseString)
				}
			}

			if tc.expectedStatusCode != 302 {
				// everything other is an error, we dont care about the details
				return
			}

			location := recorder.Result().Header.Get("Location")
			if location != tc.expectedLocation {
				t.Errorf("%s - Expected location %s but was %s.", tc.testName, tc.expectedLocation, location)
			}
		})
	}
}

func TestVerifierAPIAuthenticationResponse(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName               string
		sameDevice             bool
		testState              string
		testVPToken            string
		mockError              error
		mockSameDeviceResponse verifier.Response
		expectedStatusCode     int
		expectedRedirect       string
		expectedError          ErrorMessage
	}

	tests := []test{
		{"If a same-device flow is authenticated, a valid redirect should be returned.", true, "my-state", getValidVPTokenJWT(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE, RedirectTarget: "http://my-verifier.org", Code: "my-code", ExternalState: "my-session-id"}, 302, "http://my-verifier.org?state=my-session-id&code=my-code", ErrorMessage{}},
		{"If a same-device flow is authenticated with an SdJwt, a valid redirect should be returned.", true, "my-state", getValidSDJwtToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE, RedirectTarget: "http://my-verifier.org", Code: "my-code", ExternalState: "my-session-id"}, 302, "http://my-verifier.org?state=my-session-id&code=my-code", ErrorMessage{}},
		{"If a cross-device flow is authenticated, a simple ok should be returned.", false, "my-state", getValidVPTokenJWT(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 200, "", ErrorMessage{}},
		{"If a cross-device flow is authenticated with an SdJwt, a simple ok should be returned.", false, "my-state", getValidSDJwtToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 200, "", ErrorMessage{}},
		{"If the same-device flow responds an error, a 400 should be returend", true, "my-state", getValidVPTokenJWT(), errors.New("verification_error"), verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 400, "", ErrorMessage{Summary: "verification_error"}},
		{"If no state is provided, a 400 should be returned.", true, "", getValidVPTokenJWT(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 400, "", ErrorMessageNoState},
		{"If an no token is provided, a 400 should be returned.", true, "my-state", "", nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 400, "", ErrorMessageNoToken},
		{"If a token with no credentials is provided, a redirect should still occur.", true, "my-state", getNoVCVPTokenJWT(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 302, "/?state=&code=", ErrorMessage{}},
		{"If a token with a non-string holder is provided, a redirect should still occur.", true, "my-state", getNoHolderVPTokenJWT(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 302, "/?state=&code=", ErrorMessage{}},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {

			// These tests exercise handler routing / redirect logic, not
			// proof verification, so the presentation parser is configured
			// WITHOUT a ProofChecker. JWT payloads are extracted without
			// signature verification, matching the original test intent.
			presentationParser = &verifier.ConfigurablePresentationParser{}
			sdJwtParser = &verifier.ConfigurableSdJwtParser{
				ProofChecker: newTestProofChecker()}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)
			apiVerifier = &mockVerifier{mockSameDevice: tc.mockSameDeviceResponse, mockError: tc.mockError}

			formArray := []string{}

			if tc.testVPToken != "" {
				formArray = append(formArray, "vp_token="+tc.testVPToken)
			}

			requestAddress := "http://my-verifier.org/"
			if tc.testState != "" {
				formArray = append(formArray, "state="+tc.testState)
			}

			body := bytes.NewBufferString(strings.Join(formArray, "&"))
			testContext.Request, _ = http.NewRequest("POST", requestAddress, body)
			testContext.Request.Header.Add("Content-Type", gin.MIMEPOSTForm)

			VerifierAPIAuthenticationResponse(testContext)

			if tc.expectedStatusCode == 400 {
				errorBody, _ := io.ReadAll(recorder.Body)
				errorMessage := ErrorMessage{}
				if err := json.Unmarshal(errorBody, &errorMessage); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if errorMessage != tc.expectedError {
					t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
					return
				}
				return
			}

			if tc.sameDevice && tc.expectedStatusCode != 302 && tc.expectedStatusCode != recorder.Code {
				t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
			}

			if tc.sameDevice {
				location := recorder.Result().Header.Get("Location")
				if location != tc.expectedRedirect {
					t.Errorf("%s - Expected location %s but was %s.", tc.testName, tc.expectedRedirect, location)
					return
				}
				return
			}

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
			}
			if tc.expectedStatusCode != 200 {
				return
			}
		})
	}
}

func TestVerifierAPIStartSIOP(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName                 string
		testState                string
		testCallback             string
		testAddress              string
		mockConnectionString     string
		mockError                error
		expectedStatusCode       int
		expectedConnectionString string
		expectedError            ErrorMessage
	}

	tests := []test{
		{"If all parameters are present, a siop flow should be started.", "my-state", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", nil, 200, "openid://mockConnectionString", ErrorMessage{}},
		{"If no state is present, a 400 should be returned.", "", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", nil, 400, "", ErrorMessageNoState},
		{"If no callback is present, a 400 should be returned.", "my-state", "", "http://my-verifier.org", "openid://mockConnectionString", nil, 400, "", ErrorMessageNoCallback},
		{"If the verifier cannot start the flow, a 500 should be returend.", "my-state", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", errors.New("verifier_failure"), 500, "", ErrorMessageNoState},
	}

	for _, tc := range tests {

		logging.Log().Info("TestVerifierAPIStartSIOP +++++++++++++++++ Running test: ", tc.testName)

		t.Run(tc.testName, func(t *testing.T) {
			presentationParser = &verifier.ConfigurablePresentationParser{}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)
			apiVerifier = &mockVerifier{mockConnectionString: tc.mockConnectionString, mockError: tc.mockError}

			testParameters := []string{}
			if tc.testState != "" {
				testParameters = append(testParameters, "state="+tc.testState)
			}
			if tc.testCallback != "" {
				testParameters = append(testParameters, "client_callback="+tc.testCallback)
			}

			testContext.Request, _ = http.NewRequest("GET", tc.testAddress+"/?"+strings.Join(testParameters, "&"), nil)
			VerifierAPIStartSIOP(testContext)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("%s - Expected code %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
			}
			if tc.expectedStatusCode == 500 {
				// something internal, we dont care about the details
				return
			}

			if tc.expectedStatusCode == 400 {
				errorBody, _ := io.ReadAll(recorder.Body)
				errorMessage := ErrorMessage{}
				if err := json.Unmarshal(errorBody, &errorMessage); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if errorMessage != tc.expectedError {
					t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
					return
				}
				return
			}
			body, _ := io.ReadAll(recorder.Body)
			connectionString := string(body)
			if connectionString != tc.expectedConnectionString {
				t.Errorf("%s - Expected connectionString %s but was %s.", tc.testName, tc.expectedConnectionString, connectionString)
			}
		})
	}
}

func TestVerifierAPIStartSIOP_PassesPKCE(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	expectedPKCE := verifier.PKCEChallenge{
		Value:        strings.Repeat("a", 43),
		Method:       verifier.PKCES256,
		ChallengeSet: true,
		MethodSet:    true,
	}
	mock := &mockVerifier{mockConnectionString: "openid://mockConnectionString"}
	apiVerifier = mock
	t.Cleanup(func() { apiVerifier = nil })

	recorder := httptest.NewRecorder()
	testContext, _ := gin.CreateTestContext(recorder)
	testContext.Request, _ = http.NewRequest(
		"GET",
		"https://verifier.org/api/v1/startsiop?state=state&client_callback=https://rp.example/callback&code_challenge="+expectedPKCE.Value+"&code_challenge_method="+expectedPKCE.Method,
		nil,
	)
	VerifierAPIStartSIOP(testContext)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, expectedPKCE, mock.mockReceivedPKCE)
}

// buildJWTVPToken creates a JWT VP with the given payload (no signature
// verification — the payload is base64url-encoded without a real signature).
// Use for tests that exercise HTTP handler logic, not proof verification.
func buildJWTVPToken(payload map[string]interface{}) string {
	header := map[string]interface{}{"alg": "ES256", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + ".fakesig"
}

// buildFakeVCJWT returns a fake JWT VC token (no real signature) containing
// standard credential claims. Suitable for tests that don't verify VC proof.
func buildFakeVCJWT() string {
	header := map[string]interface{}{"alg": "ES256", "typ": "JWT", "kid": "did:key:test#key-1"}
	payload := map[string]interface{}{
		"iss": "did:key:test",
		"nbf": 1707984310,
		"jti": "urn:uuid:cb5f9f1c-017b-4d44-8461-72d323da84cf",
		"vc": map[string]interface{}{
			"type":         []string{"VerifiableCredential"},
			"issuer":       "did:key:test",
			"issuanceDate": 1707984310812,
			"@context":     []string{"https://www.w3.org/2018/credentials/v1"},
			"id":           "urn:uuid:cb5f9f1c-017b-4d44-8461-72d323da84cf",
			"credentialSubject": map[string]interface{}{
				"firstName":  "HappyPets",
				"familyName": "Prime",
				"email":      "prime-user@happypets.org",
			},
		},
	}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + ".fakesig"
}

// getValidVPTokenJWT returns a JWT-format VP token containing one VC.
// Unlike the old getValidVPToken (base64 JSON-LD), this produces a JWT VP
// that will be parsed by parseJWTPresentation rather than the now-rejected
// JSON-LD path.
func getValidVPTokenJWT() string {
	return buildJWTVPToken(map[string]interface{}{
		"iss": "did:user:gold",
		"vp": map[string]interface{}{
			"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []string{"VerifiablePresentation"},
			"holder":               "did:user:gold",
			"verifiableCredential": []interface{}{buildFakeVCJWT()},
		},
	})
}

func getValidSDJwtToken() string {
	return "eyJhbGciOiJFUzI1NiIsInR5cCIgOiAidmMrc2Qtand0Iiwia2lkIiA6ICJkaWQ6a2V5OnpEbmFlYzVmYnZkNzhjUms1UUo0elpvVnhtU1hLVUg1S1ZHblVFQjR6UnJ5elFtY3kifQ.eyJfc2QiOlsiNDdhOS1uaU9TT3B0RjZ2eXJoUlgyN3ZPVkFJZGFJSmlYR1Zpd1hJNGJ6OCIsIjdXbUhfbXFEVHV0Z3hKX1RWOXh2Q3V0MDVJYkRwTnhRRDRyZm1DUlk5aEUiLCJDUmFOT2hia2t3TUJQXzFmRWNDcEtVcjl3Rm5BbGd5VXQySnpSVUtTZXQ4IiwiUUJ0TG1LRnpDMHEyYTZGVXJJVTdBdzRoXzNheElfaVc1bms0YXA1T3hLTSIsIlJRMktXdXJRTWt1VHdEaE1OZFdjNU5yYkc3djlyOGw5MHU1Rkp6Smh3Z0kiLCJhU2pvZFNGdkR3dWtLdERVcjhzVkVhMGZtdnhvSmVtaXM5b1RyaVFVQ3pnIiwiZThIUkpES194X3k2WDVzZmlhY2RhZWlMWDNfR2RDUXdVRjFKaWpsZXRVUSIsIm5EZDZra25Cb3Bxak9JOU42enB3R3hRYk1YSy02Z0xKSG5mYXgxR0hCOGsiLCJvRi14cG1JM2NlRUN6b2xtVXRSQ2w4SmV4WExIRzAwdDhLRE1KSWdqRFZnIiwib3FuWklsM1ZXODh2QS1BZWdPM2EzSnFxbHBOS0FSbFphWEpvbm1UenpXdyIsInBPUm8yUldMTzhmVENGTUhOeTY5NXNJd1ZYZ0R0aG9IUElnc2NXT2s4Vk0iLCJ4ckZiQWZfc0IzOGhzVjV2T2t6Mmh4TFlWdVNOZTJvTlI0UVl3dXRqdmMwIl0sIl9zZF9hbGciOiJzaGEtMjU2IiwidmN0IjoiQ2l0aXplbkNyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6a2V5OnpEbmFlYzVmYnZkNzhjUms1UUo0elpvVnhtU1hLVUg1S1ZHblVFQjR6UnJ5elFtY3kiLCJlbWFpbCI6ImNpdGl6ZW5AY2l0eS5vcmcifQ.2_f_wirBJNccecvp6t-Gowx38qWq8ErYrg3aqrjsxJ09EphPhE-KeisJ9LIoldSU2VjFkiOjGpUr9rHl_YCJhg~WyJhdzVrS3FkLWFxN29QMS0zR1IzLWN3IiwgImZpcnN0TmFtZSIsICJUZXN0Il0~"
}

// getNoVCVPTokenJWT returns a JWT-format VP token with no verifiable credentials.
func getNoVCVPTokenJWT() string {
	return buildJWTVPToken(map[string]interface{}{
		"iss": "did:key:z6Mks9m9ifLwy3JWqH4c57EbBQVS2SpRCjfa79wHb5vWM6vh",
		"vp": map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiablePresentation"},
			"holder":   map[string]interface{}{"id": "did:key:z6Mks9m9ifLwy3JWqH4c57EbBQVS2SpRCjfa79wHb5vWM6vh"},
		},
	})
}

func TestIsSdJWT_MapsValidityDates(t *testing.T) {
	// Single SD-JWT VC token (not wrapped in a vp claim) — the shape produced when a
	// wallet responds with {"<query_id>": ["<sd-jwt-vc>~<disclosures>~<kb-jwt>"]}.
	header := map[string]interface{}{"alg": "ES256", "typ": "vc+sd-jwt"}
	payload := map[string]interface{}{
		"iss": "did:web:issuer.example.com",
		"vct": "VerifiableCredential",
		"iat": 1700000000,
		"exp": 1800000000,
	}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)
	token := base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + ".fakesig~"

	sdJwtParser = &verifier.ConfigurableSdJwtParser{}
	recorder := httptest.NewRecorder()
	testContext, _ := gin.CreateTestContext(recorder)

	isSdJwt, presentation, err := isSdJWT(testContext, token)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !isSdJwt {
		t.Fatal("Expected token to be recognized as SD-JWT")
	}
	creds := presentation.Credentials()
	if len(creds) != 1 {
		t.Fatalf("Expected 1 credential, got %d", len(creds))
	}
	contents := creds[0].Contents()
	if contents.ValidFrom == nil || contents.ValidFrom.Unix() != 1700000000 {
		t.Errorf("Expected ValidFrom from iat, got %v", contents.ValidFrom)
	}
	if contents.ValidUntil == nil || contents.ValidUntil.Unix() != 1800000000 {
		t.Errorf("Expected ValidUntil from exp, got %v", contents.ValidUntil)
	}
}

func newTestProofChecker() *verifier.JWTProofChecker {
	registry := did.NewRegistry(did.WithVDR(did.NewWebVDR()), did.WithVDR(did.NewKeyVDR()), did.WithVDR(did.NewJWKVDR()))
	return verifier.NewJWTProofChecker(registry)
}

// ecKeyToDidKey encodes a P-256 public key as a did:key identifier.
func ecKeyToDidKey(pub *ecdsa.PublicKey) string {
	compressed := elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	// P-256 multicodec = 0x1200, varint encoded as 2 bytes
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], 0x1200)
	keyBytes := append(buf[:n], compressed...)
	encoded, _ := multibase.Encode(multibase.Base58BTC, keyBytes)
	return "did:key:" + encoded
}

// buildSignedVPToken creates a properly signed VP JWT containing a properly signed VC JWT,
// using random P-256 keys with did:key identifiers that can be resolved.
func buildSignedVPToken(t *testing.T) string {
	t.Helper()

	// Generate issuer key for VC
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}
	issuerDID := ecKeyToDidKey(&issuerPriv.PublicKey)
	issuerJWK, _ := jwk.Import(issuerPriv)

	// Sign VC
	vcPayload, _ := json.Marshal(map[string]interface{}{
		"iss": issuerDID,
		"nbf": 1741347593,
		"jti": "urn:uuid:d83b7d83-ae1a-4b58-b427-41ef4af7a839",
		"vc": map[string]interface{}{
			"type":   []string{"UserCredential"},
			"issuer": issuerDID,
			"credentialSubject": map[string]interface{}{
				"firstName": "Test",
				"lastName":  "Reader",
				"email":     "test@user.org",
			},
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		},
	})
	vcHdrs := jws.NewHeaders()
	_ = vcHdrs.Set(jws.KeyIDKey, issuerDID)
	_ = vcHdrs.Set(jws.AlgorithmKey, jwa.ES256())
	_ = vcHdrs.Set("typ", "JWT")
	vcSigned, err := jws.Sign(vcPayload, jws.WithKey(jwa.ES256(), issuerJWK, jws.WithProtectedHeaders(vcHdrs)))
	if err != nil {
		t.Fatalf("Failed to sign VC: %v", err)
	}

	// Generate holder key for VP
	holderPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate holder key: %v", err)
	}
	holderDID := ecKeyToDidKey(&holderPriv.PublicKey)
	holderJWK, _ := jwk.Import(holderPriv)

	// Sign VP
	vpPayload, _ := json.Marshal(map[string]interface{}{
		"iss": holderDID,
		"sub": holderDID,
		"vp": map[string]interface{}{
			"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []string{"VerifiablePresentation"},
			"verifiableCredential": []string{string(vcSigned)},
			"holder":               holderDID,
		},
	})
	vpHdrs := jws.NewHeaders()
	_ = vpHdrs.Set(jws.KeyIDKey, holderDID)
	_ = vpHdrs.Set(jws.AlgorithmKey, jwa.ES256())
	_ = vpHdrs.Set("typ", "JWT")
	vpSigned, err := jws.Sign(vpPayload, jws.WithKey(jwa.ES256(), holderJWK, jws.WithProtectedHeaders(vpHdrs)))
	if err != nil {
		t.Fatalf("Failed to sign VP: %v", err)
	}

	return string(vpSigned)
}

// TestGetPresentationFromQuery exercises both shapes of the DCQL vp_token map:
//   - OID4VP drafts 22-24: {"<query_id>": "<single-presentation>"}
//   - OID4VP draft 25+:    {"<query_id>": ["<presentation>", ...]}
//
// Both must be accepted (backward-compatible). Inputs that are neither a query
// map nor parseable as a single token must return (nil, nil) so the caller
// falls through to the flat-string presentation parsing path. A token that is
// base64, but not in the raw url-safe encoding OID4VP requires, must be rejected
// with a 400 instead of falling through as an undecoded string.
func TestGetPresentationFromQuery(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	sdJwt := getValidSDJwtToken()

	stringShapeMap, err := json.Marshal(map[string]string{"lpc-query": sdJwt})
	if err != nil {
		t.Fatalf("Failed to marshal drafts 22-24 query map: %v", err)
	}
	arrayShapeMap, err := json.Marshal(map[string][]string{"lpc-query": {sdJwt}})
	if err != nil {
		t.Fatalf("Failed to marshal draft 25+ query map: %v", err)
	}
	// a spec-conform client base64url encodes the query map without padding
	encodedStringShapeMap := base64.RawURLEncoding.EncodeToString(stringShapeMap)
	// clients that encode it with a padding-emitting encoder(java, python) send a trailing '=' instead, which
	// used to make the raw string fall through to the sd-jwt parser. It has to be reported, not compensated.
	paddedStringShapeMap := base64.URLEncoding.EncodeToString(withBase64Padding(stringShapeMap))
	standardAlphabetArrayShapeMap := base64.StdEncoding.EncodeToString(withBase64Padding(arrayShapeMap))

	type test struct {
		testName       string
		vpToken        string
		expectedNonNil bool
		expectedErr    error
		expectedID     string
	}

	tests := []test{
		{"OID4VP drafts 22-24 single-string-shape query map should be parsed.", string(stringShapeMap), true, nil, "lpc-query"},
		{"OID4VP draft 25+ array-shape query map should be parsed.", string(arrayShapeMap), true, nil, "lpc-query"},
		{"A raw base64url encoded query map should be parsed.", encodedStringShapeMap, true, nil, "lpc-query"},
		{"A padded base64url encoded query map should be rejected.", paddedStringShapeMap, false, ErrorInvalidTokenEncoding, ""},
		{"A standard-alphabet base64 encoded query map should be rejected.", standardAlphabetArrayShapeMap, false, ErrorInvalidTokenEncoding, ""},
		{"A flat sd-jwt (no query map) should return nil so the caller falls through.", sdJwt, false, nil, ""},
		{"A non-JSON token should return nil so the caller falls through.", "this-is-not-json", false, nil, ""},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {

			presentationParser = &verifier.ConfigurablePresentationParser{
				ProofChecker: newTestProofChecker()}
			sdJwtParser = &verifier.ConfigurableSdJwtParser{
				ProofChecker: newTestProofChecker()}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)

			parsed, parseErr := getPresentationFromQuery(testContext, tc.vpToken)

			if tc.expectedErr != nil {
				if parseErr != tc.expectedErr {
					t.Errorf("%s - Expected error %v but was %v", tc.testName, tc.expectedErr, parseErr)
					return
				}
				if recorder.Code != http.StatusBadRequest {
					t.Errorf("%s - Expected the request to be answered with a 400 but was %d.", tc.testName, recorder.Code)
				}
				return
			}
			if parseErr != nil {
				t.Errorf("%s - Unexpected error: %v", tc.testName, parseErr)
				return
			}
			if tc.expectedNonNil && parsed == nil {
				t.Errorf("%s - Expected a non-nil presentation but got nil.", tc.testName)
				return
			}
			if !tc.expectedNonNil && parsed != nil {
				t.Errorf("%s - Expected nil presentation (so caller can fall through) but got %v.", tc.testName, parsed)
				return
			}
			if tc.expectedID != "" {
				credentials := parsed.Credentials()
				if len(credentials) == 0 || !slices.Contains(credentials[0].RequestIDs(), tc.expectedID) {
					t.Errorf("%s - Expected parsed credential to retain request id %q.", tc.testName, tc.expectedID)
				}
			}
		})
	}
}

func TestAddPresentationSubmissionRequestIDs(t *testing.T) {
	const definitionID = "configured-definition"
	submission := `{"id":"submission-1","definition_id":"configured-definition","descriptor_map":[{"id":"descriptor-a","path":"$","path_nested":{"path":"$.vp.verifiableCredential[0]"}},{"id":"descriptor-b","path":"$.verifiableCredential[1]"},{"id":"descriptor-c","path":"$","path_nested":{"path":"$.vp","path_nested":{"path":"$.verifiableCredential[1]","path_nested":{"path":"$.vc","path_nested":{"path":"$.credentialSubject.id"}}}}},{"id":"descriptor-d","path":"$.vp.verifiableCredential[0]","path_nested":{"path":"$"}}]}`
	tests := []struct {
		name       string
		submission string
	}{
		{name: "accepts JSON for backward compatibility", submission: submission},
		{name: "accepts raw base64url JSON", submission: base64.RawURLEncoding.EncodeToString([]byte(submission))},
		{name: "accepts padded base64url JSON", submission: base64.URLEncoding.EncodeToString([]byte(submission))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			presentation, err := common.NewPresentation(common.WithCredentials(&common.Credential{}, &common.Credential{}))
			if err != nil {
				t.Fatal(err)
			}
			if err := addPresentationSubmissionRequestIDs(presentation, tc.submission); err != nil {
				t.Fatalf("Expected valid presentation_submission, got %v", err)
			}
			if got := presentation.Credentials()[0].RequestIDs(); !slices.Equal(got, []string{"descriptor-a", "descriptor-d"}) {
				t.Errorf("Expected descriptor-a to map to the first credential, got %v", got)
			}
			if got := presentation.Credentials()[1].RequestIDs(); !slices.Equal(got, []string{"descriptor-b", "descriptor-c"}) {
				t.Errorf("Expected descriptor-b and descriptor-c to map to the second credential, got %v", got)
			}
			if got := presentation.PresentationSubmissionDefinitionID(); got != definitionID {
				t.Errorf("Expected definition id %q, got %q", definitionID, got)
			}
		})
	}

	for _, malformed := range []string{
		`not-json`,
		`{"id":"submission-1","definition_id":"configured-definition","descriptor_map":[]}`,
		`{"id":"submission-1","definition_id":"configured-definition","descriptor_map":[{}]}`,
		`{"id":"submission-1","definition_id":"configured-definition","descriptor_map":[{"id":"unsupported","path":"$.ignored.verifiableCredential[0]"}]}`,
		`{"id":"submission-1","definition_id":"configured-definition","descriptor_map":[{"id":"out-of-range","path":"$.verifiableCredential[2]"}]}`,
		`{"id":"submission-1","definition_id":"","descriptor_map":[{"id":"descriptor-a","path":"$.verifiableCredential[0]"}]}`,
		`{"id":"submission-1","definition_id":"configured-definition","descriptor_map":[{"id":"mismatched-nesting","path":"$.vp","path_nested":{"path":"$.vp.verifiableCredential[0]"}}]}`,
		`{"id":"submission-1","definition_id":"configured-definition","descriptor_map":[{"id":"invalid-credential-relative-path","path":"$.verifiableCredential[0]","path_nested":{"path":"$..vc"}}]}`,
	} {
		presentation, err := common.NewPresentation(common.WithCredentials(&common.Credential{}, &common.Credential{}))
		if err != nil {
			t.Fatal(err)
		}
		if err := addPresentationSubmissionRequestIDs(presentation, malformed); err == nil {
			t.Errorf("Expected malformed presentation_submission %q to fail", malformed)
		}
	}

	for _, tc := range []struct {
		submission string
		wantError  string
	}{
		{submission: `{"definition_id":"configured-definition","descriptor_map":[{"id":"descriptor-a","path":"$.verifiableCredential[0]"}]}`, wantError: "presentation_submission has no id"},
		{submission: `{"id":"submission-1","descriptor_map":[{"id":"descriptor-a","path":"$.verifiableCredential[0]"}]}`, wantError: "presentation_submission has no definition_id"},
	} {
		presentation, err := common.NewPresentation(common.WithCredentials(&common.Credential{}))
		if err != nil {
			t.Fatal(err)
		}
		err = addPresentationSubmissionRequestIDs(presentation, tc.submission)
		if err == nil || err.Error() != tc.wantError {
			t.Errorf("Expected error %q, got %v", tc.wantError, err)
		}
	}
}

func TestBuildFrontendV2Address(t *testing.T) {
	tests := []struct {
		testName    string
		prefix      string
		redirectUri string
		wantPath    string
	}{
		{testName: "No prefix configured, path is unchanged", prefix: "", redirectUri: "https://wallet.example/callback", wantPath: "/api/v2/loginQR"},
		{testName: "Prefix is inserted before the loginQR path", prefix: "/myservice", redirectUri: "https://wallet.example/callback", wantPath: "/myservice/api/v2/loginQR"},
		{testName: "Redirect URI query parameters remain intact", prefix: "", redirectUri: "https://wallet.example/callback?tenant=one&mode=login", wantPath: "/api/v2/loginQR"},
	}
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			actual := buildFrontendV2Address("https", "verifier.org", tc.prefix, "my-state", "my-client", tc.redirectUri, "", "my-nonce", "byReference")
			parsed, err := url.Parse(actual)
			if err != nil {
				t.Fatalf("Could not parse frontend address %q: %v", actual, err)
			}
			if parsed.Scheme != "https" || parsed.Host != "verifier.org" || parsed.Path != tc.wantPath {
				t.Errorf("Expected https://verifier.org%s, got %s", tc.wantPath, actual)
			}
			query := parsed.Query()
			if got := query.Get("redirect_uri"); got != tc.redirectUri {
				t.Errorf("Expected redirect_uri %q, got %q", tc.redirectUri, got)
			}
			if got := query.Get("state"); got != "my-state" {
				t.Errorf("Expected state %q, got %q", "my-state", got)
			}
			if got := query.Get("client_id"); got != "my-client" {
				t.Errorf("Expected client_id %q, got %q", "my-client", got)
			}
			if got := query.Get("request_mode"); got != "byReference" {
				t.Errorf("Expected request_mode %q, got %q", "byReference", got)
			}
		})
	}
}

func TestBuildFrontendV2Address_UsesProvidedRequestMode(t *testing.T) {
	actual := buildFrontendV2Address("https", "verifier.org", "", "my-state", "my-client", "https://wallet.example/callback", "", "my-nonce", "urlEncoded")
	parsed, err := url.Parse(actual)
	if err != nil {
		t.Fatalf("Could not parse frontend address %q: %v", actual, err)
	}
	if got := parsed.Query().Get("request_mode"); got != "urlEncoded" {
		t.Errorf("Expected request_mode %q, got %q", "urlEncoded", got)
	}
}

func TestBuildFrontendV2Address_PropagatesPKCE(t *testing.T) {
	pkce := verifier.PKCEChallenge{Value: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", Method: verifier.PKCES256}
	actual := buildFrontendV2Address("https", "verifier.org", "", "my-state", "my-client", "https://wallet.example/callback", "", "my-nonce", "urlEncoded", pkce)
	parsed, err := url.Parse(actual)
	if err != nil {
		t.Fatalf("Could not parse frontend address %q: %v", actual, err)
	}
	if got := parsed.Query().Get("code_challenge"); got != pkce.Value {
		t.Errorf("Expected code_challenge %q, got %q", pkce.Value, got)
	}
	if got := parsed.Query().Get("code_challenge_method"); got != pkce.Method {
		t.Errorf("Expected code_challenge_method %q, got %q", pkce.Method, got)
	}

	methodOnly := buildFrontendV2Address("https", "verifier.org", "", "my-state", "my-client", "https://wallet.example/callback", "", "my-nonce", "urlEncoded", verifier.PKCEChallenge{Method: verifier.PKCES256})
	methodOnlyURL, err := url.Parse(methodOnly)
	if err != nil {
		t.Fatalf("Could not parse frontend address %q: %v", methodOnly, err)
	}
	if got := methodOnlyURL.Query().Get("code_challenge_method"); got != verifier.PKCES256 {
		t.Errorf("Expected method-only request to preserve %q so it can be rejected, got %q", verifier.PKCES256, got)
	}
}

// withBase64Padding appends json-insignificant whitespace until the length is not a multiple of 3, so
// that encoding the result is guaranteed to emit '=' padding regardless of the fixture that is used.
func withBase64Padding(raw []byte) []byte {
	for len(raw)%3 == 0 {
		raw = append(raw, ' ')
	}
	return raw
}

func TestDecodeVpString(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	// 4 bytes, so the encodings emit padding, and chosen so that the standard alphabet uses '+' and '/'
	// where the url-safe one uses '-' and '_' - the four encodings therefore produce four distinct strings
	decoded := []byte{0xfb, 0xff, 0xbe, 0x2a}

	type test struct {
		testName    string
		vpToken     string
		expected    []byte
		expectedErr error
	}

	tests := []test{
		{"Raw base64url, the only encoding OID4VP allows, should be decoded.", base64.RawURLEncoding.EncodeToString(decoded), decoded, nil},
		{"Padded base64url should be rejected.", base64.URLEncoding.EncodeToString(decoded), nil, ErrorInvalidTokenEncoding},
		{"Raw standard base64 should be rejected.", base64.RawStdEncoding.EncodeToString(decoded), nil, ErrorInvalidTokenEncoding},
		{"Padded standard base64 should be rejected.", base64.StdEncoding.EncodeToString(decoded), nil, ErrorInvalidTokenEncoding},
		{"A compact jwt should be returned unchanged.", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtZSJ9.sig", []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtZSJ9.sig"), nil},
		{"An sd-jwt should be returned unchanged.", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtZSJ9.sig~disclosure~", []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtZSJ9.sig~disclosure~"), nil},
		{"A plain json query map should be returned unchanged.", `{"lpc-query":"a.b.c"}`, []byte(`{"lpc-query":"a.b.c"}`), nil},
		{"A non-base64 string should be returned unchanged.", "this-is-not-base64!", []byte("this-is-not-base64!"), nil},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			actual, err := decodeVpString(tc.vpToken)
			if err != tc.expectedErr {
				t.Errorf("%s - Expected error %v but was %v", tc.testName, tc.expectedErr, err)
				return
			}
			if !bytes.Equal(actual, tc.expected) {
				t.Errorf("%s - Expected %s but was %s", tc.testName, tc.expected, actual)
			}
		})
	}
}

// getNoHolderVPTokenJWT returns a JWT-format VP token where the holder is
// a JSON object (not a plain string). Tests that the handler tolerates
// non-string holders gracefully.
func getNoHolderVPTokenJWT() string {
	return buildJWTVPToken(map[string]interface{}{
		"vp": map[string]interface{}{
			"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []string{"VerifiablePresentation"},
			"holder":               map[string]interface{}{"nota": "holder"},
			"verifiableCredential": []interface{}{buildFakeVCJWT()},
		},
	})
}

// TestLoginStartRefusesRedirectUri checks that every entry point of a login answers a redirect
// URI the client does not allow with 400, and never redirects to it.
func TestLoginStartRefusesRedirectUri(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	gin.SetMode(gin.TestMode)

	type test struct {
		testName string
		path     string
		handler  gin.HandlerFunc
		mock     *mockVerifier
	}
	tests := []test{
		{"the oidc authorization endpoint", "/api/v1/authorization?client_id=listed-client&response_type=code&scope=default&redirect_uri=https://evil.example/cb&state=s&nonce=n", AuthorizationEndpoint,
			&mockVerifier{mockAuthorizationType: FRONTEND_V2, mockRedirectUriError: verifier.ErrorRedirectUriNotAllowed}},
		{"the cross-device v2 login page", "/api/v2/loginQR?state=s&client_id=listed-client&redirect_uri=https://evil.example/cb", VerifierLoginQr,
			&mockVerifier{mockError: verifier.ErrorRedirectUriNotAllowed}},
		{"the cross-device v1 login page", "/api/v1/loginQR?state=s&client_id=listed-client&client_callback=https://evil.example/cb", VerifierPageDisplayQRSIOP,
			&mockVerifier{mockError: verifier.ErrorRedirectUriNotAllowed}},
		{"the cross-device v1 connection string", "/api/v1/startsiop?state=s&client_id=listed-client&client_callback=https://evil.example/cb", VerifierAPIStartSIOP,
			&mockVerifier{mockError: verifier.ErrorRedirectUriNotAllowed}},
		{"the same-device flow", "/api/v1/samedevice?state=s&client_id=listed-client&scope=s&redirect_path=/cb", StartSIOPSameDevice,
			&mockVerifier{mockError: verifier.ErrorRedirectUriNotAllowed}},
	}
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			apiVerifier = tc.mock
			frontendVerifier = tc.mock
			t.Cleanup(func() { apiVerifier = nil; frontendVerifier = nil })

			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodGet, tc.path, nil)
			tc.handler(c)

			if recorder.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", recorder.Code)
			}
			if location := recorder.Header().Get("Location"); location != "" {
				t.Errorf("A refused redirect URI must not be redirected to, got Location %q", location)
			}
			var body ErrorMessage
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body != ErrorMessageRedirectUriNotAllowed {
				t.Errorf("Expected %v, got %s (err %v)", ErrorMessageRedirectUriNotAllowed, recorder.Body.String(), err)
			}
		})
	}
}

// TestCodeRedirectUrl checks that the authorization response is appended to the redirect target as
// escaped query parameters, keeping a query the target already has.
func TestCodeRedirectUrl(t *testing.T) {
	type test struct {
		testName       string
		redirectTarget string
		state          string
		code           string
		nonce          string
		expectedUrl    string
	}
	tests := []test{
		{"A plain target gets the parameters as its query.", "https://rp.example/callback", "my-state", "my-code", "", "https://rp.example/callback?state=my-state&code=my-code"},
		{"The nonce is added when there is one.", "https://rp.example/callback", "my-state", "my-code", "my-nonce", "https://rp.example/callback?state=my-state&code=my-code&nonce=my-nonce"},
		{"A query of the target is kept.", "https://rp.example/callback?tenant=a", "my-state", "my-code", "", "https://rp.example/callback?tenant=a&state=my-state&code=my-code"},
		{"A state cannot add parameters of its own.", "https://rp.example/callback", "s&code=injected", "my-code", "", "https://rp.example/callback?state=s%26code%3Dinjected&code=my-code"},
		{"A state cannot move the code into a fragment.", "https://rp.example/callback", "s#", "my-code", "", "https://rp.example/callback?state=s%23&code=my-code"},
	}
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			redirectUrl, err := codeRedirectUrl(tc.redirectTarget, tc.state, tc.code, tc.nonce)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedUrl, redirectUrl)
			parsed, err := url.Parse(redirectUrl)
			assert.NoError(t, err)
			assert.Equal(t, []string{tc.code}, parsed.Query()["code"])
			assert.Equal(t, tc.state, parsed.Query().Get("state"))
		})
	}
}

// TestStartSIOPSameDeviceRejectsInvalidRedirectPath checks that a redirect_path leaving the
// verifier's host is answered with 400 and never redirected to.
func TestStartSIOPSameDeviceRejectsInvalidRedirectPath(t *testing.T) {
	apiVerifier = &mockVerifier{mockError: verifier.ErrorInvalidRedirectPath}
	t.Cleanup(func() { apiVerifier = nil })

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/samedevice?state=s&scope=s&redirect_path=@evil.example/cb", nil)
	StartSIOPSameDevice(c)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Empty(t, recorder.Header().Get("Location"))
	var body ErrorMessage
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, ErrorMessageInvalidRedirectPath, body)
}
