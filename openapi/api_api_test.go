package openapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	verifier "github.com/fiware/VCVerifier/verifier"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/multiformats/go-multibase"

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
	mockJWTString           string
	mockQR                  string
	mockConnectionString    string
	mockAuthRequest         string
	mockJWKS                jwk.Set
	mockOpenIDConfig        common.OpenIDProviderMetadata
	mockSameDevice          verifier.Response
	mockExpiration          int64
	mockError               error
	mockAuthorizationType   string
	mockRefreshTokenEnabled bool
	mockRefreshToken        string
	mockRefreshTokenError   error
	mockExchangeJWT         string
	mockExchangeExpiration  int64
	mockExchangeRefresh     string
	mockExchangeError       error
}

func (mV *mockVerifier) ReturnLoginQR(host string, protocol string, callback string, sessionId string, clientId string, nonce string, requestType string) (qr string, err error) {
	return mV.mockQR, mV.mockError
}
func (mV *mockVerifier) ReturnLoginQRV2(host string, protocol string, callback string, sessionId string, clientId string, scope string, nonce string, requestMode string) (qrInfo verifier.QRLoginInfo, err error) {
	return verifier.QRLoginInfo{QR: mV.mockQR}, mV.mockError
}
func (mV *mockVerifier) StartSiopFlow(host string, protocol string, callback string, sessionId string, clientId string, nonce string, requestType string) (connectionString string, err error) {
	return mV.mockConnectionString, mV.mockError
}
func (mV *mockVerifier) StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string, clientId string, nonce string, requestType string, scope string, requestProtocol string) (authenticationRequest string, err error) {
	return mV.mockAuthRequest, mV.mockError
}
func (mV *mockVerifier) GetToken(authorizationCode string, redirectUri string, validated bool) (jwtString string, expiration int64, refreshToken string, err error) {
	return mV.mockJWTString, mV.mockExpiration, mV.mockRefreshToken, mV.mockError
}
func (mV *mockVerifier) GetJWKS() jwk.Set {
	return mV.mockJWKS
}
func (mV *mockVerifier) GetDefaultScope(clientId string) (string, error) {
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
	return ""
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
		{testName: "If no grant type is provided, the request should fail.", proofCheck: false, testGrantType: "", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessagNoGrantType},
		{testName: "If an invalid grant type is provided, the request should fail.", proofCheck: false, testGrantType: "my_special_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessageUnsupportedGrantType},
		{testName: "If no auth code is provided, the request should fail.", proofCheck: false, testGrantType: "authorization_code", testCode: "", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessageNoCode},
		{testName: "If no redirect uri is provided, the request should fail.", proofCheck: false, testGrantType: "authorization_code", testCode: "my-auth-code", expectedStatusCode: 400, expectedError: ErrorMessageInvalidTokenRequest},
		{testName: "If the verify returns an error, a 403 should be answerd.", proofCheck: false, testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockError: errors.New("invalid"), expectedStatusCode: 403, expectedError: ErrorMessage{}},
		{testName: "If no valid scope is provided, the request should be executed in the default scope.", proofCheck: false, testVPToken: getValidVPToken(), testGrantType: "vp_token", expectedStatusCode: 200},

		{testName: "If a valid vp_token request is received a token should be responded.", proofCheck: false, testGrantType: "vp_token", testVPToken: getValidVPToken(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, IdToken: "theJWT"}},
		{testName: "If a valid signed vp_token request is received a token should be responded.", proofCheck: true, testGrantType: "vp_token", testVPToken: buildSignedVPToken(t), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, IdToken: "theJWT"}},
		{testName: "If no valid vp_token is provided, the request should fail.", proofCheck: false, testGrantType: "vp_token", testScope: "tir_read", expectedStatusCode: 400, expectedError: ErrorMessageNoToken},
		// token-exchange
		{testName: "If a valid token-exchange request is received a token should be responded.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN}},
		{testName: "If a token-exchange request is received without resource, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testSubjectTokenType: "urn:eu:oidf:vp_token", expectedStatusCode: 400, expectedError: ErrorMessageNoResource},
		{testName: "If a token-exchange request is received with invalid subject_token_type, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "invalid_type", expectedStatusCode: 400, expectedError: ErrorMessageInvalidSubjectTokenType},
		{testName: "If a token-exchange request is received with invalid requested_token_type, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", testRequestedTokenType: "invalid_type", expectedStatusCode: 400, expectedError: ErrorMessageInvalidRequestedTokenType},
		{testName: "If a token-exchange request is received without subject_token, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", expectedStatusCode: 400, expectedError: ErrorMessageNoToken},
		{testName: "If a token-exchange request is received without scope, the default scope should be used.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", expectedStatusCode: 200},
		// refresh_token grant type
		{testName: "If a valid refresh_token request is received, new tokens should be returned.", testGrantType: "refresh_token", testRefreshToken: "valid-refresh-token", mockExchangeJWT: "newJWT", mockExchangeExpiration: 300, mockExchangeRefresh: "rotated-refresh-token", expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 300, AccessToken: "newJWT", IdToken: "newJWT", RefreshToken: "rotated-refresh-token"}},
		{testName: "If no refresh_token is provided in a refresh_token request, a 400 should be returned.", testGrantType: "refresh_token", expectedStatusCode: 400, expectedError: ErrorMessageNoRefreshToken},
		{testName: "If an invalid refresh_token is provided, a 403 should be returned.", testGrantType: "refresh_token", testRefreshToken: "invalid-token", mockExchangeError: errors.New("token not found"), expectedStatusCode: 403, expectedError: ErrorMessageInvalidRefreshToken},
		// authorization_code with refresh token enabled
		{testName: "If refresh tokens are enabled, authorization_code response includes refresh_token.", testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: true, mockRefreshToken: "new-refresh-token", expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT", RefreshToken: "new-refresh-token"}},
		// vp_token with refresh token enabled
		{testName: "If refresh tokens are enabled, vp_token response includes refresh_token.", testGrantType: "vp_token", testVPToken: getValidVPToken(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: true, mockRefreshToken: "new-refresh-token", expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, IdToken: "theJWT", RefreshToken: "new-refresh-token"}},
		// token-exchange with refresh token enabled
		{testName: "If refresh tokens are enabled, token-exchange response includes refresh_token.", testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: true, mockRefreshToken: "new-refresh-token", expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, RefreshToken: "new-refresh-token"}},
		// refresh token disabled — verify no refresh_token in existing grant type responses
		{testName: "If refresh tokens are disabled, authorization_code response omits refresh_token.", testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: false, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT"}},
		{testName: "If refresh tokens are disabled, vp_token response omits refresh_token.", testGrantType: "vp_token", testVPToken: getValidVPToken(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: false, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, IdToken: "theJWT"}},
		{testName: "If refresh tokens are disabled, token-exchange response omits refresh_token.", testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: false, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN}},
		// non-fatal CreateRefreshToken error — access token returned without refresh_token
		{testName: "If CreateRefreshToken fails for vp_token, access token is still returned.", testGrantType: "vp_token", testVPToken: getValidVPToken(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: true, mockRefreshTokenError: errors.New("db write failed"), expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN, IdToken: "theJWT"}},
		{testName: "If CreateRefreshToken fails for token-exchange, access token is still returned.", testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", mockJWTString: "theJWT", mockExpiration: 10, mockRefreshEnabled: true, mockRefreshTokenError: errors.New("db write failed"), expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", IdToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN}},
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
		mockRedirect       string
		mockError          error
		expectedStatusCode int
		expectedLocation   string
		expectedResponse   string
	}

	tests := []test{
		{testName: "If all neccessary parameters provided, a valid redirect should be returned.", testState: "my-state", testRedirectPath: "/my-redirect", testRequestAddress: "http://host.org", mockRedirect: "http://host.org/api/v1/authentication_response", mockError: nil, expectedStatusCode: 302, expectedLocation: "http://host.org/api/v1/authentication_response"},
		{testName: "If no state is provided, a 400 should be returned.", testState: "", testRedirectPath: "", testRequestAddress: "http://host.org", mockRedirect: "http://host.org/api/v1/authentication_response", mockError: nil, expectedStatusCode: 400, expectedLocation: ""},
		{testName: "If the verifier returns an error, a 500 should be returned.", testState: "my-state", testRedirectPath: "/", testRequestAddress: "http://host.org", mockRedirect: "http://host.org/api/v1/authentication_response", mockError: errors.New("verifier_failure"), expectedStatusCode: 500, expectedLocation: ""},
		{testName: "If no path is provided, a deeplink should be returned.", testState: "my-state", testRedirectPath: "", testRequestAddress: "http://host.org", mockRedirect: "http://host.org/api/v1/authentication_response", mockError: nil, expectedStatusCode: 302, expectedLocation: "http://host.org/api/v1/authentication_response", expectedResponse: ""},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {
			presentationParser = &verifier.ConfigurablePresentationParser{}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)
			apiVerifier = &mockVerifier{mockAuthRequest: tc.mockRedirect, mockError: tc.mockError}

			testParameters := []string{}
			if tc.testState != "" {
				testParameters = append(testParameters, "state="+tc.testState)
			}
			if tc.testRedirectPath != "" {
				testParameters = append(testParameters, "redirect_path="+tc.testRedirectPath)
			}

			testContext.Request, _ = http.NewRequest("GET", tc.testRequestAddress+"/?"+strings.Join(testParameters, "&"), nil)
			StartSIOPSameDevice(testContext)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
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
		{"If a same-device flow is authenticated, a valid redirect should be returned.", true, "my-state", getValidVPToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE, RedirectTarget: "http://my-verifier.org", Code: "my-code", SessionId: "my-session-id"}, 302, "http://my-verifier.org?state=my-session-id&code=my-code", ErrorMessage{}},
		{"If a same-device flow is authenticated with an SdJwt, a valid redirect should be returned.", true, "my-state", getValidSDJwtToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE, RedirectTarget: "http://my-verifier.org", Code: "my-code", SessionId: "my-session-id"}, 302, "http://my-verifier.org?state=my-session-id&code=my-code", ErrorMessage{}},
		{"If a cross-device flow is authenticated, a simple ok should be returned.", false, "my-state", getValidVPToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 200, "", ErrorMessage{}},
		{"If a cross-device flow is authenticated with an SdJwt, a simple ok should be returned.", false, "my-state", getValidSDJwtToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 200, "", ErrorMessage{}},
		{"If the same-device flow responds an error, a 400 should be returend", true, "my-state", getValidVPToken(), errors.New("verification_error"), verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 400, "", ErrorMessage{Summary: "verification_error"}},
		{"If no state is provided, a 400 should be returned.", true, "", getValidVPToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 400, "", ErrorMessageNoState},
		{"If an no token is provided, a 400 should be returned.", true, "my-state", "", nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 400, "", ErrorMessageNoToken},
		{"If a token with no credentials is provided, a redirect should still occur.", true, "my-state", getNoVCVPToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 302, "/?state=&code=", ErrorMessage{}},
		{"If a token with a non-string holder is provided, a redirect should still occur.", true, "my-state", getNoHolderVPToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 302, "/?state=&code=", ErrorMessage{}},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {

			presentationParser = &verifier.ConfigurablePresentationParser{
				ProofChecker: newTestProofChecker()}
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

func getValidVPToken() string {
	return "eyJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJZ09pQWlTbGRVSWl3aWEybGtJaUE2SUNKa2FXUTZhMlY1T25wRWJtRmxWbGhVVGxGNVpEbFFaSE5oVmpOaGIySkdhMDFaYmxSMlNsSmplVFJCVVZKSWRVVTJaMUZ0T1ZOdFYwUWlmUS5leUp1WW1ZaU9qRTNNRGM1T0RRek1UQXNJbXAwYVNJNkluVnlhVHAxZFdsa09tTmlOV1k1WmpGakxUQXhOMkl0TkdRME5DMDRORFl4TFRjeVpETXlNMlJoT0RSalppSXNJbWx6Y3lJNkltUnBaRHByWlhrNmVrUnVZV1ZXV0ZST1VYbGtPVkJrYzJGV00yRnZZa1pyVFZsdVZIWktVbU41TkVGUlVraDFSVFpuVVcwNVUyMVhSQ0lzSW5OMVlpSTZJblZ5YmpwMWRXbGtPbVF5TUdZd09URmhMVGt4Wm1RdE5EZGhNaTA0WVRnM0xUUTFZamcyTURJMFltVTVaU0lzSW5aaklqcDdJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbXRsZVRwNlJHNWhaVlpZVkU1UmVXUTVVR1J6WVZZellXOWlSbXROV1c1VWRrcFNZM2swUVZGU1NIVkZObWRSYlRsVGJWZEVJaXdpYVhOemRXRnVZMlZFWVhSbElqb3hOekEzT1RnME16RXdPREV5TENKcFpDSTZJblZ5YVRwMWRXbGtPbU5pTldZNVpqRmpMVEF4TjJJdE5HUTBOQzA0TkRZeExUY3laRE15TTJSaE9EUmpaaUlzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0ltWnBjbk4wVG1GdFpTSTZJa2hoY0hCNVVHVjBjeUlzSW5KdmJHVnpJanBiZXlKdVlXMWxjeUk2V3lKSFQweEVYME5WVTFSUFRVVlNJaXdpVTFSQlRrUkJVa1JmUTFWVFZFOU5SVklpWFN3aWRHRnlaMlYwSWpvaVpHbGtPbXRsZVRwNk5rMXJjMVUyZEUxbVltRkVlblpoVW1VMWIwWkZOR1ZhVkZaVVZqUklTazAwWm0xUlYxZEhjMFJIVVZaelJYSWlmVjBzSW1aaGJXbHNlVTVoYldVaU9pSlFjbWx0WlNJc0ltbGtJam9pZFhKdU9uVjFhV1E2WkRJd1pqQTVNV0V0T1RGbVpDMDBOMkV5TFRoaE9EY3RORFZpT0RZd01qUmlaVGxsSWl3aWMzVmlhbVZqZEVScFpDSTZJbVJwWkRwM1pXSTZaRzl0WlMxdFlYSnJaWFJ3YkdGalpTNXZjbWNpTENKbmVEcHNaV2RoYkU1aGJXVWlPaUprYjIxbExXMWhjbXRsZEhCc1lXTmxMbTl5WnlJc0ltVnRZV2xzSWpvaWNISnBiV1V0ZFhObGNrQm9ZWEJ3ZVhCbGRITXViM0puSW4wc0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWwxOWZRLlBqSVEtdEh5Zy1UZEdGTFVld1BreWc0cTJVODFkUGhpNG4wV3dXZ05KRGx3VW5mbk5OV1BIUkpDWlJnckQxMmFVYmRhakgtRlRkYTE3N21VRUd5RGZnIl0sImhvbGRlciI6ImRpZDp1c2VyOmdvbGQiLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdfQ"
}

func getValidSDJwtToken() string {
	return "eyJhbGciOiJFUzI1NiIsInR5cCIgOiAidmMrc2Qtand0Iiwia2lkIiA6ICJkaWQ6a2V5OnpEbmFlYzVmYnZkNzhjUms1UUo0elpvVnhtU1hLVUg1S1ZHblVFQjR6UnJ5elFtY3kifQ.eyJfc2QiOlsiNDdhOS1uaU9TT3B0RjZ2eXJoUlgyN3ZPVkFJZGFJSmlYR1Zpd1hJNGJ6OCIsIjdXbUhfbXFEVHV0Z3hKX1RWOXh2Q3V0MDVJYkRwTnhRRDRyZm1DUlk5aEUiLCJDUmFOT2hia2t3TUJQXzFmRWNDcEtVcjl3Rm5BbGd5VXQySnpSVUtTZXQ4IiwiUUJ0TG1LRnpDMHEyYTZGVXJJVTdBdzRoXzNheElfaVc1bms0YXA1T3hLTSIsIlJRMktXdXJRTWt1VHdEaE1OZFdjNU5yYkc3djlyOGw5MHU1Rkp6Smh3Z0kiLCJhU2pvZFNGdkR3dWtLdERVcjhzVkVhMGZtdnhvSmVtaXM5b1RyaVFVQ3pnIiwiZThIUkpES194X3k2WDVzZmlhY2RhZWlMWDNfR2RDUXdVRjFKaWpsZXRVUSIsIm5EZDZra25Cb3Bxak9JOU42enB3R3hRYk1YSy02Z0xKSG5mYXgxR0hCOGsiLCJvRi14cG1JM2NlRUN6b2xtVXRSQ2w4SmV4WExIRzAwdDhLRE1KSWdqRFZnIiwib3FuWklsM1ZXODh2QS1BZWdPM2EzSnFxbHBOS0FSbFphWEpvbm1UenpXdyIsInBPUm8yUldMTzhmVENGTUhOeTY5NXNJd1ZYZ0R0aG9IUElnc2NXT2s4Vk0iLCJ4ckZiQWZfc0IzOGhzVjV2T2t6Mmh4TFlWdVNOZTJvTlI0UVl3dXRqdmMwIl0sIl9zZF9hbGciOiJzaGEtMjU2IiwidmN0IjoiQ2l0aXplbkNyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6a2V5OnpEbmFlYzVmYnZkNzhjUms1UUo0elpvVnhtU1hLVUg1S1ZHblVFQjR6UnJ5elFtY3kiLCJlbWFpbCI6ImNpdGl6ZW5AY2l0eS5vcmcifQ.2_f_wirBJNccecvp6t-Gowx38qWq8ErYrg3aqrjsxJ09EphPhE-KeisJ9LIoldSU2VjFkiOjGpUr9rHl_YCJhg~WyJhdzVrS3FkLWFxN29QMS0zR1IzLWN3IiwgImZpcnN0TmFtZSIsICJUZXN0Il0~"
}

func getNoVCVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAiaWQiOiAiZWJjNmYxYzIiLAogICJob2xkZXIiOiB7CiAgICAiaWQiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgiCiAgfSwKICAicHJvb2YiOiB7CiAgICAidHlwZSI6ICJKc29uV2ViU2lnbmF0dXJlMjAyMCIsCiAgICAiY3JlYXRvciI6ICJkaWQ6a2V5Ono2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgICAiY3JlYXRlZCI6ICIyMDIzLTAxLTA2VDA3OjUxOjM2WiIsCiAgICAidmVyaWZpY2F0aW9uTWV0aG9kIjogImRpZDprZXk6ejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoI3o2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgICAiandzIjogImV5SmlOalFpT21aaGJITmxMQ0pqY21sMElqcGJJbUkyTkNKZExDSmhiR2NpT2lKRlpFUlRRU0o5Li42eFNxb1pqYTBOd2pGMGFmOVprbnF4M0NiaDlHRU51bkJmOUM4dUwydWxHZnd1czNVRk1fWm5oUGpXdEhQbC03MkU5cDNCVDVmMnB0Wm9Za3RNS3BEQSIKICB9Cn0"
}

func newTestProofChecker() *verifier.JWTProofChecker {
	registry := did.NewRegistry(did.WithVDR(did.NewWebVDR()), did.WithVDR(did.NewKeyVDR()), did.WithVDR(did.NewJWKVDR()))
	return verifier.NewJWTProofChecker(registry, nil)
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

func getNoHolderVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAidmVyaWZpYWJsZUNyZWRlbnRpYWwiOiBbCiAgICB7CiAgICAgICJ0eXBlcyI6IFsKICAgICAgICAiUGFja2V0RGVsaXZlcnlTZXJ2aWNlIiwKICAgICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiCiAgICAgIF0sCiAgICAgICJAY29udGV4dCI6IFsKICAgICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAgICJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSIKICAgICAgXSwKICAgICAgImNyZWRlbnRpYWxzU3ViamVjdCI6IHt9LAogICAgICAiYWRkaXRpb25hbFByb3AxIjoge30KICAgIH0KICBdLAogICJpZCI6ICJlYmM2ZjFjMiIsCiAgImhvbGRlciI6IHsKICAgICJub3RhIjogImhvbGRlciIKICB9LAogICJwcm9vZiI6IHsKICAgICJ0eXBlIjogIkpzb25XZWJTaWduYXR1cmUyMDIwIiwKICAgICJjcmVhdG9yIjogImRpZDprZXk6ejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoIiwKICAgICJjcmVhdGVkIjogIjIwMjMtMDEtMDZUMDc6NTE6MzZaIiwKICAgICJ2ZXJpZmljYXRpb25NZXRob2QiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgjejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoIiwKICAgICJqd3MiOiAiZXlKaU5qUWlPbVpoYkhObExDSmpjbWwwSWpwYkltSTJOQ0pkTENKaGJHY2lPaUpGWkVSVFFTSjkuLjZ4U3FvWmphME53akYwYWY5WmtucXgzQ2JoOUdFTnVuQmY5Qzh1TDJ1bEdmd3VzM1VGTV9abmhQald0SFBsLTcyRTlwM0JUNWYycHRab1lrdE1LcERBIgogIH0KfQ"
}
