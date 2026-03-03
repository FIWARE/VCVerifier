package openapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	verifier "github.com/fiware/VCVerifier/verifier"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vc-go/proof/defaults"
	sdv "github.com/trustbloc/vc-go/sdjwt/verifier"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var LOGGING_CONFIG = logging.LoggingConfig{
	Level:         "DEBUG",
	JsonLogging:   true,
	LogRequests:   true,
	PathsToSkip:   []string{},
	DisableCaller: false,
}

type mockVerifier struct {
	mockJWTString         string
	mockQR                string
	mockConnectionString  string
	mockAuthRequest       string
	mockJWKS              jwk.Set
	mockOpenIDConfig      common.OpenIDProviderMetadata
	mockSameDevice        verifier.Response
	mockExpiration        int64
	mockError             error
	mockAuthorizationType string
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
func (mV *mockVerifier) GetToken(authorizationCode string, redirectUri string, validated bool) (jwtString string, expiration int64, err error) {
	return mV.mockJWTString, mV.mockExpiration, mV.mockError
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

func (mV *mockVerifier) AuthenticationResponse(state string, presentation *verifiable.Presentation) (sameDevice verifier.Response, err error) {
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

func (mV *mockVerifier) GenerateToken(clientId, subject, audience string, scope []string, presentation *verifiable.Presentation) (int64, string, error) {
	return mV.mockExpiration, mV.mockJWTString, mV.mockError
}

func TestGetToken(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName               string
		proofCheck             bool
		testGrantType          string
		testCode               string
		testRedirectUri        string
		testVPToken            string
		testScope              string
		testResource           string
		testSubjectTokenType   string
		testRequestedTokenType string
		mockJWTString          string
		mockExpiration         int64
		mockError              error
		expectedStatusCode     int
		expectedResponse       TokenResponse
		expectedError          ErrorMessage
	}
	tests := []test{
		{testName: "If a valid authorization_code request is received a token should be responded.", proofCheck: false, testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockJWTString: "theJWT", mockExpiration: 10, mockError: nil, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT"}, expectedError: ErrorMessage{}},
		{testName: "If no grant type is provided, the request should fail.", proofCheck: false, testGrantType: "", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessagNoGrantType},
		{testName: "If an invalid grant type is provided, the request should fail.", proofCheck: false, testGrantType: "my_special_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessageUnsupportedGrantType},
		{testName: "If no auth code is provided, the request should fail.", proofCheck: false, testGrantType: "authorization_code", testCode: "", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessageNoCode},
		{testName: "If no redirect uri is provided, the request should fail.", proofCheck: false, testGrantType: "authorization_code", testCode: "my-auth-code", expectedStatusCode: 400, expectedError: ErrorMessageInvalidTokenRequest},
		{testName: "If the verify returns an error, a 403 should be answerd.", proofCheck: false, testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockError: errors.New("invalid"), expectedStatusCode: 403, expectedError: ErrorMessage{}},
		{testName: "If no valid scope is provided, the request should be executed in the default scope.", proofCheck: false, testVPToken: getValidVPToken(), testGrantType: "vp_token", expectedStatusCode: 200},

		{testName: "If a valid vp_token request is received a token should be responded.", proofCheck: false, testGrantType: "vp_token", testVPToken: getValidVPToken(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN}},
		{testName: "If a valid signed vp_token request is received a token should be responded.", proofCheck: true, testGrantType: "vp_token", testVPToken: getValidSignedDidKeyVPToken(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN}},
		{testName: "If no valid vp_token is provided, the request should fail.", proofCheck: false, testGrantType: "vp_token", testScope: "tir_read", expectedStatusCode: 400, expectedError: ErrorMessageNoToken},
		// token-exchange
		{testName: "If a valid token-exchange request is received a token should be responded.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT", Scope: "tir_read", IssuedTokenType: common.TYPE_ACCESS_TOKEN}},
		{testName: "If a token-exchange request is received without resource, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testSubjectTokenType: "urn:eu:oidf:vp_token", expectedStatusCode: 400, expectedError: ErrorMessageNoResource},
		{testName: "If a token-exchange request is received with invalid subject_token_type, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "invalid_type", expectedStatusCode: 400, expectedError: ErrorMessageInvalidSubjectTokenType},
		{testName: "If a token-exchange request is received with invalid requested_token_type, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", testRequestedTokenType: "invalid_type", expectedStatusCode: 400, expectedError: ErrorMessageInvalidRequestedTokenType},
		{testName: "If a token-exchange request is received without subject_token, it should fail.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testScope: "tir_read", testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", expectedStatusCode: 400, expectedError: ErrorMessageNoToken},
		{testName: "If a token-exchange request is received without scope, the default scope should be used.", proofCheck: false, testGrantType: "urn:ietf:params:oauth:grant-type:token-exchange", testVPToken: getValidVPToken(), testResource: "my-client-id", testSubjectTokenType: "urn:eu:oidf:vp_token", expectedStatusCode: 200},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			if tc.proofCheck {
				presentationParser = &verifier.ConfigurablePresentationParser{
					PresentationOpts: []verifiable.PresentationOpt{
						verifiable.WithPresProofChecker(defaults.NewDefaultProofChecker(verifier.JWTVerfificationMethodResolver{})),
						verifiable.WithPresJSONLDDocumentLoader(verifier.NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient)))}}
			} else {
				presentationParser = &verifier.ConfigurablePresentationParser{
					PresentationOpts: []verifiable.PresentationOpt{verifiable.WithPresDisabledProofCheck(), verifiable.WithDisabledJSONLDChecks()}}
			}

			sdJwtParser = &verifier.ConfigurableSdJwtParser{
				ParserOpts: []sdv.ParseOpt{
					sdv.WithSignatureVerifier(defaults.NewDefaultProofChecker(verifier.JWTVerfificationMethodResolver{})),
					sdv.WithHolderVerificationRequired(false),
					sdv.WithIssuerSigningAlgorithms([]string{"ES256", "PS256"})}}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)
			apiVerifier = &mockVerifier{mockJWTString: tc.mockJWTString, mockExpiration: tc.mockExpiration, mockError: tc.mockError}

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

			if tc.expectedStatusCode == 400 {
				errorBody, _ := io.ReadAll(recorder.Body)
				errorMessage := ErrorMessage{}
				json.Unmarshal(errorBody, &errorMessage)
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
			presentationParser = &verifier.ConfigurablePresentationParser{
				PresentationOpts: []verifiable.PresentationOpt{verifiable.WithPresDisabledProofCheck(), verifiable.WithDisabledJSONLDChecks()}}

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
		{"If a token with invalid credentials is provided, a 400 should be returned.", true, "my-state", getNoVCVPToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 400, "", ErrorMessageUnableToDecodeToken},
		{"If a token with an invalid holder is provided, a 400 should be returned.", true, "my-state", getNoHolderVPToken(), nil, verifier.Response{FlowVersion: verifier.SAME_DEVICE}, 400, "", ErrorMessageUnableToDecodeToken},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {

			presentationParser = &verifier.ConfigurablePresentationParser{
				PresentationOpts: []verifiable.PresentationOpt{
					verifiable.WithPresProofChecker(defaults.NewDefaultProofChecker(verifier.JWTVerfificationMethodResolver{})),
					verifiable.WithPresJSONLDDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient))}}
			sdJwtParser = &verifier.ConfigurableSdJwtParser{
				ParserOpts: []sdv.ParseOpt{
					sdv.WithSignatureVerifier(defaults.NewDefaultProofChecker(verifier.JWTVerfificationMethodResolver{})),
					sdv.WithHolderVerificationRequired(false),
					sdv.WithIssuerSigningAlgorithms([]string{"ES256", "PS256"})}}

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
				json.Unmarshal(errorBody, &errorMessage)
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
			presentationParser = &verifier.ConfigurablePresentationParser{
				PresentationOpts: []verifiable.PresentationOpt{verifiable.WithPresDisabledProofCheck(), verifiable.WithDisabledJSONLDChecks()}}

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
				json.Unmarshal(errorBody, &errorMessage)
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

func getValidSignedDidKeyVPToken() string {
	return "eyJhbGciOiJFUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiZGlkOmtleTp6RG5hZXdtRXRKTVpIVVhweHo3OGFyNFFSV2JyVjdCVG1BaGlUOVlNRHAyU0ZlR1VvIn0.eyJpc3MiOiAiZGlkOmtleTp6RG5hZXdtRXRKTVpIVVhweHo3OGFyNFFSV2JyVjdCVG1BaGlUOVlNRHAyU0ZlR1VvIiwgInN1YiI6ICJkaWQ6a2V5OnpEbmFld21FdEpNWkhVWHB4ejc4YXI0UVJXYnJWN0JUbUFoaVQ5WU1EcDJTRmVHVW8iLCAidnAiOiB7CiAgICAiQGNvbnRleHQiOiBbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sCiAgICAidHlwZSI6IFsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLAogICAgInZlcmlmaWFibGVDcmVkZW50aWFsIjogWwogICAgICAgICJleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0lnT2lBaVNsZFVJaXdpYTJsa0lpQTZJQ0prYVdRNmEyVjVPbnBFYm1GbGFYTlpkV2RqYm1kM1YycEdSMUJGY21Oa1RscHBjSEpLUzBadlZURjZlbVk0VFV4a00wZENSalpEZEc4aWZRLmV5SnVZbVlpT2pFM05ERXpORGMxT1RNc0ltcDBhU0k2SW5WeWJqcDFkV2xrT21RNE0ySTNaRGd6TFdGbE1XRXROR0kxT0MxaU5ESTNMVFF4WldZMFlXWTNZVGd6T1NJc0ltbHpjeUk2SW1ScFpEcHJaWGs2ZWtSdVlXVnBjMWwxWjJOdVozZFhha1pIVUVWeVkyUk9XbWx3Y2twTFJtOVZNWHA2WmpoTlRHUXpSMEpHTmtOMGJ5SXNJblpqSWpwN0luUjVjR1VpT2xzaVZYTmxja055WldSbGJuUnBZV3dpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbXRsZVRwNlJHNWhaV2x6V1hWblkyNW5kMWRxUmtkUVJYSmpaRTVhYVhCeVNrdEdiMVV4ZW5wbU9FMU1aRE5IUWtZMlEzUnZJaXdpYVhOemRXRnVZMlZFWVhSbElqb3hOelF4TXpRM05Ua3pMamM1TmpBd01EQXdNQ3dpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVptbHljM1JPWVcxbElqb2lWR1Z6ZENJc0lteGhjM1JPWVcxbElqb2lVbVZoWkdWeUlpd2laVzFoYVd3aU9pSjBaWE4wUUhWelpYSXViM0puSW4wc0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWl3aWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkwyNXpMMk55WldSbGJuUnBZV3h6TDNZeElsMTlmUS5qbDlDeUVVM0YwUnc2bUhMaS1MLTNHRi1pWlhjLUp6OG1ONjhFcm9zWmlFaXpGZDRTRHd5WVFtU05iR2ROMXA2Q2V4SlV0Ym91M0xKRHFFckZiMGNfZyIKICAgIF0sCiAgICAiaG9sZGVyIjogImRpZDprZXk6ekRuYWV3bUV0Sk1aSFVYcHh6NzhhcjRRUldiclY3QlRtQWhpVDlZTURwMlNGZUdVbyIKICB9fQ.MEQCIDfyueLikfY19XexQ8h95jvdElQy1IUS50jaIoAWQHeNAiAB6nOqwDv5xnHUr-_fbCAkhb4WFOegbw3sKEorHAdbbQ"
}

func getNoVCVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAiaWQiOiAiZWJjNmYxYzIiLAogICJob2xkZXIiOiB7CiAgICAiaWQiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgiCiAgfSwKICAicHJvb2YiOiB7CiAgICAidHlwZSI6ICJKc29uV2ViU2lnbmF0dXJlMjAyMCIsCiAgICAiY3JlYXRvciI6ICJkaWQ6a2V5Ono2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgICAiY3JlYXRlZCI6ICIyMDIzLTAxLTA2VDA3OjUxOjM2WiIsCiAgICAidmVyaWZpY2F0aW9uTWV0aG9kIjogImRpZDprZXk6ejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoI3o2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgICAiandzIjogImV5SmlOalFpT21aaGJITmxMQ0pqY21sMElqcGJJbUkyTkNKZExDSmhiR2NpT2lKRlpFUlRRU0o5Li42eFNxb1pqYTBOd2pGMGFmOVprbnF4M0NiaDlHRU51bkJmOUM4dUwydWxHZnd1czNVRk1fWm5oUGpXdEhQbC03MkU5cDNCVDVmMnB0Wm9Za3RNS3BEQSIKICB9Cn0"
}

func getNoHolderVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAidmVyaWZpYWJsZUNyZWRlbnRpYWwiOiBbCiAgICB7CiAgICAgICJ0eXBlcyI6IFsKICAgICAgICAiUGFja2V0RGVsaXZlcnlTZXJ2aWNlIiwKICAgICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiCiAgICAgIF0sCiAgICAgICJAY29udGV4dCI6IFsKICAgICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAgICJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSIKICAgICAgXSwKICAgICAgImNyZWRlbnRpYWxzU3ViamVjdCI6IHt9LAogICAgICAiYWRkaXRpb25hbFByb3AxIjoge30KICAgIH0KICBdLAogICJpZCI6ICJlYmM2ZjFjMiIsCiAgImhvbGRlciI6IHsKICAgICJub3RhIjogImhvbGRlciIKICB9LAogICJwcm9vZiI6IHsKICAgICJ0eXBlIjogIkpzb25XZWJTaWduYXR1cmUyMDIwIiwKICAgICJjcmVhdG9yIjogImRpZDprZXk6ejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoIiwKICAgICJjcmVhdGVkIjogIjIwMjMtMDEtMDZUMDc6NTE6MzZaIiwKICAgICJ2ZXJpZmljYXRpb25NZXRob2QiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgjejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoIiwKICAgICJqd3MiOiAiZXlKaU5qUWlPbVpoYkhObExDSmpjbWwwSWpwYkltSTJOQ0pkTENKaGJHY2lPaUpGWkVSVFFTSjkuLjZ4U3FvWmphME53akYwYWY5WmtucXgzQ2JoOUdFTnVuQmY5Qzh1TDJ1bEdmd3VzM1VGTV9abmhQald0SFBsLTcyRTlwM0JUNWYycHRab1lrdE1LcERBIgogIH0KfQ"
}
