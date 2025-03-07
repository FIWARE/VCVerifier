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
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwk"
)

type mockVerifier struct {
	mockJWTString        string
	mockQR               string
	mockConnectionString string
	mockAuthRequest      string
	mockJWKS             jwk.Set
	mockOpenIDConfig     common.OpenIDProviderMetadata
	mockSameDevice       verifier.SameDeviceResponse
	mockExpiration       int64
	mockError            error
}

func (mV *mockVerifier) ReturnLoginQR(host string, protocol string, callback string, sessionId string, clientId string) (qr string, err error) {
	return mV.mockQR, mV.mockError
}
func (mV *mockVerifier) StartSiopFlow(host string, protocol string, callback string, sessionId string, clientId string) (connectionString string, err error) {
	return mV.mockConnectionString, mV.mockError
}
func (mV *mockVerifier) StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string, clientId string) (authenticationRequest string, err error) {
	return mV.mockAuthRequest, mV.mockError
}
func (mV *mockVerifier) GetToken(authorizationCode string, redirectUri string) (jwtString string, expiration int64, err error) {
	return mV.mockJWTString, mV.mockExpiration, mV.mockError
}
func (mV *mockVerifier) GetJWKS() jwk.Set {
	return mV.mockJWKS
}
func (mV *mockVerifier) AuthenticationResponse(state string, presentation *verifiable.Presentation) (sameDevice verifier.SameDeviceResponse, err error) {
	return mV.mockSameDevice, mV.mockError
}
func (mV *mockVerifier) GetOpenIDConfiguration(serviceIdentifier string) (metadata common.OpenIDProviderMetadata, err error) {
	return mV.mockOpenIDConfig, err
}

func (mV *mockVerifier) GenerateToken(clientId, subject, audience string, scope []string, presentation *verifiable.Presentation) (int64, string, error) {
	return mV.mockExpiration, mV.mockJWTString, mV.mockError
}

func TestGetToken(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName           string
		testGrantType      string
		testCode           string
		testRedirectUri    string
		testVPToken        string
		testScope          string
		mockJWTString      string
		mockExpiration     int64
		mockError          error
		expectedStatusCode int
		expectedResponse   TokenResponse
		expectedError      ErrorMessage
	}
	tests := []test{
		{testName: "If a valid authorization_code request is received a token should be responded.", testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockJWTString: "theJWT", mockExpiration: 10, mockError: nil, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT"}, expectedError: ErrorMessage{}},
		{testName: "If no grant type is provided, the request should fail.", testGrantType: "", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessagNoGrantType},
		{testName: "If an invalid grant type is provided, the request should fail.", testGrantType: "my_special_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessageUnsupportedGrantType},
		{testName: "If no auth code is provided, the request should fail.", testGrantType: "authorization_code", testCode: "", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessageNoCode},
		{testName: "If no redirect uri is provided, the request should fail.", testGrantType: "authorization_code", testCode: "my-auth-code", expectedStatusCode: 400, expectedError: ErrorMessageNoRedircetUri},
		{testName: "If the verify returns an error, a 403 should be answerd.", testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockError: errors.New("invalid"), expectedStatusCode: 403, expectedError: ErrorMessage{}},

		{testName: "If a valid vp_token request is received a token should be responded.", testGrantType: "vp_token", testVPToken: getValidVPToken(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT"}},
		{testName: "If a valid signed vp_token request is received a token should be responded.", testGrantType: "vp_token", testVPToken: getValidSignedVPToken(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT"}},
		{testName: "If no valid vp_token is provided, the request should fail.", testGrantType: "vp_token", testScope: "tir_read", expectedStatusCode: 400, expectedError: ErrorMessageNoToken},
		{testName: "If no valid scope is provided, the request should fail.", testVPToken: getValidVPToken(), testGrantType: "vp_token", expectedStatusCode: 400, expectedError: ErrorMessageNoScope},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {
			presentationParser = &verifier.ConfigurablePresentationParser{
				PresentationOpts: []verifiable.PresentationOpt{verifiable.WithPresDisabledProofCheck(), verifiable.WithDisabledJSONLDChecks()}}

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
				formArray = append(formArray, "vp_token="+tc.testVPToken)
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

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName           string
		testState          string
		testRedirectPath   string
		testRequestAddress string
		mockRedirect       string
		mockError          error
		expectedStatusCode int
		expectedLocation   string
	}

	tests := []test{
		{"If all neccessary parameters provided, a valid redirect should be returned.", "my-state", "/my-redirect", "http://host.org", "http://host.org/api/v1/authentication_response", nil, 302, "http://host.org/api/v1/authentication_response"},
		{"If no path is provided, the default redirect should be returned.", "my-state", "", "http://host.org", "http://host.org/api/v1/authentication_response", nil, 302, "http://host.org/api/v1/authentication_response"},
		{"If no state is provided, a 400 should be returned.", "", "", "http://host.org", "http://host.org/api/v1/authentication_response", nil, 400, ""},
		{"If the verifier returns an error, a 500 should be returned.", "my-state", "/", "http://host.org", "http://host.org/api/v1/authentication_response", errors.New("verifier_failure"), 500, ""},
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

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName               string
		sameDevice             bool
		testState              string
		testVPToken            string
		mockError              error
		mockSameDeviceResponse verifier.SameDeviceResponse
		expectedStatusCode     int
		expectedRedirect       string
		expectedError          ErrorMessage
	}

	tests := []test{
		{"If a same-device flow is authenticated, a valid redirect should be returned.", true, "my-state", getValidVPToken(), nil, verifier.SameDeviceResponse{RedirectTarget: "http://my-verifier.org", Code: "my-code", SessionId: "my-session-id"}, 302, "http://my-verifier.org?state=my-session-id&code=my-code", ErrorMessage{}},
		{"If a cross-device flow is authenticated, a simple ok should be returned.", false, "my-state", getValidVPToken(), nil, verifier.SameDeviceResponse{}, 200, "", ErrorMessage{}},
		{"If the same-device flow responds an error, a 400 should be returend", true, "my-state", getValidVPToken(), errors.New("verification_error"), verifier.SameDeviceResponse{}, 400, "", ErrorMessage{Summary: "verification_error"}},
		{"If no state is provided, a 400 should be returned.", true, "", getValidVPToken(), nil, verifier.SameDeviceResponse{}, 400, "", ErrorMessageNoState},
		{"If an no token is provided, a 400 should be returned.", true, "my-state", "", nil, verifier.SameDeviceResponse{}, 400, "", ErrorMessageNoToken},
		{"If a token with invalid credentials is provided, a 400 should be returned.", true, "my-state", getNoVCVPToken(), nil, verifier.SameDeviceResponse{}, 400, "", ErrorMessageUnableToDecodeToken},
		{"If a token with an invalid holder is provided, a 400 should be returned.", true, "my-state", getNoHolderVPToken(), nil, verifier.SameDeviceResponse{}, 400, "", ErrorMessageUnableToDecodeToken},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {

			presentationParser = &verifier.ConfigurablePresentationParser{
				PresentationOpts: []verifiable.PresentationOpt{
					verifiable.WithPresProofChecker(defaults.NewDefaultProofChecker(verifier.JWTVerfificationMethodResolver{})),
					verifiable.WithPresJSONLDDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient))}}

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

	logging.Configure(true, "DEBUG", true, []string{})

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

func getValidSignedVPToken() string {
	return "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDplYnNpOnpkUGoxR1BYamZFUlh4WFBFMVlUWWRKIzdqM1RwYU5kUE5UT3pPdG91T09rbmxPTFFrM0pQLXlrVGZyYVd0WTNHTUUifQ.eyJpc3MiOiJkaWQ6ZWJzaTp6ZFBqMUdQWGpmRVJYeFhQRTFZVFlkSiIsImF1ZCI6Imh0dHBzOi8vYXBpLWNvbmZvcm1hbmNlLmVic2kuZXUvY29uZm9ybWFuY2UvdjMvYXV0aC1tb2NrIiwic3ViIjoiZGlkOmVic2k6emRQajFHUFhqZkVSWHhYUEUxWVRZZEoiLCJpYXQiOjE1ODk2OTkyNjAsIm5iZiI6MTU4OTY5OTI2MCwiZXhwIjoxNTg5Njk5MjYwLCJub25jZSI6IkZna2VFcmY5MWtmbCIsImp0aSI6InVybjp1dWlkOjA3MDYwNjFhLWUyY2EtNDYxNC05ZGU3LTljMTQ1MTkzNWYwMiIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImlkIjoidXJuOnV1aWQ6MDcwNjA2MWEtZTJjYS00NjE0LTlkZTctOWMxNDUxOTM1ZjAyIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sImhvbGRlciI6ImRpZDplYnNpOnpkUGoxR1BYamZFUlh4WFBFMVlUWWRKIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJbVJwWkRwbFluTnBPbnAyU0ZkWU16VTVRVE5EZG1aS2JrTlpZVUZwUVdSbEkwWXdjalZQZVhSZmJHRm9kblo2TmsxWGJGbHpNMjFqV1U1TFdtbHBVV1JWWm5GMk9IUnphRWhPT1hjaWZRLmV5SnBjM01pT2lKa2FXUTZaV0p6YVRwNmRraFhXRE0xT1VFelEzWm1TbTVEV1dGQmFVRmtaU0lzSW5OMVlpSTZJbVJwWkRwbFluTnBPbnBrVUdveFIxQllhbVpGVWxoNFdGQkZNVmxVV1dSS0lpd2lhV0YwSWpveE5UZzVOams1TWpZd0xDSnVZbVlpT2pFMU9EazJPVGt5TmpBc0ltVjRjQ0k2TVRVNE9UWTVPVEkyTUN3aWFuUnBJam9pZFhKdU9uVjFhV1JpTmpreE5tTXhNQzA0WWpZMExUUTBNamd0T0dKbU5TMWpaR1kwT0RNNE16TXhNR01pTENKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSmRMQ0pwWkNJNkluVnlianAxZFdsa09tSTJPVEUyWXpFd0xUaGlOalF0TkRReU9DMDRZbVkxTFdOa1pqUTRNemd6TXpFd1l5SXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKV1pYSnBabWxoWW14bFFYUjBaWE4wWVhScGIyNGlMQ0pEVkZkaGJHeGxkRk5oYldWSmJsUnBiV1VpWFN3aWFYTnpkV0Z1WTJWRVlYUmxJam9pTWpBeU1DMHdOUzB4TjFRd056b3dOem8wTUZvaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJd0xUQTFMVEUzVkRBM09qQTNPalF3V2lJc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJd0xUQTFMVEUzVkRBM09qQTNPalF3V2lJc0ltVjRjR2x5WVhScGIyNUVZWFJsSWpvaU1qQXlNQzB3TlMweE4xUXdOem93TnpvME1Gb2lMQ0pwYzNOMVpXUWlPaUl5TURJd0xUQTFMVEUzVkRBM09qQTNPalF3V2lJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJbWxrSWpvaVpHbGtPbVZpYzJrNmVtUlFhakZIVUZocVprVlNXSGhZVUVVeFdWUlpaRW9pZlN3aVkzSmxaR1Z1ZEdsaGJGTmphR1Z0WVNJNmV5SnBaQ0k2SW1oMGRIQnpPaTh2WVhCcExYQnBiRzkwTG1WaWMya3VaWFV2ZEhKMWMzUmxaQzF6WTJobGJXRnpMWEpsWjJsemRISjVMM1l5TDNOamFHVnRZWE12TUhneU16QXpPV1UyTXpVMlpXRTJZamN3TTJObE5qY3laVGRqWm1Gak1HSTBNamMyTldJeE5UQm1Oak5rWmpjNFpUSmlaREU0WVdVM09EVTNPRGRtTm1FeUlpd2lkSGx3WlNJNklrWjFiR3hLYzI5dVUyTm9aVzFoVm1Gc2FXUmhkRzl5TWpBeU1TSjlmWDAuOURya3kzcGpCTXFRT3JZSzRzSVRfLXFfM0g5WVlrSG9IRHA1V0hQc055VTVsNExPSFJPajlCOHRLbVZuVnc0aGEzMlVEd0xTd2Q4YzZFbHpUSzNfLVEiXX19.fGUeTLm5mplufL1VpCNbxKGmUzBeMS-NnSkaHNf6_08pFg6iEKfJmD2Wt2eDvj4qijXwnnbLFYV4zBt3PHfpWA"
}

func getNoVCVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAiaWQiOiAiZWJjNmYxYzIiLAogICJob2xkZXIiOiB7CiAgICAiaWQiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgiCiAgfSwKICAicHJvb2YiOiB7CiAgICAidHlwZSI6ICJKc29uV2ViU2lnbmF0dXJlMjAyMCIsCiAgICAiY3JlYXRvciI6ICJkaWQ6a2V5Ono2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgICAiY3JlYXRlZCI6ICIyMDIzLTAxLTA2VDA3OjUxOjM2WiIsCiAgICAidmVyaWZpY2F0aW9uTWV0aG9kIjogImRpZDprZXk6ejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoI3o2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgICAiandzIjogImV5SmlOalFpT21aaGJITmxMQ0pqY21sMElqcGJJbUkyTkNKZExDSmhiR2NpT2lKRlpFUlRRU0o5Li42eFNxb1pqYTBOd2pGMGFmOVprbnF4M0NiaDlHRU51bkJmOUM4dUwydWxHZnd1czNVRk1fWm5oUGpXdEhQbC03MkU5cDNCVDVmMnB0Wm9Za3RNS3BEQSIKICB9Cn0"
}

func getNoHolderVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAidmVyaWZpYWJsZUNyZWRlbnRpYWwiOiBbCiAgICB7CiAgICAgICJ0eXBlcyI6IFsKICAgICAgICAiUGFja2V0RGVsaXZlcnlTZXJ2aWNlIiwKICAgICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiCiAgICAgIF0sCiAgICAgICJAY29udGV4dCI6IFsKICAgICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAgICJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSIKICAgICAgXSwKICAgICAgImNyZWRlbnRpYWxzU3ViamVjdCI6IHt9LAogICAgICAiYWRkaXRpb25hbFByb3AxIjoge30KICAgIH0KICBdLAogICJpZCI6ICJlYmM2ZjFjMiIsCiAgImhvbGRlciI6IHsKICAgICJub3RhIjogImhvbGRlciIKICB9LAogICJwcm9vZiI6IHsKICAgICJ0eXBlIjogIkpzb25XZWJTaWduYXR1cmUyMDIwIiwKICAgICJjcmVhdG9yIjogImRpZDprZXk6ejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoIiwKICAgICJjcmVhdGVkIjogIjIwMjMtMDEtMDZUMDc6NTE6MzZaIiwKICAgICJ2ZXJpZmljYXRpb25NZXRob2QiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgjejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoIiwKICAgICJqd3MiOiAiZXlKaU5qUWlPbVpoYkhObExDSmpjbWwwSWpwYkltSTJOQ0pkTENKaGJHY2lPaUpGWkVSVFFTSjkuLjZ4U3FvWmphME53akYwYWY5WmtucXgzQ2JoOUdFTnVuQmY5Qzh1TDJ1bEdmd3VzM1VGTV9abmhQald0SFBsLTcyRTlwM0JUNWYycHRab1lrdE1LcERBIgogIH0KfQ"
}
