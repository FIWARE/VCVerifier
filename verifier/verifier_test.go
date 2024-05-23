package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"

	common "github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	logging "github.com/fiware/VCVerifier/logging"
	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/exp/maps"
)

func TestVerifyConfig(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName      string
		configToTest  configModel.Verifier
		expectedError error
	}

	tests := []test{
		{"If all mandatory parameters are present, verfication should succeed.", configModel.Verifier{Did: "did:key:verifier", TirAddress: "http:tir.de", ValidationMode: "none", KeyAlgorithm: "RS256"}, nil},
		{"If no TIR is configured, the verification should fail.", configModel.Verifier{Did: "did:key:verifier", ValidationMode: "none", KeyAlgorithm: "RS256"}, ErrorNoTIR},
		{"If no DID is configured, the verification should fail.", configModel.Verifier{TirAddress: "http:tir.de", ValidationMode: "none", KeyAlgorithm: "RS256"}, ErrorNoDID},
		{"If no DID and TIR is configured, the verification should fail.", configModel.Verifier{ValidationMode: "none", KeyAlgorithm: "RS256"}, ErrorNoDID},
		{"If no validation mode is configured, verfication should fail.", configModel.Verifier{Did: "did:key:verifier", TirAddress: "http:tir.de", KeyAlgorithm: "RS256"}, ErrorUnsupportedValidationMode},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestVerifyConfig +++++++++++++++++ Running test: ", tc.testName)

			verificationResult := verifyConfig(&tc.configToTest)
			if verificationResult != tc.expectedError {
				t.Errorf("%s - Expected %v but was %v.", tc.testName, tc.expectedError, verificationResult)
			}
		})

	}

}

type mockNonceGenerator struct {
	staticValues []string
}

func (mng *mockNonceGenerator) GenerateNonce() string {
	nonce := "myMockNonce"
	if len(mng.staticValues) > 0 {
		nonce = mng.staticValues[0]
		copy(mng.staticValues[0:], mng.staticValues[1:])
		mng.staticValues[len(mng.staticValues)-1] = ""
		mng.staticValues = mng.staticValues[:len(mng.staticValues)-1]
	}
	return nonce
}

type mockSessionCache struct {
	sessions     map[string]loginSession
	errorToThrow error
}
type mockTokenCache struct {
	tokens       map[string]tokenStore
	errorToThrow error
}
type mockCredentialConfig struct {
	// ServiceId->Scope->CredentialType-> TIR/TIL URLs
	mockScopes map[string]map[string]map[string][]string
	mockError  error
}

func createMockCredentials(serviceId, scope, credentialType, url string) map[string]map[string]map[string][]string {
	return map[string]map[string]map[string][]string{serviceId: {scope: map[string][]string{credentialType: {url}}}}
}

func (mcc mockCredentialConfig) GetScope(serviceIdentifier string) (credentialTypes []string, err error) {
	if mcc.mockError != nil {
		return credentialTypes, mcc.mockError
	}
	return maps.Keys(mcc.mockScopes[serviceIdentifier]), err
}
func (mcc mockCredentialConfig) GetTrustedParticipantLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
	if mcc.mockError != nil {
		return trustedIssuersRegistryUrl, mcc.mockError
	}
	return mcc.mockScopes[serviceIdentifier][scope][credentialType], err
}
func (mcc mockCredentialConfig) GetTrustedIssuersLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
	if mcc.mockError != nil {
		return trustedIssuersRegistryUrl, mcc.mockError
	}
	return mcc.mockScopes[serviceIdentifier][scope][credentialType], err
}

func (mcc mockCredentialConfig) RequiredCredentialTypes(serviceIdentifier string, scope string) (credentialTypes []string, err error) {
	if mcc.mockError != nil {
		return credentialTypes, mcc.mockError
	}
	return maps.Keys(mcc.mockScopes[serviceIdentifier][scope]), err
}

func (msc *mockSessionCache) Add(k string, x interface{}, d time.Duration) error {
	if msc.errorToThrow != nil {
		return msc.errorToThrow
	}
	msc.sessions[k] = x.(loginSession)
	return nil
}

func (msc *mockSessionCache) Get(k string) (interface{}, bool) {
	v, found := msc.sessions[k]
	return v, found
}

func (msc *mockSessionCache) Delete(k string) {
	delete(msc.sessions, k)
}

func (mtc *mockTokenCache) Add(k string, x interface{}, d time.Duration) error {
	if mtc.errorToThrow != nil {
		return mtc.errorToThrow
	}
	mtc.tokens[k] = x.(tokenStore)
	return nil
}

func (mtc *mockTokenCache) Get(k string) (interface{}, bool) {
	v, found := mtc.tokens[k]
	return v, found
}

func (mtc *mockTokenCache) Delete(k string) {
	delete(mtc.tokens, k)
}

type siopInitTest struct {
	testName           string
	testHost           string
	testProtocol       string
	testAddress        string
	testSessionId      string
	testClientId       string
	credentialScopes   map[string]map[string]map[string][]string
	mockConfigError    error
	expectedCallback   string
	expectedConnection string
	sessionCacheError  error
	expectedError      error
}

func TestInitSiopFlow(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	tests := getInitSiopTests()
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestInitSiopFlow +++++++++++++++++ Running test: ", tc.testName)
			sessionCache := mockSessionCache{sessions: map[string]loginSession{}, errorToThrow: tc.sessionCacheError}
			nonceGenerator := mockNonceGenerator{staticValues: []string{"randomState", "randomNonce"}}
			credentialsConfig := mockCredentialConfig{tc.credentialScopes, tc.mockConfigError}
			verifier := CredentialVerifier{did: "did:key:verifier", sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, credentialsConfig: credentialsConfig}
			authReq, err := verifier.initSiopFlow(tc.testHost, tc.testProtocol, tc.testAddress, tc.testSessionId, tc.testClientId)
			verifyInitTest(t, tc, authReq, err, sessionCache, false)
		})
	}
}

// the start siop flow method just returns the init result, therefor the test is basically the same
func TestStartSiopFlow(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	tests := getInitSiopTests()
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestStartSiopFlow +++++++++++++++++ Running test: ", tc.testName)
			sessionCache := mockSessionCache{sessions: map[string]loginSession{}, errorToThrow: tc.sessionCacheError}
			nonceGenerator := mockNonceGenerator{staticValues: []string{"randomState", "randomNonce"}}
			credentialsConfig := mockCredentialConfig{tc.credentialScopes, tc.mockConfigError}
			verifier := CredentialVerifier{did: "did:key:verifier", sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, credentialsConfig: credentialsConfig}
			authReq, err := verifier.StartSiopFlow(tc.testHost, tc.testProtocol, tc.testAddress, tc.testSessionId, tc.testClientId)
			verifyInitTest(t, tc, authReq, err, sessionCache, false)
		})
	}
}

func verifyInitTest(t *testing.T, tc siopInitTest, authRequest string, err error, sessionCache mockSessionCache, sameDevice bool) {
	if tc.expectedError != err {
		t.Errorf("%s - Expected %v but was %v.", tc.testName, tc.expectedError, err)
	}
	if tc.expectedError != nil {
		// if the error was successfully verfied, we can just continue
		return
	}
	if authRequest != tc.expectedConnection {
		t.Errorf("%s - Expected %s but was %s.", tc.testName, tc.expectedConnection, authRequest)
	}
	cachedSession, found := sessionCache.sessions["randomState"]
	if !found {
		t.Errorf("%s - A login session should have been stored.", tc.testName)
	}
	expectedSession := loginSession{sameDevice, tc.expectedCallback, tc.testSessionId, tc.testClientId}
	if cachedSession != expectedSession {
		t.Errorf("%s - The login session was expected to be %v but was %v.", tc.testName, expectedSession, cachedSession)
	}
}

func getInitSiopTests() []siopInitTest {

	cacheFailError := errors.New("cache_fail")

	return []siopInitTest{
		{testName: "If all parameters are set, a proper connection string should be returned.", testHost: "verifier.org", testProtocol: "https", testAddress: "https://client.org/callback", testSessionId: "my-super-random-id", testClientId: "", credentialScopes: createMockCredentials("", "", "", ""), mockConfigError: nil, expectedCallback: "https://client.org/callback",
			expectedConnection: "openid://?response_type=vp_token&response_mode=direct_post&client_id=did:key:verifier&redirect_uri=https://verifier.org/api/v1/authentication_response&state=randomState&nonce=randomNonce", sessionCacheError: nil, expectedError: nil,
		},
		{testName: "The scope should be included if configured.", testHost: "verifier.org", testProtocol: "https", testAddress: "https://client.org/callback", testSessionId: "my-super-random-id", testClientId: "myService", credentialScopes: createMockCredentials("myService", "someScope", "org.fiware.MySpecialCredential", "some.url"), mockConfigError: nil, expectedCallback: "https://client.org/callback",
			expectedConnection: "openid://?response_type=vp_token&response_mode=direct_post&client_id=did:key:verifier&redirect_uri=https://verifier.org/api/v1/authentication_response&state=randomState&nonce=randomNonce&scope=someScope", sessionCacheError: nil, expectedError: nil,
		},
		{testName: "If the login-session could not be cached, an error should be thrown.", testHost: "verifier.org", testProtocol: "https", testAddress: "https://client.org/callback", testSessionId: "my-super-random-id", testClientId: "", credentialScopes: createMockCredentials("", "", "", ""), mockConfigError: nil, expectedCallback: "https://client.org/callback",
			expectedConnection: "", sessionCacheError: cacheFailError, expectedError: cacheFailError,
		},
		{testName: "If config service throws an error, no scope should be included.", testHost: "verifier.org", testProtocol: "https", testAddress: "https://client.org/callback", testSessionId: "my-super-random-id", testClientId: "myService", credentialScopes: createMockCredentials("", "", "", ""), mockConfigError: errors.New("config_error"), expectedCallback: "https://client.org/callback",
			expectedConnection: "openid://?response_type=vp_token&response_mode=direct_post&client_id=did:key:verifier&redirect_uri=https://verifier.org/api/v1/authentication_response&state=randomState&nonce=randomNonce", sessionCacheError: nil, expectedError: nil,
		},
	}
}

func TestStartSameDeviceFlow(t *testing.T) {

	cacheFailError := errors.New("cache_fail")
	logging.Configure(true, "DEBUG", true, []string{})

	tests := []siopInitTest{
		{testName: "If everything is provided, a samedevice flow should be started.", testHost: "myhost.org", testProtocol: "https", testAddress: "/redirect", testSessionId: "my-random-session-id", testClientId: "", credentialScopes: createMockCredentials("", "", "", ""), mockConfigError: nil, expectedCallback: "https://myhost.org/redirect",
			expectedConnection: "https://myhost.org/redirect?response_type=vp_token&response_mode=direct_post&client_id=did:key:verifier&redirect_uri=https://myhost.org/api/v1/authentication_response&state=randomState&nonce=randomNonce", sessionCacheError: nil, expectedError: nil,
		},
		{testName: "The scope should be included if configured.", testHost: "myhost.org", testProtocol: "https", testAddress: "/redirect", testSessionId: "my-random-session-id", testClientId: "myService", credentialScopes: createMockCredentials("myService", "someScope", "org.fiware.MySpecialCredential", "some.url"), mockConfigError: nil, expectedCallback: "https://myhost.org/redirect",
			expectedConnection: "https://myhost.org/redirect?response_type=vp_token&response_mode=direct_post&client_id=did:key:verifier&redirect_uri=https://myhost.org/api/v1/authentication_response&state=randomState&nonce=randomNonce&scope=someScope", sessionCacheError: nil, expectedError: nil,
		},
		{testName: "If the request cannot be cached, an error should be responded.", testHost: "myhost.org", testProtocol: "https", testAddress: "/redirect", testSessionId: "my-random-session-id", testClientId: "", credentialScopes: createMockCredentials("", "", "", ""), mockConfigError: nil, expectedCallback: "https://myhost.org/redirect",
			expectedConnection: "", sessionCacheError: cacheFailError, expectedError: cacheFailError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestSameDeviceFlow +++++++++++++++++ Running test: ", tc.testName)
			sessionCache := mockSessionCache{sessions: map[string]loginSession{}, errorToThrow: tc.sessionCacheError}
			nonceGenerator := mockNonceGenerator{staticValues: []string{"randomState", "randomNonce"}}
			credentialsConfig := mockCredentialConfig{tc.credentialScopes, tc.mockConfigError}
			verifier := CredentialVerifier{did: "did:key:verifier", sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, credentialsConfig: credentialsConfig}
			authReq, err := verifier.StartSameDeviceFlow(tc.testHost, tc.testProtocol, tc.testSessionId, tc.testAddress, tc.testClientId)
			verifyInitTest(t, tc, authReq, err, sessionCache, true)
		})
	}

}

type mockExternalSsiKit struct {
	verificationResults []bool
	verificationError   error
}

func (msk *mockExternalSsiKit) ValidateVC(verifiableCredential *verifiable.Credential, verificationContext ValidationContext) (result bool, err error) {
	if msk.verificationError != nil {
		return result, msk.verificationError
	}
	result = msk.verificationResults[0]
	copy(msk.verificationResults[0:], msk.verificationResults[1:])
	msk.verificationResults[len(msk.verificationResults)-1] = false
	msk.verificationResults = msk.verificationResults[:len(msk.verificationResults)-1]
	return
}

type mockHttpClient struct {
	callbackError error
	lastRequest   *url.URL
}

var lastRequest *url.URL

func (mhc mockHttpClient) Do(req *http.Request) (r *http.Response, err error) {
	if mhc.callbackError != nil {
		return r, mhc.callbackError
	}

	lastRequest = req.URL
	return
}

func (mhc mockHttpClient) PostForm(url string, data url.Values) (r *http.Response, err error) {
	// not used
	return
}

type authTest struct {
	testName           string
	sameDevice         bool
	testState          string
	testVP             verifiable.Presentation
	testHolder         string
	testSession        loginSession
	requestedState     string
	callbackError      error
	verificationResult []bool
	verificationError  error
	expectedResponse   SameDeviceResponse
	expectedCallback   *url.URL
	expectedError      error
	tokenCacheError    error
}

func TestAuthenticationResponse(t *testing.T) {
	logging.Configure(true, "DEBUG", true, []string{})

	ssiKitError := errors.New("ssikit_failure")
	cacheError := errors.New("cache_failure")
	callbackError := errors.New("callback_failure")

	tests := []authTest{
		// general behaviour
		{"If the credential is invalid, return an error.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{true, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{false}, nil, SameDeviceResponse{}, nil, ErrorInvalidVC, nil},
		{"If one credential is invalid, return an error.", true, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{true, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{true, false}, nil, SameDeviceResponse{}, nil, ErrorInvalidVC, nil},
		{"If an authentication response is received without a session, an error should be responded.", true, "", getVP([]string{"vc"}), "holder", loginSession{}, "login-state", nil, []bool{}, nil, SameDeviceResponse{}, nil, ErrorNoSuchSession, nil},
		{"If ssiKit throws an error, an error should be responded.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{true, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{}, ssiKitError, SameDeviceResponse{}, nil, ssiKitError, nil},
		{"If tokenCache throws an error, an error should be responded.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{true, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{true}, nil, SameDeviceResponse{}, nil, cacheError, cacheError},
		{"If the credential is invalid, return an error.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{false, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{false}, nil, SameDeviceResponse{}, nil, ErrorInvalidVC, nil},
		{"If one credential is invalid, return an error.", false, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{false, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{true, false}, nil, SameDeviceResponse{}, nil, ErrorInvalidVC, nil},
		{"If an authentication response is received without a session, an error should be responded.", false, "", getVP([]string{"vc"}), "holder", loginSession{}, "login-state", nil, []bool{}, nil, SameDeviceResponse{}, nil, ErrorNoSuchSession, nil},
		{"If ssiKit throws an error, an error should be responded.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{false, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{}, ssiKitError, SameDeviceResponse{}, nil, ssiKitError, nil},
		{"If tokenCache throws an error, an error should be responded.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{false, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{true}, nil, SameDeviceResponse{}, nil, cacheError, cacheError},
		{"If a non-existent session is requested, an error should be responded.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{false, "https://myhost.org/callback", "my-session", "clientId"}, "non-existent-state", nil, []bool{true}, nil, SameDeviceResponse{}, nil, ErrorNoSuchSession, nil},

		// same-device flow
		{"When a same device flow is present, a proper response should be returned.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{true, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{true}, nil, SameDeviceResponse{"https://myhost.org/callback", "authCode", "my-session"}, nil, nil, nil},
		{"When a same device flow is present, a proper response should be returned for VPs.", true, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{true, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{true, true}, nil, SameDeviceResponse{"https://myhost.org/callback", "authCode", "my-session"}, nil, nil, nil},

		// cross-device flow
		{"When a cross-device flow is present, a proper response should be sent to the requestors callback.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{false, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{true}, nil, SameDeviceResponse{}, getRequest("https://myhost.org/callback?code=authCode&state=my-session"), nil, nil},
		{"When a cross-device flow is present, a proper response should be sent to the requestors callback for VPs.", false, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{false, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", nil, []bool{true, true}, nil, SameDeviceResponse{}, getRequest("https://myhost.org/callback?code=authCode&state=my-session"), nil, nil},
		{"When the requestor-callback fails, an error should be returned.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{false, "https://myhost.org/callback", "my-session", "clientId"}, "login-state", callbackError, []bool{true}, nil, SameDeviceResponse{}, nil, callbackError, nil},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestAuthenticationResponse +++++++++++++++++ Running test: ", tc.testName)
			sessionCache := mockSessionCache{sessions: map[string]loginSession{}}

			// initialize siop session
			if tc.testSession != (loginSession{}) {
				sessionCache.sessions[tc.testState] = tc.testSession
			}

			tokenCache := mockTokenCache{tokens: map[string]tokenStore{}, errorToThrow: tc.tokenCacheError}

			httpClient = mockHttpClient{tc.callbackError, nil}
			ecdsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			testKey, _ := jwk.New(ecdsKey)
			jwk.AssignKeyID(testKey)
			nonceGenerator := mockNonceGenerator{staticValues: []string{"authCode"}}
			credentialsConfig := mockCredentialConfig{}
			verifier := CredentialVerifier{did: "did:key:verifier", signingKey: testKey, tokenCache: &tokenCache, sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, validationServices: []ValidationService{&mockExternalSsiKit{tc.verificationResult, tc.verificationError}}, clock: mockClock{}, credentialsConfig: credentialsConfig}

			sameDeviceResponse, err := verifier.AuthenticationResponse(tc.requestedState, &tc.testVP)
			if err != tc.expectedError {
				t.Errorf("%s - Expected error %v but was %v.", tc.testName, tc.expectedError, err)
			}
			if tc.expectedError != nil {
				return
			}

			if tc.sameDevice {
				verifySameDevice(t, sameDeviceResponse, tokenCache, tc)
				return
			}

			if *tc.expectedCallback != *lastRequest {
				t.Errorf("%s - Expected callback %s but was %s.", tc.testName, tc.expectedCallback, lastRequest)
			}
		})

	}
}

func verifySameDevice(t *testing.T, sdr SameDeviceResponse, tokenCache mockTokenCache, tc authTest) {
	if sdr != tc.expectedResponse {
		t.Errorf("%s - Expected response %v but was %v.", tc.testName, tc.expectedResponse, sdr)
	}
	_, found := tokenCache.tokens[sdr.Code]
	if !found {
		t.Errorf("%s - No token was cached.", tc.testName)
	}
}

func getVP(ids []string) verifiable.Presentation {
	credentials := []*verifiable.Credential{}
	for _, id := range ids {
		credentials = append(credentials, getVC(id))
	}
	vp, _ := verifiable.NewPresentation(verifiable.WithCredentials(credentials...))
	return *vp
}

func getVC(id string) *verifiable.Credential {

	timeWrapper, _ := utiltime.ParseTimeWrapper("2022-11-23T15:23:13Z")
	vc, _ := verifiable.CreateCredential(
		verifiable.CredentialContents{
			Context: []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://happypets.fiware.io/2022/credentials/employee/v1",
			},
			ID: "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
			Types: []string{
				"VerifiableCredential",
				"CustomerCredential",
			},
			Issuer:  &verifiable.Issuer{ID: "did:key:verifier"},
			Issued:  timeWrapper,
			Expired: timeWrapper,
			Subject: []verifiable.Subject{
				verifiable.Subject{
					ID: id,
					CustomFields: map[string]interface{}{
						"type":   "gx:NaturalParticipent",
						"target": "did:ebsi:packetdelivery",
					},
				},
			},
		},
		verifiable.CustomFields{},
	)

	return vc
}

func getRequest(request string) *url.URL {
	url, _ := url.Parse(request)
	return url
}

func TestInitVerifier(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName      string
		testConfig    configModel.Configuration
		expectedError error
	}

	tests := []test{
		{"A verifier should be properly intantiated.", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", TirAddress: "https://tir.org", ValidationMode: "none", SessionExpiry: 30, KeyAlgorithm: "RS256"}}, nil},
		{"Without a did, no verifier should be instantiated.", configModel.Configuration{Verifier: configModel.Verifier{TirAddress: "https://tir.org", ValidationMode: "none", SessionExpiry: 30, KeyAlgorithm: "RS256"}}, ErrorNoDID},
		{"Without a tir, no verifier should be instantiated.", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", SessionExpiry: 30, ValidationMode: "none", KeyAlgorithm: "RS256"}}, ErrorNoTIR},
		{"Without a validationMode, no verifier should be instantiated.", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", TirAddress: "https://tir.org", ValidationMode: "blub", SessionExpiry: 30, KeyAlgorithm: "RS256"}}, ErrorUnsupportedValidationMode},
		{"Without a valid key algorithm, no verifier should be instantiated.", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", TirAddress: "https://tir.org", ValidationMode: "none", SessionExpiry: 30, KeyAlgorithm: "SomethingWeird"}}, ErrorUnsupportedKeyAlgorithm},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			verifier = nil
			logging.Log().Info("TestInitVerifier +++++++++++++++++ Running test: ", tc.testName)

			err := InitVerifier(&tc.testConfig)
			if tc.expectedError != err {
				t.Errorf("%s - Expected error %v but was %v.", tc.testName, tc.expectedError, err)
			}
			if tc.expectedError != nil && GetVerifier() != nil {
				t.Errorf("%s - When an error happens, no verifier should be created.", tc.testName)
				return
			}
			if tc.expectedError != nil {
				return
			}

			if GetVerifier() == nil {
				t.Errorf("%s - Verifier should have been initiated, but is not available.", tc.testName)
			}
		})
	}
}

func TestGetJWKS(t *testing.T) {
	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName string
		key      interface{}
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []test{
		{"The rsa key should have been successfully returned", rsaKey},
		{"The ec key should have been successfully returned", ecdsaKey},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			testKey, _ := jwk.New(tc.key)
			verifier := CredentialVerifier{signingKey: testKey}

			jwks := verifier.GetJWKS()

			if jwks.Len() != 1 {
				t.Errorf("TestGetJWKS: Exactly the current signing key should be included.")
			}
			returnedKey, _ := jwks.Get(0)
			expectedKey, _ := testKey.PublicKey()
			// we compare the json-output to avoid address comparison instead of by-value.
			if logging.PrettyPrintObject(expectedKey) != logging.PrettyPrintObject(returnedKey) {
				t.Errorf("TestGetJWKS: Exactly the public key should be returned. Expected %v but was %v.", logging.PrettyPrintObject(expectedKey), logging.PrettyPrintObject(returnedKey))
			}
		})
	}
}

type mockClock struct{}

func (mockClock) Now() time.Time {
	return time.Unix(0, 0)
}

type mockTokenSigner struct {
	signingError error
}

func (mts mockTokenSigner) Sign(t jwt.Token, alg jwa.SignatureAlgorithm, key interface{}, options ...jwt.SignOption) ([]byte, error) {
	if mts.signingError != nil {
		return []byte{}, mts.signingError
	}
	return jwt.Sign(t, alg, key, options...)
}

func TestGetToken(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	signingError := errors.New("signature_failure")

	ecdsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testKey, _ := jwk.New(ecdsKey)
	publicKey, _ := testKey.PublicKey()

	type test struct {
		testName           string
		testCode           string
		testRedirectUri    string
		tokenSession       map[string]tokenStore
		signingKey         jwk.Key
		signingError       error
		expectedJWT        jwt.Token
		expectedExpiration int64
		expectedError      error
	}

	tests := []test{
		{"If a valid code is provided, the token should be returned.", "my-auth-code", "https://myhost.org/redirect", map[string]tokenStore{"my-auth-code": {token: getToken(), redirect_uri: "https://myhost.org/redirect"}}, testKey, nil, getToken(), 1000, nil},
		{"If the no such code exists, an error should be returned.", "another-auth-code", "https://myhost.org/redirect", map[string]tokenStore{"my-auth-code": {token: getToken(), redirect_uri: "https://myhost.org/redirect"}}, testKey, nil, nil, 0, ErrorNoSuchCode},
		{"If the redirect uri does not match, an error should be returned.", "my-auth-code", "https://my-other-host.org/redirect", map[string]tokenStore{"my-auth-code": {token: getToken(), redirect_uri: "https://myhost.org/redirect"}}, testKey, nil, nil, 0, ErrorRedirectUriMismatch},
		{"If the token cannot be signed, an error should be returned.", "my-auth-code", "https://myhost.org/redirect", map[string]tokenStore{"my-auth-code": {token: getToken(), redirect_uri: "https://myhost.org/redirect"}}, testKey, signingError, nil, 0, signingError},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestGetToken +++++++++++++++++ Running test: ", tc.testName)

			tokenCache := mockTokenCache{tokens: tc.tokenSession}
			verifier := CredentialVerifier{tokenCache: &tokenCache, signingKey: testKey, clock: mockClock{}, tokenSigner: mockTokenSigner{tc.signingError}, signingAlgorithm: "ES256"}
			jwtString, expiration, err := verifier.GetToken(tc.testCode, tc.testRedirectUri)

			if err != tc.expectedError {
				t.Errorf("%s - Expected error %v but was %v.", tc.testName, tc.expectedError, err)
				return
			}
			if tc.expectedError != nil {
				// we successfully verified that it failed.
				return
			}

			returnedToken, err := jwt.Parse([]byte(jwtString), jwt.WithVerify(jwa.ES256, publicKey))

			if err != nil {
				t.Errorf("%s - No valid token signature. Err: %v", tc.testName, err)
				return
			}
			if logging.PrettyPrintObject(returnedToken) != logging.PrettyPrintObject(tc.expectedJWT) {
				t.Errorf("%s - Expected jwt %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedJWT), logging.PrettyPrintObject(returnedToken))
				return
			}
			if expiration != tc.expectedExpiration {
				t.Errorf("%s - Expected expiration %v but was %v.", tc.testName, tc.expectedExpiration, expiration)
				return
			}
		})
	}
}

func getToken() jwt.Token {
	token, _ := jwt.NewBuilder().Expiration(time.Unix(1000, 0)).Build()
	return token
}

type badRandom struct {
}

func (br badRandom) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 1
	}
	return len(p), nil
}

/**
func TestCredentialVerifier_GenerateToken(t *testing.T) {

	ecdsKey, _ := ecdsa.GenerateKey(elliptic.P256(), badRandom{})
	testKey, _ := jwk.New(ecdsKey)
	jwk.AssignKeyID(testKey)

	type fields struct {
		signingError       error
		verificationResult []bool
		verificationError  error
		credentialConfig   mockCredentialConfig
	}
	type args struct {
		clientId              string
		subject               string
		audience              string
		scopes                []string
		verifiableCredentials []map[string]interface{}
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		expirationTime int64
		generatedToken string
		wantErr        bool
	}{
		{
			"HappyPath",
			fields{nil, []bool{true}, nil, mockCredentialConfig{mockScopes: createMockCredentials("serviceId", "someScope", "VerifiableCredential", "some.url")}},
			args{"serviceId", "someSubject", "someAudience", []string{"someScope"}, []map[string]interface{}{getVC("someId")}},
			1800,
			"eyJhbGciOiJFUzI1NiIsImtpZCI6Ik5ycWczLU1fWHd0eC0xdGJ0YzFKN1h1bDJEeWVDMGJVU3k5dV81TlNHNmciLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsic29tZUF1ZGllbmNlIl0sImNsaWVudF9pZCI6IiIsImV4cCI6MTgwMCwiaXNzIjoiIiwia2lkIjoiTnJxZzMtTV9Yd3R4LTF0YnRjMUo3WHVsMkR5ZUMwYlVTeTl1XzVOU0c2ZyIsInN1YiI6InNvbWVTdWJqZWN0IiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL2hhcHB5cGV0cy5maXdhcmUuaW8vMjAyMi9jcmVkZW50aWFscy9lbXBsb3llZS92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6InNvbWVJZCIsInRhcmdldCI6ImRpZDplYnNpOnBhY2tldGRlbGl2ZXJ5IiwidHlwZSI6Imd4Ok5hdHVyYWxQYXJ0aWNpcGVudCJ9LCJleHBpcmF0aW9uRGF0ZSI6IjIwMzItMTEtMjNUMTU6MjM6MTNaIiwiaWQiOiJodHRwczovL2hhcHB5cGV0cy5maXdhcmUuaW8vY3JlZGVudGlhbC8yNTE1OTM4OS04ZGQxN2I3OTZhYzAiLCJpc3N1YW5jZURhdGUiOiIyMDIyLTExLTIzVDE1OjIzOjEzWiIsImlzc3VlciI6ImRpZDprZXk6dmVyaWZpZXIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiQ3VzdG9tZXJDcmVkZW50aWFsIl0sInZhbGlkRnJvbSI6IjIwMjItMTEtMjNUMTU6MjM6MTNaIn19.xR-1UMvuI0-Pbox5ddlTjgMu77Ruj7Zko_Fxkt4TJZuEMFw8Y_ZljFj6XIXolBrC1I4JAUBvPPuvvm200M6N1g",
			false,
		},
		{
			"MissingVCForRequestedScope",
			fields{nil, []bool{true}, nil, mockCredentialConfig{mockScopes: createMockCredentials("serviceId", "someScope", "SomeOtherCredentialType", "some.url")}},
			args{"serviceId", "someSubject", "someAudience", []string{"someScope"}, []map[string]interface{}{getVC("someId")}},
			0,
			"",
			true,
		},
		{
			"Service unknown",
			fields{nil, []bool{true}, nil, mockCredentialConfig{mockError: errors.New("test error")}},
			args{"someOtherServiceId", "someSubject", "someAudience", []string{"someScope"}, []map[string]interface{}{getVC("someId")}},
			0,
			"",
			true,
		},
		{
			"Verification fails",
			fields{nil, []bool{false}, errors.New("Fail Verification"), mockCredentialConfig{mockScopes: createMockCredentials("serviceId", "someScope", "VerifiableCredential", "some.url")}},
			args{"serviceId", "someSubject", "someAudience", []string{"someScope"}, []map[string]interface{}{getVC("someId")}},
			0,
			"",
			true,
		},
		{
			"JWT signing fails",
			fields{errors.New("Fail signing"), []bool{true}, nil, mockCredentialConfig{mockScopes: createMockCredentials("serviceId", "someScope", "VerifiableCredential", "some.url")}},
			args{"serviceId", "someSubject", "someAudience", []string{"someScope"}, []map[string]interface{}{getVC("someId")}},
			0,
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &CredentialVerifier{
				clock:                mockClock{},
				tokenSigner:          mockTokenSigner{tt.fields.signingError},
				credentialsConfig:    tt.fields.credentialConfig,
				signingKey:           testKey,
				verificationServices: []VerificationService{&mockExternalSsiKit{tt.fields.verificationResult, tt.fields.verificationError}},
			}
			got, got1, err := v.GenerateToken(tt.args.clientId, tt.args.subject, tt.args.audience, tt.args.scopes, tt.args.verifiableCredentials)
			if (err != nil) != tt.wantErr {
				t.Errorf("CredentialVerifier.GenerateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expirationTime {
				t.Errorf("CredentialVerifier.GenerateToken() got = %v, want %v", got, tt.expirationTime)
			}
			if !tokenEquals(got1, tt.generatedToken) {
				t.Errorf("CredentialVerifier.GenerateToken() got1 = %v, want %v", base64.StdEncoding.EncodeToString([]byte(got1)), tt.generatedToken)
			}
		})
	}
}
*/

// compare the payload of two JWTs while ignoring the kid field
func tokenEquals(receivedToken, expectedToken string) bool {
	if receivedToken == "" && expectedToken == "" {
		return true
	}
	parsedReceivedToken, err := jwt.ParseString(receivedToken)
	if err != nil {
		return false
	}
	receivedTokenMap, err := parsedReceivedToken.AsMap(context.TODO())
	if err != nil {
		return false
	}
	receivedTokenMap["kid"] = ""
	parsedExpectedToken, err := jwt.ParseString(expectedToken)
	if err != nil {
		return false
	}
	expectedTokenMap, err := parsedExpectedToken.AsMap(context.TODO())
	if err != nil {
		return false
	}
	expectedTokenMap["kid"] = ""
	return cmp.Equal(receivedTokenMap, expectedTokenMap)
}

type openIdProviderMetadataTest struct {
	host              string
	testName          string
	serviceIdentifier string
	credentialScopes  map[string]map[string]map[string][]string
	mockConfigError   error
	expectedOpenID    common.OpenIDProviderMetadata
}

func getOpenIdProviderMetadataTests() []openIdProviderMetadataTest {
	const verifierHost = "https://test.com"

	return []openIdProviderMetadataTest{
		{testName: "Test OIDC metadata with existing scopes", serviceIdentifier: "serviceId", host: verifierHost,
			credentialScopes: map[string]map[string]map[string][]string{"serviceId": {"Scope1": {}, "Scope2": {}}}, mockConfigError: nil,
			expectedOpenID: common.OpenIDProviderMetadata{
				Issuer:          verifierHost,
				ScopesSupported: []string{"Scope1", "Scope2"}}},
		{testName: "Test OIDC metadata with non-existing scopes", serviceIdentifier: "serviceId", host: verifierHost,
			credentialScopes: map[string]map[string]map[string][]string{"serviceId": {}}, mockConfigError: nil,
			expectedOpenID: common.OpenIDProviderMetadata{
				Issuer:          verifierHost,
				ScopesSupported: []string{}}},
	}
}

func TestGetOpenIDConfiguration(t *testing.T) {
	tests := getOpenIdProviderMetadataTests()
	for _, tc := range tests {
		common.ResetGlobalCache()
		t.Run(tc.testName, func(t *testing.T) {
			credentialsConfig := mockCredentialConfig{tc.credentialScopes, tc.mockConfigError}
			verifier := CredentialVerifier{credentialsConfig: credentialsConfig, host: tc.host}
			actualOpenID, _ := verifier.GetOpenIDConfiguration(tc.serviceIdentifier)

			assert.Equal(t, tc.expectedOpenID.Issuer, actualOpenID.Issuer)
			assert.Equal(t, tc.expectedOpenID.ScopesSupported, actualOpenID.ScopesSupported)
		})
	}
}
