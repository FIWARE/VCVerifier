package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"

	common "github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	logging "github.com/fiware/VCVerifier/logging"
	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
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
		{"If all mandatory parameters are present, verfication should succeed.", configModel.Verifier{Did: "did:key:verifier", TirAddress: "http:tir.de", ValidationMode: "none", KeyAlgorithm: "RS256", SupportedModes: []string{"urlEncoded"}}, nil},
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
	mockScopes map[string]map[string]configModel.ScopeEntry
	mockError  error
}

func createMockCredentials(serviceId, scope, credentialType, url, holderClaim string, holderVerfication bool) map[string]map[string]configModel.ScopeEntry {
	credential := configModel.Credential{Type: credentialType, TrustedParticipantsLists: []configModel.TrustedParticipantsList{{Type: "ebsi", Url: url}}, TrustedIssuersLists: []string{url}, HolderVerification: configModel.HolderVerification{Enabled: holderVerfication, Claim: holderClaim}}

	entry := configModel.ScopeEntry{Credentials: []configModel.Credential{credential}}

	return map[string]map[string]configModel.ScopeEntry{serviceId: {scope: entry}}
}

func (mcc mockCredentialConfig) GetScope(serviceIdentifier string) (scopes []string, err error) {
	if mcc.mockError != nil {
		return scopes, mcc.mockError
	}
	return maps.Keys(mcc.mockScopes[serviceIdentifier]), err
}

func (mcc mockCredentialConfig) GetAuthorizationPath(serviceIdentifier string) (path string) {
	if mcc.mockError != nil {
		return path
	}
	return DEFAULT_AUTHORIZATION_PATH
}
func (mcc mockCredentialConfig) GetPresentationDefinition(serviceIdentifier string, scope string) (presentationDefinition *configModel.PresentationDefinition, err error) {
	if mcc.mockError != nil {
		return presentationDefinition, mcc.mockError
	}
	return mcc.mockScopes[serviceIdentifier][scope].PresentationDefinition, mcc.mockError
}

func (mcc mockCredentialConfig) GetDcqlQuery(serviceIdentifier string, scope string) (dcql *configModel.DCQL, err error) {
	if mcc.mockError != nil {
		return dcql, mcc.mockError
	}
	return mcc.mockScopes[serviceIdentifier][scope].DCQL, mcc.mockError
}
func (mcc mockCredentialConfig) GetTrustedParticipantLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []configModel.TrustedParticipantsList, err error) {
	if mcc.mockError != nil {
		return trustedIssuersRegistryUrl, mcc.mockError
	}
	for _, credential := range mcc.mockScopes[serviceIdentifier][scope].Credentials {
		if credential.Type == credentialType {
			return credential.TrustedParticipantsLists, err
		}
	}
	return trustedIssuersRegistryUrl, err
}
func (mcc mockCredentialConfig) GetTrustedIssuersLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
	if mcc.mockError != nil {
		return trustedIssuersRegistryUrl, mcc.mockError
	}

	for _, credential := range mcc.mockScopes[serviceIdentifier][scope].Credentials {
		if credential.Type == credentialType {
			return credential.TrustedIssuersLists, err
		}
	}
	return trustedIssuersRegistryUrl, err
}

func (mcc mockCredentialConfig) GetDefaultScope(serviceIdentifier string) (string, error) {
	return "openid", nil
}

func (mcc mockCredentialConfig) RequiredCredentialTypes(serviceIdentifier string, scope string) (credentialTypes []string, err error) {
	if mcc.mockError != nil {
		return credentialTypes, mcc.mockError
	}
	var types = []string{}
	for _, credential := range mcc.mockScopes[serviceIdentifier][scope].Credentials {
		types = append(types, credential.Type)
	}
	return types, err
}

func (mcc mockCredentialConfig) GetHolderVerification(serviceIdentifier string, scope string, credentialType string) (isEnabled bool, holderClaim string, err error) {
	if mcc.mockError != nil {
		return isEnabled, holderClaim, mcc.mockError
	}

	for _, credential := range mcc.mockScopes[serviceIdentifier][scope].Credentials {
		if credential.Type == credentialType {

			return credential.HolderVerification.Enabled, credential.HolderVerification.Claim, err
		}
	}
	return isEnabled, holderClaim, err
}

func (mcc mockCredentialConfig) GetAuthorizationType(serviceIdentifier string) (authorizationType string, err error) {
	return "FRONTEND_V2", err
}

func (mcc mockCredentialConfig) GetComplianceRequired(serviceIdentifier string, scope string, credentialType string) (isRequired bool, err error) {
	if mcc.mockError != nil {
		return isRequired, mcc.mockError
	}

	for _, credential := range mcc.mockScopes[serviceIdentifier][scope].Credentials {
		if credential.Type == credentialType {
			return credential.RequireCompliance, err
		}
	}
	return isRequired, err
}

func (mcc mockCredentialConfig) GetJwtInclusion(serviceIdentifier string, scope string, credentialType string) (jwtInclusion configModel.JwtInclusion, err error) {
	if mcc.mockError != nil {
		return jwtInclusion, mcc.mockError
	}

	for _, credential := range mcc.mockScopes[serviceIdentifier][scope].Credentials {
		if credential.Type == credentialType {
			return credential.JwtInclusion, err
		}
	}
	return jwtInclusion, err
}

func (mcc mockCredentialConfig) GetFlatClaims(serviceIdentifier string, scope string) (flatClaims bool, err error) {
	if mcc.mockError != nil {
		return flatClaims, mcc.mockError
	}

	return mcc.mockScopes[serviceIdentifier][scope].FlatClaims, err
}

func (msc *mockSessionCache) Add(k string, x interface{}, d time.Duration) error {
	if msc.errorToThrow != nil {
		return msc.errorToThrow
	}
	msc.sessions[k] = x.(loginSession)
	return nil
}

func (msc *mockSessionCache) Set(k string, x interface{}, d time.Duration) {
	msc.sessions[k] = x.(loginSession)
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

func (msc *mockTokenCache) Set(k string, x interface{}, d time.Duration) {
	msc.tokens[k] = x.(tokenStore)
}

func (mtc *mockTokenCache) Get(k string) (interface{}, bool) {
	v, found := mtc.tokens[k]
	return v, found
}

func (mtc *mockTokenCache) Delete(k string) {
	delete(mtc.tokens, k)
}

type siopInitTest struct {
	testName             string
	testHost             string
	testProtocol         string
	testAddress          string
	testState            string
	testClientId         string
	testRequestObjectJwt string
	testNonce            string
	testScope            string
	testRequestProtocol  string
	requestMode          string
	credentialScopes     map[string]map[string]configModel.ScopeEntry
	mockConfigError      error
	expectedCallback     string
	expectedConnection   string
	sessionCacheError    error
	expectedError        error
}

func getInitSiopTests() []siopInitTest {

	cacheFailError := errors.New("cache_fail")

	return []siopInitTest{
		{testName: "If the login-session could not be cached, an error should be thrown.", testHost: "verifier.org", testProtocol: "https", testAddress: "https://client.org/callback", testState: "my-super-random-id", testClientId: "", requestMode: REQUEST_MODE_BY_VALUE, credentialScopes: createMockCredentials("", "", "", "", "", false), mockConfigError: nil, expectedCallback: "https://client.org/callback",
			expectedConnection: "", sessionCacheError: cacheFailError, expectedError: cacheFailError,
		},
		{testName: "If all parameters are set, a proper connection string byValue should be returned.", testHost: "verifier.org", testProtocol: "https", testAddress: "https://client.org/callback", testState: "my-super-random-id", testClientId: "", requestMode: REQUEST_MODE_BY_VALUE, credentialScopes: createMockCredentials("", "", "", "", "", false), mockConfigError: nil, expectedCallback: "https://client.org/callback",
			expectedConnection: "openid4vp://?client_id=did:key:verifier&request=eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJkaWQ6a2V5OnZlcmlmaWVyIiwiZXhwIjozMCwiaXNzIjoiZGlkOmtleTp2ZXJpZmllciIsIm5vbmNlIjoicmFuZG9tTm9uY2UiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLm9yZy9hcGkvdjEvYXV0aGVudGljYXRpb25fcmVzcG9uc2UiLCJzdGF0ZSI6Im15LXN1cGVyLXJhbmRvbS1pZCJ9", sessionCacheError: nil, expectedError: nil,
		},
		{testName: "If all parameters are set, a proper connection string byReference should be returned.", testHost: "verifier.org", testProtocol: "https", testAddress: "https://client.org/callback", testState: "my-super-random-id", testClientId: "", requestMode: REQUEST_MODE_BY_REFERENCE, credentialScopes: createMockCredentials("", "", "", "", "", false), mockConfigError: nil, expectedCallback: "https://client.org/callback",
			expectedConnection: "openid4vp://?client_id=did:key:verifier&request_uri=verifier.org/api/v1/request/my-super-random-id&request_uri_method=get", sessionCacheError: nil, expectedError: nil, testRequestObjectJwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJkaWQ6a2V5OnZlcmlmaWVyIiwiZXhwIjozMCwiaXNzIjoiZGlkOmtleTp2ZXJpZmllciIsIm5vbmNlIjoicmFuZG9tTm9uY2UiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLm9yZy9hcGkvdjEvYXV0aGVudGljYXRpb25fcmVzcG9uc2UiLCJzdGF0ZSI6Im15LXN1cGVyLXJhbmRvbS1pZCJ9",
		},
		{testName: "If all parameters, including the nonce, are set, a proper connection string byValue should be returned.", testHost: "verifier.org", testProtocol: "https", testAddress: "https://client.org/callback", testState: "my-super-random-id", testClientId: "", testNonce: "my-nonce", requestMode: REQUEST_MODE_BY_VALUE, credentialScopes: createMockCredentials("", "", "", "", "", false), mockConfigError: nil, expectedCallback: "https://client.org/callback",
			expectedConnection: "openid4vp://?client_id=did:key:verifier&request=eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJkaWQ6a2V5OnZlcmlmaWVyIiwiZXhwIjozMCwiaXNzIjoiZGlkOmtleTp2ZXJpZmllciIsIm5vbmNlIjoibXktbm9uY2UiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLm9yZy9hcGkvdjEvYXV0aGVudGljYXRpb25fcmVzcG9uc2UiLCJzdGF0ZSI6Im15LXN1cGVyLXJhbmRvbS1pZCJ9", sessionCacheError: nil, expectedError: nil,
		},
		{testName: "If all parameters are set, including the nonce, a proper connection string byReference should be returned.", testHost: "verifier.org", testProtocol: "https", testAddress: "https://client.org/callback", testState: "my-super-random-id", testClientId: "", testNonce: "my-nonce", requestMode: REQUEST_MODE_BY_REFERENCE, credentialScopes: createMockCredentials("", "", "", "", "", false), mockConfigError: nil, expectedCallback: "https://client.org/callback",
			expectedConnection: "openid4vp://?client_id=did:key:verifier&request_uri=verifier.org/api/v1/request/my-super-random-id&request_uri_method=get", sessionCacheError: nil, expectedError: nil, testRequestObjectJwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJkaWQ6a2V5OnZlcmlmaWVyIiwiZXhwIjozMCwiaXNzIjoiZGlkOmtleTp2ZXJpZmllciIsIm5vbmNlIjoibXktbm9uY2UiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLm9yZy9hcGkvdjEvYXV0aGVudGljYXRpb25fcmVzcG9uc2UiLCJzdGF0ZSI6Im15LXN1cGVyLXJhbmRvbS1pZCJ9",
		},
	}
}

func TestInitSiopFlow(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	testKey := getECDSAKey()

	tests := getInitSiopTests()
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestInitSiopFlow +++++++++++++++++ Running test: ", tc.testName)
			sessionCache := mockSessionCache{sessions: map[string]loginSession{}, errorToThrow: tc.sessionCacheError}
			nonceGenerator := mockNonceGenerator{staticValues: []string{"randomNonce"}}
			credentialsConfig := mockCredentialConfig{tc.credentialScopes, tc.mockConfigError}
			verifier := CredentialVerifier{host: tc.testHost, did: "did:key:verifier", sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, tokenSigner: mockTokenSigner{}, clock: mockClock{}, credentialsConfig: credentialsConfig, requestSigningKey: &testKey, clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier", KeyPath: "/my-signing-key.pem", KeyAlgorithm: "ES256"}}
			authReq, err := verifier.initSiopFlow(tc.testHost, tc.testProtocol, tc.testAddress, tc.testState, tc.testClientId, tc.testNonce, tc.requestMode)
			verifyInitTest(t, tc, authReq, err, sessionCache, CROSS_DEVICE_V1)
		})
	}
}

// the start siop flow method just returns the init result, therefor the test is basically the same
func TestStartSiopFlow(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	testKey := getECDSAKey()

	tests := getInitSiopTests()
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestStartSiopFlow +++++++++++++++++ Running test: ", tc.testName)
			sessionCache := mockSessionCache{sessions: map[string]loginSession{}, errorToThrow: tc.sessionCacheError}
			nonceGenerator := mockNonceGenerator{staticValues: []string{"randomNonce"}}
			credentialsConfig := mockCredentialConfig{tc.credentialScopes, tc.mockConfigError}
			verifier := CredentialVerifier{host: tc.testHost, did: "did:key:verifier", sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, tokenSigner: mockTokenSigner{}, clock: mockClock{}, requestSigningKey: &testKey, credentialsConfig: credentialsConfig, clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier", KeyPath: "/my-signing-key.pem", KeyAlgorithm: "ES256"}}
			authReq, err := verifier.StartSiopFlow(tc.testHost, tc.testProtocol, tc.testAddress, tc.testState, tc.testClientId, tc.testNonce, tc.requestMode)
			verifyInitTest(t, tc, authReq, err, sessionCache, CROSS_DEVICE_V1)
		})
	}
}

func verifyInitTest(t *testing.T, tc siopInitTest, authRequest string, err error, sessionCache mockSessionCache, flowVersion int) {
	if tc.expectedError != err {
		t.Errorf("%s - Expected %v but was %v.", tc.testName, tc.expectedError, err)
	}
	if tc.expectedError != nil {
		// if the error was successfully verfied, we can just continue
		return
	}
	// in this case the request contains a JWT. Due to the indeterminism of ECDSA signatures a plain compare wont do it here.
	if tc.requestMode == REQUEST_MODE_BY_VALUE {

		// we know that the last part should be the jwt, thus just removing the signature part(e.g. everything after the last dot) is enough
		cleanedRequest := removeSignature(authRequest)
		if cleanedRequest != tc.expectedConnection {
			t.Errorf("%s - Expected %s but was %s", tc.testName, tc.expectedConnection, cleanedRequest)
		}
	}

	if authRequest != tc.expectedConnection && tc.requestMode != REQUEST_MODE_BY_VALUE {
		t.Errorf("%s - Expected %s but was %s", tc.testName, tc.expectedConnection, authRequest)
	}
	cachedSession, found := sessionCache.sessions[tc.testState]
	if !found {
		t.Errorf("%s - A login session should have been stored.", tc.testName)
	}
	var expectedSession loginSession

	expectedNonce := tc.testNonce
	if expectedNonce == "" {
		expectedNonce = "randomNonce"
	}
	if tc.requestMode == REQUEST_MODE_BY_REFERENCE {
		expectedSession = loginSession{version: flowVersion, callback: tc.expectedCallback, nonce: expectedNonce, sessionId: tc.testState, clientId: tc.testClientId, requestObject: tc.testRequestObjectJwt}
		cachedSession.requestObject = removeSignature(cachedSession.requestObject)
	} else {
		expectedSession = loginSession{version: flowVersion, callback: tc.expectedCallback, nonce: expectedNonce, sessionId: tc.testState, clientId: tc.testClientId, requestObject: tc.testRequestObjectJwt}
	}
	if cachedSession != expectedSession {
		t.Errorf("%s - The login session was expected to be %v but was %v.", tc.testName, expectedSession, cachedSession)
	}
}

func removeSignature(jwt string) string {
	splitted := strings.Split(jwt, ".")
	splitted = splitted[:len(splitted)-1]
	return strings.Join(splitted, ".")
}

func TestStartSameDeviceFlow(t *testing.T) {

	cacheFailError := errors.New("cache_fail")
	logging.Configure(true, "DEBUG", true, []string{})

	testKey := getECDSAKey()

	tests := []siopInitTest{
		{testName: "If the request cannot be cached, an error should be responded.", testHost: "verifier.org", testProtocol: "https", testAddress: "/redirect", testState: "my-random-session-id", testClientId: "", credentialScopes: createMockCredentials("", "", "", "", "", false), mockConfigError: nil, expectedCallback: "https://verifier.org/redirect",
			requestMode: REQUEST_MODE_BY_VALUE, expectedConnection: "", sessionCacheError: cacheFailError, expectedError: cacheFailError,
		},
		{testName: "If everything is provided, a samedevice flow should be started in by_value mode.", testHost: "verifier.org", testProtocol: "https", testAddress: "/redirect", testState: "my-random-session-id", testClientId: "", credentialScopes: createMockCredentials("", "", "", "", "", false), mockConfigError: nil, expectedCallback: "https://verifier.org/redirect",
			requestMode: REQUEST_MODE_BY_VALUE, expectedConnection: "https://verifier.org/redirect?client_id=did:key:verifier&request=eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJkaWQ6a2V5OnZlcmlmaWVyIiwiZXhwIjozMCwiaXNzIjoiZGlkOmtleTp2ZXJpZmllciIsIm5vbmNlIjoicmFuZG9tTm9uY2UiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLm9yZy9hcGkvdjEvYXV0aGVudGljYXRpb25fcmVzcG9uc2UiLCJzdGF0ZSI6Im15LXJhbmRvbS1zZXNzaW9uLWlkIn0", sessionCacheError: nil, expectedError: nil,
		},
		{testName: "If everything is provided, a samedevice flow should be started in by_reference mode.", testHost: "verifier.org", testProtocol: "https", testAddress: "/redirect", testState: "my-random-session-id", testClientId: "", credentialScopes: createMockCredentials("", "", "", "", "", false), mockConfigError: nil, expectedCallback: "https://verifier.org/redirect",
			requestMode: REQUEST_MODE_BY_REFERENCE, expectedConnection: "https://verifier.org/redirect?client_id=did:key:verifier&request_uri=verifier.org/api/v1/request/my-random-session-id&request_uri_method=get", sessionCacheError: nil, expectedError: nil, testRequestObjectJwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJkaWQ6a2V5OnZlcmlmaWVyIiwiZXhwIjozMCwiaXNzIjoiZGlkOmtleTp2ZXJpZmllciIsIm5vbmNlIjoicmFuZG9tTm9uY2UiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLm9yZy9hcGkvdjEvYXV0aGVudGljYXRpb25fcmVzcG9uc2UiLCJzdGF0ZSI6Im15LXJhbmRvbS1zZXNzaW9uLWlkIn0",
		},
		{testName: "If everything is provided, a samedevice flow should be started.", testHost: "verifier.org", testProtocol: "https", testAddress: "/redirect", testState: "my-random-session-id", testClientId: "", credentialScopes: createMockCredentials("", "", "", "", "", false), mockConfigError: nil, expectedCallback: "https://verifier.org/redirect",
			requestMode: REQUEST_MODE_BY_REFERENCE, expectedConnection: "https://verifier.org/redirect?client_id=did:key:verifier&request_uri=verifier.org/api/v1/request/my-random-session-id&request_uri_method=get", sessionCacheError: nil, expectedError: nil, testRequestObjectJwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJkaWQ6a2V5OnZlcmlmaWVyIiwiZXhwIjozMCwiaXNzIjoiZGlkOmtleTp2ZXJpZmllciIsIm5vbmNlIjoicmFuZG9tTm9uY2UiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLm9yZy9hcGkvdjEvYXV0aGVudGljYXRpb25fcmVzcG9uc2UiLCJzdGF0ZSI6Im15LXJhbmRvbS1zZXNzaW9uLWlkIn0",
			testScope: "test",
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestSameDeviceFlow +++++++++++++++++ Running test: ", tc.testName)
			sessionCache := mockSessionCache{sessions: map[string]loginSession{}, errorToThrow: tc.sessionCacheError}
			nonceGenerator := mockNonceGenerator{staticValues: []string{"randomNonce"}}
			credentialsConfig := mockCredentialConfig{tc.credentialScopes, tc.mockConfigError}
			verifier := CredentialVerifier{host: tc.testHost, did: "did:key:verifier", sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, tokenSigner: mockTokenSigner{}, clock: mockClock{}, requestSigningKey: &testKey, credentialsConfig: credentialsConfig, clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier", KeyPath: "/my-signing-key.pem", KeyAlgorithm: "ES256"}}
			authReq, err := verifier.StartSameDeviceFlow(tc.testHost, tc.testProtocol, tc.testState, tc.testAddress, tc.testClientId, "", tc.requestMode, tc.testScope, tc.testRequestProtocol)
			verifyInitTest(t, tc, authReq, err, sessionCache, SAME_DEVICE)
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
	expectedResponse   Response
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
		{"If the credential is invalid, return an error.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{false}, nil, Response{}, nil, ErrorInvalidVC, nil},
		{"If one credential is invalid, return an error.", true, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true, false}, nil, Response{}, nil, ErrorInvalidVC, nil},
		{"If an authentication response is received without a session, an error should be responded.", true, "", getVP([]string{"vc"}), "holder", loginSession{}, "login-state", nil, []bool{}, nil, Response{}, nil, ErrorNoSuchSession, nil},
		{"If ssiKit throws an error, an error should be responded.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{}, ssiKitError, Response{}, nil, ssiKitError, nil},
		{"If tokenCache throws an error, an error should be responded.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true}, nil, Response{}, nil, cacheError, cacheError},
		{"If the credential is invalid, return an error.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{false}, nil, Response{}, nil, ErrorInvalidVC, nil},
		{"If one credential is invalid, return an error.", false, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true, false}, nil, Response{}, nil, ErrorInvalidVC, nil},
		{"If an authentication response is received without a session, an error should be responded.", false, "", getVP([]string{"vc"}), "holder", loginSession{}, "login-state", nil, []bool{}, nil, Response{}, nil, ErrorNoSuchSession, nil},
		{"If ssiKit throws an error, an error should be responded.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{}, ssiKitError, Response{}, nil, ssiKitError, nil},
		{"If tokenCache throws an error, an error should be responded.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true}, nil, Response{}, nil, cacheError, cacheError},
		{"If a non-existent session is requested, an error should be responded.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "non-existent-state", nil, []bool{true}, nil, Response{}, nil, ErrorNoSuchSession, nil},

		// same-device flow
		{"When a same device flow is present, a proper response should be returned.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true}, nil, Response{FlowVersion: SAME_DEVICE, RedirectTarget: "https://myhost.org/callback", Code: "authCode", SessionId: "my-session"}, nil, nil, nil},
		{"When a same device flow is present, a proper response should be returned for VPs.", true, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true, true}, nil, Response{FlowVersion: SAME_DEVICE, RedirectTarget: "https://myhost.org/callback", Code: "authCode", SessionId: "my-session"}, nil, nil, nil},

		// cross-device flow
		{"When a cross-device flow is present, a proper response should be sent to the requestors callback.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true}, nil, Response{}, getRequest("https://myhost.org/callback?code=authCode&state=my-session"), nil, nil},
		{"When a cross-device flow is present, a proper response should be sent to the requestors callback for VPs.", false, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true, true}, nil, Response{}, getRequest("https://myhost.org/callback?code=authCode&state=my-session"), nil, nil},
		{"When the requestor-callback fails, an error should be returned.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", callbackError, []bool{true}, nil, Response{}, nil, callbackError, nil},
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
			ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			testKey, _ := jwk.Import(ecdsaKey)
			jwk.AssignKeyID(testKey)
			nonceGenerator := mockNonceGenerator{staticValues: []string{"authCode"}}
			credentialsConfig := mockCredentialConfig{}
			verifier := CredentialVerifier{did: "did:key:verifier", signingKey: testKey, tokenCache: &tokenCache, sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, validationServices: []ValidationService{&mockExternalSsiKit{tc.verificationResult, tc.verificationError}}, clock: mockClock{}, credentialsConfig: credentialsConfig, clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier"}}

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

func verifySameDevice(t *testing.T, sdr Response, tokenCache mockTokenCache, tc authTest) {
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
				{
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
	// Generate a key without KID
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPath := filepath.Join(t.TempDir(), "private.pem")
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	}
	pemBytes := pem.EncodeToMemory(privBlock)
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}

	tests := []test{
		{"A verifier should be properly intantiated.", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", TirAddress: "https://tir.org", ValidationMode: "none", SessionExpiry: 30, KeyAlgorithm: "RS256", GenerateKey: true, SupportedModes: []string{"urlEncoded"}}}, nil},
		{"Without a did, no verifier should be instantiated.", configModel.Configuration{Verifier: configModel.Verifier{TirAddress: "https://tir.org", ValidationMode: "none", SessionExpiry: 30, KeyAlgorithm: "RS256", SupportedModes: []string{"urlEncoded"}}}, ErrorNoDID},
		{"Without a tir, no verifier should be instantiated.", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", SessionExpiry: 30, ValidationMode: "none", KeyAlgorithm: "RS256", SupportedModes: []string{"urlEncoded"}}}, ErrorNoTIR},
		{"Without a validationMode, no verifier should be instantiated.", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", TirAddress: "https://tir.org", ValidationMode: "blub", SessionExpiry: 30, KeyAlgorithm: "RS256", SupportedModes: []string{"urlEncoded"}}}, ErrorUnsupportedValidationMode},
		{"Without a valid key algorithm, no verifier should be instantiated.", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", TirAddress: "https://tir.org", ValidationMode: "none", SessionExpiry: 30, KeyAlgorithm: "SomethingWeird", SupportedModes: []string{"urlEncoded"}}}, ErrorInvalidKeyConfig},
		{"Without supported modes, no verifier should be instantiated.", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", TirAddress: "https://tir.org", ValidationMode: "none", SessionExpiry: 30, KeyAlgorithm: "RS256"}}, ErrorSupportedModesNotSet},
		{"KID should be added if the key does not contain it and a KID value is configured", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", TirAddress: "https://tir.org", ValidationMode: "none", SessionExpiry: 30, KeyAlgorithm: "RS256", GenerateKey: false, SupportedModes: []string{"urlEncoded"}, KeyPath: keyPath, ClientIdentification: configModel.ClientIdentification{Kid: "random-kid"}}}, nil},
		{"ClientID should be added to the key when KID value and config are missing", configModel.Configuration{Verifier: configModel.Verifier{Did: "did:key:verifier", TirAddress: "https://tir.org", ValidationMode: "none", SessionExpiry: 30, KeyAlgorithm: "RS256", GenerateKey: false, SupportedModes: []string{"urlEncoded"}, KeyPath: keyPath, ClientIdentification: configModel.ClientIdentification{Id: "client-id-value"}}}, nil},
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

			verifier = GetVerifier()
			if verifier == nil {
				t.Errorf("%s - Verifier should have been initiated, but is not available.", tc.testName)
				return
			}
			jwks := verifier.GetJWKS()
			if jwks.Len() != 1 {
				t.Errorf("%s - Unexpected JWKS length: expected 1, got %d.", tc.testName, jwks.Len())
				return
			}
			key, _ := jwks.Key(0)

			kid, existsKid := key.KeyID()
			if !existsKid || kid == "" {
				t.Errorf("%s - JWK does not contain a valid KID.", tc.testName)
				return
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
			testKey, _ := jwk.Import(tc.key)
			verifier := CredentialVerifier{signingKey: testKey}

			jwks := verifier.GetJWKS()

			if jwks.Len() != 1 {
				t.Errorf("TestGetJWKS: Exactly the current signing key should be included.")
			}
			returnedKey, _ := jwks.Key(0)
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

func (mts mockTokenSigner) Sign(t jwt.Token, options ...jwt.SignOption) ([]byte, error) {
	if mts.signingError != nil {
		return []byte{}, mts.signingError
	}
	return jwt.Sign(t, options...)
}

// get the static key
func getECDSAKey() (key jwk.Key) {

	d := new(big.Int)
	d.SetString("1234567890123456789012345678901234567890", 10) // example private scalar

	// Choose the curve
	curve := elliptic.P256()

	// Derive the public key point (X, Y)
	x, y := curve.ScalarBaseMult(d.Bytes())

	// Construct the private key
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}

	testKey, _ := jwk.Import(priv)

	return testKey
}

func TestGetToken(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	signingError := errors.New("signature_failure")

	testKey := getECDSAKey()
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
			jwtString, expiration, err := verifier.GetToken(tc.testCode, tc.testRedirectUri, false)

			if err != tc.expectedError {
				t.Errorf("%s - Expected error %v but was %v.", tc.testName, tc.expectedError, err)
				return
			}
			if tc.expectedError != nil {
				// we successfully verified that it failed.
				return
			}

			returnedToken, err := jwt.Parse([]byte(jwtString), jwt.WithVerify(false), jwt.WithValidate(false))

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

type openIdProviderMetadataTest struct {
	host              string
	testName          string
	serviceIdentifier string
	credentialScopes  map[string]map[string]configModel.ScopeEntry
	mockConfigError   error
	expectedOpenID    common.OpenIDProviderMetadata
}

func getOpenIdProviderMetadataTests() []openIdProviderMetadataTest {
	const verifierHost = "https://test.com"

	return []openIdProviderMetadataTest{
		{testName: "Test OIDC metadata with existing scopes", serviceIdentifier: "serviceId", host: verifierHost,
			credentialScopes: map[string]map[string]configModel.ScopeEntry{"serviceId": {"Scope1": {}, "Scope2": {}}}, mockConfigError: nil,
			expectedOpenID: common.OpenIDProviderMetadata{
				Issuer:          verifierHost,
				ScopesSupported: []string{"Scope1", "Scope2"}}},
		{testName: "Test OIDC metadata with non-existing scopes", serviceIdentifier: "serviceId", host: verifierHost,
			credentialScopes: map[string]map[string]configModel.ScopeEntry{"serviceId": {}}, mockConfigError: nil,
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
			assert.Equal(t, len(tc.expectedOpenID.ScopesSupported), len(actualOpenID.ScopesSupported))
			for _, scope := range tc.expectedOpenID.ScopesSupported {
				assert.True(t, slices.Contains(actualOpenID.ScopesSupported, scope))
			}
		})
	}
}

func TestRemoveDuplicate(t *testing.T) {
	type test struct {
		testName      string
		inputSlice    interface{}
		expectedSlice interface{}
	}

	tests := []test{
		{
			testName:      "String slice with duplicates",
			inputSlice:    []string{"a", "b", "a", "c", "b"},
			expectedSlice: []string{"a", "b", "c"},
		},
		{
			testName:      "String slice without duplicates",
			inputSlice:    []string{"a", "b", "c"},
			expectedSlice: []string{"a", "b", "c"},
		},
		{
			testName:      "Empty string slice",
			inputSlice:    []string{},
			expectedSlice: []string{},
		},
		{
			testName:      "Int slice with duplicates",
			inputSlice:    []int{1, 2, 1, 3, 2},
			expectedSlice: []int{1, 2, 3},
		},
		{
			testName:      "Int slice without duplicates",
			inputSlice:    []int{1, 2, 3},
			expectedSlice: []int{1, 2, 3},
		},
		{
			testName:      "Empty int slice",
			inputSlice:    []int{},
			expectedSlice: []int{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			var result interface{}
			switch s := tc.inputSlice.(type) {
			case []string:
				result = removeDuplicate(s)
			case []int:
				result = removeDuplicate(s)
			}

			if !cmp.Equal(result, tc.expectedSlice) {
				t.Errorf("Expected %v, but got %v", tc.expectedSlice, result)
			}
		})
	}
}

func TestGetValueFromPath(t *testing.T) {
	t.Log("Running TestGetValueFromPath")
	type test struct {
		testName      string
		inputMap      map[string]interface{}
		path          []string
		expectedValue interface{}
		expectedOk    bool
	}

	tests := []test{
		{
			testName: "Valid path",
			inputMap: map[string]interface{}{
				"a": map[string]interface{}{
					"b": "c",
				},
			},
			path:          []string{"a", "b"},
			expectedValue: "c",
			expectedOk:    true,
		},
		{
			testName: "Path does not exist",
			inputMap: map[string]interface{}{
				"a": map[string]interface{}{
					"b": "c",
				},
			},
			path:          []string{"a", "d"},
			expectedValue: nil,
			expectedOk:    false,
		},
		{
			testName: "Path through non-map element",
			inputMap: map[string]interface{}{
				"a": "not a map",
			},
			path:          []string{"a", "b"},
			expectedValue: nil,
			expectedOk:    false,
		},
		{
			testName: "Empty path",
			inputMap: map[string]interface{}{
				"a": "value",
			},
			path:          []string{},
			expectedValue: nil,
			expectedOk:    false,
		},
		{
			testName: "Path to a map",
			inputMap: map[string]interface{}{
				"a": map[string]interface{}{
					"b": "c",
				},
			},
			path:          []string{"a"},
			expectedValue: map[string]interface{}{"b": "c"},
			expectedOk:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			value, ok := getValueFromPath(tc.inputMap, tc.path)

			if ok != tc.expectedOk {
				t.Errorf("Expected ok to be %v, but got %v", tc.expectedOk, ok)
			}

			if !cmp.Equal(value, tc.expectedValue) {
				t.Errorf("Expected value %v, but got %v", tc.expectedValue, value)
			}
		})
	}
}

func TestSetValueAtPath(t *testing.T) {
	type test struct {
		testName    string
		inputMap    map[string]interface{}
		path        []string
		value       interface{}
		expectedMap map[string]interface{}
	}

	tests := []test{
		{
			testName: "Set value at new path",
			inputMap: map[string]interface{}{},
			path:     []string{"a", "b"},
			value:    "c",
			expectedMap: map[string]interface{}{
				"a": map[string]interface{}{
					"b": "c",
				},
			},
		},
		{
			testName: "Overwrite existing value",
			inputMap: map[string]interface{}{
				"a": map[string]interface{}{
					"b": "old_value",
				},
			},
			path:  []string{"a", "b"},
			value: "new_value",
			expectedMap: map[string]interface{}{
				"a": map[string]interface{}{
					"b": "new_value",
				},
			},
		},
		{
			testName: "Set value at path that goes through non-map element",
			inputMap: map[string]interface{}{
				"a": "not a map",
			},
			path:  []string{"a", "b"},
			value: "c",
			expectedMap: map[string]interface{}{
				"a": map[string]interface{}{
					"b": "c",
				},
			},
		},
		{
			testName: "Set value with empty path",
			inputMap: map[string]interface{}{
				"a": "value",
			},
			path:  []string{},
			value: "new_value",
			expectedMap: map[string]interface{}{
				"a": "value",
			},
		},
		{
			testName: "Set map as value",
			inputMap: map[string]interface{}{},
			path:     []string{"a"},
			value: map[string]interface{}{
				"b": "c",
			},
			expectedMap: map[string]interface{}{
				"a": map[string]interface{}{
					"b": "c",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			setValueAtPath(tc.inputMap, tc.path, tc.value)

			if !cmp.Equal(tc.inputMap, tc.expectedMap) {
				t.Errorf("Expected map %v, but got %v", tc.expectedMap, tc.inputMap)
			}
		})
	}
}

func TestExtractCredentialTypes(t *testing.T) {
	type test struct {
		testName                  string
		presentation              *verifiable.Presentation
		expectedCredentialsByType map[string][]*verifiable.Credential
		expectedCredentialTypes   []string
	}

	vc1, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		ID:    "vc1",
		Types: []string{"type1", "typeA"},
	}, verifiable.CustomFields{})
	vc2, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		ID:    "vc2",
		Types: []string{"type2", "typeB"},
	}, verifiable.CustomFields{})
	vp1, _ := verifiable.NewPresentation(verifiable.WithCredentials(vc1))
	vp2, _ := verifiable.NewPresentation(verifiable.WithCredentials(vc1, vc2))
	vp3, _ := verifiable.NewPresentation()

	tests := []test{
		{
			testName:     "Presentation with one credential",
			presentation: vp1,
			expectedCredentialsByType: map[string][]*verifiable.Credential{
				"type1": {vc1},
				"typeA": {vc1},
			},
			expectedCredentialTypes: []string{"type1", "typeA"},
		},
		{
			testName:     "Presentation with multiple credentials",
			presentation: vp2,
			expectedCredentialsByType: map[string][]*verifiable.Credential{
				"type1": {vc1},
				"typeA": {vc1},
				"type2": {vc2},
				"typeB": {vc2},
			},
			expectedCredentialTypes: []string{"type1", "typeA", "type2", "typeB"},
		},
		{
			testName:                  "Empty presentation",
			presentation:              vp3,
			expectedCredentialsByType: map[string][]*verifiable.Credential{},
			expectedCredentialTypes:   []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			credentialsByType, credentialTypes := extractCredentialTypes(tc.presentation)

			if len(credentialsByType) != len(tc.expectedCredentialsByType) {
				t.Errorf("Expected credentialsByType to have length %d, but got %d", len(tc.expectedCredentialsByType), len(credentialsByType))
			}

			for key, expectedVCs := range tc.expectedCredentialsByType {
				vcs, ok := credentialsByType[key]
				if !ok {
					t.Errorf("Expected key %s to be in credentialsByType", key)
				}
				if len(vcs) != len(expectedVCs) {
					t.Errorf("Expected %d credentials for type %s, but got %d", len(expectedVCs), key, len(vcs))
				}
				for i, vc := range vcs {
					if vc.Contents().ID != expectedVCs[i].Contents().ID {
						t.Errorf("Expected credential ID %s, but got %s", expectedVCs[i].Contents().ID, vc.Contents().ID)
					}
				}
			}

			if !cmp.Equal(credentialTypes, tc.expectedCredentialTypes) {
				t.Errorf("Expected credentialTypes %v, but got %v", tc.expectedCredentialTypes, credentialTypes)
			}
		})
	}
}
