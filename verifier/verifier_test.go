package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
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

	"encoding/json"

	common "github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
	logging "github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/exp/maps"
)

var LOGGING_CONFIG = logging.LoggingConfig{
	Level:         "DEBUG",
	JsonLogging:   true,
	LogRequests:   true,
	PathsToSkip:   []string{},
	DisableCaller: false,
}

func TestVerifyConfig(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

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
	credential := configModel.Credential{
		Type:                     credentialType,
		TrustedParticipantsLists: []configModel.TrustedParticipantsList{{Type: "ebsi", Url: url}},
		TrustedIssuersLists:      configModel.TrustedIssuersLists{{Type: "ebsi", Url: url}},
		HolderVerification:       configModel.HolderVerification{Enabled: holderVerfication, Claim: holderClaim},
	}

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
func (mcc mockCredentialConfig) GetTrustedIssuersLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []configModel.TrustedIssuersList, err error) {
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

func (mcc mockCredentialConfig) GetCredentialStatusConfig(serviceIdentifier string, scope string, credentialType string) (credentialStatus configModel.CredentialStatus, err error) {
	if mcc.mockError != nil {
		return credentialStatus, mcc.mockError
	}

	for _, credential := range mcc.mockScopes[serviceIdentifier][scope].Credentials {
		if credential.Type == credentialType {
			return credential.CredentialStatus, err
		}
	}
	return credentialStatus, err
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

func (msc *mockSessionCache) GetWithExpiration(k string) (interface{}, time.Time, bool) {
	v, found := msc.sessions[k]
	return v, <-time.After(5 * time.Second), found
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

func (mtc *mockTokenCache) GetWithExpiration(k string) (interface{}, time.Time, bool) {
	v, found := mtc.tokens[k]
	return v, <-time.After(5 * time.Second), found
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

	logging.Configure(LOGGING_CONFIG)

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

	logging.Configure(LOGGING_CONFIG)

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
		expectedSession = loginSession{version: flowVersion, callback: tc.expectedCallback, nonce: expectedNonce, sessionId: tc.testState, clientId: tc.testClientId, requestObject: tc.testRequestObjectJwt, scope: tc.testScope}
		cachedSession.requestObject = removeSignature(cachedSession.requestObject)
	} else {
		expectedSession = loginSession{version: flowVersion, callback: tc.expectedCallback, nonce: expectedNonce, sessionId: tc.testState, clientId: tc.testClientId, requestObject: tc.testRequestObjectJwt, scope: tc.testScope}
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
	logging.Configure(LOGGING_CONFIG)

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

// extractResponseUri decodes the (unsigned) JWT payload embedded in a
// REQUEST_MODE_BY_VALUE authentication request and returns its response_uri claim.
func extractResponseUri(t *testing.T, authRequest string) string {
	t.Helper()
	parsed, err := url.Parse(authRequest)
	if err != nil {
		t.Fatalf("Was not able to parse authentication request as URL: %v", err)
	}
	request := parsed.Query().Get("request")
	parts := strings.Split(request, ".")
	if len(parts) < 2 {
		t.Fatalf("Expected a JWT with at least header.payload, got %s", request)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Was not able to base64-decode the JWT payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("Was not able to unmarshal the JWT payload: %v", err)
	}
	responseUri, _ := claims["response_uri"].(string)
	return responseUri
}

func TestStartSameDeviceFlow_ResponseUriIncludesPathPrefix(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	testKey := getECDSAKey()
	sessionCache := mockSessionCache{sessions: map[string]loginSession{}}
	nonceGenerator := mockNonceGenerator{staticValues: []string{"randomNonce"}}
	credentialsConfig := mockCredentialConfig{createMockCredentials("", "", "", "", "", false), nil}
	verifier := CredentialVerifier{host: "verifier.org", pathPrefix: "/myservice", did: "did:key:verifier", sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, tokenSigner: mockTokenSigner{}, clock: mockClock{}, requestSigningKey: &testKey, credentialsConfig: credentialsConfig, clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier", KeyPath: "/my-signing-key.pem", KeyAlgorithm: "ES256"}}

	authReq, err := verifier.StartSameDeviceFlow("verifier.org", "https", "my-state", "/redirect", "", "", REQUEST_MODE_BY_VALUE, "", "")
	assert.NoError(t, err)
	assert.Equal(t, "https://verifier.org/myservice/api/v1/authentication_response", extractResponseUri(t, authReq))
}

func TestStartSiopFlow_ResponseUriIncludesPathPrefix(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	testKey := getECDSAKey()
	sessionCache := mockSessionCache{sessions: map[string]loginSession{}}
	nonceGenerator := mockNonceGenerator{staticValues: []string{"randomNonce"}}
	credentialsConfig := mockCredentialConfig{createMockCredentials("", "", "", "", "", false), nil}
	verifier := CredentialVerifier{host: "verifier.org", pathPrefix: "/myservice", did: "did:key:verifier", sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, tokenSigner: mockTokenSigner{}, clock: mockClock{}, requestSigningKey: &testKey, credentialsConfig: credentialsConfig, clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier", KeyPath: "/my-signing-key.pem", KeyAlgorithm: "ES256"}}

	authReq, err := verifier.StartSiopFlow("verifier.org", "https", "/redirect", "my-state", "", "", REQUEST_MODE_BY_VALUE)
	assert.NoError(t, err)
	assert.Equal(t, "https://verifier.org/myservice/api/v1/authentication_response", extractResponseUri(t, authReq))
}

func TestInitOid4VPCrossDevice_ResponseUriIncludesPathPrefix(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)
	testKey := getECDSAKey()
	sessionCache := mockSessionCache{sessions: map[string]loginSession{}}
	nonceGenerator := mockNonceGenerator{staticValues: []string{"randomNonce"}}
	credentialsConfig := mockCredentialConfig{createMockCredentials("", "", "", "", "", false), nil}
	verifier := CredentialVerifier{host: "verifier.org", pathPrefix: "/myservice", did: "did:key:verifier", sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, tokenSigner: mockTokenSigner{}, clock: mockClock{}, requestSigningKey: &testKey, credentialsConfig: credentialsConfig, clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier", KeyPath: "/my-signing-key.pem", KeyAlgorithm: "ES256"}}

	authReq, err := verifier.initOid4VPCrossDevice("verifier.org", "https", "https://wallet.example/callback", "my-state", "", "", "", REQUEST_MODE_BY_VALUE)
	assert.NoError(t, err)
	assert.Equal(t, "https://verifier.org/myservice/api/v1/authentication_response", extractResponseUri(t, authReq))
}

type mockExternalSsiKit struct {
	verificationResults []bool
	verificationError   error
}

func (msk *mockExternalSsiKit) ValidateVC(verifiableCredential *common.Credential, verificationContext ValidationContext) (result bool, err error) {
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
	testName              string
	sameDevice            bool
	testState             string
	testVP                common.Presentation
	testHolder            string
	testSession           loginSession
	requestedState        string
	callbackError         error
	verificationResult    []bool
	verificationError     error
	expectedResponse      Response
	expectedCallback      *url.URL
	expectedError         error
	tokenCacheError       error
	numValidationServices int
	verifyToken           func(t *testing.T, tok jwt.Token)
}

func TestAuthenticationResponse(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ssiKitError := errors.New("ssikit_failure")
	cacheError := errors.New("cache_failure")
	callbackError := errors.New("callback_failure")

	tests := []authTest{
		// general behaviour
		{"If the credential is invalid, return an error.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{false}, nil, Response{}, nil, ErrorInvalidVC, nil, 0, nil},
		{"If one credential is invalid, return an error.", true, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true, false}, nil, Response{}, nil, ErrorInvalidVC, nil, 0, nil},
		{"If an authentication response is received without a session, an error should be responded.", true, "", getVP([]string{"vc"}), "holder", loginSession{}, "login-state", nil, []bool{}, nil, Response{}, nil, ErrorNoSuchSession, nil, 0, nil},
		{"If ssiKit throws an error, an error should be responded.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{}, ssiKitError, Response{}, nil, ssiKitError, nil, 0, nil},
		{"If tokenCache throws an error, an error should be responded.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true}, nil, Response{}, nil, cacheError, cacheError, 0, nil},
		{"If the credential is invalid, return an error.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{false}, nil, Response{}, nil, ErrorInvalidVC, nil, 0, nil},
		{"If one credential is invalid, return an error.", false, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true, false}, nil, Response{}, nil, ErrorInvalidVC, nil, 0, nil},
		{"If an authentication response is received without a session, an error should be responded.", false, "", getVP([]string{"vc"}), "holder", loginSession{}, "login-state", nil, []bool{}, nil, Response{}, nil, ErrorNoSuchSession, nil, 0, nil},
		{"If ssiKit throws an error, an error should be responded.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{}, ssiKitError, Response{}, nil, ssiKitError, nil, 0, nil},
		{"If tokenCache throws an error, an error should be responded.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true}, nil, Response{}, nil, cacheError, cacheError, 0, nil},
		{"If a non-existent session is requested, an error should be responded.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "non-existent-state", nil, []bool{true}, nil, Response{}, nil, ErrorNoSuchSession, nil, 0, nil},

		// same-device flow
		{"When a same device flow is present, a proper response should be returned.", true, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true}, nil, Response{FlowVersion: SAME_DEVICE, RedirectTarget: "https://myhost.org/callback", Code: "authCode", SessionId: "my-session"}, nil, nil, nil, 0, nil},
		{"When a same device flow is present, a proper response should be returned for VPs.", true, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true, true}, nil, Response{FlowVersion: SAME_DEVICE, RedirectTarget: "https://myhost.org/callback", Code: "authCode", SessionId: "my-session"}, nil, nil, nil, 0, nil},

		// cross-device flow
		{"When a cross-device flow is present, a proper response should be sent to the requestors callback.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true}, nil, Response{}, getRequest("https://myhost.org/callback?code=authCode&state=my-session"), nil, nil, 0, nil},
		{"When a cross-device flow is present, a proper response should be sent to the requestors callback for VPs.", false, "login-state", getVP([]string{"vc1", "vc2"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", nil, []bool{true, true}, nil, Response{}, getRequest("https://myhost.org/callback?code=authCode&state=my-session"), nil, nil, 0, nil},
		{"When the requestor-callback fails, an error should be returned.", false, "login-state", getVP([]string{"vc"}), "holder", loginSession{version: CROSS_DEVICE_V1, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"}, "login-state", callbackError, []bool{true}, nil, Response{}, nil, callbackError, nil, 0, nil},

		// regression: credential must not be duplicated when multiple validation services are present
		{
			testName:   "When a single credential is presented with multiple validation services, the JWT uses verifiableCredential (not verifiablePresentation).",
			sameDevice: true, testState: "login-state",
			testVP:         getVP([]string{"vc"}),
			testHolder:     "holder",
			testSession:    loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"},
			requestedState: "login-state", verificationResult: []bool{true},
			expectedResponse:      Response{FlowVersion: SAME_DEVICE, RedirectTarget: "https://myhost.org/callback", Code: "authCode", SessionId: "my-session"},
			numValidationServices: 2,
			verifyToken: func(t *testing.T, tok jwt.Token) {
				var vcClaim any
				if err := tok.Get("verifiableCredential", &vcClaim); err != nil {
					t.Errorf("expected verifiableCredential claim but got error: %v", err)
				}
				var vpClaim any
				if err := tok.Get("verifiablePresentation", &vpClaim); err == nil {
					t.Errorf("expected no verifiablePresentation claim (credential was duplicated), but it was present")
				}
			},
		},
	}

	for _, tc := range tests {
		trueOption := true
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
			_ = jwk.AssignKeyID(testKey)
			nonceGenerator := mockNonceGenerator{staticValues: []string{"authCode"}}
			credentialsConfig := mockCredentialConfig{
				mockScopes: map[string]map[string]configModel.ScopeEntry{"clientId": {
					"": {
						Credentials: []configModel.Credential{{
							Type:         "VerifiableCredential",
							JwtInclusion: configModel.JwtInclusion{Enabled: &trueOption},
						}},
					},
				},
				},
			}
			numServices := tc.numValidationServices
			if numServices == 0 {
				numServices = 1
			}
			validationServices := make([]ValidationService, numServices)
			for i := range validationServices {
				results := tc.verificationResult
				if i > 0 {
					results = make([]bool, len(tc.testVP.Credentials()))
					for j := range results {
						results[j] = true
					}
				}
				validationServices[i] = &mockExternalSsiKit{results, tc.verificationError}
			}
			verifier := CredentialVerifier{did: "did:key:verifier", signingKey: testKey, tokenCache: &tokenCache, sessionCache: &sessionCache, nonceGenerator: &nonceGenerator, validationServices: validationServices, clock: mockClock{}, credentialsConfig: credentialsConfig, clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier"}}

			sameDeviceResponse, err := verifier.AuthenticationResponse(tc.requestedState, &tc.testVP)
			if err != tc.expectedError {
				t.Errorf("%s - Expected error %v but was %v.", tc.testName, tc.expectedError, err)
			}
			if tc.expectedError != nil {
				return
			}

			if tc.sameDevice {
				verifySameDevice(t, sameDeviceResponse, tokenCache, tc)
				if tc.verifyToken != nil {
					tc.verifyToken(t, tokenCache.tokens[sameDeviceResponse.Code].token)
				}
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

func getVP(ids []string) common.Presentation {
	credentials := []*common.Credential{}
	for _, id := range ids {
		credentials = append(credentials, getVC(id))
	}
	vp, _ := common.NewPresentation(common.WithCredentials(credentials...))
	return *vp
}

func getVC(id string) *common.Credential {

	testTime, _ := time.Parse(time.RFC3339, "2022-11-23T15:23:13Z")
	vc, _ := common.CreateCredential(
		common.CredentialContents{
			Context: []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://happypets.fiware.io/2022/credentials/employee/v1",
			},
			ID: "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
			Types: []string{
				"VerifiableCredential",
				"CustomerCredential",
			},
			Issuer:     &common.Issuer{ID: "did:key:verifier"},
			ValidFrom:  &testTime,
			ValidUntil: &testTime,
			Subject: []common.Subject{
				{
					ID: id,
					CustomFields: map[string]interface{}{
						"type":   "gx:NaturalParticipent",
						"target": "did:ebsi:packetdelivery",
					},
				},
			},
		},
		common.CustomFields{},
	)

	return vc
}

func getRequest(request string) *url.URL {
	url, _ := url.Parse(request)
	return url
}

func TestInitVerifier(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

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

			err := InitVerifier(&tc.testConfig, nil)
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
	logging.Configure(LOGGING_CONFIG)

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
	x, y := curve.ScalarBaseMult(d.Bytes()) //nolint:staticcheck

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

	logging.Configure(LOGGING_CONFIG)

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
			jwtString, expiration, _, err := verifier.GetToken(tc.testCode, tc.testRedirectUri, false)

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

// TestGetTokenWithRefreshToken tests the GetToken method when the refresh
// token feature is enabled, verifying that a refresh token is generated and
// returned alongside the access token, and that failures in refresh token
// creation propagate correctly.
func TestGetTokenWithRefreshToken(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	testKey := getECDSAKey()
	repoErr := errors.New("repo_store_failure")

	// refreshTokenExpirationMinutes is the lifetime used for the mock verifier.
	const refreshTokenExpirationMinutes = 60

	type test struct {
		testName             string
		testCode             string
		testRedirectUri      string
		tokenSession         map[string]tokenStore
		refreshTokenEnabled  bool
		refreshTokenRepo     *mockRefreshTokenRepository
		expectedRefreshToken bool
		expectedError        error
		repoStoreErr         error
	}

	tests := []test{
		{
			testName:             "When refresh tokens are enabled and store succeeds, a refresh token is returned.",
			testCode:             "my-auth-code",
			testRedirectUri:      "https://myhost.org/redirect",
			tokenSession:         map[string]tokenStore{"my-auth-code": {token: getToken(), redirect_uri: "https://myhost.org/redirect", clientId: "test-client"}},
			refreshTokenEnabled:  true,
			refreshTokenRepo:     newMockRefreshTokenRepo(),
			expectedRefreshToken: true,
			expectedError:        nil,
		},
		{
			testName:             "When refresh tokens are disabled, no refresh token is returned.",
			testCode:             "my-auth-code",
			testRedirectUri:      "https://myhost.org/redirect",
			tokenSession:         map[string]tokenStore{"my-auth-code": {token: getToken(), redirect_uri: "https://myhost.org/redirect", clientId: "test-client"}},
			refreshTokenEnabled:  false,
			refreshTokenRepo:     newMockRefreshTokenRepo(),
			expectedRefreshToken: false,
			expectedError:        nil,
		},
		{
			testName:             "When refresh token store fails, an error is returned.",
			testCode:             "my-auth-code",
			testRedirectUri:      "https://myhost.org/redirect",
			tokenSession:         map[string]tokenStore{"my-auth-code": {token: getToken(), redirect_uri: "https://myhost.org/redirect", clientId: "test-client"}},
			refreshTokenEnabled:  true,
			refreshTokenRepo:     &mockRefreshTokenRepository{tokens: make(map[string]database.RefreshTokenRow), storeErr: repoErr},
			expectedRefreshToken: false,
			expectedError:        repoErr,
			repoStoreErr:         repoErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestGetTokenWithRefreshToken +++++++++++++++++ Running test: ", tc.testName)

			tokenCache := mockTokenCache{tokens: tc.tokenSession}
			verifier := CredentialVerifier{
				tokenCache:             &tokenCache,
				signingKey:             testKey,
				clock:                  mockClock{},
				tokenSigner:            mockTokenSigner{},
				signingAlgorithm:       "ES256",
				refreshTokenEnabled:    tc.refreshTokenEnabled,
				refreshTokenExpiration: refreshTokenExpirationMinutes * time.Minute,
				refreshTokenRepo:       tc.refreshTokenRepo,
			}
			jwtString, expiration, refreshToken, err := verifier.GetToken(tc.testCode, tc.testRedirectUri, false)

			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
				return
			}
			assert.NoError(t, err)

			// Access token must always be present on success.
			assert.NotEmpty(t, jwtString)
			assert.Greater(t, expiration, int64(0))

			if tc.expectedRefreshToken {
				assert.NotEmpty(t, refreshToken, "Expected a refresh token to be returned")
				// Verify the token was stored in the repository.
				assert.Len(t, tc.refreshTokenRepo.tokens, 1, "Exactly one refresh token should be stored")
			} else {
				assert.Empty(t, refreshToken, "Expected no refresh token to be returned")
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
	signingAlgorithm  string
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
				Issuer:                           verifierHost,
				ScopesSupported:                  []string{"Scope1", "Scope2"},
				IdTokenSigningAlgValuesSupported: []string{}}},
		{testName: "Test OIDC metadata with non-existing scopes", serviceIdentifier: "serviceId", host: verifierHost,
			credentialScopes: map[string]map[string]configModel.ScopeEntry{"serviceId": {}}, mockConfigError: nil,
			expectedOpenID: common.OpenIDProviderMetadata{
				Issuer:                           verifierHost,
				ScopesSupported:                  []string{},
				IdTokenSigningAlgValuesSupported: []string{}}},
		{testName: "Test OIDC metadata supported algorithms with RS256 signing key", serviceIdentifier: "serviceId", host: verifierHost,
			signingAlgorithm: "RS256",
			credentialScopes: map[string]map[string]configModel.ScopeEntry{"serviceId": {}}, mockConfigError: nil,
			expectedOpenID: common.OpenIDProviderMetadata{
				Issuer:                           verifierHost,
				ScopesSupported:                  []string{},
				IdTokenSigningAlgValuesSupported: []string{"RS256"}}},
		{testName: "Test OIDC metadata supported algorithms with ES256 signing key", serviceIdentifier: "serviceId", host: verifierHost,
			signingAlgorithm: "ES256",
			credentialScopes: map[string]map[string]configModel.ScopeEntry{"serviceId": {}}, mockConfigError: nil,
			expectedOpenID: common.OpenIDProviderMetadata{
				Issuer:                           verifierHost,
				ScopesSupported:                  []string{},
				IdTokenSigningAlgValuesSupported: []string{"ES256"}}},
		{testName: "Test OIDC metadata supported algorithms with EdDSA signing key", serviceIdentifier: "serviceId", host: verifierHost,
			signingAlgorithm: "EdDSA",
			credentialScopes: map[string]map[string]configModel.ScopeEntry{"serviceId": {}}, mockConfigError: nil,
			expectedOpenID: common.OpenIDProviderMetadata{
				Issuer:                           verifierHost,
				ScopesSupported:                  []string{},
				IdTokenSigningAlgValuesSupported: []string{"EdDSA"}}},
		{testName: "Test OIDC metadata with a path prefix baked into host", serviceIdentifier: "serviceId", host: verifierHost + "/myservice",
			credentialScopes: map[string]map[string]configModel.ScopeEntry{"serviceId": {}}, mockConfigError: nil,
			expectedOpenID: common.OpenIDProviderMetadata{
				Issuer:                           verifierHost + "/myservice",
				ScopesSupported:                  []string{},
				IdTokenSigningAlgValuesSupported: []string{}}},
	}
}

func TestGetOpenIDConfiguration(t *testing.T) {
	tests := getOpenIdProviderMetadataTests()
	for _, tc := range tests {
		common.ResetGlobalCache()
		t.Run(tc.testName, func(t *testing.T) {
			credentialsConfig := mockCredentialConfig{tc.credentialScopes, tc.mockConfigError}
			verifier := CredentialVerifier{credentialsConfig: credentialsConfig, host: tc.host, signingAlgorithm: tc.signingAlgorithm}
			actualOpenID, _ := verifier.GetOpenIDConfiguration(tc.serviceIdentifier)

			assert.Equal(t, tc.expectedOpenID.Issuer, actualOpenID.Issuer)
			assert.Equal(t, len(tc.expectedOpenID.ScopesSupported), len(actualOpenID.ScopesSupported))
			for _, scope := range tc.expectedOpenID.ScopesSupported {
				assert.True(t, slices.Contains(actualOpenID.ScopesSupported, scope))
			}
			assert.Equal(t, len(tc.expectedOpenID.IdTokenSigningAlgValuesSupported), len(actualOpenID.IdTokenSigningAlgValuesSupported))
			for _, alg := range tc.expectedOpenID.IdTokenSigningAlgValuesSupported {
				assert.True(t, slices.Contains(actualOpenID.IdTokenSigningAlgValuesSupported, alg))
			}
			// the discovery doc derives everything from host, so a path prefix baked
			// into host (as InitVerifier does) must propagate to every endpoint URL.
			assert.Contains(t, actualOpenID.TokenEndpoint, tc.host)
			assert.Contains(t, actualOpenID.JwksUri, tc.host)
		})
	}
}

func TestGetPathPrefix(t *testing.T) {
	v := CredentialVerifier{pathPrefix: "/myservice"}
	assert.Equal(t, "/myservice", v.GetPathPrefix())
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
		presentation              *common.Presentation
		expectedCredentialsByType map[string][]*common.Credential
		expectedCredentialTypes   []string
	}

	vc1, _ := common.CreateCredential(common.CredentialContents{
		ID:    "vc1",
		Types: []string{"type1", "typeA"},
	}, common.CustomFields{})
	vc2, _ := common.CreateCredential(common.CredentialContents{
		ID:    "vc2",
		Types: []string{"type2", "typeB"},
	}, common.CustomFields{})
	vp1, _ := common.NewPresentation(common.WithCredentials(vc1))
	vp2, _ := common.NewPresentation(common.WithCredentials(vc1, vc2))
	vp3, _ := common.NewPresentation()

	tests := []test{
		{
			testName:     "Presentation with one credential",
			presentation: vp1,
			expectedCredentialsByType: map[string][]*common.Credential{
				"type1": {vc1},
				"typeA": {vc1},
			},
			expectedCredentialTypes: []string{"type1", "typeA"},
		},
		{
			testName:     "Presentation with multiple credentials",
			presentation: vp2,
			expectedCredentialsByType: map[string][]*common.Credential{
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
			expectedCredentialsByType: map[string][]*common.Credential{},
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

// TestGenerateToken_LDProofDomainBinding verifies that the vp_token and
// token-exchange grants — which both go through GenerateToken — enforce the
// audience binding of a JSON-LD VP proof. Unlike the authorization-code flow
// there is no session nonce here, so the domain is the only binding available
// and omitting it must not be a way around the check.
func TestGenerateToken_LDProofDomainBinding(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	const verifierId = "did:key:verifier"

	tests := []struct {
		name        string
		proofDomain string
		expectedErr error
	}{
		{name: "matching_domain_passes_binding", proofDomain: verifierId},
		{name: "foreign_domain_rejected", proofDomain: "did:key:other-verifier", expectedErr: ErrorProofDomainMismatch},
		{name: "omitted_domain_rejected", proofDomain: "", expectedErr: ErrorProofDomainMismatch},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			presentation, _ := common.NewPresentation()
			presentation.Holder = "did:web:holder.example.com"
			presentation.Proofs = []*common.LDProof{{
				Type:               common.ProofTypeJsonWebSignature2020,
				VerificationMethod: "did:web:holder.example.com#key-1",
				ProofPurpose:       common.ProofPurposeAuthentication,
				Domain:             tc.proofDomain,
			}}

			mockConfig := mockCredentialConfig{mockScopes: map[string]map[string]configModel.ScopeEntry{}}
			verifier := CredentialVerifier{
				credentialsConfig:    &mockConfig,
				validationServices:   []ValidationService{},
				signingKey:           getECDSAKey(),
				clock:                mockClock{},
				tokenSigner:          mockTokenSigner{},
				signingAlgorithm:     "ES256",
				host:                 "https://verifier.example.com",
				jwtExpiration:        time.Hour,
				clientIdentification: configModel.ClientIdentification{Id: verifierId},
			}

			_, _, err := verifier.GenerateToken("test-client", "subject-id", "audience-id", []string{"test-scope"}, presentation)

			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr)
				return
			}
			// The binding passed; the call still fails later because the
			// presentation carries no credentials. That is the expected
			// outcome for this fixture and confirms the binding check let it
			// through.
			assert.ErrorIs(t, err, ErrorNoValidCredentialTypeProvided)
		})
	}
}

// TestGenerateToken_LDProofFreshness covers the only replay protection the
// vp_token and token-exchange grants have: there is no server-issued nonce to
// bind against, so a captured ldp_vc presentation must be rejected once its
// proof is older than the configured window.
func TestGenerateToken_LDProofFreshness(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	const verifierId = "did:key:verifier"
	const maxAge = 5 * time.Minute
	now := mockClock{}.Now()

	tests := []struct {
		name        string
		created     string
		maxAge      time.Duration
		expectedErr error
	}{
		{name: "fresh_proof_passes", created: now.Format(time.RFC3339), maxAge: maxAge},
		{name: "proof_within_window_passes", created: now.Add(-maxAge / 2).Format(time.RFC3339), maxAge: maxAge},
		{name: "stale_proof_rejected", created: now.Add(-2 * maxAge).Format(time.RFC3339), maxAge: maxAge, expectedErr: ErrorProofNotFresh},
		{name: "future_proof_rejected", created: now.Add(maxAge).Format(time.RFC3339), maxAge: maxAge, expectedErr: ErrorProofCreatedInFuture},
		{name: "missing_created_rejected", created: "", maxAge: maxAge, expectedErr: ErrorProofCreatedMissing},
		{name: "unparseable_created_rejected", created: "yesterday", maxAge: maxAge, expectedErr: ErrorProofCreatedUnparseable},
		{name: "zero_max_age_disables_the_check", created: now.Add(-100 * maxAge).Format(time.RFC3339), maxAge: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			presentation, _ := common.NewPresentation()
			presentation.Holder = "did:web:holder.example.com"
			presentation.Proofs = []*common.LDProof{{
				Type:               common.ProofTypeJsonWebSignature2020,
				Created:            tc.created,
				VerificationMethod: "did:web:holder.example.com#key-1",
				ProofPurpose:       common.ProofPurposeAuthentication,
				Domain:             verifierId,
			}}

			mockConfig := mockCredentialConfig{mockScopes: map[string]map[string]configModel.ScopeEntry{}}
			verifier := CredentialVerifier{
				credentialsConfig:    &mockConfig,
				validationServices:   []ValidationService{},
				signingKey:           getECDSAKey(),
				clock:                mockClock{},
				tokenSigner:          mockTokenSigner{},
				signingAlgorithm:     "ES256",
				host:                 "https://verifier.example.com",
				jwtExpiration:        time.Hour,
				clientIdentification: configModel.ClientIdentification{Id: verifierId},
				ldProofMaxAge:        tc.maxAge,
			}

			_, _, err := verifier.GenerateToken("test-client", "subject-id", "audience-id", []string{"test-scope"}, presentation)

			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr)
				return
			}
			// The freshness check passed; the call still fails later because
			// the presentation carries no credentials.
			assert.ErrorIs(t, err, ErrorNoValidCredentialTypeProvided)
		})
	}
}

// TestAuthenticationResponse_LDProofBinding covers the challenge and domain
// binding of the main OID4VP flow. Without it the whole binding block in
// AuthenticationResponse could be deleted without a single test failing — the
// other fixtures are JWT VPs and carry no LD proofs.
func TestAuthenticationResponse_LDProofBinding(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	const verifierId = "did:key:verifier"
	const sessionNonce = "session-nonce"
	const testState = "login-state"

	tests := []struct {
		name          string
		proofs        []*common.LDProof
		expectedError error
	}{
		{
			name: "matching_challenge_and_domain_pass",
			proofs: []*common.LDProof{{
				Type:      common.ProofTypeJsonWebSignature2020,
				Challenge: sessionNonce,
				Domain:    verifierId,
			}},
		},
		{
			name: "wrong_challenge_rejected",
			proofs: []*common.LDProof{{
				Type:      common.ProofTypeJsonWebSignature2020,
				Challenge: "replayed-nonce",
				Domain:    verifierId,
			}},
			expectedError: ErrorProofChallengeMismatch,
		},
		{
			name: "omitted_challenge_rejected",
			proofs: []*common.LDProof{{
				Type:   common.ProofTypeJsonWebSignature2020,
				Domain: verifierId,
			}},
			expectedError: ErrorProofChallengeMismatch,
		},
		{
			name: "wrong_domain_rejected",
			proofs: []*common.LDProof{{
				Type:      common.ProofTypeJsonWebSignature2020,
				Challenge: sessionNonce,
				Domain:    "did:key:other-verifier",
			}},
			expectedError: ErrorProofDomainMismatch,
		},
		{
			name: "challenge_and_domain_split_across_proofs_rejected",
			proofs: []*common.LDProof{
				{Type: common.ProofTypeJsonWebSignature2020, Challenge: sessionNonce},
				{Type: common.ProofTypeJsonWebSignature2020, Domain: verifierId},
			},
			expectedError: ErrorProofChallengeMismatch,
		},
	}

	trueOption := true
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			presentation := getVP([]string{"vc"})
			presentation.Proofs = tc.proofs

			sessionCache := mockSessionCache{sessions: map[string]loginSession{testState: {
				version:       SAME_DEVICE,
				callback:      "https://myhost.org/callback",
				sessionId:     "my-session",
				nonce:         sessionNonce,
				clientId:      "clientId",
				requestObject: "requestObjectJwt",
			}}}
			tokenCache := mockTokenCache{tokens: map[string]tokenStore{}}
			nonceGenerator := mockNonceGenerator{staticValues: []string{"authCode"}}
			credentialsConfig := mockCredentialConfig{
				mockScopes: map[string]map[string]configModel.ScopeEntry{"clientId": {
					"": {
						Credentials: []configModel.Credential{{
							Type:         "VerifiableCredential",
							JwtInclusion: configModel.JwtInclusion{Enabled: &trueOption},
						}},
					},
				}},
			}
			verifier := CredentialVerifier{
				did:                  verifierId,
				signingKey:           getECDSAKey(),
				tokenCache:           &tokenCache,
				sessionCache:         &sessionCache,
				nonceGenerator:       &nonceGenerator,
				validationServices:   []ValidationService{&mockExternalSsiKit{[]bool{true}, nil}},
				clock:                mockClock{},
				credentialsConfig:    credentialsConfig,
				clientIdentification: configModel.ClientIdentification{Id: verifierId},
			}

			_, err := verifier.AuthenticationResponse(testState, &presentation)

			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
				assert.Empty(t, tokenCache.tokens, "no token must be cached for a rejected presentation")
				return
			}
			assert.NoError(t, err, "a correctly bound presentation must be accepted")
			assert.NotEmpty(t, tokenCache.tokens, "a token must be cached for an accepted presentation")
		})
	}
}

func TestGenerateToken(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName           string
		clientId           string
		subject            string
		audience           string
		scopes             []string
		presentation       *common.Presentation
		credentialScopes   map[string]map[string]configModel.ScopeEntry
		configError        error
		mockTokenSignError error
		expectedError      error
	}

	testKey := getECDSAKey()
	emptyPresentation, _ := common.NewPresentation()
	vc1, _ := common.CreateCredential(common.CredentialContents{
		ID:    "vc1",
		Types: []string{"type1", "typeA"},
	}, common.CustomFields{})
	invalidPresentation, _ := common.NewPresentation(common.WithCredentials(vc1))

	tests := []test{
		{
			testName:           "When presentation is empty, ErrorNoValidCredentialTypeProvided should be returned",
			clientId:           "test-client",
			subject:            "subject-id",
			audience:           "audience-id",
			scopes:             []string{"test-scope"},
			presentation:       emptyPresentation,
			credentialScopes:   map[string]map[string]configModel.ScopeEntry{},
			configError:        nil,
			mockTokenSignError: nil,
			expectedError:      ErrorNoValidCredentialTypeProvided,
		},
		{
			testName:           "When presentation has not valid types, ErrorNoValidCredentialTypeProvided should be returned",
			clientId:           "test-client",
			subject:            "subject-id",
			audience:           "audience-id",
			scopes:             []string{"test-scope"},
			presentation:       invalidPresentation,
			credentialScopes:   map[string]map[string]configModel.ScopeEntry{},
			configError:        nil,
			mockTokenSignError: nil,
			expectedError:      ErrorNoValidCredentialTypeProvided,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			mockConfig := mockCredentialConfig{mockScopes: tc.credentialScopes, mockError: tc.configError}

			verifier := CredentialVerifier{
				credentialsConfig:  &mockConfig,
				validationServices: []ValidationService{},
				signingKey:         testKey,
				clock:              mockClock{},
				tokenSigner:        mockTokenSigner{tc.mockTokenSignError},
				signingAlgorithm:   "ES256",
				host:               "https://verifier.example.com",
				jwtExpiration:      time.Hour,
			}

			expiration, tokenString, err := verifier.GenerateToken(tc.clientId, tc.subject, tc.audience, tc.scopes, tc.presentation)

			if tc.expectedError != nil {
				if err == nil {
					t.Errorf("%s - Expected error %v but got none.", tc.testName, tc.expectedError)
					return
				}
				if err.Error() != tc.expectedError.Error() {
					t.Errorf("%s - Expected error %v but was %v.", tc.testName, tc.expectedError, err)
					return
				}
				return
			}

			if err != nil {
				t.Errorf("%s - Expected no error but got %v.", tc.testName, err)
				return
			}

			if tokenString == "" {
				t.Errorf("%s - Expected token string but got empty.", tc.testName)
				return
			}

			if expiration == 0 {
				t.Errorf("%s - Expected expiration but got 0.", tc.testName)
				return
			}
		})
	}
}

func TestGenerateJWT(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	testKey := getECDSAKey()
	v := CredentialVerifier{
		signingKey:    testKey,
		clock:         mockClock{},
		host:          "https://verifier.example.com",
		jwtExpiration: time.Hour,
	}

	type jwtTest struct {
		testName    string
		credentials []map[string]any
		holder      string
		audience    string
		flat        bool
		verify      func(t *testing.T, tok jwt.Token)
	}

	cred1 := map[string]any{"role": "superadmin"}
	cred2 := map[string]any{"organizationId": "super-id"}

	tests := []jwtTest{
		{
			testName:    "single credential uses verifiableCredential claim and subject",
			credentials: []map[string]any{cred1},
			holder:      "holder1",
			audience:    "aud1",
			flat:        false,
			verify: func(t *testing.T, tok jwt.Token) {
				sub, exists := tok.Subject()
				if !exists || sub != "holder1" {
					t.Errorf("expected subject holder1, got %s", sub)
				}

				var vcClaim any
				err := tok.Get("verifiableCredential", &vcClaim)
				if err != nil {
					t.Errorf("expected verifiableCredential claim, got error %v", err)
				}
				b1, _ := json.Marshal(vcClaim)
				bExp1, _ := json.Marshal(cred1)
				if string(b1) != string(bExp1) {
					t.Errorf("credential claim mismatch, expected %s got %s", string(bExp1), string(b1))
				}
			},
		},
		{
			testName:    "multiple credentials use verifiablePresentation claim",
			credentials: []map[string]any{cred1, cred2},
			holder:      "",
			audience:    "aud2",
			flat:        false,
			verify: func(t *testing.T, tok jwt.Token) {
				var vpClaim any
				err := tok.Get("verifiablePresentation", &vpClaim)
				if err != nil {
					t.Errorf("expected verifiablePresentation claim, got error %v", err)
				}
				bvp, _ := json.Marshal(vpClaim)
				expvp, _ := json.Marshal([]map[string]any{cred1, cred2})
				if string(bvp) != string(expvp) {
					t.Errorf("presentation claim mismatch, expected %s got %s", string(expvp), string(bvp))
				}
			},
		},
		{
			testName:    "flat claim mode flattens all values",
			credentials: []map[string]any{cred1, cred2},
			holder:      "",
			audience:    "aud3",
			flat:        true,
			verify: func(t *testing.T, tok jwt.Token) {
				var role any
				err := tok.Get("role", &role)
				if err != nil {
					t.Errorf("expected flat claim role, got error %v", err)
				}
				if role != cred1["role"] {
					t.Errorf("flat claim role expected %s got %v", cred1["role"], role)
				}
				var organizationId any
				err = tok.Get("organizationId", &organizationId)
				if err != nil {
					t.Errorf("expected flat claim organizationId, got error %v", err)
				}
				if organizationId != cred2["organizationId"] {
					t.Errorf("flat claim organizationId expected %s got %v", cred2["organizationId"], organizationId)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			token, err := v.generateJWT(tc.credentials, tc.holder, tc.audience, tc.flat, "nonce")
			if err != nil {
				t.Fatalf("unexpected error building jwt: %v", err)
			}

			iss, issExists := token.Issuer()
			assert.True(t, issExists, "iss claim must be present")
			assert.Equal(t, "https://verifier.example.com", iss)

			aud, audExists := token.Audience()
			assert.True(t, audExists, "aud claim must be present")
			assert.Contains(t, aud, tc.audience, "aud claim must contain the audience")

			exp, expExists := token.Expiration()
			assert.True(t, expExists, "exp claim must be present")
			assert.Equal(t, int64(3600), exp.Unix())

			iat, iatExists := token.IssuedAt()
			assert.True(t, iatExists, "iat claim must be present")
			assert.Equal(t, int64(0), iat.Unix())

			if tc.holder != "" {
				sub, subExists := token.Subject()
				assert.True(t, subExists, "sub claim must be present when holder is set")
				assert.Equal(t, tc.holder, sub)
			}

			tc.verify(t, token)
		})
	}
}

// testStatusWiringServiceID / Scope / CredentialType are named constants used
// by the TestInitVerifier_CredentialStatusWiring test-case fixtures so that no
// magic strings appear inside the table.
const (
	testStatusWiringServiceID      = "wiring-service"
	testStatusWiringScope          = "openid"
	testStatusWiringCredentialType = "VerifiableCredential"
)

// TestInitVerifier_CredentialStatusWiring verifies that the
// CredentialStatusValidationService is unconditionally appended to the
// verifier's validation chain (Step 6) and that the per-credential-type
// context assembled via getCredentialStatusValidationContext reflects whatever
// CredentialStatus block is configured on the static services (Step 2).
//
// The test never exercises the real HTTP status-list client: it only verifies
// that (a) the service was constructed, (b) its ValidateVC call is a no-op
// when no credential opts in, and (c) the context's PerType map contains the
// expected per-type Enabled flag for the provided credential type.
func TestInitVerifier_CredentialStatusWiring(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	baseVerifierConfig := configModel.Verifier{
		Did:            "did:key:verifier",
		TirAddress:     "https://tir.org",
		ValidationMode: "none",
		SessionExpiry:  30,
		KeyAlgorithm:   "RS256",
		GenerateKey:    true,
		SupportedModes: []string{"urlEncoded"},
	}

	type test struct {
		testName               string
		services               []configModel.ConfiguredService
		expectedPerTypeEnabled bool
	}

	tests := []test{
		{
			testName: "Case A: credential without explicit CredentialStatus defaults to enabled.",
			services: []configModel.ConfiguredService{
				{
					Id: testStatusWiringServiceID,
					ServiceScopes: map[string]configModel.ScopeEntry{
						testStatusWiringScope: {
							Credentials: []configModel.Credential{
								{Type: testStatusWiringCredentialType},
							},
						},
					},
				},
			},
			expectedPerTypeEnabled: true,
		},
		{
			testName: "Case B: credential with explicit CredentialStatus.Enabled=true.",
			services: []configModel.ConfiguredService{
				{
					Id: testStatusWiringServiceID,
					ServiceScopes: map[string]configModel.ScopeEntry{
						testStatusWiringScope: {
							Credentials: []configModel.Credential{
								{
									Type:             testStatusWiringCredentialType,
									CredentialStatus: configModel.CredentialStatus{Enabled: boolPtr(true)},
								},
							},
						},
					},
				},
			},
			expectedPerTypeEnabled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestInitVerifier_CredentialStatusWiring +++++++++++++++++ Running test: ", tc.testName)
			common.ResetGlobalCache()
			t.Cleanup(func() { common.ResetGlobalCache() })

			verifier = nil
			cfg := configModel.Configuration{
				Verifier:   baseVerifierConfig,
				ConfigRepo: configModel.ConfigRepo{Services: tc.services},
			}
			if err := InitVerifier(&cfg, nil); err != nil {
				t.Fatalf("%s - InitVerifier returned unexpected error: %v", tc.testName, err)
			}
			if GetVerifier() == nil {
				t.Fatalf("%s - expected a verifier to be available after InitVerifier", tc.testName)
			}
			// GetVerifier returns the Verifier interface; the concrete type
			// stored globally is *CredentialVerifier so we type-assert to reach
			// the package-internal fields exercised by the test.
			initialised, ok := GetVerifier().(*CredentialVerifier)
			if !ok {
				t.Fatalf("%s - expected global verifier to be of type *CredentialVerifier, got %T", tc.testName, GetVerifier())
			}

			// The CredentialStatusValidationService must always be appended,
			// regardless of per-credential opt-in.
			var statusService *CredentialStatusValidationService
			for _, svc := range initialised.validationServices {
				if s, ok := svc.(*CredentialStatusValidationService); ok {
					statusService = s
					break
				}
			}
			assert.NotNil(t, statusService, "%s - CredentialStatusValidationService must be registered", tc.testName)

			// The per-credential-type context is the mechanism the verifier
			// uses at dispatch time to pass config to the status service;
			// assert that it reflects the configured CredentialStatus block.
			ctx, err := initialised.getCredentialStatusValidationContext(
				testStatusWiringServiceID,
				testStatusWiringScope,
				[]string{testStatusWiringCredentialType},
			)
			assert.NoError(t, err, "%s - getCredentialStatusValidationContext returned an unexpected error", tc.testName)
			perTypeEntry, present := ctx.PerType[testStatusWiringCredentialType]
			assert.True(t, present, "%s - PerType must contain the configured credential type", tc.testName)
			assert.Equal(t, tc.expectedPerTypeEnabled, perTypeEntry.IsEnabled(), "%s - PerType Enabled flag mismatch", tc.testName)

			// No matter whether any credential opted in, validating with an
			// empty PerType context must be a no-op — this covers Case A's
			// "feature off" path without issuing any network calls.
			emptyCtx := CredentialStatusValidationContext{PerType: map[string]configModel.CredentialStatus{}}
			vc := getVC("vc-status-wiring")
			ok, validateErr := statusService.ValidateVC(vc, emptyCtx)
			assert.NoError(t, validateErr, "%s - ValidateVC with empty PerType must not error", tc.testName)
			assert.True(t, ok, "%s - ValidateVC with empty PerType must return true", tc.testName)
		})
	}
}

// ---------------------------------------------------------------------------
// TIR v5 — getTrustRegistriesValidationContext type propagation
// ---------------------------------------------------------------------------

// TestGetTrustRegistriesValidationContext_V5TypePropagation verifies that
// getTrustRegistriesValidationContext correctly propagates "ebsi-v5" type
// information from config through to the TrustRegistriesValidationContext.
func TestGetTrustRegistriesValidationContext_V5TypePropagation(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName             string
		credentialScopes     map[string]map[string]configModel.ScopeEntry
		clientId             string
		scope                string
		credentialTypes      []string
		expectedIssuersMap   map[string][]configModel.TrustedIssuersList
		expectedParticipants map[string][]configModel.TrustedParticipantsList
		configError          error
		expectedError        error
	}

	tests := []test{
		{
			testName: "ebsi-v5 issuers and participants are propagated through validation context",
			credentialScopes: map[string]map[string]configModel.ScopeEntry{
				"client-v5": {
					"v5-scope": {
						Credentials: []configModel.Credential{
							{
								Type: "VerifiableCredential",
								TrustedIssuersLists: configModel.TrustedIssuersLists{
									{Type: "ebsi-v5", Url: "https://til-v5.example.com"},
								},
								TrustedParticipantsLists: []configModel.TrustedParticipantsList{
									{Type: "ebsi-v5", Url: "https://tir-v5.example.com"},
								},
							},
						},
					},
				},
			},
			clientId:        "client-v5",
			scope:           "v5-scope",
			credentialTypes: []string{"VerifiableCredential"},
			expectedIssuersMap: map[string][]configModel.TrustedIssuersList{
				"VerifiableCredential": {
					{Type: "ebsi-v5", Url: "https://til-v5.example.com"},
				},
			},
			expectedParticipants: map[string][]configModel.TrustedParticipantsList{
				"VerifiableCredential": {
					{Type: "ebsi-v5", Url: "https://tir-v5.example.com"},
				},
			},
		},
		{
			testName: "mixed ebsi and ebsi-v5 types are propagated correctly",
			credentialScopes: map[string]map[string]configModel.ScopeEntry{
				"client-mixed": {
					"mixed-scope": {
						Credentials: []configModel.Credential{
							{
								Type: "VerifiableCredential",
								TrustedIssuersLists: configModel.TrustedIssuersLists{
									{Type: "ebsi", Url: "https://til-ebsi.example.com"},
									{Type: "ebsi-v5", Url: "https://til-v5.example.com"},
								},
								TrustedParticipantsLists: []configModel.TrustedParticipantsList{
									{Type: "ebsi", Url: "https://tir-ebsi.example.com"},
									{Type: "ebsi-v5", Url: "https://tir-v5.example.com"},
								},
							},
						},
					},
				},
			},
			clientId:        "client-mixed",
			scope:           "mixed-scope",
			credentialTypes: []string{"VerifiableCredential"},
			expectedIssuersMap: map[string][]configModel.TrustedIssuersList{
				"VerifiableCredential": {
					{Type: "ebsi", Url: "https://til-ebsi.example.com"},
					{Type: "ebsi-v5", Url: "https://til-v5.example.com"},
				},
			},
			expectedParticipants: map[string][]configModel.TrustedParticipantsList{
				"VerifiableCredential": {
					{Type: "ebsi", Url: "https://tir-ebsi.example.com"},
					{Type: "ebsi-v5", Url: "https://tir-v5.example.com"},
				},
			},
		},
		{
			testName: "multiple credential types each with their own v5 config",
			credentialScopes: map[string]map[string]configModel.ScopeEntry{
				"client-multi": {
					"multi-scope": {
						Credentials: []configModel.Credential{
							{
								Type: "VerifiableCredential",
								TrustedIssuersLists: configModel.TrustedIssuersLists{
									{Type: "ebsi-v5", Url: "https://til-vc-v5.example.com"},
								},
								TrustedParticipantsLists: []configModel.TrustedParticipantsList{
									{Type: "ebsi-v5", Url: "https://tir-vc-v5.example.com"},
								},
							},
							{
								Type: "CustomerCredential",
								TrustedIssuersLists: configModel.TrustedIssuersLists{
									{Type: "ebsi", Url: "https://til-cc-ebsi.example.com"},
								},
								TrustedParticipantsLists: []configModel.TrustedParticipantsList{
									{Type: "ebsi", Url: "https://tir-cc-ebsi.example.com"},
								},
							},
						},
					},
				},
			},
			clientId:        "client-multi",
			scope:           "multi-scope",
			credentialTypes: []string{"VerifiableCredential", "CustomerCredential"},
			expectedIssuersMap: map[string][]configModel.TrustedIssuersList{
				"VerifiableCredential": {
					{Type: "ebsi-v5", Url: "https://til-vc-v5.example.com"},
				},
				"CustomerCredential": {
					{Type: "ebsi", Url: "https://til-cc-ebsi.example.com"},
				},
			},
			expectedParticipants: map[string][]configModel.TrustedParticipantsList{
				"VerifiableCredential": {
					{Type: "ebsi-v5", Url: "https://tir-vc-v5.example.com"},
				},
				"CustomerCredential": {
					{Type: "ebsi", Url: "https://tir-cc-ebsi.example.com"},
				},
			},
		},
		{
			testName:         "config error is propagated",
			configError:      errors.New("config_failure"),
			clientId:         "client-err",
			scope:            "scope-err",
			credentialScopes: map[string]map[string]configModel.ScopeEntry{},
			credentialTypes:  []string{"VerifiableCredential"},
			expectedError:    errors.New("config_failure"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			mockConfig := mockCredentialConfig{mockScopes: tc.credentialScopes, mockError: tc.configError}
			verifier := CredentialVerifier{credentialsConfig: &mockConfig}

			ctx, err := verifier.getTrustRegistriesValidationContext(tc.clientId, tc.credentialTypes, tc.scope)

			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedError.Error(), err.Error())
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedIssuersMap, ctx.GetTrustedIssuersLists())
			assert.Equal(t, tc.expectedParticipants, ctx.GetTrustedParticipantLists())
		})
	}
}

// TestGetTrustRegistriesValidationContextFromScope_V5 verifies that
// getTrustRegistriesValidationContextFromScope correctly propagates "ebsi-v5"
// type information and validates required credential types.
func TestGetTrustRegistriesValidationContextFromScope_V5(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName             string
		credentialScopes     map[string]map[string]configModel.ScopeEntry
		clientId             string
		scope                string
		presentedTypes       []string
		expectedIssuersMap   map[string][]configModel.TrustedIssuersList
		expectedParticipants map[string][]configModel.TrustedParticipantsList
		expectedError        error
	}

	tests := []test{
		{
			testName: "v5 issuers propagated from scope when all required types are presented",
			credentialScopes: map[string]map[string]configModel.ScopeEntry{
				"client-v5": {
					"v5-scope": {
						Credentials: []configModel.Credential{
							{
								Type: "VerifiableCredential",
								TrustedIssuersLists: configModel.TrustedIssuersLists{
									{Type: "ebsi-v5", Url: "https://til-v5.example.com"},
								},
								TrustedParticipantsLists: []configModel.TrustedParticipantsList{
									{Type: "ebsi-v5", Url: "https://tir-v5.example.com"},
								},
							},
						},
					},
				},
			},
			clientId:       "client-v5",
			scope:          "v5-scope",
			presentedTypes: []string{"VerifiableCredential"},
			expectedIssuersMap: map[string][]configModel.TrustedIssuersList{
				"VerifiableCredential": {
					{Type: "ebsi-v5", Url: "https://til-v5.example.com"},
				},
			},
			expectedParticipants: map[string][]configModel.TrustedParticipantsList{
				"VerifiableCredential": {
					{Type: "ebsi-v5", Url: "https://tir-v5.example.com"},
				},
			},
		},
		{
			testName: "missing required credential type returns error",
			credentialScopes: map[string]map[string]configModel.ScopeEntry{
				"client-v5": {
					"v5-scope": {
						Credentials: []configModel.Credential{
							{
								Type: "VerifiableCredential",
								TrustedIssuersLists: configModel.TrustedIssuersLists{
									{Type: "ebsi-v5", Url: "https://til-v5.example.com"},
								},
							},
						},
					},
				},
			},
			clientId:       "client-v5",
			scope:          "v5-scope",
			presentedTypes: []string{"OtherCredential"},
			expectedError:  ErrorRequiredCredentialNotProvided,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			mockConfig := mockCredentialConfig{mockScopes: tc.credentialScopes}
			v := CredentialVerifier{credentialsConfig: &mockConfig}

			ctx, err := v.getTrustRegistriesValidationContextFromScope(tc.clientId, tc.scope, tc.presentedTypes)

			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedIssuersMap, ctx.GetTrustedIssuersLists())
			assert.Equal(t, tc.expectedParticipants, ctx.GetTrustedParticipantLists())
		})
	}
}

// TestAuthenticationResponse_V5ValidationServices exercises the full
// AuthenticationResponse flow with "ebsi-v5" configured trust registries
// and a mocked validation service, verifying that the v5-typed trust config
// flows end-to-end through verification to JWT caching.
func TestAuthenticationResponse_V5ValidationServices(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	trueOption := true

	// Configure mock credentials with ebsi-v5 trust registries
	v5CredentialScopes := map[string]map[string]configModel.ScopeEntry{
		"clientId": {
			"": {
				Credentials: []configModel.Credential{
					{
						Type: "VerifiableCredential",
						TrustedIssuersLists: configModel.TrustedIssuersLists{
							{Type: "ebsi-v5", Url: "https://til-v5.example.com"},
						},
						TrustedParticipantsLists: []configModel.TrustedParticipantsList{
							{Type: "ebsi-v5", Url: "https://tir-v5.example.com"},
						},
						JwtInclusion: configModel.JwtInclusion{Enabled: &trueOption},
					},
				},
			},
		},
	}

	tests := []authTest{
		{
			testName:   "Same-device flow with ebsi-v5 trust registries succeeds when credential is valid.",
			sameDevice: true, testState: "login-state",
			testVP:             getVP([]string{"vc"}),
			testHolder:         "holder",
			testSession:        loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"},
			requestedState:     "login-state",
			verificationResult: []bool{true},
			expectedResponse:   Response{FlowVersion: SAME_DEVICE, RedirectTarget: "https://myhost.org/callback", Code: "authCode", SessionId: "my-session"},
		},
		{
			testName:   "Same-device flow with ebsi-v5 trust registries fails when credential is invalid.",
			sameDevice: true, testState: "login-state",
			testVP:             getVP([]string{"vc"}),
			testHolder:         "holder",
			testSession:        loginSession{version: SAME_DEVICE, callback: "https://myhost.org/callback", sessionId: "my-session", clientId: "clientId", requestObject: "requestObjectJwt"},
			requestedState:     "login-state",
			verificationResult: []bool{false},
			expectedError:      ErrorInvalidVC,
			expectedResponse:   Response{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			sessionCache := mockSessionCache{sessions: map[string]loginSession{}}
			if tc.testSession != (loginSession{}) {
				sessionCache.sessions[tc.testState] = tc.testSession
			}
			tokenCache := mockTokenCache{tokens: map[string]tokenStore{}, errorToThrow: tc.tokenCacheError}
			httpClient = mockHttpClient{tc.callbackError, nil}
			ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			testKey, _ := jwk.Import(ecdsaKey)
			_ = jwk.AssignKeyID(testKey)
			nonceGenerator := mockNonceGenerator{staticValues: []string{"authCode"}}
			credentialsConfig := mockCredentialConfig{mockScopes: v5CredentialScopes}

			validationServices := []ValidationService{
				&mockExternalSsiKit{
					verificationResults: tc.verificationResult,
					verificationError:   tc.verificationError,
				},
			}
			v := CredentialVerifier{
				did:                  "did:key:verifier",
				signingKey:           testKey,
				tokenCache:           &tokenCache,
				sessionCache:         &sessionCache,
				nonceGenerator:       &nonceGenerator,
				validationServices:   validationServices,
				clock:                mockClock{},
				credentialsConfig:    credentialsConfig,
				clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier"},
			}

			sameDeviceResponse, err := v.AuthenticationResponse(tc.requestedState, &tc.testVP)
			if tc.expectedError != nil {
				assert.Equal(t, tc.expectedError, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedResponse, sameDeviceResponse)
			_, found := tokenCache.tokens[sameDeviceResponse.Code]
			assert.True(t, found, "a token should be cached after successful authentication")
		})
	}
}

// TestGetHolderValidationContext verifies that one validation context is built per credential type with
// holder verification enabled. Every enabled type has to survive: dropping one silently skips its holder
// check in GenerateToken.
func TestGetHolderValidationContext(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	credentialsWithHolderVerification := func(credentials ...configModel.Credential) map[string]map[string]configModel.ScopeEntry {
		return map[string]map[string]configModel.ScopeEntry{
			"my-service": {"my-scope": configModel.ScopeEntry{Credentials: credentials}},
		}
	}
	enabled := func(credentialType, claim string) configModel.Credential {
		return configModel.Credential{Type: credentialType, HolderVerification: configModel.HolderVerification{Enabled: true, Claim: claim}}
	}
	disabled := func(credentialType string) configModel.Credential {
		return configModel.Credential{Type: credentialType, HolderVerification: configModel.HolderVerification{Enabled: false}}
	}

	type test struct {
		testName        string
		mockScopes      map[string]map[string]configModel.ScopeEntry
		mockError       error
		credentialTypes []string
		expectedClaims  []string
		expectedError   error
	}

	configError := errors.New("config_error")

	tests := []test{
		{testName: "Every type with holder verification enabled should get its own context.",
			mockScopes:      credentialsWithHolderVerification(enabled("TypeA", "subject"), enabled("TypeB", "sub.holder")),
			credentialTypes: []string{"TypeA", "TypeB"},
			expectedClaims:  []string{"subject", "sub.holder"}},
		{testName: "Types with holder verification disabled should be skipped.",
			mockScopes:      credentialsWithHolderVerification(enabled("TypeA", "subject"), disabled("TypeB"), enabled("TypeC", "otherClaim")),
			credentialTypes: []string{"TypeA", "TypeB", "TypeC"},
			expectedClaims:  []string{"subject", "otherClaim"}},
		{testName: "If no type has holder verification enabled, no context should be created.",
			mockScopes:      credentialsWithHolderVerification(disabled("TypeA"), disabled("TypeB")),
			credentialTypes: []string{"TypeA", "TypeB"},
			expectedClaims:  []string{}},
		{testName: "If the config cannot be read, the error should be returned.",
			mockScopes:      credentialsWithHolderVerification(enabled("TypeA", "subject")),
			mockError:       configError,
			credentialTypes: []string{"TypeA"},
			expectedError:   configError},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			v := CredentialVerifier{credentialsConfig: mockCredentialConfig{mockScopes: tc.mockScopes, mockError: tc.mockError}}

			validationContexts, err := v.getHolderValidationContext("my-service", "my-scope", tc.credentialTypes, "did:web:holder")

			if tc.expectedError != nil {
				assert.Equal(t, tc.expectedError, err)
				return
			}
			assert.NoError(t, err)

			claims := []string{}
			for _, validationContext := range validationContexts {
				claims = append(claims, validationContext.GetClaim())
				assert.Equal(t, "did:web:holder", validationContext.GetHolder(), "every context should carry the presented holder")
			}
			assert.Equal(t, tc.expectedClaims, claims)
		})
	}
}

// getVCWithHttpsIssuer creates a test credential where the Issuer.ID is an HTTPS URL
// instead of a DID. This simulates a credential issued by an HTTPS-based issuer.
func getVCWithHttpsIssuer(issuerURL string) *common.Credential {
	testTime, _ := time.Parse(time.RFC3339, "2022-11-23T15:23:13Z")
	vc, _ := common.CreateCredential(
		common.CredentialContents{
			Context: []string{
				"https://www.w3.org/2018/credentials/v1",
				"https://happypets.fiware.io/2022/credentials/employee/v1",
			},
			ID: "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
			Types: []string{
				"VerifiableCredential",
				"CustomerCredential",
			},
			Issuer:     &common.Issuer{ID: issuerURL},
			ValidFrom:  &testTime,
			ValidUntil: &testTime,
			Subject: []common.Subject{
				{
					ID: "holder-subject",
					CustomFields: map[string]interface{}{
						"type":   "gx:NaturalParticipent",
						"target": "did:ebsi:packetdelivery",
					},
				},
			},
		},
		common.CustomFields{},
	)
	return vc
}

// getVPWithHttpsIssuer creates a test presentation containing a credential from
// an HTTPS-based issuer. Used in integration-level tests for AuthenticationResponse.
func getVPWithHttpsIssuer(issuerURL string) common.Presentation {
	credentials := []*common.Credential{getVCWithHttpsIssuer(issuerURL)}
	vp, _ := common.NewPresentation(common.WithCredentials(credentials...))
	return *vp
}

// TestAuthenticationResponseHttpsIssuer verifies the full AuthenticationResponse
// flow when the credential issuer is identified by an HTTPS URL rather than a DID.
// The trust validation services (TrustedParticipantValidationService and
// TrustedIssuerValidationService) accept the HTTPS issuer via URL matching
// against the configured trust lists.
func TestAuthenticationResponseHttpsIssuer(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	const httpsIssuerURL = "https://issuer.example.com"

	const registryURL = "https://til-pdc.ebsi.fiware.dev"

	type httpsAuthTest struct {
		testName  string
		issuerURL string
		// trustedIssuersURL is the trusted-issuers-list entry: a registry
		// endpoint to query, or the wildcard that waives the lookup.
		trustedIssuersURL string
		// registeredIssuers are the identifiers the registry knows.
		registeredIssuers []string
		expectedError     error
		expectedResponse  Response
	}

	successResponse := Response{FlowVersion: SAME_DEVICE, RedirectTarget: "https://myhost.org/callback", Code: "authCode", SessionId: "my-session"}

	tests := []httpsAuthTest{
		{
			testName:          "HTTPS issuer registered at the configured registry should succeed (same device).",
			issuerURL:         httpsIssuerURL,
			trustedIssuersURL: registryURL,
			registeredIssuers: []string{httpsIssuerURL},
			expectedError:     nil,
			expectedResponse:  successResponse,
		},
		{
			testName:          "HTTPS issuer with a wildcard til skips the issuer lookup but still has to be a known participant.",
			issuerURL:         httpsIssuerURL,
			trustedIssuersURL: WILDCARD_TIL,
			registeredIssuers: []string{httpsIssuerURL},
			expectedError:     nil,
			expectedResponse:  successResponse,
		},
		{
			testName:          "HTTPS issuer unknown to the registry should fail at participant validation.",
			issuerURL:         httpsIssuerURL,
			trustedIssuersURL: registryURL,
			registeredIssuers: []string{},
			expectedError:     ErrorInvalidCredential,
		},
		{
			testName:          "HTTPS issuer equal to the configured registry URL must not be trusted.",
			issuerURL:         registryURL,
			trustedIssuersURL: registryURL,
			registeredIssuers: []string{},
			expectedError:     ErrorInvalidCredential,
		},
	}

	for _, tc := range tests {
		trueOption := true
		t.Run(tc.testName, func(t *testing.T) {
			sessionCache := mockSessionCache{sessions: map[string]loginSession{}}
			sessionCache.sessions["login-state"] = loginSession{
				version:       SAME_DEVICE,
				callback:      "https://myhost.org/callback",
				sessionId:     "my-session",
				clientId:      "clientId",
				requestObject: "requestObjectJwt",
			}

			tokenCache := mockTokenCache{tokens: map[string]tokenStore{}}

			ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			testKey, _ := jwk.Import(ecdsaKey)
			_ = jwk.AssignKeyID(testKey)

			nonceGenerator := mockNonceGenerator{staticValues: []string{"authCode"}}

			credentialsConfig := mockCredentialConfig{
				mockScopes: map[string]map[string]configModel.ScopeEntry{
					"clientId": {
						"": {
							Credentials: []configModel.Credential{
								{
									Type:                     "CustomerCredential",
									TrustedParticipantsLists: []configModel.TrustedParticipantsList{{Type: "ebsi", Url: registryURL}},
									TrustedIssuersLists:      configModel.TrustedIssuersLists{{Type: "ebsi", Url: tc.trustedIssuersURL}},
									JwtInclusion:             configModel.JwtInclusion{Enabled: &trueOption},
								},
							},
						},
					},
				},
			}

			// Use the real validation services with a mocked registry client:
			// an HTTPS issuer is resolved through the very same registry
			// lookups as a DID-based one.
			tirClient := mockTirClient{
				participantsList: tc.registeredIssuers,
				expectedIssuer:   getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "CustomerCredential", map[string][]interface{}{})}),
			}
			tpvs := &TrustedParticipantValidationService{tirClient: tirClient, gaiaXClient: mockGaiaXClient{}}
			tivs := &TrustedIssuerValidationService{tirClient: tirClient}
			validationServices := []ValidationService{tpvs, tivs}

			cv := CredentialVerifier{
				did:                  "did:key:verifier",
				signingKey:           testKey,
				tokenCache:           &tokenCache,
				sessionCache:         &sessionCache,
				nonceGenerator:       &nonceGenerator,
				validationServices:   validationServices,
				clock:                mockClock{},
				credentialsConfig:    credentialsConfig,
				clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier"},
			}

			vp := getVPWithHttpsIssuer(tc.issuerURL)
			sameDeviceResponse, err := cv.AuthenticationResponse("login-state", &vp)

			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError,
					"Expected error %v but got %v", tc.expectedError, err)
				return
			}
			assert.NoError(t, err, "AuthenticationResponse should succeed for HTTPS issuer")
			assert.Equal(t, tc.expectedResponse, sameDeviceResponse,
				"Response should match expected for HTTPS issuer")

			// Verify a token was cached
			_, found := tokenCache.tokens[sameDeviceResponse.Code]
			assert.True(t, found, "Token should be cached after successful authentication")
		})
	}
}

// TestGetTrustRegistriesValidationContextWithHttpsIssuerURLs verifies that
// getTrustRegistriesValidationContext correctly propagates HTTPS issuer URLs
// from the credential configuration through to the returned validation context.
func TestGetTrustRegistriesValidationContextWithHttpsIssuerURLs(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	const httpsIssuerURL = "https://issuer.example.com"
	const didBasedURL = "https://tir.ebsi.fiware.dev"

	type contextTest struct {
		testName           string
		credentialTypes    []string
		mockScopes         map[string]map[string]configModel.ScopeEntry
		expectedTILCount   map[string]int
		expectedTPLCount   map[string]int
		expectedIssuerURLs map[string][]string
		expectedPartURLs   map[string][]string
		expectedError      error
	}

	tests := []contextTest{
		{
			testName:        "HTTPS issuer URLs should be propagated in trusted issuers list",
			credentialTypes: []string{"CustomerCredential"},
			mockScopes: map[string]map[string]configModel.ScopeEntry{
				"serviceId": {
					"testScope": {
						Credentials: []configModel.Credential{
							{
								Type:                     "CustomerCredential",
								TrustedParticipantsLists: []configModel.TrustedParticipantsList{{Type: "ebsi", Url: httpsIssuerURL}},
								TrustedIssuersLists:      configModel.TrustedIssuersLists{{Type: "ebsi", Url: httpsIssuerURL}},
							},
						},
					},
				},
			},
			expectedTILCount:   map[string]int{"CustomerCredential": 1},
			expectedTPLCount:   map[string]int{"CustomerCredential": 1},
			expectedIssuerURLs: map[string][]string{"CustomerCredential": {httpsIssuerURL}},
			expectedPartURLs:   map[string][]string{"CustomerCredential": {httpsIssuerURL}},
		},
		{
			testName:        "Mixed HTTPS and DID-based URLs should both be propagated",
			credentialTypes: []string{"CustomerCredential"},
			mockScopes: map[string]map[string]configModel.ScopeEntry{
				"serviceId": {
					"testScope": {
						Credentials: []configModel.Credential{
							{
								Type: "CustomerCredential",
								TrustedParticipantsLists: []configModel.TrustedParticipantsList{
									{Type: "ebsi", Url: didBasedURL},
									{Type: "ebsi", Url: httpsIssuerURL},
								},
								TrustedIssuersLists: configModel.TrustedIssuersLists{
									{Type: "ebsi", Url: didBasedURL},
									{Type: "ebsi", Url: httpsIssuerURL},
								},
							},
						},
					},
				},
			},
			expectedTILCount:   map[string]int{"CustomerCredential": 2},
			expectedTPLCount:   map[string]int{"CustomerCredential": 2},
			expectedIssuerURLs: map[string][]string{"CustomerCredential": {didBasedURL, httpsIssuerURL}},
			expectedPartURLs:   map[string][]string{"CustomerCredential": {didBasedURL, httpsIssuerURL}},
		},
		{
			testName:        "Wildcard trusted issuer URL should be propagated",
			credentialTypes: []string{"CustomerCredential"},
			mockScopes: map[string]map[string]configModel.ScopeEntry{
				"serviceId": {
					"testScope": {
						Credentials: []configModel.Credential{
							{
								Type:                     "CustomerCredential",
								TrustedParticipantsLists: []configModel.TrustedParticipantsList{{Type: "ebsi", Url: "*"}},
								TrustedIssuersLists:      configModel.TrustedIssuersLists{{Type: "ebsi", Url: "*"}},
							},
						},
					},
				},
			},
			expectedTILCount:   map[string]int{"CustomerCredential": 1},
			expectedTPLCount:   map[string]int{"CustomerCredential": 1},
			expectedIssuerURLs: map[string][]string{"CustomerCredential": {"*"}},
			expectedPartURLs:   map[string][]string{"CustomerCredential": {"*"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			cv := CredentialVerifier{
				credentialsConfig: mockCredentialConfig{
					mockScopes: tc.mockScopes,
				},
			}

			ctx, err := cv.getTrustRegistriesValidationContext("serviceId", tc.credentialTypes, "testScope")

			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
				return
			}
			assert.NoError(t, err)

			// Verify trusted issuers lists
			til := ctx.GetTrustedIssuersLists()
			for credType, expectedCount := range tc.expectedTILCount {
				assert.Len(t, til[credType], expectedCount,
					"TIL count mismatch for credential type %s", credType)
			}
			for credType, expectedURLs := range tc.expectedIssuerURLs {
				actualURLs := make([]string, len(til[credType]))
				for i, entry := range til[credType] {
					actualURLs[i] = entry.Url
				}
				assert.Equal(t, expectedURLs, actualURLs,
					"TIL URLs mismatch for credential type %s", credType)
			}

			// Verify trusted participants lists
			tpl := ctx.GetTrustedParticipantLists()
			for credType, expectedCount := range tc.expectedTPLCount {
				assert.Len(t, tpl[credType], expectedCount,
					"TPL count mismatch for credential type %s", credType)
			}
			for credType, expectedURLs := range tc.expectedPartURLs {
				actualURLs := make([]string, len(tpl[credType]))
				for i, entry := range tpl[credType] {
					actualURLs[i] = entry.Url
				}
				assert.Equal(t, expectedURLs, actualURLs,
					"TPL URLs mismatch for credential type %s", credType)
			}
		})
	}
}

// TestAuthenticationResponseHttpsIssuerCrossDevice verifies that the
// AuthenticationResponse flow handles cross-device sessions correctly
// when the credential issuer is HTTPS-based.
func TestAuthenticationResponseHttpsIssuerCrossDevice(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	const httpsIssuerURL = "https://issuer.example.com"
	const registryURL = "https://til-pdc.ebsi.fiware.dev"

	sessionCache := mockSessionCache{sessions: map[string]loginSession{}}
	sessionCache.sessions["login-state"] = loginSession{
		version:       CROSS_DEVICE_V1,
		callback:      "https://myhost.org/callback",
		sessionId:     "my-session",
		clientId:      "clientId",
		requestObject: "requestObjectJwt",
	}

	trueOption := true
	tokenCache := mockTokenCache{tokens: map[string]tokenStore{}}
	httpClient = mockHttpClient{nil, nil}

	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testKey, _ := jwk.Import(ecdsaKey)
	_ = jwk.AssignKeyID(testKey)

	nonceGenerator := mockNonceGenerator{staticValues: []string{"authCode"}}

	credentialsConfig := mockCredentialConfig{
		mockScopes: map[string]map[string]configModel.ScopeEntry{
			"clientId": {
				"": {
					Credentials: []configModel.Credential{
						{
							Type:                     "CustomerCredential",
							TrustedParticipantsLists: []configModel.TrustedParticipantsList{{Type: "ebsi", Url: registryURL}},
							TrustedIssuersLists:      configModel.TrustedIssuersLists{{Type: "ebsi", Url: registryURL}},
							JwtInclusion:             configModel.JwtInclusion{Enabled: &trueOption},
						},
					},
				},
			},
		},
	}

	tirClient := mockTirClient{
		participantsList: []string{httpsIssuerURL},
		expectedIssuer:   getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "CustomerCredential", map[string][]interface{}{})}),
	}
	tpvs := &TrustedParticipantValidationService{tirClient: tirClient, gaiaXClient: mockGaiaXClient{}}
	tivs := &TrustedIssuerValidationService{tirClient: tirClient}

	cv := CredentialVerifier{
		did:                  "did:key:verifier",
		signingKey:           testKey,
		tokenCache:           &tokenCache,
		sessionCache:         &sessionCache,
		nonceGenerator:       &nonceGenerator,
		validationServices:   []ValidationService{tpvs, tivs},
		clock:                mockClock{},
		credentialsConfig:    credentialsConfig,
		clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier"},
	}

	vp := getVPWithHttpsIssuer(httpsIssuerURL)
	_, err := cv.AuthenticationResponse("login-state", &vp)

	assert.NoError(t, err, "AuthenticationResponse should succeed for cross-device HTTPS issuer")

	// Verify callback was called correctly
	expectedCallback := getRequest("https://myhost.org/callback?code=authCode&state=my-session")
	assert.Equal(t, expectedCallback, lastRequest,
		"Cross-device callback URL should contain auth code and state")
}

// TestAuthenticationResponseMultipleHttpsIssuers verifies that when a VP contains
// multiple credentials from different HTTPS-based issuers, the validation flow
// correctly handles each one via URL matching against the configured trust lists.
func TestAuthenticationResponseMultipleHttpsIssuers(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	const httpsIssuerURL1 = "https://issuer-one.example.com"
	const httpsIssuerURL2 = "https://issuer-two.example.com"
	const registryURL = "https://til-pdc.ebsi.fiware.dev"

	// Create a VP with two credentials from different HTTPS-based issuers.
	httpsVC1 := getVCWithHttpsIssuer(httpsIssuerURL1)
	httpsVC2 := getVCWithHttpsIssuer(httpsIssuerURL2)

	vp, _ := common.NewPresentation(common.WithCredentials(httpsVC1, httpsVC2))

	sessionCache := mockSessionCache{sessions: map[string]loginSession{}}
	sessionCache.sessions["login-state"] = loginSession{
		version:       SAME_DEVICE,
		callback:      "https://myhost.org/callback",
		sessionId:     "my-session",
		clientId:      "clientId",
		requestObject: "requestObjectJwt",
	}

	trueOption := true
	tokenCache := mockTokenCache{tokens: map[string]tokenStore{}}

	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testKey, _ := jwk.Import(ecdsaKey)
	_ = jwk.AssignKeyID(testKey)

	nonceGenerator := mockNonceGenerator{staticValues: []string{"authCode"}}

	// A single registry endpoint; both HTTPS issuers are registered there.
	credentialsConfig := mockCredentialConfig{
		mockScopes: map[string]map[string]configModel.ScopeEntry{
			"clientId": {
				"": {
					Credentials: []configModel.Credential{
						{
							Type: "CustomerCredential",
							TrustedParticipantsLists: []configModel.TrustedParticipantsList{
								{Type: "ebsi", Url: registryURL},
							},
							TrustedIssuersLists: configModel.TrustedIssuersLists{
								{Type: "ebsi", Url: registryURL},
							},
							JwtInclusion: configModel.JwtInclusion{Enabled: &trueOption},
						},
					},
				},
			},
		},
	}

	tirClient := mockTirClient{
		participantsList: []string{httpsIssuerURL1, httpsIssuerURL2},
		expectedIssuer:   getTrustedIssuer([]tir.IssuerAttribute{getAttribute(tir.TimeRange{}, "CustomerCredential", map[string][]interface{}{})}),
	}
	tpvs := &TrustedParticipantValidationService{tirClient: tirClient, gaiaXClient: mockGaiaXClient{}}
	tivs := &TrustedIssuerValidationService{tirClient: tirClient}

	cv := CredentialVerifier{
		did:                  "did:key:verifier",
		signingKey:           testKey,
		tokenCache:           &tokenCache,
		sessionCache:         &sessionCache,
		nonceGenerator:       &nonceGenerator,
		validationServices:   []ValidationService{tpvs, tivs},
		clock:                mockClock{},
		credentialsConfig:    credentialsConfig,
		clientIdentification: configModel.ClientIdentification{Id: "did:key:verifier"},
	}

	sameDeviceResponse, err := cv.AuthenticationResponse("login-state", vp)

	assert.NoError(t, err, "AuthenticationResponse should succeed with multiple HTTPS issuers")
	assert.Equal(t, SAME_DEVICE, sameDeviceResponse.FlowVersion)
	assert.Equal(t, "https://myhost.org/callback", sameDeviceResponse.RedirectTarget)
}

// --- verifyVPSignatureIfRequired: JSON-LD VP path tests ---

// testServiceID and testScope are shared constants for holder binding test configs.
const testServiceID = "test-client"
const testScope = "openid"
const testCredentialType = "VerifiableCredential"

// TestVerifyVPSignatureIfRequired_JSONLDVPs uses table-driven tests to verify
// that verifyVPSignatureIfRequired handles JSON-LD VPs correctly. It covers:
// - No holder binding required: always succeeds
// - Holder binding required with HolderKey present: succeeds
// - Holder binding required with HolderKey absent: returns ErrorHolderBindingMissingKey
// - No LD proofs and no raw token (JWT VP path): no-op
func TestVerifyVPSignatureIfRequired_JSONLDVPs(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	// Generate a JWK for use as a holder key.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	holderJWK, err := jwk.Import(&ecKey.PublicKey)
	assert.NoError(t, err)

	type testCase struct {
		name           string
		holderRequired bool
		hasProofs      bool
		hasHolderKey   bool
		holder         string
		expectedErr    error
	}

	tests := []testCase{
		{
			name:           "no_holder_binding_required_with_ld_proofs",
			holderRequired: false,
			hasProofs:      true,
			hasHolderKey:   false,
			expectedErr:    nil,
		},
		{
			name:           "holder_binding_required_with_holder_key_present",
			holderRequired: true,
			hasProofs:      true,
			hasHolderKey:   true,
			holder:         "did:web:holder.example.com",
			expectedErr:    nil,
		},
		{
			name:           "holder_binding_required_without_holder_key",
			holderRequired: true,
			hasProofs:      true,
			hasHolderKey:   false,
			holder:         "did:web:holder.example.com",
			expectedErr:    ErrorHolderBindingMissingKey,
		},
		{
			// A holder key without a holder proves control of some key, but
			// not of the presenter identity.
			name:           "holder_binding_required_without_holder",
			holderRequired: true,
			hasProofs:      true,
			hasHolderKey:   true,
			holder:         "",
			expectedErr:    ErrorHolderBindingMissingKey,
		},
		{
			name:           "no_proofs_no_raw_token_jwt_path_noop",
			holderRequired: true,
			hasProofs:      false,
			hasHolderKey:   false,
			expectedErr:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set up mock credentials config with holder verification as required.
			mockScopes := createMockCredentials(
				testServiceID, testScope, testCredentialType,
				"https://tir.example.com", "sub", tc.holderRequired,
			)

			verifier := CredentialVerifier{
				credentialsConfig: mockCredentialConfig{mockScopes: mockScopes},
			}

			// Build a presentation with optional LD proofs and holder key.
			pres, _ := common.NewPresentation()
			if tc.hasProofs {
				pres.Proofs = []*common.LDProof{{
					Type:               common.ProofTypeJsonWebSignature2020,
					VerificationMethod: "did:web:holder.example.com#key-1",
					JWS:                "dummy-jws-value",
				}}
			}
			if tc.hasHolderKey {
				pres.SetHolderKey(holderJWK)
			}
			pres.Holder = tc.holder

			err := verifier.verifyVPSignatureIfRequired(
				testServiceID,
				[]string{testScope},
				[]string{testCredentialType},
				pres,
			)

			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr, "expected %v, got %v", tc.expectedErr, err)
			} else {
				assert.NoError(t, err, "expected no error, got %v", err)
			}
		})
	}
}

// TestVerifyVPSignatureIfRequired_ConfigError verifies that a credentials config
// error is propagated correctly when checking JSON-LD VP holder binding.
func TestVerifyVPSignatureIfRequired_ConfigError(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	verifier := CredentialVerifier{
		credentialsConfig: mockCredentialConfig{
			mockScopes: createMockCredentials(testServiceID, testScope, testCredentialType, "https://tir.example.com", "sub", true),
			mockError:  errors.New("config unavailable"),
		},
	}

	pres, _ := common.NewPresentation()
	pres.Proofs = []*common.LDProof{{
		Type: common.ProofTypeJsonWebSignature2020,
		JWS:  "dummy-jws",
	}}

	err := verifier.verifyVPSignatureIfRequired(
		testServiceID,
		[]string{testScope},
		[]string{testCredentialType},
		pres,
	)
	assert.ErrorIs(t, err, ErrorVerficationContextSetup)
}
