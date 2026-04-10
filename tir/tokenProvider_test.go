package tir

import (
	"errors"
	"testing"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
)

type mockFileAccessor struct {
	files  map[string][]byte
	errors map[string]error
}

func (mfa mockFileAccessor) ReadFile(filename string) ([]byte, error) {
	return mfa.files[filename], mfa.errors[filename]
}

func TestTokenProvider_GetToken(t *testing.T) {
	type test struct {
		testName       string
		testKey        *rsa.PrivateKey
		testCredential *common.Credential
		expectedError  bool
	}

	tests := []test{
		{testName: "A valid token should be returned.", testKey: getRandomRsaKey(), testCredential: getTestAuthCredential()},
		{testName: "If credential with an invalid context is provided, no token should be returned", testKey: getRandomRsaKey(), testCredential: getInvalidContextAuthCredential(), expectedError: true},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			tokenProvider := M2MTokenProvider{tokenEncoder: Base64TokenEncoder{}, signingKey: tc.testKey, clock: common.RealClock{}, verificationMethod: "JsonWebKey2020", signatureType: "JsonWebSignature2020", keyType: "RSAPS256"}

			token, err := tokenProvider.GetToken(tc.testCredential, "myAudience")
			if tc.expectedError && err == nil {
				t.Errorf("%s - Expected error but none was returned.", tc.testName)
			} else {
				return
			}
			bytes, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				t.Errorf("%s - Token should be properly encoded. Err: %v", tc.testName, err)
			}
			var vpObjectMap map[string]json.RawMessage
			err = json.Unmarshal(bytes, &vpObjectMap)
			if err != nil {
				t.Errorf("%s - Token should contain json. Err: %v", tc.testName, err)
			}
			_, credentialsExits := vpObjectMap["verifiableCredential"]
			_, proofExists := vpObjectMap["proof"]
			if !credentialsExits {
				t.Errorf("%s - Token should contain the credential.", tc.testName)
			}
			if !proofExists {
				t.Errorf("%s - Token should contain a proof.", tc.testName)
			}
		})
	}
}

func TestTokenProvider_InitM2MTokenProvider(t *testing.T) {

	type test struct {
		testName        string
		testConfig      configModel.Configuration
		fileAccessError map[string]error
		expectedError   error
	}

	noKeyError := errors.New("no_key")
	noCredError := errors.New("no_cred")

	tests := []test{
		{testName: "A token provider should have been initiated for a valid config.", testConfig: getInitialConfig()},
		{testName: "Without a did, no provider should be configured.", testConfig: getConfig("", "JsonWebKey2020", "JsonWebSignature2020", "RSAPS256"), expectedError: ErrorTokenProviderNoDid},
		{testName: "Without a verification method, no provider should be configured.", testConfig: getConfig("did:web:test.org", "", "JsonWebSignature2020", "RSAPS256"), expectedError: ErrorTokenProviderNoVerificationMethod},
		{testName: "Without a credential, no provider should be configured.", testConfig: getInitialConfig(), fileAccessError: map[string]error{"/test/credential.json": noCredError}, expectedError: noCredError},
		{testName: "Without a key, no provider should be configured.", testConfig: getInitialConfig(), fileAccessError: map[string]error{"/test/key.tls": noKeyError}, expectedError: noKeyError},
	}
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			localFileAccessor = mockFileAccessor{files: map[string][]byte{"/test/key.tls": getRandomSigningKey(), "/test/credential.json": getTestCredential()}, errors: tc.fileAccessError}
			_, err := InitM2MTokenProvider(&tc.testConfig, common.RealClock{})
			if tc.expectedError != err {
				t.Errorf("%s - Expected error %v but was %v.", tc.testName, tc.expectedError, err)
			}
		})
	}
}

func getRandomRsaKey() *rsa.PrivateKey {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return key
}

func getRandomSigningKey() []byte {

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(getRandomRsaKey()),
		},
	)
}

func getTestAuthCredential() *common.Credential {
	now := time.Now()
	contents := common.CredentialContents{
		Context:   []string{common.ContextCredentialsV1},
		Types:     []string{common.TypeVerifiableCredential},
		ID:        "urn:uuid:aee3ffc9-9700-4e7e-b903-039c446d1bfe",
		Issuer:    &common.Issuer{ID: "did:web:test.org"},
		ValidFrom: &now,
		Subject:   []common.Subject{{ID: "urn:uuid:credenital"}},
	}
	vc, _ := common.CreateCredential(contents, common.CustomFields{})
	return vc
}

func getInvalidContextAuthCredential() *common.Credential {
	now := time.Now()
	contents := common.CredentialContents{
		Context:   []string{"https://this.is.nowhere.org"},
		Types:     []string{common.TypeVerifiableCredential},
		ID:        "urn:uuid:aee3ffc9-9700-4e7e-b903-039c446d1bfe",
		Issuer:    &common.Issuer{ID: "did:web:test.org"},
		ValidFrom: &now,
		Subject:   []common.Subject{{ID: "urn:uuid:credenital"}},
	}
	vc, _ := common.CreateCredential(contents, common.CustomFields{})
	return vc
}

func getTestCredential() []byte {
	return []byte(testCredential)
}

func getInitialConfig() configModel.Configuration {
	return configModel.Configuration{
		Verifier: configModel.Verifier{Did: "did:web:my.did"},
		M2M: configModel.M2M{
			KeyPath:            "/test/key.tls",
			CredentialPath:     "/test/credential.json",
			VerificationMethod: "JsonWebKey2020",
			SignatureType:      "JsonWebSignature2020",
			KeyType:            KeyTypeRSAPS256,
		},
	}
}

func getConfig(did string, method string, signature string, key string) configModel.Configuration {

	config := getInitialConfig()
	config.Verifier.Did = did
	config.M2M.KeyType = key
	config.M2M.VerificationMethod = method
	config.M2M.SignatureType = signature

	return config
}

const testCredential = "{   \"type\": [      \"VerifiableCredential\"    ],    \"@context\": [      \"https://www.w3.org/2018/credentials/v1\",      \"https://w3id.org/security/suites/jws-2020/v1\"    ],    \"id\": \"urn:uuid:aee3ffc9-9700-4e7e-b903-039c446d1bfe\",    \"issuer\": \"did:web:marketplace.dsba.fiware.dev:did\",    \"issuanceDate\": \"2023-12-05T14:05:16Z\",    \"issued\": \"2023-12-05T14:05:16Z\",    \"validFrom\": \"2023-12-05T14:05:16Z\",    \"credentialSubject\": {      \"id\": \"06713097-5bd1-45fd-ba31-23aca2f7b715\",      \"roles\": [        {          \"names\": [            \"TIR_READER\"          ],          \"target\": \"did:web:onboarding.dsba.fiware.dev:did\"        }      ]    },    \"proof\": {      \"type\": \"JsonWebSignature2020\",      \"created\": \"2023-12-05T14:05:17Z\",      \"verificationMethod\": \"did:web:marketplace.dsba.fiware.dev:did#6f4c1255f4a54090bc8ff7365b13a9b7\",      \"jws\": \"eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJQUzI1NiJ9..QqlbI05RDBEA8Km4BsEr6Zdxnmjng3WXHq3fY9548gxwf0QGbEBxcbCm7_8QCJcTAxXfjK6uqyeWcDUIPpurBnIDI0s6x8THHp3Z1a3kFK-HhwK88eq29oFt5XkpfiiF-nmGoc1S1eEj4WMAi0O86KOI2LY3JjcUw6P-uT3PADyqOZdCTV0uGIZXML4V1awGH3QAN329rLOZJMOUf47DqF88OKgtFz4nuw64CSei-nsirrLgM7__Zv-xi42yeYUy_pInRsgpPAzg5niGCtUOJfI-LIPYWKJP3d7K8ZKPZn61_QYUwSdPhj7jVIbYswQQy5BSG5VFDpqFoBzJ5WO8qQ\"    }}"
