package tir

import (
	"errors"
	"strings"
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
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/piprate/json-gold/ld"
)

// testVerificationMethod is an absolute DID URL. A relative value (such as
// the bare "JsonWebKey2020" default) is dropped during JSON-LD expansion and
// would therefore not be covered by the proof signature.
const testVerificationMethod = "did:web:test.org#key-1"

type mockFileAccessor struct {
	files  map[string][]byte
	errors map[string]error
}

func (mfa mockFileAccessor) ReadFile(filename string) ([]byte, error) {
	return mfa.files[filename], mfa.errors[filename]
}

func TestTokenProvider_GetToken(t *testing.T) {
	type test struct {
		testName          string
		testKey           *rsa.PrivateKey
		testCredential    *common.Credential
		keyType           string
		expectedAlgorithm string
		expectedError     bool
	}

	tests := []test{
		{testName: "A valid token should be returned.", testKey: getRandomRsaKey(), testCredential: getTestAuthCredential(), keyType: KeyTypeRSAPS256, expectedAlgorithm: AlgorithmPS256},
		{testName: "A token signed with an RS256 key should be returned.", testKey: getRandomRsaKey(), testCredential: getTestAuthCredential(), keyType: KeyTypeRSARS256, expectedAlgorithm: AlgorithmRS256},
		{testName: "A presentation without an explicit context should still be signed verifiably.", testKey: getRandomRsaKey(), testCredential: getNoContextAuthCredential(), keyType: KeyTypeRSAPS256, expectedAlgorithm: AlgorithmPS256},
		{testName: "If credential with an invalid context is provided, no token should be returned", testKey: getRandomRsaKey(), testCredential: getInvalidContextAuthCredential(), keyType: KeyTypeRSAPS256, expectedError: true},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			tokenProvider := M2MTokenProvider{
				tokenEncoder:       Base64TokenEncoder{},
				signingKey:         tc.testKey,
				clock:              common.RealClock{},
				verificationMethod: testVerificationMethod,
				signatureType:      common.ProofTypeJsonWebSignature2020,
				keyType:            tc.keyType,
				documentLoader:     testDocumentLoader(),
			}

			token, err := tokenProvider.GetToken(tc.testCredential, "myAudience")
			if tc.expectedError {
				if err == nil {
					t.Errorf("%s - Expected error but none was returned.", tc.testName)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s - Expected no error but got: %v", tc.testName, err)
			}
			bytes, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				t.Fatalf("%s - Token should be properly encoded. Err: %v", tc.testName, err)
			}
			var vpObjectMap map[string]json.RawMessage
			err = json.Unmarshal(bytes, &vpObjectMap)
			if err != nil {
				t.Fatalf("%s - Token should contain json. Err: %v", tc.testName, err)
			}
			_, credentialsExits := vpObjectMap["verifiableCredential"]
			proofRaw, proofExists := vpObjectMap["proof"]
			if !credentialsExits {
				t.Errorf("%s - Token should contain the credential.", tc.testName)
			}
			if !proofExists {
				t.Fatalf("%s - Token should contain a proof.", tc.testName)
			}

			// The emitted presentation has to verify against its own proof —
			// which only holds if the signed @context, the advertised
			// algorithm and the signature algorithm all agree.
			assertPresentationProofVerifies(t, tc.testName, bytes, proofRaw, tc.expectedAlgorithm, &tc.testKey.PublicKey)
		})
	}
}

// mockDocumentLoader records calls and delegates to a real default loader.
type mockDocumentLoader struct {
	delegate  ld.DocumentLoader
	callCount int
}

func (m *mockDocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	m.callCount++
	return m.delegate.LoadDocument(u)
}

func TestTokenProvider_GetToken_UsesInjectedDocumentLoader(t *testing.T) {
	mock := &mockDocumentLoader{
		delegate: testDocumentLoader(),
	}

	tokenProvider := M2MTokenProvider{
		tokenEncoder:       Base64TokenEncoder{},
		signingKey:         getRandomRsaKey(),
		clock:              common.RealClock{},
		verificationMethod: testVerificationMethod,
		signatureType:      common.ProofTypeJsonWebSignature2020,
		keyType:            KeyTypeRSAPS256,
		documentLoader:     mock,
	}

	_, err := tokenProvider.GetToken(getTestAuthCredential(), "myAudience")
	if err != nil {
		t.Fatalf("Expected no error but got: %v", err)
	}
	if mock.callCount == 0 {
		t.Error("Expected the injected document loader to be called at least once during signing")
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
		{testName: "Without a did, no provider should be configured.", testConfig: getConfig("", testVerificationMethod, common.ProofTypeJsonWebSignature2020, KeyTypeRSAPS256), expectedError: ErrorTokenProviderNoDid},
		{testName: "Without a verification method, no provider should be configured.", testConfig: getConfig("did:web:test.org", "", common.ProofTypeJsonWebSignature2020, KeyTypeRSAPS256), expectedError: ErrorTokenProviderNoVerificationMethod},
		{testName: "With a relative verification method, no provider should be configured.", testConfig: getConfig("did:web:test.org", "JsonWebKey2020", common.ProofTypeJsonWebSignature2020, KeyTypeRSAPS256), expectedError: ErrorTokenProviderNoVerificationMethod},
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

// getNoContextAuthCredential returns a credential without an explicit
// @context. Presentation.MarshalJSON defaults it to credentials/v1, so the
// signed document and the emitted presentation must agree on that default.
func getNoContextAuthCredential() *common.Credential {
	now := time.Now()
	contents := common.CredentialContents{
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
			VerificationMethod: testVerificationMethod,
			SignatureType:      common.ProofTypeJsonWebSignature2020,
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

// testDocumentLoader serves the vendored security contexts from the binary and
// resolves nothing else. Signing tests must not depend on network access.
func testDocumentLoader() ld.DocumentLoader {
	return common.NewVerificationDocumentLoader(nil)
}

// assertPresentationProofVerifies re-verifies the proof of an emitted
// presentation against the signing key, and checks that the JWS header
// advertises the expected algorithm.
func assertPresentationProofVerifies(t *testing.T, testName string, vpJSON []byte, proofRaw json.RawMessage, expectedAlgorithm string, publicKey *rsa.PublicKey) {
	t.Helper()

	var proofMap map[string]interface{}
	if err := json.Unmarshal(proofRaw, &proofMap); err != nil {
		t.Fatalf("%s - Proof should be a json object. Err: %v", testName, err)
	}
	proof, err := common.ParseLDProof(proofMap)
	if err != nil {
		t.Fatalf("%s - Proof should be parseable. Err: %v", testName, err)
	}

	if algorithm := jwsHeaderAlgorithm(t, testName, proof.JWS); algorithm != expectedAlgorithm {
		t.Errorf("%s - Proof should advertise algorithm %s but was %s.", testName, expectedAlgorithm, algorithm)
	}

	key, err := jwk.Import(publicKey)
	if err != nil {
		t.Fatalf("%s - Public key should be importable. Err: %v", testName, err)
	}
	if err := common.VerifyLinkedDataProof(vpJSON, proof, key, testDocumentLoader()); err != nil {
		t.Errorf("%s - The emitted presentation should verify against its own proof. Err: %v", testName, err)
	}
}

// jwsHeaderAlgorithm extracts the `alg` header value from a detached JWS.
func jwsHeaderAlgorithm(t *testing.T, testName string, detachedJWS string) string {
	t.Helper()

	header, _, found := strings.Cut(detachedJWS, ".")
	if !found {
		t.Fatalf("%s - Proof should contain a detached jws but was %q.", testName, detachedJWS)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("%s - The jws header should be base64url encoded. Err: %v", testName, err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(headerJSON, &parsed); err != nil {
		t.Fatalf("%s - The jws header should be json. Err: %v", testName, err)
	}
	algorithm, _ := parsed[common.JWSHeaderAlg].(string)
	return algorithm
}
