package tir

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"

	"github.com/stretchr/testify/assert"
)

const ISHARE_EXAMPLE = "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/suites/jws-2020/v1\"],\"id\":\"did:elsi:eu.eori.denhaag19902304\",\"verificationMethod\":[{\"id\":\"did:elsi:eu.eori.denhaag19902304#key-assertion\",\"type\":\"JsonWebKey2020\",\"controller\":\"did:elsi:eu.eori.denhaag19902304\",\"publicKeyJwk\":{\"kid\":\"key-assertion\",\"kty\":\"RSA\",\"x5c\":[\"MIIEzDCCA7SgAwIBAgIIU2Bx+k6hNH8wDQYJKoZIhvcNAQELBQAwPDE6MDgGA1UEAwwxVEVTVCBpU0hBUkUgRVUgSXNzdWluZyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBHNTAeFw0yMzA1MjAwOTQ5NThaFw0yNjA1MTkwOTQ5NTdaMFgxETAPBgNVBAMMCG1hbnNwYWNlMSAwHgYDVQQFExdFVS5FT1JJLkRFTkhBQUcxOTkwMjMwNDESMBAGA1UECgwJU2VydmJsb2NrMQ0wCwYDVQQGEwRJRS1EMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlIeNCe+HoNrmGHdi3ZWnu4jmuaRRgog+JV0+7hMBhSDTI/gwcfhn9xIJ8qpmvGm2PxHkHX4o1VLDg/02Ii0mkyPg9Tc0e6x0rCMwRiN1ANShTRwyPumcOoA9FiKR6tPjwm32sOEqxw9Cs2PWtsWpONlDRySWmM8l99o4tnsQHKWNnsJPwgURwXbmGNKRKUePIRmU4fA0k/NZSpy6rkjYpLkXWt3RaPhsqp7ZR4cNU9/MKJgA9EsDJgXkkMYh90/lBoU8Q4GBOgOF4Rk4iuIQUhN0DcBaNZKtN4BYxmT91I7IXnUfTo1LjSjSFozS59ERNsqEk5AvoMcjgCHhsuLVYY8o9rU7e+whO9U43wNhI9CzBvUZM7dr66hi4Rn10w4aV5Fufzs6w+wMRKjDVRLZTUWrpyW9O6Tq7qpUC0k7HwXTZryGP6LORz/9isW4NlgLD5P3ayK+QS7WfgxkGZF19y2UHeC1iCw9C8F6OY1T4ScMc3xLBGfIE/GqYdq/tj6fafRJvL9al5Yp9+VBw1HOXnwdWuixT7AXQOKX5/l6HxYlzgOMJpKdB0MKIP9AkEEzlE7P90AiUagunc/pLzqVJSlpL7EMMKFtU+uBLB6Jv837wHc/QotFdDkCjqxN7w2GUIjpFQImoYiuBmNC/vUmkVZk7UHfjDOIbuPyvLHkf6kCAwEAAaOBtTCBsjAfBgNVHSMEGDAWgBRtxWWJy9+RVNFrPLcCpS7NimiQHTAnBgNVHSUEIDAeBggrBgEFBQcDAgYIKwYBBQUHAwQGCCsGAQUFBwMBMDcGCCsGAQUFBwEDBCswKTAIBgYEAI5GAQEwCAYGBACORgEEMBMGBgQAjkYBBjAJBgcEAI5GAQYCMB0GA1UdDgQWBBTaFjV/ENI1bpHim18LXUXoglLjrzAOBgNVHQ8BAf8EBAMCBsAwDQYJKoZIhvcNAQELBQADggEBAJEdDj9d8KNbIwgC066JXP1cQSaI9yeEoCWWx2RVQrZzcsYyNWyJRZVgHP56Q4U/HTB76JZ9yGhqD8Ns2XiUCcKAxhz5Lt+bM0FLrYKoGV37+ke7PhM4+QlGOZx8y9w9ASqwgxMGVyj9KLp5u+nHVgxcR7h2LKqpC7c6SiLREdtnvqOEB8/OGG57vZ5ruZG6f3H0A03LI7z0vBUbfhlptoC4lB6I7FG0Z3buu3R3Wc6LX6vWFxiC34MGD8y71tSYUgGlAcm+HjU/6o3L/ajVkYhS3XbrrpJ2X/2dfJY5m2ZyQAHKsHH1WczXG/i2oPgXhy/2esdl5H/AXkyHMARY2Dk=\"]}}],\"authentication\":[\"did:elsi:eu.eori.denhaag19902304#key-assertion\"],\"assertionMethod\":[\"did:elsi:eu.eori.denhaag19902304#key-assertion\"]}"

type getClient struct {
	client *http.Client
}

func (gc getClient) Get(tirAddress string, tirPath string) (resp *http.Response, err error) {
	return gc.client.Get(tirAddress + "/" + tirPath)
}

type mockClient struct {
	responses map[string]*http.Response
	errors    map[string]error
}

func (mc mockClient) Get(tirAddress string, tirPath string) (resp *http.Response, err error) {
	return mc.responses[tirAddress+"/"+tirPath], mc.errors[tirAddress+"/"+tirPath]
}

type mockCache struct{}

func (mc mockCache) Add(k string, x interface{}, d time.Duration) error { return nil }
func (mc mockCache) Set(k string, x interface{}, d time.Duration)       {}
func (mc mockCache) Get(k string) (interface{}, bool)                   { return nil, false }
func (mc mockCache) Delete(k string)                                    {}
func (mc mockCache) GetWithExpiration(k string) (interface{}, time.Time, bool) {
	return nil, time.Now(), false
}

func TestIsTrustedParticipant(t *testing.T) {
	type test struct {
		testName       string
		testIssuer     string
		testEndpoint   string
		mockResponses  map[string]*http.Response
		mockErrors     map[string]error
		expectedResult bool
	}
	tests := []test{
		{testName: "The issuer should have been returned.", testIssuer: "did:web:test.org", testEndpoint: "https://my-tir.org",
			mockResponses: map[string]*http.Response{"https://my-tir.org/v4/issuers/did:web:test.org": getIssuerResponse("did:web:test.org")}, expectedResult: true},
		{testName: "The issuer should not be returned, if its nowhere found.", testIssuer: "did:web:test.org", testEndpoint: "https://my-other-tir.org",
			mockResponses: map[string]*http.Response{"https://my-other-tir.org/v4/issuers/did:web:test.org": getNotFoundResponse(), "https://my-tir.org/v4/issuers/did:web:test.org": getNotFoundResponse()}, expectedResult: false},
		{testName: "The issuer not should be returned, if an error is thrown at the endpoint.", testIssuer: "did:web:test.org", testEndpoint: "https://my-erronous-tir.org",
			mockErrors: map[string]error{"https://https://my-erronous-tir.org/v4/issuers/did:web:test.org": errors.New("something_bad")}, expectedResult: false},
		{testName: "The issuer not should be returned, if the response cannot be parsed.", testIssuer: "did:web:test.org", testEndpoint: "https://my-erronous-tir.org",
			mockResponses: map[string]*http.Response{"https://https://my-erronous-tir.org/v4/issuers/did:web:test.org": getUnparsableResponse()}, expectedResult: false},
	}

	for _, tc := range tests {
		common.ResetGlobalCache()
		t.Run(tc.testName, func(t *testing.T) {
			tirClient := TirHttpClient{client: mockClient{responses: tc.mockResponses, errors: tc.mockErrors}, tilCache: mockCache{}, tirCache: mockCache{}}
			isTrusted := tirClient.IsTrustedParticipant(tc.testEndpoint, tc.testIssuer)

			if tc.expectedResult != isTrusted {
				t.Errorf("%s - Expected the issuer to be trusted %v but was %v.", tc.testName, tc.expectedResult, isTrusted)
			}
		})
	}

}

func TestGetTrustedIssuer(t *testing.T) {
	type test struct {
		testName       string
		testIssuer     string
		testEndpoints  []string
		mockResponses  map[string]*http.Response
		mockErrors     map[string]error
		expectedIssuer string
		expectExists   bool
		expectedError  error
	}
	tests := []test{
		{testName: "The issuer should have been returned.", testIssuer: "did:web:test.org", testEndpoints: []string{"https://my-tir.org"},
			mockResponses: map[string]*http.Response{"https://my-tir.org/v4/issuers/did:web:test.org": getIssuerResponse("did:web:test.org")}, expectExists: true, expectedIssuer: "did:web:test.org"},
		{testName: "The issuer should be returned, if its found at one of the endpoints", testIssuer: "did:web:test.org", testEndpoints: []string{"https://my-other-tir.org", "https://my-tir.org"},
			mockResponses: map[string]*http.Response{"https://my-other-tir.org/v4/issuers/did:web:test.org": getNotFoundResponse(), "https://my-tir.org/v4/issuers/did:web:test.org": getIssuerResponse("did:web:test.org")}, expectExists: true, expectedIssuer: "did:web:test.org"},
		{testName: "The issuer should not be returned, if its nowhere found.", testIssuer: "did:web:test.org", testEndpoints: []string{"https://my-other-tir.org", "https://my-tir.org"},
			mockResponses: map[string]*http.Response{"https://my-other-tir.org/v4/issuers/did:web:test.org": getNotFoundResponse(), "https://my-tir.org/v4/issuers/did:web:test.org": getNotFoundResponse()}, expectExists: false},
		{testName: "The issuer should be returned, even if an error is thrown at one endpoint.", testIssuer: "did:web:test.org", testEndpoints: []string{"https://my-other-tir.org", "https://my-tir.org"},
			mockResponses: map[string]*http.Response{"https://my-tir.org/v4/issuers/did:web:test.org": getIssuerResponse("did:web:test.org")}, mockErrors: map[string]error{"https://my-other-tir.org/v4/issuers/did:web:test.org": errors.New("something_bad")}, expectExists: true, expectedIssuer: "did:web:test.org"},
		{testName: "The issuer should be returned, even if something unparsable is returned at one endpoint.", testIssuer: "did:web:test.org", testEndpoints: []string{"https://my-other-tir.org", "https://my-tir.org"},
			mockResponses: map[string]*http.Response{"https://my-other-tir.org/v4/issuers/did:web:test.org": getUnparsableResponse(), "https://my-tir.org/v4/issuers/did:web:test.org": getIssuerResponse("did:web:test.org")}, expectExists: true, expectedIssuer: "did:web:test.org"},
		{testName: "The issuer not should be returned, if an error is thrown at the endpoint.", testIssuer: "did:web:test.org", testEndpoints: []string{"https://my-erronous-tir.org"},
			mockErrors: map[string]error{"https://https://my-erronous-tir.org/v4/issuers/did:web:test.org": errors.New("something_bad")}, expectExists: false},
		{testName: "The issuer not should be returned, if the response cannot be parsed.", testIssuer: "did:web:test.org", testEndpoints: []string{"https://my-erronous-tir.org"},
			mockResponses: map[string]*http.Response{"https://https://my-erronous-tir.org/v4/issuers/did:web:test.org": getUnparsableResponse()}, expectExists: false},
	}

	for _, tc := range tests {
		common.ResetGlobalCache()
		t.Run(tc.testName, func(t *testing.T) {
			tirClient := TirHttpClient{client: mockClient{responses: tc.mockResponses, errors: tc.mockErrors}, tilCache: mockCache{}, tirCache: mockCache{}}
			exists, issuer, err := tirClient.GetTrustedIssuer(tc.testEndpoints, tc.testIssuer)
			if tc.expectedError != err {
				t.Errorf("%s - Expected error %v but was %v.", tc.testName, tc.expectedError, err)
			}
			if tc.expectExists != exists {
				t.Errorf("%s - Expected the issuer to exist.", tc.testName)
			}
			if tc.expectedIssuer != issuer.Did {
				t.Errorf("%s - Expected the issuer %v, but was %v.", tc.testName, tc.expectedIssuer, tc.testIssuer)
			}
		})
	}

}

func getNotFoundResponse() *http.Response {
	return &http.Response{StatusCode: 404}
}
func getUnparsableResponse() *http.Response {
	issuer := io.NopCloser(strings.NewReader("did-i-dachs"))
	response := http.Response{
		StatusCode: 200,
		Body:       issuer,
	}
	return &response
}

func getIssuerResponse(did string) *http.Response {
	issuer := io.NopCloser(strings.NewReader(fmt.Sprintf("{\"did\": \"%s\"}", did)))
	response := http.Response{
		StatusCode: 200,
		Body:       issuer,
	}
	return &response
}

func TestDidRegistry(t *testing.T) {
	// Start a local HTTP server
	server := getTestServer("/v4/issuers/did:elsi:eu.eori.denhaag19902304", 404)
	// Close the server when test finishes
	defer server.Close()

	tirClient := TirHttpClient{client: getClient{server.Client()}, tilCache: mockCache{}, tirCache: mockCache{}}
	trusted := tirClient.issuerExists(server.URL, "did:elsi:eu.eori.denhaag19902304")
	assert.Equal(t, true, trusted, "Should return that issuer is trusted")

	trusted = tirClient.issuerExists(server.URL, "did:elsi:someThingElse")
	assert.Equal(t, false, trusted, "Should return that issuer is not trusted")
}

func getTestServer(path string, errorCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

		// Test request parameters
		if req.URL.String() == path {
			rw.Header().Set("Content-Type", "json")
			// Send response to be tested
			rw.Write([]byte(ISHARE_EXAMPLE))
		} else {
			rw.WriteHeader(errorCode)
		}
	}))
}
