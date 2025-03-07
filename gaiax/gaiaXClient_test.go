package gaiax

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/trustbloc/did-go/doc/did"
	diddoc "github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
)

type mockHttpClient struct {
	responses map[string]*http.Response
	errors    map[string]error
}

func (mhc mockHttpClient) Do(req *http.Request) (*http.Response, error) {
	ur := req.URL.String()
	response := mhc.responses[ur]
	return response, mhc.errors[req.RequestURI]
}

type mockVDR struct {
	didDocs map[string]*did.DocResolution
	errors  map[string]error
}

func (vdr *mockVDR) Resolve(did string, opts ...vdrapi.DIDMethodOption) (*diddoc.DocResolution, error) {
	return vdr.didDocs[did], vdr.errors[did]
}

func (vdr *mockVDR) Create(didMethod string, did *diddoc.Doc, opts ...vdrapi.DIDMethodOption) (*diddoc.DocResolution, error) {
	return nil, errors.ErrUnsupported
}

func (vdr *mockVDR) Update(didDoc *diddoc.Doc, opts ...vdrapi.DIDMethodOption) error {
	return errors.ErrUnsupported
}

func (vdr *mockVDR) Deactivate(did string, opts ...vdrapi.DIDMethodOption) error {
	return errors.ErrUnsupported
}

func (vdr *mockVDR) Close() error { return errors.ErrUnsupported }

func TestGaiaXClient_IsTrustedParticipant(t *testing.T) {
	type test struct {
		testName       string
		testEndpoint   string
		testIssuer     string
		responses      map[string]*http.Response
		httpErrors     map[string]error
		didDocs        map[string]*did.DocResolution
		didErrors      map[string]error
		expectedResult bool
	}

	tests := []test{
		{
			testName:       "The issuer should be a valid participant.",
			testEndpoint:   "https://gaia-x.registry",
			testIssuer:     "did:web:test.org",
			responses:      map[string]*http.Response{"https://gaia-x.registry/v2/api/trustAnchor/chain/file": getOKResponse()},
			didDocs:        map[string]*did.DocResolution{"did:web:test.org": getDidDoc("did:web:test.org")},
			expectedResult: true,
		},
		{
			testName:       "If the registry does not return an ok, the issuer should not be considered a participant.",
			testEndpoint:   "https://gaia-x.registry",
			testIssuer:     "did:web:test.org",
			responses:      map[string]*http.Response{"https://gaia-x.registry/v2/api/trustAnchor/chain/file": getNotOKResponse()},
			didDocs:        map[string]*did.DocResolution{"did:web:test.org": getDidDoc("did:web:test.org")},
			expectedResult: false,
		},
		{
			testName:       "If the did cannot be resolved, the issuer should not be considered a participant.",
			testEndpoint:   "https://gaia-x.registry",
			testIssuer:     "did:key:some-key",
			didErrors:      map[string]error{"did:key:some-key": errors.New("no_resolvable_issuer")},
			expectedResult: false,
		},
		{
			testName:       "x5u is mandated by Gaia-X, the issuer should not be considered a participant.",
			testEndpoint:   "https://gaia-x.registry",
			testIssuer:     "did:web:test.org",
			responses:      map[string]*http.Response{"https://gaia-x.registry/v2/api/trustAnchor/chain/file": getNotOKResponse()},
			didDocs:        map[string]*did.DocResolution{"did:web:test.org": getDidDocWithoutX5U("did:web:test.org")},
			expectedResult: false,
		},
		{
			testName:       "If the did-doc does not contain a matching key, the issuer should not be considered a participant.",
			testEndpoint:   "https://gaia-x.registry",
			testIssuer:     "did:web:test.org",
			responses:      map[string]*http.Response{"https://gaia-x.registry/v2/api/trustAnchor/chain/file": getNotOKResponse()},
			didDocs:        map[string]*did.DocResolution{"did:web:test.org": getDidDoc("did:web:another-controller.org")},
			expectedResult: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			gaiaXClient := GaiaXHttpClient{
				client:      mockHttpClient{responses: tc.responses, errors: tc.httpErrors},
				didRegistry: &mockVDR{didDocs: tc.didDocs, errors: tc.didErrors},
			}
			isTrusted := gaiaXClient.IsTrustedParticipant(tc.testEndpoint, tc.testIssuer)

			if tc.expectedResult != isTrusted {
				t.Errorf("%s - Expected the issuer to be trusted %v but was %v.", tc.testName, tc.expectedResult, isTrusted)
			}
		})
	}
}

func getOKResponse() *http.Response {
	body := io.NopCloser(strings.NewReader("{\"valid\": true}"))
	response := http.Response{
		StatusCode: 200,
		Body:       body,
	}
	return &response
}

func getNotOKResponse() *http.Response {
	body := io.NopCloser(strings.NewReader("{\"valid\": false}"))
	response := http.Response{
		StatusCode: 400,
		Body:       body,
	}
	return &response
}

func getDidDoc(did string) *did.DocResolution {
	jwkJson := "{\"kty\": \"RSA\",\"e\": \"AQAB\",\"n\": \"ozaiCEhCBjv31zDVii1Btmt4tjTQvUTIqo-3221OM89gQtVxyIB8z73U2hecFK1FyXa0fWwoy2PYcV6hSuEPnwilNsheP09TJPTptKFwM5fZoOzuZNd95RZFclOLtD8BWzpr3pQwRr5y6F69SNYCQTKejfSKo2eWCjdNUndBmZ8bHAHME9jWZUG-BDO3ag8ykYA-aMzq4RSW_UNqFnkita30F95AzVZ4mF_7-0uc0CGE_u66f4T8mFIqMbEPiiNBEG9Yt4giLdi1xgyLGu6-8xifQekTyr_owIKGmPtu__UBAFmB-y2P6vnLsGRxvB2uatoYceZD6WBfGzj2QZpftQCgJ6QR6d-1Ag-8-1NJRUYVIQjZm45fc2WRi58QLg2urOhIbVYeCALdQIb_S9FP82VzLVWk6aOVL8TU_9QK9qwXLWiM5vRa_EKwJfr1bwsT8kTp20R6vfAlbqLD6QnQdmAtzZsR7Zqw3ef1G5TvelQFFTh49DMP7upTGkmZGIZO6qkHbWUq87LhWgFzHqNCe7O6jHTAHO3UIjpZJBCYg3RtEHV8UN07eIkYaYqnzEv9UJRjMqGQP6CeE7woUx2CHPemrxopEEQV1URCVIZ00BcHy-tyxWs56uo59QASVr9Ut0xRQm-L-x9QQKdB1XMpXw5UR-9Oe7ZW3Fokkk3wwMs\",\"x5u\": \"https://my-issuer.org/tls.crt\"}"

	joseKey := jose.JSONWebKey{}
	joseKey.UnmarshalJSON([]byte(jwkJson))

	jwk := jwk.JWK{
		JSONWebKey: joseKey,
	}
	verificationMethod, err := diddoc.NewVerificationMethodFromJWK(did, "JsonWebKey2020", did, &jwk)
	if err != nil {
		return nil
	}
	didDocument := diddoc.Doc{
		VerificationMethod: []diddoc.VerificationMethod{*verificationMethod},
	}
	docResolution := diddoc.DocResolution{
		DIDDocument: &didDocument,
	}
	return &docResolution
}

func getDidDocWithoutX5U(did string) *did.DocResolution {
	jwkJson := "{\"kty\": \"RSA\",\"e\": \"AQAB\",\"n\": \"ozaiCEhCBjv31zDVii1Btmt4tjTQvUTIqo-3221OM89gQtVxyIB8z73U2hecFK1FyXa0fWwoy2PYcV6hSuEPnwilNsheP09TJPTptKFwM5fZoOzuZNd95RZFclOLtD8BWzpr3pQwRr5y6F69SNYCQTKejfSKo2eWCjdNUndBmZ8bHAHME9jWZUG-BDO3ag8ykYA-aMzq4RSW_UNqFnkita30F95AzVZ4mF_7-0uc0CGE_u66f4T8mFIqMbEPiiNBEG9Yt4giLdi1xgyLGu6-8xifQekTyr_owIKGmPtu__UBAFmB-y2P6vnLsGRxvB2uatoYceZD6WBfGzj2QZpftQCgJ6QR6d-1Ag-8-1NJRUYVIQjZm45fc2WRi58QLg2urOhIbVYeCALdQIb_S9FP82VzLVWk6aOVL8TU_9QK9qwXLWiM5vRa_EKwJfr1bwsT8kTp20R6vfAlbqLD6QnQdmAtzZsR7Zqw3ef1G5TvelQFFTh49DMP7upTGkmZGIZO6qkHbWUq87LhWgFzHqNCe7O6jHTAHO3UIjpZJBCYg3RtEHV8UN07eIkYaYqnzEv9UJRjMqGQP6CeE7woUx2CHPemrxopEEQV1URCVIZ00BcHy-tyxWs56uo59QASVr9Ut0xRQm-L-x9QQKdB1XMpXw5UR-9Oe7ZW3Fokkk3wwMs\"}"

	joseKey := jose.JSONWebKey{}
	joseKey.UnmarshalJSON([]byte(jwkJson))

	jwk := jwk.JWK{
		JSONWebKey: joseKey,
	}
	verificationMethod, err := diddoc.NewVerificationMethodFromJWK(did, "JsonWebKey2020", did, &jwk)
	if err != nil {
		return nil
	}
	didDocument := diddoc.Doc{
		VerificationMethod: []diddoc.VerificationMethod{*verificationMethod},
	}
	docResolution := diddoc.DocResolution{
		DIDDocument: &didDocument,
	}
	return &docResolution
}
