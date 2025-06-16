package verifier

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/trustbloc/did-go/vdr/api"

	vdr_jwk "github.com/trustbloc/did-go/method/jwk"
	vdr_key "github.com/trustbloc/did-go/method/key"
	vdr_web "github.com/trustbloc/did-go/method/web"
)

var ErrorNoRequestObjectReturned = errors.New("no_request_object")
var ErrorInvalidJWT = errors.New("invalid_jwt")
var ErrorInvalidKid = errors.New("invalid_kid")

type RequestObjectClient struct {
	HttpClient  common.HttpClient
	KeyResolver KeyResolver
}

type ClientRequestObject struct {
	Iss          string   `json:"iss"`
	Aud          []string `json:"aud"`
	ResponseType string   `json:"response_type"`
	ClientId     string   `json:"client_id"`
	RedirectUri  string   `json:"redirect_uri"`
	Scope        string   `json:"scope"`
}

func NewRequestObjectClient() (roc *RequestObjectClient) {
	return &RequestObjectClient{&http.Client{}, &VdrKeyResolver{Vdr: []api.VDR{vdr_key.New(), vdr_jwk.New(), vdr_web.New()}}}
}

func (roc *RequestObjectClient) GetClientRequestObject(requestUri string) (clientRequestObject *ClientRequestObject, err error) {
	request, err := http.NewRequest("GET", requestUri, nil)
	if err != nil {
		logging.Log().Warnf("Was not able to build request for %s. Err: %v", requestUri, err)
		return clientRequestObject, err
	}
	response, err := roc.HttpClient.Do(request)
	if err != nil {
		logging.Log().Warnf("Was not able to get request object for %s. Err: %v", requestUri, err)
		return clientRequestObject, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logging.Log().Warnf("Was not able to close the response body. Err: %v", err)
		}
	}(response.Body)

	if response.StatusCode != 200 {
		logging.Log().Warnf("Was not able to get request object for %s. Status: %v, Message: %s", requestUri, response.StatusCode, response.Body)
		return clientRequestObject, ErrorNoRequestObjectReturned
	}

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		logging.Log().Warnf("Was not able to read the response body. Err: %v", err)
		return clientRequestObject, err
	}

	kid, err := roc.KeyResolver.ExtractKIDFromJWT(string(bytes))
	if err != nil {
		logging.Log().Warnf("Was not able to get the kid. Token: %s, Err: %v", string(bytes), err)
		return clientRequestObject, err
	}

	pubKey, err := roc.KeyResolver.ResolvePublicKeyFromDID(kid)
	if err != nil {
		return clientRequestObject, err
	}

	alg, algExists := pubKey.Algorithm()
	if !algExists {
		// fallback to default
		alg = jwa.ES256()
	}

	parsed, err := jwt.Parse(bytes, jwt.WithKey(alg, pubKey))
	if err != nil {
		logging.Log().Warnf("Was not able to parse and verify the token %s. Err: %v", string(bytes), err)
		return clientRequestObject, err
	}

	return parseJWTToClientRequestObject(parsed)
}

func parseJWTToClientRequestObject(token jwt.Token) (*ClientRequestObject, error) {
	// Serialize token to JSON
	jsonBytes, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}

	// Unmarshal to your struct
	var clientRequestObject ClientRequestObject
	if err := json.Unmarshal(jsonBytes, &clientRequestObject); err != nil {
		logging.Log().Warnf("Was not able to unmarshal object: %s", string(jsonBytes))
		return nil, err
	}

	return &clientRequestObject, nil
}
