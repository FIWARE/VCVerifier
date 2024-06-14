package tir

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/procyon-projects/chrono"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
)

const ISSUERS_V4_PATH = "v4/issuers"
const ISSUERS_V3_PATH = "v3/issuers"

const DID_V4_Path = "v4/identifiers"

var ErrorTirNoResponse = errors.New("no_response_from_tir")
var ErrorTirEmptyResponse = errors.New("empty_response_from_tir")

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type TirClient interface {
	IsTrustedParticipant(tirEndpoints []string, did string) (trusted bool)
	GetTrustedIssuer(tirEndpoints []string, did string) (exists bool, trustedIssuer TrustedIssuer, err error)
}

/**
* A client to retrieve infromation from EBSI-compatible TrustedIssuerRegistry APIs.
 */
type TirHttpClient struct {
	client   HttpGetClient
	tirCache common.Cache
	tilCache common.Cache
}

/**
* A trusted issuer as defined by EBSI
 */
type TrustedIssuer struct {
	Did        string            `json:"did"`
	Attributes []IssuerAttribute `json:"attributes"`
}

/**
* Attribute of an issuer
 */
type IssuerAttribute struct {
	Hash       string `json:"hash"`
	Body       string `json:"body"`
	IssuerType string `json:"issuerType"`
	Tao        string `json:"tao"`
	RootTao    string `json:"rootTao"`
}

/**
* Configuration of a credentialType, its validity time and the claims allowed to be issued
 */
type Credential struct {
	ValidFor        TimeRange `json:"validFor"`
	CredentialsType string    `json:"credentialsType"`
	Claims          []Claim   `json:"claims"`
}

type TimeRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type Claim struct {
	Name          string        `json:"name"`
	AllowedValues []interface{} `json:"allowedValues"`
}

func NewTirHttpClient(tokenProvider TokenProvider, m2mConfig config.M2M, verifierConfig config.Verifier) (client TirClient, err error) {

	// disable keep alive, to avoid EOFs due to race conditions
	// not performance critical, since we serve most responses from the cache
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	httpClient := &http.Client{Transport: transport}

	tirCache := cache.New(time.Duration(verifierConfig.TirCacheExpiry)*time.Second, time.Duration(2*verifierConfig.TirCacheExpiry)*time.Second)
	tilCache := cache.New(time.Duration(verifierConfig.TilCacheExpiry)*time.Second, time.Duration(2*verifierConfig.TilCacheExpiry)*time.Second)

	var httpGetClient HttpGetClient
	if m2mConfig.AuthEnabled {
		logging.Log().Debug("Authorization for the trusted-issuers-registry is enabled.")
		authorizingHttpClient := AuthorizingHttpClient{httpClient: httpClient, tokenProvider: tokenProvider, clientId: m2mConfig.ClientId}

		_, err := chrono.NewDefaultTaskScheduler().ScheduleAtFixedRate(authorizingHttpClient.FillMetadataCache, time.Duration(30)*time.Second)
		if err != nil {
			logging.Log().Errorf("failed scheduling task: %v", err)
			return nil, err
		}

		httpGetClient = authorizingHttpClient
	} else {
		httpGetClient = NoAuthHttpClient{httpClient: httpClient}
	}

	return TirHttpClient{client: httpGetClient, tirCache: tirCache, tilCache: tilCache}, err
}

func (tc TirHttpClient) IsTrustedParticipant(tirEndpoints []string, did string) (trusted bool) {
	for _, tirEndpoint := range tirEndpoints {
		logging.Log().Debugf("Check if a participant %s is trusted through %s.", did, tirEndpoint)
		if tc.issuerExists(tirEndpoint, did) {
			logging.Log().Debugf("Issuer %s is a trusted participant via %s.", did, tirEndpoint)
			return true
		}
	}
	return false
}

func (tc TirHttpClient) GetTrustedIssuer(tirEndpoints []string, did string) (exists bool, trustedIssuer TrustedIssuer, err error) {
	for _, tirEndpoint := range tirEndpoints {
		trustedIssuer, hit := tc.tilCache.Get(tirEndpoint + did)
		if !hit {
			exists, trustedIssuer, err = tc.getIssuerWithRetry(tirEndpoint, did)
			if err != nil {
				continue
			}
			if !exists {
				continue
			}
			tc.tilCache.Set(tirEndpoint+did, trustedIssuer, cache.DefaultExpiration)
			logging.Log().Debugf("Got issuer %s.", logging.PrettyPrintObject(trustedIssuer))
		}
		return true, trustedIssuer.(TrustedIssuer), err
	}
	return false, trustedIssuer, err
}

func (tc TirHttpClient) getIssuerWithRetry(tirEndpoint string, did string) (exists bool, trustedIssuer TrustedIssuer, err error) {

	currentTry := 0
	for currentTry < 3 {
		resp, err := tc.requestIssuer(tirEndpoint, did)
		if err != nil {
			logging.Log().Warnf("Was not able to get the issuer %s from %s because of err: %v.", did, tirEndpoint, err)
			return false, trustedIssuer, err
		}
		if resp.StatusCode != 200 {
			logging.Log().Debugf("Issuer %s is not known at %s.", did, tirEndpoint)
			return false, trustedIssuer, err
		}
		trustedIssuer, err = parseTirResponse(*resp)
		if err != nil && err.Error() == "EOF" {
			logging.Log().Warnf("Was not able to parse the response from til %s for %s. Err: %v", tirEndpoint, did, err)
			logging.Log().Debugf("Response was %v ", resp)
			currentTry++
			continue
		} else if err != nil {
			return false, trustedIssuer, err
		}
		exists = true
		break
	}
	return exists, trustedIssuer, err
}

func parseTirResponse(resp http.Response) (trustedIssuer TrustedIssuer, err error) {

	if resp.Body == nil {
		logging.Log().Info("Received an empty body from the tir.")
		return trustedIssuer, ErrorTirEmptyResponse
	}

	err = json.NewDecoder(resp.Body).Decode(&trustedIssuer)
	if err != nil {
		logging.Log().Warn("Was not able to decode the tir-response.")
		return trustedIssuer, err
	}
	return trustedIssuer, err
}

func (tc TirHttpClient) issuerExists(tirEndpoint string, did string) (trusted bool) {

	exists, hit := tc.tirCache.Get(tirEndpoint + did)

	if !hit {
		resp, err := tc.requestIssuer(tirEndpoint, did)
		if err != nil {
			return false
		}
		logging.Log().Debugf("Issuer %s response from %s is %v", did, tirEndpoint, resp.StatusCode)
		exists = resp.StatusCode == 200
		tc.tirCache.Set(tirEndpoint, exists, cache.DefaultExpiration)
	}

	// if a 200 is returned, the issuer exists. We dont have to parse the whole response
	return exists.(bool)
}

func (tc TirHttpClient) requestIssuer(tirEndpoint string, did string) (response *http.Response, err error) {
	didPath := ISSUERS_V4_PATH + "/" + did

	logging.Log().Debugf("Get issuer %s/%s.", tirEndpoint, didPath)
	cacheKey := common.BuildUrlString(tirEndpoint, didPath)
	responseInterface, hit := common.GlobalCache.IssuerCache.Get(cacheKey)
	if hit {
		return responseInterface.(*http.Response), nil
	}

	resp, err := tc.client.Get(tirEndpoint, didPath)
	if err != nil {
		logging.Log().Warnf("Was not able to get the issuer %s from %s. Err: %v", didPath, tirEndpoint, err)
		return resp, err
	}
	if resp == nil {
		logging.Log().Warnf("Was not able to get any response for issuer %s from %s.", didPath, tirEndpoint)
		return nil, ErrorTirNoResponse
	}

	common.GlobalCache.IssuerCache.Set(cacheKey, resp, cache.DefaultExpiration)
	logging.Log().Debugf("Added cache entry for %s", cacheKey)
	return resp, err
}
