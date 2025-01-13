package tir

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
	"golang.org/x/exp/slices"
)

const WELL_KNOWN_ENDPOINT = "/.well-known/openid-configuration"
const SCOPE_TIR_READ = "tir_read"
const TirEndpointsCache = "tirEndpoints"

// http client to be used
var ErrorTokenEndpointNoResponse = errors.New("no_response_from_token_endpoint")
var ErrorMetaDataNotOk = errors.New("no_metadata_available")
var ErrorGrantTypeNotSupported = errors.New("grant_type_not_supported")
var ErrorScopeNotSupported = errors.New("scope_not_supported")
var ErrorCachedOpenidMetadataNotFound = errors.New("cached_openid_metadata_not_found")

type HttpGetClient interface {
	Get(tirAddress string, tirPath string) (resp *http.Response, err error)
}

type AuthorizingHttpClient struct {
	httpClient    common.HttpClient
	tokenProvider TokenProvider
	clientId      string
}

type NoAuthHttpClient struct {
	httpClient common.HttpClient
}

func (ac AuthorizingHttpClient) FillMetadataCache(context.Context) {
	tirEndpointsInterface, hit := common.GlobalCache.TirEndpoints.Get(TirEndpointsCache)
	if !hit {
		logging.Log().Info("issuers list not found in cache")
		return
	}

	tirEndpoints := tirEndpointsInterface.([]string)
	for _, tirEndpoint := range tirEndpoints {
		metaData, err := ac.getMetaData(tirEndpoint)
		if err != nil {
			logging.Log().Errorf("Was not able to get the openid metadata from endpoint %s. Err: %v", tirEndpoint, err)
		}
		err = common.GlobalCache.IssuersCache.Add(tirEndpoint, metaData, cache.NoExpiration)
		if err != nil {
			logging.Log().Errorf("failed caching issuer metadata in FillMetadataCache(): %v", err)
		}
	}
}

func (nac NoAuthHttpClient) Get(tirAddress string, tirPath string) (resp *http.Response, err error) {
	urlString := common.BuildUrlString(tirAddress, tirPath)
	return closingGet(nac.httpClient, urlString)
}

// excutes get requests via "DO" and close the connection afterwards, to avoid EOFs on keep-alive race-conditions
func closingGet(httpClient common.HttpClient, url string) (resp *http.Response, err error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Close = true
	return httpClient.Do(req)
}

func (ac AuthorizingHttpClient) Get(tirAddress string, tirPath string) (resp *http.Response, err error) {
	urlString := common.BuildUrlString(tirAddress, tirPath)
	resp, err = closingGet(ac.httpClient, urlString)
	if err != nil {
		logging.Log().Infof("Was not able to get a response. Err: %v", err)
		return resp, err
	}
	if resp.StatusCode != 403 && resp.StatusCode != 401 {
		logging.Log().Infof("Response was %v", resp)
		return resp, err
	}
	bearerToken, err := ac.handleAuthorization(tirAddress)
	if err != nil {
		logging.Log().Warnf("Was not able to get a bearer token. Err: %v", err)
		return resp, err
	}

	// repeat with auth
	authenticatedRequest, err := http.NewRequest("GET", urlString, nil)
	if err != nil {
		logging.Log().Warnf("Was not able to build the authenticated request. Err: %v", err)
		return resp, err
	}
	authenticatedRequest.Close = true
	authenticatedRequest.Header.Add("Authorization", "Bearer "+bearerToken)
	return ac.httpClient.Do(authenticatedRequest)
}

func (ac AuthorizingHttpClient) handleAuthorization(tirAddress string) (bearerToken string, err error) {
	logging.Log().Debugf("Handle authorization for %s", tirAddress)
	vc, err := ac.tokenProvider.GetAuthCredential()
	if err != nil {
		logging.Log().Warnf("No credential configured for auth. Err: %v", err)
		return bearerToken, err
	}

	vpToken, err := ac.tokenProvider.GetToken(vc, tirAddress)
	if err != nil {
		logging.Log().Warnf("Was not able to get a VP Token. Err: %v", err)
		return bearerToken, err
	}

	metaDataInterface, hit := common.GlobalCache.IssuersCache.Get(tirAddress)
	if !hit {
		logging.Log().Warnf("Was not able to get the openid metadata from address %s. Err: %v", tirAddress, err)
		return bearerToken, ErrorCachedOpenidMetadataNotFound
	}

	metaData := metaDataInterface.(common.OpenIDProviderMetadata)
	if !slices.Contains(metaData.GrantTypesSupported, common.TYPE_VP_TOKEN) {
		logging.Log().Warnf("The server does not support grant type vp_token. Config: %v", logging.PrettyPrintObject(metaData))
		return bearerToken, ErrorGrantTypeNotSupported
	}
	if !slices.Contains(metaData.ScopesSupported, SCOPE_TIR_READ) {
		logging.Log().Warnf("The server does not support scope tir_read. Config: %v", logging.PrettyPrintObject(metaData))
		return bearerToken, ErrorScopeNotSupported
	}
	// presentation submission is not yet used.
	bearerToken, err = ac.postVpToken(metaData.TokenEndpoint, vpToken, "", SCOPE_TIR_READ)
	if err != nil {
		logging.Log().Warnf("Was not able to get an access token. Err: %v", err)
	}
	return bearerToken, err

}

func (ac AuthorizingHttpClient) getMetaData(tokenHost string) (metadata common.OpenIDProviderMetadata, err error) {
	logging.Log().Debugf("Retrieve openid-metadata from %s", tokenHost)
	resp, err := closingGet(ac.httpClient, common.BuildUrlString(tokenHost, WELL_KNOWN_ENDPOINT))
	if err != nil {
		logging.Log().Warnf("Was not able to get openid metadata from %s. Err: %v", tokenHost, err)
		return metadata, err
	}
	if resp == nil {
		logging.Log().Warnf("Did not receive a valid response from %v.", tokenHost)
		return metadata, ErrorMetaDataNotOk
	}
	if resp.StatusCode != 200 {
		logging.Log().Warnf("Was not able to get openid metadata from %s. Response was %v.", tokenHost, resp)
		return metadata, ErrorMetaDataNotOk
	}
	if resp.Body == nil {
		logging.Log().Warnf("Did not receive a valid response from %v. Was %v", tokenHost, resp)
		return metadata, ErrorMetaDataNotOk
	}
	var metaDataResponse common.OpenIDProviderMetadata

	err = json.NewDecoder(resp.Body).Decode(&metaDataResponse)
	if err != nil {
		logging.Log().Warnf("Was not able to decode the metadata response. Err: %v", err)
		return metadata, err
	}
	return metaDataResponse, err

}

func (ac AuthorizingHttpClient) postVpToken(tokenEndpoint string, vpToken string, presentationSubmission string, scope string) (accessToken string, err error) {

	formRequest := url.Values{}
	formRequest.Add("grant_type", "vp_token")
	formRequest.Add("vp_token", vpToken)
	formRequest.Add("presentation_submission", presentationSubmission)
	formRequest.Add("scope", scope)

	logging.Log().Infof("Get token from %s.", tokenEndpoint)
	tokenHttpRequest, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(formRequest.Encode()))
	if err != nil {
		logging.Log().Warnf("Was not able to create token request. Err: %v", err)
		return accessToken, err
	}
	// move to the vc?
	tokenHttpRequest.Header.Set("client_id", ac.clientId)
	tokenHttpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenHttpResponse, err := ac.httpClient.Do(tokenHttpRequest) // evaluate the results
	if err != nil {
		logging.Log().Warnf("Did not receive a valid token response. Err: %v", err)
		return accessToken, err
	}
	if tokenHttpResponse == nil {
		logging.Log().Warn("Did not receive any response from the token endpoint.")
		return accessToken, ErrorTokenEndpointNoResponse
	}
	if tokenHttpResponse.StatusCode != 200 {
		logging.Log().Infof("Did not receive an ok(was %v) from the token request.", tokenHttpResponse.StatusCode)
		return accessToken, err
	}
	if tokenHttpResponse.Body == nil {
		logging.Log().Info("Received an empty body for the token request.")
		return accessToken, err
	}

	var tokenResponse TokenResponse

	err = json.NewDecoder(tokenHttpResponse.Body).Decode(&tokenResponse)
	if err != nil {
		logging.Log().Warn("Was not able to decode the token response.")
		return accessToken, err
	}
	return tokenResponse.AccessToken, err
}

type TokenResponse struct {
	TokenType string `json:"token_type,omitempty"`

	// The lifetime in seconds of the access token
	ExpiresIn float32 `json:"expires_in,omitempty"`

	AccessToken string `json:"access_token,omitempty"`

	// The scope of the access token
	Scope string `json:"scope,omitempty"`
	// ID Token value associated with the authenticated session. Presents client's identity. ID Token is issued in a JWS format. See also the \"ID Token\" schema definition.
	IdToken string `json:"id_token,omitempty"`
}
