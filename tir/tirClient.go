package tir

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/procyon-projects/chrono"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
)

const ISSUERS_V4_PATH = "v4/issuers"
const ISSUERS_V3_PATH = "v3/issuers"
const ISSUERS_V5_PATH = "v5/issuers"

const DID_V4_Path = "v4/identifiers"

// maxPaginationPages limits the number of pages fetched during v5 attribute
// list pagination to prevent infinite loops or excessively long request chains.
const maxPaginationPages = 100

var ErrorTirNoResponse = errors.New("no_response_from_tir")
var ErrorTirEmptyResponse = errors.New("empty_response_from_tir")

type TirClient interface {
	IsTrustedParticipant(tirEndpoints string, did string) (trusted bool)
	GetTrustedIssuer(tirEndpoints []string, did string) (exists bool, trustedIssuer TrustedIssuer, err error)
	// IsTrustedParticipantV5 checks whether the given DID is registered as a
	// trusted participant at the specified v5 TIR endpoint.
	IsTrustedParticipantV5(tirEndpoint string, did string) (trusted bool)
	// GetTrustedIssuerV5 fetches a trusted issuer from v5 TIR endpoints. The v5
	// API requires multi-step fetching: get issuer, list attributes (with
	// pagination), then fetch each attribute individually.
	GetTrustedIssuerV5(tirEndpoints []string, did string) (exists bool, trustedIssuer TrustedIssuer, err error)
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
	Path          string        `json:"path"`
	AllowedValues []interface{} `json:"allowedValues"`
}

// TrustedIssuerV5Response represents the response from GET /v5/issuers/{did}.
// The Attributes field contains a URL reference to the paginated attributes list,
// rather than inline attribute data as in v3/v4.
type TrustedIssuerV5Response struct {
	Did           string `json:"did"`
	Attributes    string `json:"attributes"`
	HasAttributes bool   `json:"hasAttributes"`
}

// AttributesListV5Response represents a paginated list of attribute references
// returned by GET /v5/issuers/{did}/attributes.
type AttributesListV5Response struct {
	Items    []AttributeListItem `json:"items"`
	Links    PaginationLinks     `json:"links"`
	Total    int                 `json:"total"`
	PageSize int                 `json:"pageSize"`
	Self     string              `json:"self"`
}

// AttributeListItem represents a single entry in the paginated attributes list,
// containing the attribute's ID and an href to fetch its full details.
type AttributeListItem struct {
	ID   string `json:"id"`
	Href string `json:"href"`
}

// PaginationLinks holds the pagination navigation links returned by the v5 API.
type PaginationLinks struct {
	First string `json:"first"`
	Last  string `json:"last"`
	Next  string `json:"next"`
	Prev  string `json:"prev"`
}

// AttributeV5Response represents the response from fetching a single attribute
// via GET /v5/issuers/{did}/attributes/{id}.
type AttributeV5Response struct {
	Attribute IssuerAttribute `json:"attribute"`
	Did       string          `json:"did"`
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

func (tc TirHttpClient) IsTrustedParticipant(tirEndpoint string, did string) (trusted bool) {
	if tc.issuerExists(tirEndpoint, did) {
		logging.Log().Debugf("Issuer %s is a trusted participant via %s.", did, tirEndpoint)
		return true
	}
	return false
}

func (tc TirHttpClient) GetTrustedIssuer(tirEndpoints []string, did string) (exists bool, trustedIssuer TrustedIssuer, err error) {
	for _, tirEndpoint := range tirEndpoints {

		cacheKey := tirEndpoint + did
		trustedIssuer, hit := tc.tirCache.Get(cacheKey)
		if !hit {
			resp, err := tc.requestIssuer(tirEndpoint, did)
			if err != nil {
				logging.Log().Warnf("Was not able to get the issuer %s from %s because of err: %v.", did, tirEndpoint, err)
				continue
			}
			if resp.StatusCode != 200 {
				logging.Log().Debugf("Issuer %s is not known at %s.", did, tirEndpoint)
				continue
			}
			trustedIssuer, err = parseTirResponse(*resp)
			if err != nil {
				logging.Log().Warnf("Was not able to parse the response from til %s for %s. Err: %v", tirEndpoint, did, err)
				logging.Log().Debugf("Response was %v ", resp)
				continue
			}
			logging.Log().Debugf("Got issuer %s.", logging.PrettyPrintObject(trustedIssuer))

			logging.Log().Debugf("Added cache entry for %s", cacheKey)
			tc.tirCache.Set(cacheKey, trustedIssuer, cache.DefaultExpiration)
		}
		return true, trustedIssuer.(TrustedIssuer), err

	}
	return false, trustedIssuer, err
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
	response, err = tc.requestIssuerWithVersion(tirEndpoint, getIssuerV4Url(did))
	if err != nil {
		logging.Log().Debugf("Got error %v", err)
		return tc.requestIssuerWithVersion(tirEndpoint, getIssuerV3Url(did))
	}

	if response.StatusCode != 200 {
		logging.Log().Debugf("Got status %v", response.StatusCode)
		return tc.requestIssuerWithVersion(tirEndpoint, getIssuerV3Url(did))
	}
	return response, err
}

func (tc TirHttpClient) requestIssuerWithVersion(tirEndpoint string, didPath string) (response *http.Response, err error) {
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

	return resp, err
}

// structuralPathCharacters are the characters that would end the path segment
// an issuer identifier is placed in, mapped to their percent-encoding.
var structuralPathCharacters = strings.NewReplacer(
	"/", "%2F",
	"?", "%3F",
	"#", "%23",
)

// issuerPathSegment prepares an issuer identifier for use as a single path
// segment of a registry lookup URL.
//
// Only the characters that would break out of the segment are encoded, so an
// issuer identified by an HTTPS URL addresses one issuer instead of a nested
// path below the issuers endpoint. Everything else is left untouched on
// purpose: a DID is passed to the registry exactly as it is written, including
// the percent-encoding a `did:web` with a port already carries — running it
// through a general-purpose escaper would turn `%3A` into `%253A` and address
// a different issuer.
func issuerPathSegment(issuer string) string {
	return structuralPathCharacters.Replace(issuer)
}

func getIssuerV4Url(did string) string {
	return ISSUERS_V4_PATH + "/" + issuerPathSegment(did)
}

func getIssuerV3Url(did string) string {
	return ISSUERS_V3_PATH + "/" + issuerPathSegment(did)
}

// getIssuerV5Url returns the v5 API path for fetching issuer information by DID.
func getIssuerV5Url(did string) string {
	return ISSUERS_V5_PATH + "/" + issuerPathSegment(did)
}

// getAttributesV5Url returns the v5 API path for listing an issuer's attributes.
func getAttributesV5Url(did string) string {
	return ISSUERS_V5_PATH + "/" + issuerPathSegment(did) + "/attributes"
}

// IsTrustedParticipantV5 checks whether the given DID is registered as a
// trusted participant at the specified v5 TIR endpoint. Returns true if the
// endpoint responds with HTTP 200 for the issuer lookup.
func (tc TirHttpClient) IsTrustedParticipantV5(tirEndpoint string, did string) (trusted bool) {
	if tc.issuerExistsV5(tirEndpoint, did) {
		logging.Log().Debugf("Issuer %s is a trusted participant via v5 endpoint %s.", did, tirEndpoint)
		return true
	}
	return false
}

// issuerExistsV5 checks the v5 endpoint for the existence of a given DID,
// using the cache to avoid redundant requests.
func (tc TirHttpClient) issuerExistsV5(tirEndpoint string, did string) (trusted bool) {
	cacheKey := tirEndpoint + "/v5/" + did
	exists, hit := tc.tirCache.Get(cacheKey)

	if !hit {
		resp, err := tc.client.Get(tirEndpoint, getIssuerV5Url(did))
		if err != nil {
			logging.Log().Warnf("V5: Was not able to check issuer %s at %s. Err: %v", did, tirEndpoint, err)
			return false
		}
		if resp == nil {
			logging.Log().Warnf("V5: No response for issuer %s from %s.", did, tirEndpoint)
			return false
		}
		logging.Log().Debugf("V5: Issuer %s response from %s is %v", did, tirEndpoint, resp.StatusCode)
		exists = resp.StatusCode == 200
		tc.tirCache.Set(cacheKey, exists, cache.DefaultExpiration)
	}

	return exists.(bool)
}

// GetTrustedIssuerV5 fetches a trusted issuer from v5 TIR endpoints. For each
// endpoint it performs a multi-step fetch: (1) get issuer, (2) if the issuer has
// attributes, paginate through the attributes list, (3) fetch each individual
// attribute. The assembled TrustedIssuer is cached for subsequent lookups.
func (tc TirHttpClient) GetTrustedIssuerV5(tirEndpoints []string, did string) (exists bool, trustedIssuer TrustedIssuer, err error) {
	for _, tirEndpoint := range tirEndpoints {
		cacheKey := tirEndpoint + "/v5/" + did + "/full"
		cached, hit := tc.tilCache.Get(cacheKey)
		if hit {
			return true, cached.(TrustedIssuer), nil
		}

		issuer, fetchErr := tc.fetchTrustedIssuerV5(tirEndpoint, did)
		if fetchErr != nil {
			logging.Log().Warnf("V5: Was not able to get the issuer %s from %s. Err: %v", did, tirEndpoint, fetchErr)
			err = fetchErr
			continue
		}

		logging.Log().Debugf("V5: Got issuer %s.", logging.PrettyPrintObject(issuer))
		tc.tilCache.Set(cacheKey, issuer, cache.DefaultExpiration)
		return true, issuer, nil
	}
	return false, trustedIssuer, err
}

// fetchTrustedIssuerV5 performs the full multi-step v5 fetch for a single
// endpoint: get issuer metadata, paginate attribute list, and fetch each
// attribute's details.
func (tc TirHttpClient) fetchTrustedIssuerV5(tirEndpoint string, did string) (TrustedIssuer, error) {
	// Step 1: GET /v5/issuers/{did}
	resp, err := tc.client.Get(tirEndpoint, getIssuerV5Url(did))
	if err != nil {
		return TrustedIssuer{}, err
	}
	if resp == nil {
		return TrustedIssuer{}, ErrorTirNoResponse
	}
	if resp.StatusCode != 200 {
		logging.Log().Debugf("V5: Issuer %s not found at %s (status %d).", did, tirEndpoint, resp.StatusCode)
		return TrustedIssuer{}, fmt.Errorf("issuer %s not found at %s: status %d", did, tirEndpoint, resp.StatusCode)
	}

	var issuerResp TrustedIssuerV5Response
	if resp.Body == nil {
		return TrustedIssuer{}, ErrorTirEmptyResponse
	}
	if err := json.NewDecoder(resp.Body).Decode(&issuerResp); err != nil {
		return TrustedIssuer{}, fmt.Errorf("failed to decode v5 issuer response: %w", err)
	}

	result := TrustedIssuer{Did: issuerResp.Did}

	// Step 2: If issuer has no attributes, return early
	if !issuerResp.HasAttributes {
		logging.Log().Debugf("V5: Issuer %s has no attributes.", did)
		return result, nil
	}

	// Step 3: Paginate through attributes list
	attributeItems, err := tc.fetchAllAttributeItemsV5(tirEndpoint, did)
	if err != nil {
		return TrustedIssuer{}, fmt.Errorf("failed to fetch attribute list for %s: %w", did, err)
	}

	// Step 4: Fetch each individual attribute
	var attributes []IssuerAttribute
	for _, item := range attributeItems {
		attr, err := tc.fetchSingleAttributeV5(tirEndpoint, item.Href)
		if err != nil {
			logging.Log().Warnf("V5: Failed to fetch attribute %s for issuer %s: %v", item.ID, did, err)
			return TrustedIssuer{}, fmt.Errorf("failed to fetch attribute %s for %s: %w", item.ID, did, err)
		}
		attributes = append(attributes, attr)
	}

	result.Attributes = attributes
	return result, nil
}

// fetchAllAttributeItemsV5 paginates through the v5 attributes list endpoint,
// collecting all AttributeListItem entries across pages. It follows the
// Links.Next URL until exhausted or until the safety limit is reached.
func (tc TirHttpClient) fetchAllAttributeItemsV5(tirEndpoint string, did string) ([]AttributeListItem, error) {
	var allItems []AttributeListItem
	currentPath := getAttributesV5Url(did)

	for page := 0; page < maxPaginationPages; page++ {
		resp, err := tc.client.Get(tirEndpoint, currentPath)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch attributes page: %w", err)
		}
		if resp == nil {
			return nil, ErrorTirNoResponse
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("unexpected status %d when fetching attributes", resp.StatusCode)
		}
		if resp.Body == nil {
			return nil, ErrorTirEmptyResponse
		}

		var listResp AttributesListV5Response
		if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
			return nil, fmt.Errorf("failed to decode attributes list: %w", err)
		}

		allItems = append(allItems, listResp.Items...)

		// Stop if there is no next page
		if listResp.Links.Next == "" || listResp.Links.Next == listResp.Self {
			break
		}
		currentPath = listResp.Links.Next
	}

	return allItems, nil
}

// fetchSingleAttributeV5 fetches a single attribute by its href path from the
// v5 API and returns the parsed IssuerAttribute.
func (tc TirHttpClient) fetchSingleAttributeV5(tirEndpoint string, href string) (IssuerAttribute, error) {
	resp, err := tc.client.Get(tirEndpoint, href)
	if err != nil {
		return IssuerAttribute{}, fmt.Errorf("failed to fetch attribute: %w", err)
	}
	if resp == nil {
		return IssuerAttribute{}, ErrorTirNoResponse
	}
	if resp.StatusCode != 200 {
		return IssuerAttribute{}, fmt.Errorf("unexpected status %d when fetching attribute", resp.StatusCode)
	}
	if resp.Body == nil {
		return IssuerAttribute{}, ErrorTirEmptyResponse
	}

	var attrResp AttributeV5Response
	if err := json.NewDecoder(resp.Body).Decode(&attrResp); err != nil {
		return IssuerAttribute{}, fmt.Errorf("failed to decode attribute response: %w", err)
	}

	return attrResp.Attribute, nil
}
