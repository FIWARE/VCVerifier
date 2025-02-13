package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fiware/VCVerifier/logging"
)

const SERVICES_PATH = "service"

const SERVICE_DEFAULT_SCOPE = ""

var ErrorCcsNoResponse = errors.New("no_response_from_ccs")
var ErrorCcsErrorResponse = errors.New("error_response_from_ccs")
var ErrorCcsEmptyResponse = errors.New("empty_response_from_ccs")

type HttpClient interface {
	Get(url string) (resp *http.Response, err error)
}

type ConfigClient interface {
	GetServices() (services []ConfiguredService, err error)
}

type HttpConfigClient struct {
	client         HttpClient
	configEndpoint string
}

type ServicesResponse struct {
	Total      int                 `json:"total"`
	PageNumber int                 `json:"pageNumber"`
	PageSize   int                 `json:"pageSize"`
	Services   []ConfiguredService `json:"services"`
}

type ConfiguredService struct {
	// Default OIDC scope to be used if none is specified
	DefaultOidcScope string                  `json:"defaultOidcScope" mapstructure:"defaultOidcScope"`
	ServiceScopes    map[string][]Credential `json:"oidcScopes" mapstructure:"oidcScopes"`
	Id               string                  `json:"id" mapstructure:"id"`
}

type Credential struct {
	// Type of the credential
	Type string `json:"type" mapstructure:"type"`
	// A list of (EBSI Trusted Issuers Registry compatible) endpoints to  retrieve the trusted participants from.
	TrustedParticipantsLists []TrustedParticipantsList `json:"trustedParticipantsLists,omitempty" mapstructure:"trustedParticipantsLists,omitempty"`
	// A list of (EBSI Trusted Issuers Registry compatible) endpoints to  retrieve the trusted issuers from. The attributes need to be formated to comply with the verifiers requirements.
	TrustedIssuersLists []string `json:"trustedIssuersLists,omitempty" mapstructure:"trustedIssuersLists,omitempty"`
	// Configuration of Holder Verfification
	HolderVerification HolderVerification `json:"holderVerification" mapstructure:"holderVerification"`
}

type TrustedParticipantsList struct {
	// Type of praticipants list to be used - either gaia-x or ebsi
	Type string `json:"type" mapstructure:"type"`
	// url of the list
	Url string `json:"url" mapstructure:"url"`
}

type HolderVerification struct {
	// should holder verification be enabled
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// the claim containing the holder
	Claim string `json:"claim" mapstructure:"claim"`
}

func (cs ConfiguredService) GetRequiredCredentialTypes(scope string) []string {
	types := []string{}
	for _, credential := range cs.GetCredentials(scope) {
		types = append(types, credential.Type)
	}
	return types
}

func (cs ConfiguredService) GetCredentials(scope string) []Credential {
	if scope != SERVICE_DEFAULT_SCOPE {
		return cs.ServiceScopes[scope]
	}
	return cs.ServiceScopes[cs.DefaultOidcScope]
}

func (cs ConfiguredService) GetCredential(scope, credentialType string) (Credential, bool) {
	credentials := cs.GetCredentials(scope)
	for _, credential := range credentials {
		if credential.Type == credentialType {
			return credential, true
		}
	}
	return Credential{}, false
}

func NewCCSHttpClient(configEndpoint string) (client ConfigClient, err error) {

	// no need for a caching client here, since the repo handles the "caching"
	httpClient := &http.Client{}
	return HttpConfigClient{httpClient, getServiceUrl(configEndpoint)}, err
}

func (hcc HttpConfigClient) GetServices() (services []ConfiguredService, err error) {
	var currentPage int = 0
	var pageSize int = 100
	var finished bool = false
	services = []ConfiguredService{}

	for !finished {
		servicesResponse, err := hcc.getServicesPage(currentPage, pageSize)
		if err != nil {
			logging.Log().Warnf("Failed to receive services page %v with size %v. Err: %v", currentPage, pageSize, err)
			return nil, err
		}
		services = append(services, servicesResponse.Services...)
		// we check both, since its possible that druing the iterration new services where added to old pages(total != len(services)).
		// those will be retrieved on next iterration, thus can be ignored
		if servicesResponse.Total == 0 || len(servicesResponse.Services) < pageSize || servicesResponse.Total == len(services) {
			finished = true
		}
		currentPage++
	}
	return services, err
}

func (hcc HttpConfigClient) getServicesPage(page int, pageSize int) (servicesResponse ServicesResponse, err error) {
	logging.Log().Debugf("Retrieve services from %s for page %v and size %v.", hcc.configEndpoint, page, pageSize)
	resp, err := hcc.client.Get(fmt.Sprintf("%s?pageSize=%v&page=%v", hcc.configEndpoint, pageSize, page))
	if err != nil {
		logging.Log().Warnf("Was not able to get the services from %s. Err: %v", hcc.configEndpoint, err)
		return servicesResponse, err
	}
	if resp == nil {
		logging.Log().Warnf("Was not able to get any response for from %s.", hcc.configEndpoint)
		return servicesResponse, ErrorCcsNoResponse
	}
	if resp.StatusCode != 200 {
		logging.Log().Warnf("Was not able to get the services from %s. Stauts: %v", hcc.configEndpoint, resp.StatusCode)
		return servicesResponse, ErrorCcsErrorResponse
	}
	if resp.Body == nil {
		logging.Log().Info("Received an empty body from the ccs.")
		return servicesResponse, ErrorCcsEmptyResponse
	}

	err = json.NewDecoder(resp.Body).Decode(&servicesResponse)
	if err != nil {
		logging.Log().Warn("Was not able to decode the ccs-response.")
		return servicesResponse, err
	}
	logging.Log().Debugf("Services response was: %s.", logging.PrettyPrintObject(servicesResponse))
	return servicesResponse, err
}

func getServiceUrl(endpoint string) string {
	if strings.HasSuffix(endpoint, "/") {
		return endpoint + SERVICES_PATH
	} else {
		return endpoint + "/" + SERVICES_PATH
	}
}
