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
	DefaultOidcScope string                `json:"defaultOidcScope" mapstructure:"defaultOidcScope"`
	ServiceScopes    map[string]ScopeEntry `json:"oidcScopes" mapstructure:"oidcScopes"`
	Id               string                `json:"id" mapstructure:"id"`
}

type ScopeEntry struct {
	// credential types with their trust configuration
	Credentials []Credential `json:"credentials" mapstructure:"credentials"`
	// 	Proofs to be requested - see https://identity.foundation/presentation-exchange/#presentation-definition
	PresentationDefinition PresentationDefinition `json:"presentationDefinition" mapstructure:"presentationDefinition"`
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

type PresentationDefinition struct {
	// Id of the definition
	Id string `json:"id" mapstructure:"id"`
	// List of requested inputs
	InputDescriptors []InputDescriptor `json:"input_descriptors" mapstructure:"input_descriptors"`
	// Format of the credential to be requested
	Format map[string]FormatObject `json:"format" mapstructure:"format"`
}

type FormatObject struct {
	// list of algorithms to be requested for credential - f.e. ES256
	Alg []string `json:"alg" mapstructure:"alg"`
}

type InputDescriptor struct {
	// Id of the descriptor
	Id string `json:"id" mapstructure:"id"`
	// defines the infromation to be requested
	Constraints Constraints `json:"constraints" mapstructure:"constraints"`
	// Format of the credential to be requested
	Format map[string]FormatObject `json:"format" mapstructure:"format"`
}

type Constraints struct {
	// array of objects to describe the information to be included
	Fields []Fields `json:"fields" mapstructure:"fields"`
}

type Fields struct {
	// Id of the field
	Id string `json:"id" mapstructure:"id"`
	// A list of JsonPaths for the requested claim
	Path []string `json:"path" mapstructure:"path"`
	// Does it need to be included?
	Optional bool `json:"optional" mapstructure:"optional" default:"true"`
	// a custom filter to be applied on the fields, f.e. restrict to certain values
	Filter interface{} `json:"filter" mapstructure:"filter"`
}

func (cs ConfiguredService) GetRequiredCredentialTypes(scope string) []string {
	types := []string{}
	for _, credential := range cs.GetCredentials(scope) {
		types = append(types, credential.Type)
	}
	return types
}

func (cs ConfiguredService) GetScope(scope string) ScopeEntry {
	if scope != SERVICE_DEFAULT_SCOPE {
		return cs.ServiceScopes[scope]
	}
	return cs.ServiceScopes[cs.DefaultOidcScope]
}

func (cs ConfiguredService) GetCredentials(scope string) []Credential {
	return cs.GetScope(scope).Credentials
}

func (cs ConfiguredService) GetPresentationDefinition(scope string) PresentationDefinition {
	return cs.GetScope(scope).PresentationDefinition
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
