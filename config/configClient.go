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

var ErrorCcsNoResponse = errors.New("no_response_from_ccs")
var ErrorCcsErrorResponse = errors.New("error_response_from_ccs")
var ErrorCcsEmptyResponse = errors.New("empty_response_from_ccs")
var ErrorNoSuchScope = errors.New("requested_scope_does_not_exist")

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
	DefaultOidcScope  string                `json:"defaultOidcScope" mapstructure:"defaultOidcScope"`
	ServiceScopes     map[string]ScopeEntry `json:"oidcScopes" mapstructure:"oidcScopes"`
	Id                string                `json:"id" mapstructure:"id"`
	AuthorizationType string                `json:"authorizationType,omitempty" mapstructure:"authorizationType,omitempty"`
	AuthorizationPath string                `json:"authorizationPath,omitempty" mapstructure:"authorizationPath,omitempty"`
}

type ScopeEntry struct {
	// credential types with their trust configuration
	Credentials []Credential `json:"credentials" mapstructure:"credentials"`
	// 	Proofs to be requested - see https://identity.foundation/presentation-exchange/#presentation-definition
	PresentationDefinition *PresentationDefinition `json:"presentationDefinition" mapstructure:"presentationDefinition"`
	// JSON encoded query to request the credentials to be included in the presentation
	DCQL *DCQL `json:"dcql" mapstructure:"dcql"`
	// When set, the claim are flatten to plain JWT-claims before beeing included, instead of keeping the credential/presentation structure, where the claims are under the key vc or vp
	FlatClaims bool `json:"flatClaims" mapstructure:"flatClaims"`
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
	// Does the given credential require a compliancy credential
	RequireCompliance bool `json:"requireCompliance" mapstructure:"requireCompliance"`
	// Configuration for the credential its inclusion into the JWT.
	JwtInclusion JwtInclusion `json:"jwtInclusion" mapstructure:"jwtInclusion"`
}

type JwtInclusion struct {
	// Should the given credential be included into the generated JWT
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// Should the complete credential be embedded
	FullInclusion bool `json:"fullInclusion" mapstructure:"fullInclusion"`
	// Claims to be included
	ClaimsToInclude []ClaimInclusion `json:"claimsToInclude" mapstructure:"claimsToInclude"`
}

type ClaimInclusion struct {
	// Key of the claim to be included. All objects under this key will be included unchanged.
	OriginalKey string `json:"originalKey" mapstructure:"originalKey"`
	// Key of the claim to be used in the jwt. If not provided, the original one will be used.
	NewKey string `json:"newKey" mapstructure:"newKey"`
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

// DCQL defines a JSON encoded query to request the credentials to be included in the presentation
type DCQL struct {
	// A non-empty array of Credential Queries that specify the requested Credentials.
	Credentials []CredentialQuery `json:"credentials" mapstructure:"credentials"`
	// A non-empty array of Credential Set Queries that specifies additional constraints on which of the requested Credentials to return.
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty" mapstructure:"credential_sets,omitempty"`
}

// CredentialQuery is an object representing a request for a presentation of one or more matching Credentials
type CredentialQuery struct {
	// A string identifying the Credential in the response and, if provided, the constraints in credential_sets. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the Authorization Request, the same id MUST NOT be present more than once.
	Id string `json:"id,omitempty" mapstructure:"id,omitempty"`
	// A string that specifies the format of the requested Credential.
	Format string `json:"format,omitempty" mapstructure:"format,omitempty"`
	// A boolean which indicates whether multiple Credentials can be returned for this Credential Query. If omitted, the default value is false.
	Multiple bool `json:"multiple" mapstructure:"multiple"`
	// A non-empty array of objects  that specifies claims in the requested Credential. Verifiers MUST NOT point to the same claim more than once in a single query. Wallets SHOULD ignore such duplicate claim queries.
	Claims []ClaimsQuery `json:"claims,omitempty" mapstructure:"claims,omitempty"`
	// Defines additional properties requested by the Verifier that apply to the metadata and validity data of the Credential. The properties of this object are defined per Credential Format. If empty, no specific constraints are placed on the metadata or validity of the requested Credential.
	Meta *MetaDataQuery `json:"meta,omitempty" mapstructure:"meta,omitempty"`
	// A boolean which indicates whether the Verifier requires a Cryptographic Holder Binding proof. The default value is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required. If set to false, the Verifier accepts a Credential without Cryptographic Holder Binding proof.
	RequireCryptographicHolderBinding bool `json:"require_cryptographic_holder_binding,omitempty" mapstructure:"require_cryptographic_holder_binding,omitempty"`
	// A non-empty array containing arrays of identifiers for elements in claims that specifies which combinations of claims for the Credential are requested.
	ClaimSets [][]string `json:"claim_sets,omitempty" mapstructure:"claim_sets,omitempty"`
	// A non-empty array of objects  that specifies expected authorities or trust frameworks that certify Issuers, that the Verifier will accept. Every Credential returned by the Wallet SHOULD match at least one of the conditions present in the corresponding trusted_authorities array if present.
	TrustedAuthorities []TrustedAuthorityQuery `json:"trusted_authorities,omitempty" mapstructure:"trusted_authorities,omitempty"`
}

// ClaimsQuery is a query to specifies claims in the requested Credential.
type ClaimsQuery struct {
	// REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise. A string identifying the particular claim. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the particular claims array, the same id MUST NOT be present more than once.
	Id string `json:"id,omitempty" mapstructure:"id,omitempty"`
	//  The value MUST be a non-empty array representing a claims path pointer that specifies the path to a claim within the Credential. See https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-claims-path-pointer
	Path []interface{} `json:"path,omitempty" mapstructure:"path,omitempty"`
	// A non-empty array of strings, integers or boolean values that specifies the expected values of the claim. If the values property is present, the Wallet SHOULD return the claim only if the type and value of the claim both match exactly for at least one of the elements in the array.
	Values []interface{} `json:"values,omitempty" mapstructure:"values,omitempty"`
	// MDoc specific parameter, ignored for all other types. The flag can be set to inform that the reader wishes to keep(store) the data. In case of false, its data is only used to be dispalyed and verified.
	IntentToRetain bool `json:"intent_to_retain,omitempty" mapstructure:"intent_to_retain,omitempty"`
	// MDoc specific parameter, ignored for all other types. Refers to a namespace inside an mdoc.
	Namespace string `json:"namespace,omitempty" mapstructure:"namespace,omitempty"`
	// MDoc specific parameter, ignored for all other types. Identifier for the data-element in the namespace.
	ClaimName string `json:"claim_name,omitempty" mapstructure:"claim_name,omitempty"`
}

// MetaDataQuery defines additional properties requested by the Verifier that apply to the metadata and validity data of the Credential.
type MetaDataQuery struct {
	// SD-JWT and JWT specific parameter. A non-empty array of strings that specifies allowed values for the type of the requested Verifiable Credential.The Wallet MAY return Credentials that inherit from any of the specified types, following the inheritance logic defined in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-10
	VctValues []string `json:"vct_values,omitempty" mapstructure:"vct_values,omitempty"`
	// Required for MDoc. String that specifies an allowed value for the doctype of the requested Verifiable Credential. It MUST be a valid doctype identifier as defined in https://www.iso.org/standard/69084.html
	DoctypeValue string `json:"doctype_value,omitempty" mapstructure:"doctype_value,omitempty"`
	// Required for ldp_vc. A non-empty array of string arrays. The Type value of the credential needs to be a subset of at least one of the string-arrays.
	TypeValues [][]string `json:"type_values,omitempty" mapstructure:"type_values,omitempty"`
}

// TrustedAuthorityQuery is an object representing information that helps to identify an authority or the trust framework that certifies Issuers.
type TrustedAuthorityQuery struct {
	//  A string uniquely identifying the type of information about the issuer trust framework.
	Type string `json:"type" mapstructure:"type"`
	// A non-empty array of strings, where each string (value) contains information specific to the used Trusted Authorities Query type that allows the identification of an issuer, a trust framework, or a federation that an issuer belongs to.
	Values []string `json:"values" mapstructure:"values"`
}

// CredentialSetQuery is a Credential Set Query is an object representing a request for one or more Credentials to satisfy a particular use case with the Verifier.
type CredentialSetQuery struct {
	// A non-empty array, where each value in the array is a list of Credential Query identifiers representing one set of Credentials that satisfies the use case. The value of each element in the options array is a non-empty array of identifiers which reference elements in credentials.
	Options [][]string `json:"options,omitempty" mapstructure:"options,omitempty"`
	// A boolean which indicates whether this set of Credentials is required to satisfy the particular use case at the Verifier.
	Required bool `json:"required,omitempty" mapstructure:"required,omitempty"`
	// A string, number or object specifying the purpose of the query. This specification does not define a specific structure or specific values for this property. The purpose is intended to be used by the Verifier to communicate the reason for the query to the Wallet. The Wallet MAY use this information to show the user the reason for the request.
	Purpose interface{} `json:"purpose,omitempty" mapstructure:"purpose,omitempty"`
}

func (cs ConfiguredService) GetRequiredCredentialTypes(scope string) (types []string, err error) {
	credentials, err := cs.GetCredentials(scope)
	if err != nil {
		return types, err
	}
	for _, credential := range credentials {
		types = append(types, credential.Type)
	}
	return types, err
}

func (cs ConfiguredService) GetScope(scope string) (scopeEntry ScopeEntry, err error) {

	scopeEntry, exists := cs.ServiceScopes[scope]
	if !exists {
		return scopeEntry, ErrorNoSuchScope
	}
	return scopeEntry, nil
}

func (cs ConfiguredService) GetCredentials(scope string) (credentials []Credential, err error) {

	scopeEntry, err := cs.GetScope(scope)
	if err != nil {
		return credentials, err
	}
	return scopeEntry.Credentials, err
}

func (cs ConfiguredService) GetPresentationDefinition(scope string) (pd *PresentationDefinition, err error) {
	scopeEntry, err := cs.GetScope(scope)
	if err != nil {
		return pd, err
	}
	return scopeEntry.PresentationDefinition, err
}

func (cs ConfiguredService) GetDcqlQuery(scope string) (dcql *DCQL, err error) {
	scopeEntry, err := cs.GetScope(scope)
	if err != nil {
		return dcql, err
	}
	return scopeEntry.DCQL, err
}

func (cs ConfiguredService) GetCredential(scope, credentialType string) (Credential, bool) {

	credentials, err := cs.GetCredentials(scope)
	if err == nil {
		for _, credential := range credentials {
			if credential.Type == credentialType {
				return credential, true
			}
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
