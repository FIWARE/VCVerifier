package common

const TYPE_CODE = "authorization_code"
const TYPE_VP_TOKEN = "vp_token"
const TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
const TYPE_VP_TOKEN_SUBJECT = "urn:eu:oidf:vp_token"
const TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"

type OpenIDProviderMetadata struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	PresentationDefinitionEndpoint         string   `json:"presentation_definition_endpoint,omitempty"`
	JwksUri                                string   `json:"jwks_uri"`
	ScopesSupported                        []string `json:"scopes_supported"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	ResponseModeSupported                  []string `json:"response_mode_supported,omitempty"`
	GrantTypesSupported                    []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported                  []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestParameterSupported              bool     `json:"request_parameter_supported,omitempty"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}
