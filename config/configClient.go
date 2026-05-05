package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fiware/VCVerifier/logging"
)

type EndpointType int

const DEFAULT_LIST_TYPE = "ebsi"

const (
	Unknown EndpointType = iota
	TrustedIssuers
	TrustedParticipants
)

func (e EndpointType) String() string {
	switch e {
	case TrustedIssuers:
		return "TRUSTED_ISSUERS"
	case TrustedParticipants:
		return "TRUSTED_PARTICIPANTS"
	default:
		return "UNKNOWN"
	}
}

func (e EndpointType) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func (e *EndpointType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	switch s {
	case "TRUSTED_ISSUERS":
		*e = TrustedIssuers
	case "TRUSTED_PARTICIPANTS":
		*e = TrustedParticipants
	default:
		*e = Unknown
	}
	return nil
}

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
	Total      int                   `json:"total"`
	PageNumber int                   `json:"pageNumber"`
	PageSize   int                   `json:"pageSize"`
	Services   []ConfiguredServiceVO `json:"services"`
}

type ConfiguredService struct {
	// Default OIDC scope to be used if none is specified
	DefaultOidcScope  string                `json:"defaultOidcScope" mapstructure:"defaultOidcScope"`
	ServiceScopes     map[string]ScopeEntry `json:"oidcScopes" mapstructure:"oidcScopes"`
	Id                string                `json:"id" mapstructure:"id"`
	AuthorizationType string                `json:"authorizationType,omitempty" mapstructure:"authorizationType,omitempty"`
	AuthorizationPath string                `json:"authorizationPath,omitempty" mapstructure:"authorizationPath,omitempty"`
	// AllowedOrigins specifies the list of origins permitted for CORS requests
	// to this service. When empty or nil, no service-specific restriction is
	// applied and the verifier falls back to the global default (wildcard).
	// Set to ["*"] to explicitly allow all origins for this service.
	AllowedOrigins []string `json:"allowedOrigins,omitempty" mapstructure:"allowedOrigins,omitempty"`
}

type ConfiguredServiceVO struct {
	DefaultOidcScope  string                  `json:"defaultOidcScope" mapstructure:"defaultOidcScope"`
	ServiceScopes     map[string]ScopeEntryVO `json:"oidcScopes" mapstructure:"oidcScopes"`
	Id                string                  `json:"id" mapstructure:"id"`
	AuthorizationType string                  `json:"authorizationType,omitempty" mapstructure:"authorizationType,omitempty"`
	AuthorizationPath string                  `json:"authorizationPath,omitempty" mapstructure:"authorizationPath,omitempty"`
	AllowedOrigins    []string                `json:"allowedOrigins,omitempty" mapstructure:"allowedOrigins,omitempty"`
}

func (cs ConfiguredService) FromVO(vo ConfiguredServiceVO) ConfiguredService {

	cs.DefaultOidcScope = vo.DefaultOidcScope
	cs.Id = vo.Id
	cs.AuthorizationType = vo.AuthorizationType
	cs.AuthorizationPath = vo.AuthorizationPath
	cs.AllowedOrigins = vo.AllowedOrigins
	if vo.ServiceScopes != nil {
		cs.ServiceScopes = make(map[string]ScopeEntry, len(vo.ServiceScopes))
		for key, value := range vo.ServiceScopes {
			cs.ServiceScopes[key] = ScopeEntry{}.FromVO(value)
		}
	}
	return cs
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

type ScopeEntryVO struct {
	Credentials            []CredentialVo            `json:"credentials" mapstructure:"credentials"`
	PresentationDefinition *PresentationDefinitionVO `json:"presentationDefinition,omitempty" mapstructure:"presentationDefinition,omitempty"`
	DCQL                   *DCQLVO                   `json:"dcql,omitempty" mapstructure:"dcql,omitempty"`
	FlatClaims             bool                      `json:"flatClaims" mapstructure:"flatClaims"`
}

func (se ScopeEntry) FromVO(seVO ScopeEntryVO) ScopeEntry {
	creds := make([]Credential, 0, len(seVO.Credentials))
	for _, credVO := range seVO.Credentials {
		creds = append(creds, Credential{}.FromVO(credVO))
	}
	model := ScopeEntry{
		Credentials: creds,
		FlatClaims:  seVO.FlatClaims,
	}
	if seVO.DCQL != nil {
		dcql := DCQL{}.FromVO(*seVO.DCQL)
		model.DCQL = &dcql
	}
	if seVO.PresentationDefinition != nil {
		pd := PresentationDefinition{}.FromVO(*seVO.PresentationDefinition)
		model.PresentationDefinition = &pd
	}
	return model
}

func (se ScopeEntry) VO() ScopeEntryVO {
	creds := make([]CredentialVo, 0, len(se.Credentials))
	for _, cred := range se.Credentials {
		creds = append(creds, cred.VO())
	}
	vo := ScopeEntryVO{
		Credentials: creds,
		FlatClaims:  se.FlatClaims,
	}
	if se.DCQL != nil {
		dcql := se.DCQL.VO()
		vo.DCQL = &dcql
	}
	if se.PresentationDefinition != nil {
		pdVO := se.PresentationDefinition.VO()
		vo.PresentationDefinition = &pdVO
	}
	return vo
}

type Credential struct {
	// Type of the credential
	Type string `json:"credentialType" mapstructure:"credentialType"`
	// Set if the holder id should be verified
	VerifyHolder bool `json:"verifyHolder" mapstructure:"verifyHolder"`
	// A list of (EBSI Trusted Issuers Registry compatible) endpoints to  retrieve the trusted issuers from. The attributes need to be formated to comply with the verifiers requirements.
	TrustedIssuersLists []EndpointEntry `json:"trustedLists,omitempty" mapstructure:"trustedLists,omitempty"`
	// Configuration of Holder Verfification
	HolderVerification HolderVerification `json:"holderVerification" mapstructure:"holderVerification"`
	// Does the given credential require a compliancy credential
	RequireCompliance bool `json:"requireCompliance" mapstructure:"requireCompliance"`
	// Configuration for the credential its inclusion into the JWT.
	JwtInclusion JwtInclusion `json:"jwtInclusion" mapstructure:"jwtInclusion"`
	// Per-credential configuration for the W3C Bitstring Status List /
	// StatusList2021 revocation-list check. When omitted or disabled no
	// revocation check is performed for credentials of this type, preserving
	// prior behaviour for configurations that do not opt in.
	CredentialStatus CredentialStatus `json:"credentialStatus,omitempty" mapstructure:"credentialStatus,omitempty"`
}

func (cred Credential) VO() CredentialVo {
	trustedIssuerList := make([]string, 0, len(cred.TrustedIssuersLists))
	trustedParticipantsList := make([]TrustedParticipantsList, 0, len(cred.TrustedIssuersLists))
	for _, trustedIssuer := range cred.TrustedIssuersLists {
		if trustedIssuer.Type == TrustedParticipants {
			listType := trustedIssuer.ListType
			if listType == "" {
				listType = DEFAULT_LIST_TYPE
			}
			trustedParticipantsList = append(trustedParticipantsList, TrustedParticipantsList{
				Type: listType,
				Url:  trustedIssuer.Endpoint,
			})
		} else if trustedIssuer.Type == TrustedIssuers {
			trustedIssuerList = append(trustedIssuerList, trustedIssuer.Endpoint)
		}
	}

	return CredentialVo{
		Type:                     cred.Type,
		TrustedParticipantsLists: trustedParticipantsList,
		TrustedIssuersLists:      trustedIssuerList,
		HolderVerification:       cred.HolderVerification,
		RequireCompliance:        cred.RequireCompliance,
		JwtInclusion:             cred.JwtInclusion,
		CredentialStatus:         cred.CredentialStatus,
	}
}

func (c Credential) FromVO(cv CredentialVo) Credential {
	trustedLists := make([]EndpointEntry, 0, len(cv.TrustedParticipantsLists)+len(cv.TrustedIssuersLists))
	for _, tp := range cv.TrustedParticipantsLists {
		listType := tp.Type
		if listType == "" {
			listType = DEFAULT_LIST_TYPE
		}
		trustedLists = append(trustedLists, EndpointEntry{
			Type:     TrustedParticipants,
			ListType: tp.Type,
			Endpoint: tp.Url,
		})
	}
	for _, endpoint := range cv.TrustedIssuersLists {
		trustedLists = append(trustedLists, EndpointEntry{
			Type:     TrustedIssuers,
			ListType: DEFAULT_LIST_TYPE,
			Endpoint: endpoint,
		})
	}
	return Credential{
		Type:                cv.Type,
		TrustedIssuersLists: trustedLists,
		HolderVerification:  cv.HolderVerification,
		RequireCompliance:   cv.RequireCompliance,
		JwtInclusion:        cv.JwtInclusion,
		CredentialStatus:    cv.CredentialStatus,
	}
}

type CredentialVo struct {
	Type string `json:"type"`

	TrustedParticipantsLists []TrustedParticipantsList `json:"trustedParticipantsLists,omitempty"`

	TrustedIssuersLists []string `json:"trustedIssuersLists,omitempty"`

	HolderVerification HolderVerification `json:"holderVerification"`

	RequireCompliance bool `json:"requireCompliance"`

	JwtInclusion JwtInclusion `json:"jwtInclusion"`

	CredentialStatus CredentialStatus `json:"credentialStatus,omitempty"`
}

// CredentialStatus holds the per-credential-type configuration for the
// status-list based revocation check. The zero-value disables the check, so
// credentials that omit the block behave exactly as they did before the
// feature was introduced.
type CredentialStatus struct {
	// Enabled toggles the revocation-list check for this credential type.
	// When false (the default), no status-list lookup is performed for
	// credentials of this type.
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// AcceptedPurposes lists the status purposes this credential type enforces
	// (for example "revocation" or "suspension"). When empty callers should
	// fall back to DefaultAcceptedStatusPurposes(). The field is intentionally
	// left un-defaulted at mapstructure level so the YAML can distinguish
	// "not set" from an explicit empty list.
	AcceptedPurposes []string `json:"acceptedPurposes,omitempty" mapstructure:"acceptedPurposes,omitempty"`
	// RequireStatus rejects credentials of this type that are missing a
	// credentialStatus entry when set to true. Defaults to false so that
	// credentials without status information are accepted.
	RequireStatus bool `json:"requireStatus" mapstructure:"requireStatus"`
}

type JwtInclusion struct {
	// Should the given credential be included into the generated JWT
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// Should the complete credential be embedded
	FullInclusion bool `json:"fullInclusion" mapstructure:"fullInclusion"`
	// Claims to be included
	ClaimsToInclude []ClaimInclusion `json:"claimsToInclude" mapstructure:"claimsToInclude" default:"[]"`
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

type EndpointEntry struct {
	Type     EndpointType `json:"type" mapstructure:"type"`
	ListType string       `json:"listType" mapstructure:"listType" default:"ebsi"`
	Endpoint string       `json:"endpoint" mapstructure:"endpoint"`
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
	InputDescriptors []InputDescriptor `json:"inputDescriptors" mapstructure:"inputDescriptors"`
	// Format of the credential to be requested
	Format []FormatObject `json:"format" mapstructure:"format"`
}

func (pd PresentationDefinition) VO() PresentationDefinitionVO {
	inputDescs := make([]InputDescriptorVO, 0, len(pd.InputDescriptors))
	for _, id := range pd.InputDescriptors {
		inputDescs = append(inputDescs, id.VO())
	}
	return PresentationDefinitionVO{
		Id:               pd.Id,
		InputDescriptors: inputDescs,
		Format:           toFormatVOMap(pd.Format),
	}
}

func (pd PresentationDefinition) FromVO(pdVO PresentationDefinitionVO) PresentationDefinition {
	inputDescs := make([]InputDescriptor, 0, len(pdVO.InputDescriptors))
	for _, idVO := range pdVO.InputDescriptors {
		inputDescs = append(inputDescs, InputDescriptor{}.FromVO(idVO))
	}
	return PresentationDefinition{
		Id:               pdVO.Id,
		InputDescriptors: inputDescs,
		Format:           fromFormatVOMap(pdVO.Format),
	}
}

func toFormatVOMap(formats []FormatObject) map[string]FormatObjectVO {
	m := make(map[string]FormatObjectVO, len(formats))
	for _, f := range formats {
		m[f.FormatKey] = f.VO()
	}
	return m
}

func fromFormatVOMap(m map[string]FormatObjectVO) []FormatObject {
	formats := make([]FormatObject, 0, len(m))
	for key, fVO := range m {
		formats = append(formats, FormatObject{FormatKey: key, Alg: fVO.Alg, ProofType: fVO.ProofType})
	}
	return formats
}

type PresentationDefinitionVO struct {
	Id string `json:"id"`
	// List of requested inputs
	InputDescriptors []InputDescriptorVO `json:"input_descriptors" mapstructure:"input_descriptors"`
	// Format of the credential to be requested
	Format map[string]FormatObjectVO `json:"format" mapstructure:"format"`
}
type FormatObjectVO struct {
	Alg       []string `json:"alg" mapstructure:"alg"`
	ProofType []string `json:"proofType,omitempty" mapstructure:"proofType,omitempty"`
}

type FormatObject struct {
	// format of the key
	FormatKey string `json:"formatKey" mapstructure:"formatKey"`
	// list of algorithms to be requested for credential - f.e. ES256
	Alg       []string `json:"alg" mapstructure:"alg"`
	ProofType []string `json:"proofType,omitempty" mapstructure:"proofType"`
}

func (f FormatObject) VO() FormatObjectVO {
	return FormatObjectVO{Alg: f.Alg, ProofType: f.ProofType}
}

type InputDescriptor struct {
	// Id of the descriptor
	Id string `json:"id" mapstructure:"id"`
	// defines the information to be requested
	Constraints Constraints `json:"constraints" mapstructure:"constraints"`
	// Format of the credential to be requested
	Format []FormatObject `json:"format" mapstructure:"format"`
}

type InputDescriptorVO struct {
	Id          string                    `json:"id" mapstructure:"id"`
	Constraints Constraints               `json:"constraints" mapstructure:"constraints"`
	Format      map[string]FormatObjectVO `json:"format,omitempty" mapstructure:"format,omitempty"`
}

func (id InputDescriptor) VO() InputDescriptorVO {
	return InputDescriptorVO{
		Id:          id.Id,
		Constraints: id.Constraints,
		Format:      toFormatVOMap(id.Format),
	}
}

func (id InputDescriptor) FromVO(idVO InputDescriptorVO) InputDescriptor {
	return InputDescriptor{
		Id:          idVO.Id,
		Constraints: idVO.Constraints,
		Format:      fromFormatVOMap(idVO.Format),
	}
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
	Filter interface{} `json:"filter,omitempty" mapstructure:"filter"`
}

// DCQL defines a JSON encoded query to request the credentials to be included in the presentation
type DCQL struct {
	// A non-empty array of Credential Queries that specify the requested Credentials.
	Credentials []CredentialQuery `json:"credentials" mapstructure:"credentials"`
	// A non-empty array of Credential Set Queries that specifies additional constraints on which of the requested Credentials to return.
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty" mapstructure:"credential_sets,omitempty"`
}

func (dcql DCQL) VO() DCQLVO {
	creds := make([]CredentialQueryVO, 0, len(dcql.Credentials))
	for _, cred := range dcql.Credentials {
		creds = append(creds, cred.VO())
	}
	return DCQLVO{
		Credentials:    creds,
		CredentialSets: dcql.CredentialSets,
	}
}

func (d DCQL) FromVO(dVO DCQLVO) DCQL {
	creds := make([]CredentialQuery, 0, len(dVO.Credentials))
	for _, cqVO := range dVO.Credentials {
		creds = append(creds, CredentialQuery{}.FromVO(cqVO))
	}
	return DCQL{
		Credentials:    creds,
		CredentialSets: dVO.CredentialSets,
	}
}

type DCQLVO struct {
	Credentials    []CredentialQueryVO  `json:"credentials" mapstructure:"credentials"`
	CredentialSets []CredentialSetQuery `json:"credential_sets" mapstructure:"credential_sets"`
}

// CredentialQuery is an object representing a request for a presentation of one or more matching Credentials
type CredentialQuery struct {
	// A string identifying the Credential in the response and, if provided, the constraints in credential_sets. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the Authorization Request, the same id MUST NOT be present more than once.
	Id string `json:"id,omitempty" mapstructure:"id,omitempty"`
	// A string that specifies the format of the requested Credential.
	Format string `json:"format,omitempty" mapstructure:"format,omitempty"`
	// A boolean which indicates whether multiple Credentials can be returned for this Credential Query. If omitted, the default value is false.
	Multiple bool `json:"multiple" mapstructure:"multiple" default:"false"`
	// A non-empty array of objects  that specifies claims in the requested Credential. Verifiers MUST NOT point to the same claim more than once in a single query. Wallets SHOULD ignore such duplicate claim queries.
	Claims []ClaimsQuery `json:"claims" mapstructure:"claims"`
	// Defines additional properties requested by the Verifier that apply to the metadata and validity data of the Credential. The properties of this object are defined per Credential Format. If empty, no specific constraints are placed on the metadata or validity of the requested Credential.
	Meta *MetaDataQuery `json:"meta,omitempty" mapstructure:"meta,omitempty"`
	// A boolean which indicates whether the Verifier requires a Cryptographic Holder Binding proof. The default value is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required. If set to false, the Verifier accepts a Credential without Cryptographic Holder Binding proof.
	RequireCryptographicHolderBinding bool `json:"requireCryptographicHolderBinding,omitempty" mapstructure:"requireCryptographicHolderBinding,omitempty" default:"false"`
	// A non-empty array containing arrays of identifiers for elements in claims that specifies which combinations of claims for the Credential are requested.
	ClaimSets [][]string `json:"claim_sets,omitempty" mapstructure:"claim_sets,omitempty"`
	// A non-empty array of objects  that specifies expected authorities or trust frameworks that certify Issuers, that the Verifier will accept. Every Credential returned by the Wallet SHOULD match at least one of the conditions present in the corresponding trusted_authorities array if present.
	TrustedAuthorities []TrustedAuthorityQuery `json:"trusted_authorities" mapstructure:"trusted_authorities" default:"[]"`
}

func (cq CredentialQuery) VO() CredentialQueryVO {
	vo := CredentialQueryVO{
		Id:                                cq.Id,
		Format:                            strings.ToLower(cq.Format),
		Multiple:                          cq.Multiple,
		Claims:                            cq.Claims,
		Meta:                              cq.Meta,
		RequireCryptographicHolderBinding: cq.RequireCryptographicHolderBinding,
		ClaimSets:                         cq.ClaimSets,
		TrustedAuthorities:                cq.TrustedAuthorities,
	}
	if vo.Claims == nil {
		vo.Claims = make([]ClaimsQuery, 0)
	}
	if vo.TrustedAuthorities == nil {
		vo.TrustedAuthorities = make([]TrustedAuthorityQuery, 0)
	}
	return vo
}

func (cq CredentialQuery) FromVO(cqVO CredentialQueryVO) CredentialQuery {
	return CredentialQuery{
		Id:                                cqVO.Id,
		Format:                            strings.ToUpper(cqVO.Format),
		Multiple:                          cqVO.Multiple,
		Claims:                            cqVO.Claims,
		Meta:                              cqVO.Meta,
		RequireCryptographicHolderBinding: cqVO.RequireCryptographicHolderBinding,
		ClaimSets:                         cqVO.ClaimSets,
		TrustedAuthorities:                cqVO.TrustedAuthorities,
	}
}

type CredentialQueryVO struct {
	Id                                string                  `json:"id,omitempty" mapstructure:"id,omitempty"`
	Format                            string                  `json:"format,omitempty" mapstructure:"format,omitempty"`
	Multiple                          bool                    `json:"multiple" mapstructure:"multiple"`
	Claims                            []ClaimsQuery           `json:"claims" mapstructure:"claims"`
	Meta                              *MetaDataQuery          `json:"meta,omitempty" mapstructure:"meta,omitempty"`
	RequireCryptographicHolderBinding bool                    `json:"require_cryptographic_holder_binding" mapstructure:"require_cryptographic_holder_binding"`
	ClaimSets                         [][]string              `json:"claim_sets,omitempty" mapstructure:"claim_sets,omitempty"`
	TrustedAuthorities                []TrustedAuthorityQuery `json:"trusted_authorities" mapstructure:"trusted_authorities"`
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
		for _, svcVO := range servicesResponse.Services {
			services = append(services, ConfiguredService{}.FromVO(svcVO))
		}
		// we check both, since its possible that during the iteration new services where added to old pages(total != len(services)).
		// those will be retrieved on next iteration, thus can be ignored
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
