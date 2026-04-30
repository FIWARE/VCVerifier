package database

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fiware/VCVerifier/config"
)

// ServiceRow represents a row in the service table.
type ServiceRow struct {
	// ID is the unique service identifier (primary key).
	ID string
	// DefaultOidcScope is the default OIDC scope name; may be nil.
	DefaultOidcScope *string
	// AuthorizationType describes the authorization mode; may be nil.
	AuthorizationType *string
}

// ScopeEntryRow represents a row in the scope_entry table.
type ScopeEntryRow struct {
	// ID is the auto-generated primary key.
	ID int64
	// ServiceID is the foreign key referencing service.id.
	ServiceID string
	// ScopeKey is the OIDC scope name (map key in ServiceScopes).
	ScopeKey string
	// Credentials is a JSON-encoded array of config.Credential objects.
	Credentials string
	// PresentationDefinition is a JSON-encoded config.PresentationDefinition; may be nil.
	PresentationDefinition *string
	// FlatClaims indicates whether claims should be flattened in the JWT.
	FlatClaims bool
	// DcqlQuery is a JSON-encoded config.DCQL object; may be nil.
	DcqlQuery *string
}

// RefreshTokenRow represents a row in the refresh_token table. Each row
// stores the full JWT claims payload so that access tokens can be re-issued
// without re-applying credential inclusion configurations.
type RefreshTokenRow struct {
	// Token is the opaque refresh token string (primary key).
	Token string
	// ClientID identifies the relying party that requested the token.
	ClientID string
	// JWTPayload is the full signed JWT string (compact serialization)
	// produced by the original token generation. On exchange, the stored
	// token is parsed, the time-dependent fields (iat, exp) are refreshed,
	// and a new access token is signed without re-applying credential
	// inclusion configurations.
	JWTPayload string
	// ExpiresAt is the Unix timestamp (seconds) at which this refresh token
	// expires.
	ExpiresAt int64
}

// ServiceToRow converts a config.ConfiguredService into a ServiceRow.
// The scope entries are handled separately via ScopeEntryToRows.
func ServiceToRow(service config.ConfiguredService) ServiceRow {
	row := ServiceRow{ID: service.Id}
	if service.DefaultOidcScope != "" {
		row.DefaultOidcScope = &service.DefaultOidcScope
	}
	if service.AuthorizationType != "" {
		row.AuthorizationType = &service.AuthorizationType
	}
	return row
}

// ScopeEntryToRows converts the ServiceScopes map from a ConfiguredService
// into a slice of ScopeEntryRow values, marshalling the complex fields to
// JSON text. An error is returned if any JSON serialisation fails.
func ScopeEntryToRows(serviceID string, scopes map[string]config.ScopeEntry) ([]ScopeEntryRow, error) {
	rows := make([]ScopeEntryRow, 0, len(scopes))
	for key, entry := range scopes {
		row, err := scopeEntryToRow(serviceID, key, ScopeEntryDB{}.FromVO(entry))
		if err != nil {
			return nil, fmt.Errorf("scope %q: %w", key, err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// scopeEntryToRow converts a single scope key + ScopeEntry pair into a
// ScopeEntryRow, marshalling credentials, presentationDefinition, and dcql
// to JSON text columns.
func scopeEntryToRow(serviceID, scopeKey string, entry ScopeEntryDB) (ScopeEntryRow, error) {
	credJSON, err := json.Marshal(entry.Credentials)
	if err != nil {
		return ScopeEntryRow{}, fmt.Errorf("failed to marshal credentials: %w", err)
	}

	row := ScopeEntryRow{
		ServiceID:   serviceID,
		ScopeKey:    scopeKey,
		Credentials: string(credJSON),
		FlatClaims:  entry.FlatClaims,
	}

	if entry.PresentationDefinition != nil {
		pdJSON, err := json.Marshal(entry.PresentationDefinition)
		if err != nil {
			return ScopeEntryRow{}, fmt.Errorf("failed to marshal presentationDefinition: %w", err)
		}
		s := string(pdJSON)
		row.PresentationDefinition = &s
	}

	if entry.DCQL != nil {
		dcqlJSON, err := json.Marshal(entry.DCQL)
		if err != nil {
			return ScopeEntryRow{}, fmt.Errorf("failed to marshal dcql: %w", err)
		}
		s := string(dcqlJSON)
		row.DcqlQuery = &s
	}

	return row, nil
}

// RowToService assembles a config.ConfiguredService from a ServiceRow and
// its associated ScopeEntryRow values, unmarshalling JSON text columns back
// into typed Go structs.
func RowToService(row ServiceRow, scopeRows []ScopeEntryRow) (config.ConfiguredService, error) {
	svc := config.ConfiguredService{
		Id:            row.ID,
		ServiceScopes: make(map[string]config.ScopeEntry, len(scopeRows)),
	}
	if row.DefaultOidcScope != nil {
		svc.DefaultOidcScope = *row.DefaultOidcScope
	}
	if row.AuthorizationType != nil {
		svc.AuthorizationType = *row.AuthorizationType
	}

	for _, sr := range scopeRows {
		scopeKey, entry, err := rowToScopeEntry(sr)
		if err != nil {
			return svc, fmt.Errorf("scope_entry id=%d: %w", sr.ID, err)
		}
		svc.ServiceScopes[scopeKey] = entry.VO()
	}
	return svc, nil
}

// rowToScopeEntry converts a single ScopeEntryRow back into a scope key
// and config.ScopeEntry, unmarshalling JSON text columns.
func rowToScopeEntry(row ScopeEntryRow) (string, ScopeEntryDB, error) {
	var entry ScopeEntryDB

	if err := json.Unmarshal([]byte(row.Credentials), &entry.Credentials); err != nil {
		return "", entry, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	entry.FlatClaims = row.FlatClaims

	if row.PresentationDefinition != nil {
		var pd PresentationDefinitionDB
		if err := json.Unmarshal([]byte(*row.PresentationDefinition), &pd); err != nil {
			return "", entry, fmt.Errorf("failed to unmarshal presentationDefinition: %w", err)
		}
		entry.PresentationDefinition = &pd
	}

	if row.DcqlQuery != nil {
		var dcql DCQLDB
		if err := json.Unmarshal([]byte(*row.DcqlQuery), &dcql); err != nil {
			return "", entry, fmt.Errorf("failed to unmarshal dcql: %w", err)
		}
		entry.DCQL = &dcql
	}

	return row.ScopeKey, entry, nil
}

// DATABASE models
type ScopeEntryDB struct {
	// credential types with their trust configuration
	Credentials []CredentialDB `json:"credentials" mapstructure:"credentials"`
	// 	Proofs to be requested - see https://identity.foundation/presentation-exchange/#presentation-definition
	PresentationDefinition *PresentationDefinitionDB `json:"presentationDefinition" mapstructure:"presentationDefinition"`
	// JSON encoded query to request the credentials to be included in the presentation
	DCQL *DCQLDB `json:"dcql" mapstructure:"dcql"`
	// When set, the claim are flatten to plain JWT-claims before beeing included, instead of keeping the credential/presentation structure, where the claims are under the key vc or vp
	FlatClaims bool `json:"flatClaims" mapstructure:"flatClaims"`
}

func (se ScopeEntryDB) FromVO(seVO config.ScopeEntry) ScopeEntryDB {
	creds := make([]CredentialDB, 0, len(seVO.Credentials))
	for _, credVO := range seVO.Credentials {
		creds = append(creds, CredentialDB{}.FromVO(credVO))
	}
	model := ScopeEntryDB{
		Credentials: creds,
		FlatClaims:  seVO.FlatClaims,
	}
	if seVO.DCQL != nil {
		dcql := DCQLDB{}.FromVO(*seVO.DCQL)
		model.DCQL = &dcql
	}
	if seVO.PresentationDefinition != nil {
		pd := PresentationDefinitionDB{}.FromVO(*seVO.PresentationDefinition)
		model.PresentationDefinition = &pd
	}
	return model
}

func (se ScopeEntryDB) VO() config.ScopeEntry {
	creds := make([]config.Credential, 0, len(se.Credentials))
	for _, cred := range se.Credentials {
		creds = append(creds, cred.VO())
	}
	vo := config.ScopeEntry{
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

type CredentialDB struct {
	// Type of the credential
	Type string `json:"credentialType" mapstructure:"credentialType"`
	// Set if the holder id should be verified
	VerifyHolder bool `json:"verifyHolder" mapstructure:"verifyHolder"`
	// A list of (EBSI Trusted Issuers Registry compatible) endpoints to  retrieve the trusted issuers from. The attributes need to be formated to comply with the verifiers requirements.
	TrustedIssuersLists []config.EndpointEntry `json:"trustedLists,omitempty" mapstructure:"trustedLists,omitempty"`
	// Configuration of Holder Verfification
	HolderVerification config.HolderVerification `json:"holderVerification" mapstructure:"holderVerification"`
	// Does the given credential require a compliancy credential
	RequireCompliance bool `json:"requireCompliance" mapstructure:"requireCompliance"`
	// Configuration for the credential its inclusion into the JWT.
	JwtInclusion config.JwtInclusion `json:"jwtInclusion" mapstructure:"jwtInclusion"`
	// Per-credential configuration for the W3C Bitstring Status List /
	// StatusList2021 revocation-list check. When omitted or disabled no
	// revocation check is performed for credentials of this type, preserving
	// prior behaviour for configurations that do not opt in.
	CredentialStatus config.CredentialStatus `json:"credentialStatus,omitempty" mapstructure:"credentialStatus,omitempty"`
}

func (cred CredentialDB) VO() config.Credential {
	trustedIssuerList := make([]string, 0, len(cred.TrustedIssuersLists))
	trustedParticipantsList := make([]config.TrustedParticipantsList, 0, len(cred.TrustedIssuersLists))
	for _, trustedIssuer := range cred.TrustedIssuersLists {
		if trustedIssuer.Type == config.TrustedParticipants {
			listType := trustedIssuer.ListType
			if listType == "" {
				listType = config.DEFAULT_LIST_TYPE
			}
			trustedParticipantsList = append(trustedParticipantsList, config.TrustedParticipantsList{
				Type: listType,
				Url:  trustedIssuer.Endpoint,
			})
		} else if trustedIssuer.Type == config.TrustedIssuers {
			trustedIssuerList = append(trustedIssuerList, trustedIssuer.Endpoint)
		}
	}

	return config.Credential{
		Type:                     cred.Type,
		TrustedParticipantsLists: trustedParticipantsList,
		TrustedIssuersLists:      trustedIssuerList,
		HolderVerification:       cred.HolderVerification,
		RequireCompliance:        cred.RequireCompliance,
		JwtInclusion:             cred.JwtInclusion,
		CredentialStatus:         cred.CredentialStatus,
	}
}

func (c CredentialDB) FromVO(cv config.Credential) CredentialDB {
	trustedLists := make([]config.EndpointEntry, 0, len(cv.TrustedParticipantsLists)+len(cv.TrustedIssuersLists))
	for _, tp := range cv.TrustedParticipantsLists {
		listType := tp.Type
		if listType == "" {
			listType = config.DEFAULT_LIST_TYPE
		}
		trustedLists = append(trustedLists, config.EndpointEntry{
			Type:     config.TrustedParticipants,
			ListType: tp.Type,
			Endpoint: tp.Url,
		})
	}
	for _, endpoint := range cv.TrustedIssuersLists {
		trustedLists = append(trustedLists, config.EndpointEntry{
			Type:     config.TrustedIssuers,
			ListType: config.DEFAULT_LIST_TYPE,
			Endpoint: endpoint,
		})
	}
	return CredentialDB{
		Type:                cv.Type,
		TrustedIssuersLists: trustedLists,
		HolderVerification:  cv.HolderVerification,
		RequireCompliance:   cv.RequireCompliance,
		JwtInclusion:        cv.JwtInclusion,
		CredentialStatus:    cv.CredentialStatus,
	}
}

type PresentationDefinitionDB struct {
	// Id of the definition
	Id string `json:"id" mapstructure:"id"`

	// List of requested inputs
	InputDescriptors []InputDescriptorDB `json:"inputDescriptors" mapstructure:"inputDescriptors"`
	// Format of the credential to be requested
	Format []FormatObjectDB `json:"format" mapstructure:"format"`
}

func (pd PresentationDefinitionDB) VO() config.PresentationDefinition {
	inputDescs := make([]config.InputDescriptor, 0, len(pd.InputDescriptors))
	for _, id := range pd.InputDescriptors {
		inputDescs = append(inputDescs, id.VO())
	}
	return config.PresentationDefinition{
		Id:               pd.Id,
		InputDescriptors: inputDescs,
		Format:           toFormatVOMap(pd.Format),
	}
}

func (pd PresentationDefinitionDB) FromVO(pdVO config.PresentationDefinition) PresentationDefinitionDB {
	inputDescs := make([]InputDescriptorDB, 0, len(pdVO.InputDescriptors))
	for _, idVO := range pdVO.InputDescriptors {
		inputDescs = append(inputDescs, InputDescriptorDB{}.FromVO(idVO))
	}
	return PresentationDefinitionDB{
		Id:               pdVO.Id,
		InputDescriptors: inputDescs,
		Format:           fromFormatVOMap(pdVO.Format),
	}
}

func toFormatVOMap(formats []FormatObjectDB) map[string]config.FormatObject {
	m := make(map[string]config.FormatObject, len(formats))
	for _, f := range formats {
		m[f.FormatKey] = f.VO()
	}
	return m
}

func fromFormatVOMap(m map[string]config.FormatObject) []FormatObjectDB {
	formats := make([]FormatObjectDB, 0, len(m))
	for key, fVO := range m {
		formats = append(formats, FormatObjectDB{FormatKey: key, Alg: fVO.Alg, ProofType: fVO.ProofType})
	}
	return formats
}

type FormatObjectDB struct {
	// format of the key
	FormatKey string `json:"formatKey" mapstructure:"formatKey"`
	// list of algorithms to be requested for credential - f.e. ES256
	Alg       []string `json:"alg" mapstructure:"alg"`
	ProofType []string `json:"proofType,omitempty" mapstructure:"proofType"`
}

func (f FormatObjectDB) VO() config.FormatObject {
	return config.FormatObject{Alg: f.Alg, ProofType: f.ProofType}
}

type InputDescriptorDB struct {
	// Id of the descriptor
	Id string `json:"id" mapstructure:"id"`
	// defines the information to be requested
	Constraints config.Constraints `json:"constraints" mapstructure:"constraints"`
	// Format of the credential to be requested
	Format []FormatObjectDB `json:"format" mapstructure:"format"`
}

func (id InputDescriptorDB) VO() config.InputDescriptor {
	return config.InputDescriptor{
		Id:          id.Id,
		Constraints: id.Constraints,
		Format:      toFormatVOMap(id.Format),
	}
}

func (id InputDescriptorDB) FromVO(idVO config.InputDescriptor) InputDescriptorDB {
	return InputDescriptorDB{
		Id:          idVO.Id,
		Constraints: idVO.Constraints,
		Format:      fromFormatVOMap(idVO.Format),
	}
}

type DCQLDB struct {
	// A non-empty array of Credential Queries that specify the requested Credentials.
	Credentials []CredentialQueryDB `json:"credentials" mapstructure:"credentials"`
	// A non-empty array of Credential Set Queries that specifies additional constraints on which of the requested Credentials to return.
	CredentialSets []config.CredentialSetQuery `json:"credential_sets,omitempty" mapstructure:"credential_sets,omitempty"`
}

func (dcql DCQLDB) VO() config.DCQL {
	creds := make([]config.CredentialQuery, 0, len(dcql.Credentials))
	for _, cred := range dcql.Credentials {
		creds = append(creds, cred.VO())
	}
	return config.DCQL{
		Credentials:    creds,
		CredentialSets: dcql.CredentialSets,
	}
}

func (d DCQLDB) FromVO(dVO config.DCQL) DCQLDB {
	creds := make([]CredentialQueryDB, 0, len(dVO.Credentials))
	for _, cqVO := range dVO.Credentials {
		creds = append(creds, CredentialQueryDB{}.FromVO(cqVO))
	}
	return DCQLDB{
		Credentials:    creds,
		CredentialSets: dVO.CredentialSets,
	}
}

type CredentialQueryDB struct {
	// A string identifying the Credential in the response and, if provided, the constraints in credential_sets. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the Authorization Request, the same id MUST NOT be present more than once.
	Id string `json:"id,omitempty" mapstructure:"id,omitempty"`
	// A string that specifies the format of the requested Credential.
	Format string `json:"format,omitempty" mapstructure:"format,omitempty"`
	// A boolean which indicates whether multiple Credentials can be returned for this Credential Query. If omitted, the default value is false.
	Multiple bool `json:"multiple" mapstructure:"multiple" default:"false"`
	// A non-empty array of objects  that specifies claims in the requested Credential. Verifiers MUST NOT point to the same claim more than once in a single query. Wallets SHOULD ignore such duplicate claim queries.
	Claims []config.ClaimsQuery `json:"claims" mapstructure:"claims"`
	// Defines additional properties requested by the Verifier that apply to the metadata and validity data of the Credential. The properties of this object are defined per Credential Format. If empty, no specific constraints are placed on the metadata or validity of the requested Credential.
	Meta *config.MetaDataQuery `json:"meta,omitempty" mapstructure:"meta,omitempty"`
	// A boolean which indicates whether the Verifier requires a Cryptographic Holder Binding proof. The default value is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required. If set to false, the Verifier accepts a Credential without Cryptographic Holder Binding proof.
	RequireCryptographicHolderBinding bool `json:"requireCryptographicHolderBinding,omitempty" mapstructure:"requireCryptographicHolderBinding,omitempty" default:"false"`
	// A non-empty array containing arrays of identifiers for elements in claims that specifies which combinations of claims for the Credential are requested.
	ClaimSets [][]string `json:"claim_sets,omitempty" mapstructure:"claim_sets,omitempty"`
	// A non-empty array of objects  that specifies expected authorities or trust frameworks that certify Issuers, that the Verifier will accept. Every Credential returned by the Wallet SHOULD match at least one of the conditions present in the corresponding trusted_authorities array if present.
	TrustedAuthorities []config.TrustedAuthorityQuery `json:"trusted_authorities" mapstructure:"trusted_authorities" default:"[]"`
}

func (cq CredentialQueryDB) VO() config.CredentialQuery {
	vo := config.CredentialQuery{
		Id:                                cq.Id,
		Format:                            strings.ToLower(cq.Format),
		Multiple:                          cq.Multiple,
		Claims:                            cq.Claims,
		Meta:                              cq.Meta,
		RequireCryptographicHolderBinding: &cq.RequireCryptographicHolderBinding,
		ClaimSets:                         cq.ClaimSets,
		TrustedAuthorities:                cq.TrustedAuthorities,
	}
	if vo.Claims == nil {
		vo.Claims = make([]config.ClaimsQuery, 0)
	}
	if vo.TrustedAuthorities == nil {
		vo.TrustedAuthorities = make([]config.TrustedAuthorityQuery, 0)
	}
	return vo
}

func (cq CredentialQueryDB) FromVO(cqVO config.CredentialQuery) CredentialQueryDB {
	return CredentialQueryDB{
		Id:                                cqVO.Id,
		Format:                            strings.ToUpper(cqVO.Format),
		Multiple:                          cqVO.Multiple,
		Claims:                            cqVO.Claims,
		Meta:                              cqVO.Meta,
		RequireCryptographicHolderBinding: cqVO.RequiresCryptographicHolderBinding(),
		ClaimSets:                         cqVO.ClaimSets,
		TrustedAuthorities:                cqVO.TrustedAuthorities,
	}
}
