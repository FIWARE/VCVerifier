package common

import (
	"encoding/json"
	"time"
)

// W3C Verifiable Credentials Data Model constants
// See https://www.w3.org/TR/vc-data-model-2.0/
const (
	// ContextCredentialsV1 is the W3C VC Data Model v1.1 context URI.
	ContextCredentialsV1 = "https://www.w3.org/2018/credentials/v1"

	// ContextCredentialsV2 is the W3C VC Data Model v2.0 context URI.
	ContextCredentialsV2 = "https://www.w3.org/ns/credentials/v2"

	// TypeVerifiableCredential is the base type for all Verifiable Credentials.
	TypeVerifiableCredential = "VerifiableCredential"

	// TypeVerifiablePresentation is the base type for all Verifiable Presentations.
	TypeVerifiablePresentation = "VerifiablePresentation"

	// JSONLDKeyContext is the JSON-LD @context key.
	JSONLDKeyContext = "@context"

	// JSONLDKeyType is the JSON-LD type key.
	JSONLDKeyType = "type"

	// JSONLDKeyID is the JSON-LD id key.
	JSONLDKeyID = "id"

	// VCKeyIssuer is the issuer key in a VC JSON representation.
	VCKeyIssuer = "issuer"

	// VCKeyCredentialSubject is the credentialSubject key in a VC JSON representation.
	VCKeyCredentialSubject = "credentialSubject"

	// VCKeyValidFrom is the validFrom key (VC Data Model 2.0).
	VCKeyValidFrom = "validFrom"

	// VCKeyValidUntil is the validUntil key (VC Data Model 2.0).
	VCKeyValidUntil = "validUntil"

	// VCKeyCredentialStatus is the credentialStatus key.
	VCKeyCredentialStatus = "credentialStatus"

	// VCKeyCredentialSchema is the credentialSchema key.
	VCKeyCredentialSchema = "credentialSchema"

	// VCKeyEvidence is the evidence key.
	VCKeyEvidence = "evidence"

	// VCKeyTermsOfUse is the termsOfUse key.
	VCKeyTermsOfUse = "termsOfUse"

	// VCKeyRefreshService is the refreshService key.
	VCKeyRefreshService = "refreshService"

	// VPKeyHolder is the holder key in a VP JSON representation.
	VPKeyHolder = "holder"

	// VPKeyVerifiableCredential is the verifiableCredential key in a VP JSON representation.
	VPKeyVerifiableCredential = "verifiableCredential"

	// VPKeyProof is the proof key in a VP/VC JSON representation.
	VPKeyProof = "proof"

	// VCKeyIssuanceDate is the issuanceDate key (VC Data Model 1.1).
	VCKeyIssuanceDate = "issuanceDate"

	// VCKeyExpirationDate is the expirationDate key (VC Data Model 1.1).
	VCKeyExpirationDate = "expirationDate"

	// VCKeyIssued is the issued key (legacy VC date field).
	VCKeyIssued = "issued"
)

// JWT standard claim keys (RFC 7519).
const (
	JWTClaimIss = "iss" // Issuer
	JWTClaimSub = "sub" // Subject
	JWTClaimJti = "jti" // JWT ID
	JWTClaimNbf = "nbf" // Not Before
	JWTClaimIat = "iat" // Issued At
	JWTClaimExp = "exp" // Expiration Time
)

// JWT-VC/VP specific claim keys.
const (
	JWTClaimVC  = "vc"  // VC claim in a JWT-encoded Verifiable Credential
	JWTClaimVP  = "vp"  // VP claim in a JWT-encoded Verifiable Presentation
	JWTClaimVct = "vct" // Verifiable Credential Type (SD-JWT VC)
	JWTClaimCnf = "cnf" // Confirmation method (RFC 7800, used for cryptographic holder binding)
	CnfKeyJWK   = "jwk" // JWK key within the cnf claim (RFC 7800 §3.2)
)

// JSONObject is an alias for a generic JSON map.
type JSONObject = map[string]interface{}

// CustomFields holds additional fields beyond the standard VC fields.
type CustomFields map[string]interface{}

// Issuer identifies the entity that issued a Verifiable Credential.
type Issuer struct {
	ID string
}

// Subject holds the claims made about a credential subject.
type Subject struct {
	ID           string
	CustomFields map[string]interface{}
}

// TypedID represents a typed identifier used for status, schema, evidence, etc.
type TypedID struct {
	ID   string
	Type string
}

// CredentialContents contains the structured content of a Verifiable Credential.
// Fields align with the W3C VC Data Model 2.0 specification.
type CredentialContents struct {
	Context        []string
	ID             string
	Types          []string
	Issuer         *Issuer
	Subject        []Subject
	ValidFrom      *time.Time
	ValidUntil     *time.Time
	Status         *TypedID
	Schemas        []TypedID
	Evidence       []interface{}
	TermsOfUse     []TypedID
	RefreshService []TypedID
}

// Credential represents a Verifiable Credential.
type Credential struct {
	contents     CredentialContents
	customFields CustomFields
	// rawJSON, if set, is returned by ToRawJSON() instead of building from contents.
	rawJSON JSONObject
}

// Contents returns the structured content of the credential.
func (c *Credential) Contents() CredentialContents {
	return c.contents
}

// CustomFields returns the custom fields of the credential.
func (c *Credential) CustomFields() CustomFields {
	return c.customFields
}

// ToRawJSON converts the credential to a JSON map representation.
// Custom fields from the subject are placed at the top level of credentialSubject.
func (c *Credential) ToRawJSON() JSONObject {
	if c.rawJSON != nil {
		return c.rawJSON
	}
	result := JSONObject{}

	if len(c.contents.Context) > 0 {
		result[JSONLDKeyContext] = c.contents.Context
	}
	if c.contents.ID != "" {
		result[JSONLDKeyID] = c.contents.ID
	}
	if len(c.contents.Types) > 0 {
		result[JSONLDKeyType] = c.contents.Types
	}
	if c.contents.Issuer != nil {
		result[VCKeyIssuer] = c.contents.Issuer.ID
	}
	if c.contents.ValidFrom != nil {
		result[VCKeyValidFrom] = c.contents.ValidFrom.Format(time.RFC3339)
	}
	if c.contents.ValidUntil != nil {
		result[VCKeyValidUntil] = c.contents.ValidUntil.Format(time.RFC3339)
	}
	if c.contents.Status != nil {
		result[VCKeyCredentialStatus] = JSONObject{JSONLDKeyID: c.contents.Status.ID, JSONLDKeyType: c.contents.Status.Type}
	}
	if len(c.contents.Schemas) > 0 {
		result[VCKeyCredentialSchema] = typedIDsToJSON(c.contents.Schemas)
	}
	if len(c.contents.Evidence) > 0 {
		result[VCKeyEvidence] = c.contents.Evidence
	}
	if len(c.contents.TermsOfUse) > 0 {
		result[VCKeyTermsOfUse] = typedIDsToJSON(c.contents.TermsOfUse)
	}
	if len(c.contents.RefreshService) > 0 {
		result[VCKeyRefreshService] = typedIDsToJSON(c.contents.RefreshService)
	}

	if len(c.contents.Subject) > 0 {
		subjects := make([]JSONObject, 0, len(c.contents.Subject))
		for _, s := range c.contents.Subject {
			subj := JSONObject{}
			if s.ID != "" {
				subj[JSONLDKeyID] = s.ID
			}
			for k, v := range s.CustomFields {
				subj[k] = v
			}
			subjects = append(subjects, subj)
		}
		if len(subjects) == 1 {
			result[VCKeyCredentialSubject] = subjects[0]
		} else {
			result[VCKeyCredentialSubject] = subjects
		}
	}

	for k, v := range c.customFields {
		if _, exists := result[k]; !exists {
			result[k] = v
		}
	}

	return result
}

// MarshalJSON serializes the credential to JSON bytes.
func (c *Credential) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.ToRawJSON())
}

// SetRawJSON stores a pre-built raw JSON map to be returned by ToRawJSON().
func (c *Credential) SetRawJSON(raw JSONObject) {
	c.rawJSON = raw
}

// CreateCredential constructs a Credential from CredentialContents and custom fields.
func CreateCredential(contents CredentialContents, customFields CustomFields) (*Credential, error) {
	return &Credential{
		contents:     contents,
		customFields: customFields,
	}, nil
}

// PresentationOpt is a functional option for configuring a Presentation.
type PresentationOpt func(*Presentation)

// Presentation represents a Verifiable Presentation.
type Presentation struct {
	Context     []string
	ID          string
	Type        []string
	Holder      string
	credentials []*Credential
	Proof       *LDProof
	// holderKey stores the resolved public key that signed the VP JWT.
	// Stored as interface{} to avoid jwx dependency in the common package.
	// The verifier package type-asserts to jwk.Key.
	holderKey interface{}
	// rawToken stores the original VP JWT bytes for deferred signature verification.
	// Only set in the SD-JWT VP path; nil for JSON-LD VPs.
	rawToken []byte
}

// HolderKey returns the public key that signed the VP JWT, if available.
func (p *Presentation) HolderKey() interface{} {
	return p.holderKey
}

// SetHolderKey stores the public key that signed the VP JWT.
func (p *Presentation) SetHolderKey(key interface{}) {
	p.holderKey = key
}

// RawToken returns the original VP JWT bytes, if available.
func (p *Presentation) RawToken() []byte {
	return p.rawToken
}

// SetRawToken stores the original VP JWT bytes for deferred verification.
func (p *Presentation) SetRawToken(token []byte) {
	p.rawToken = token
}

// Credentials returns the credentials contained in the presentation.
func (p *Presentation) Credentials() []*Credential {
	return p.credentials
}

// AddCredentials appends one or more credentials to the presentation.
func (p *Presentation) AddCredentials(credentials ...*Credential) {
	p.credentials = append(p.credentials, credentials...)
}

// MarshalJSON serializes the presentation to JSON bytes.
func (p *Presentation) MarshalJSON() ([]byte, error) {
	result := JSONObject{}

	ctx := p.Context
	if len(ctx) == 0 {
		ctx = []string{ContextCredentialsV1}
	}
	result[JSONLDKeyContext] = ctx

	types := p.Type
	if len(types) == 0 {
		types = []string{TypeVerifiablePresentation}
	}
	result[JSONLDKeyType] = types

	if p.ID != "" {
		result[JSONLDKeyID] = p.ID
	}
	if p.Holder != "" {
		result[VPKeyHolder] = p.Holder
	}

	if len(p.credentials) > 0 {
		vcs := make([]json.RawMessage, 0, len(p.credentials))
		for _, cred := range p.credentials {
			credJSON, err := cred.MarshalJSON()
			if err != nil {
				return nil, err
			}
			vcs = append(vcs, credJSON)
		}
		result[VPKeyVerifiableCredential] = vcs
	}

	if p.Proof != nil {
		result[VPKeyProof] = p.Proof
	}

	return json.Marshal(result)
}

// NewPresentation creates a new Presentation with the given options applied.
func NewPresentation(opts ...PresentationOpt) (*Presentation, error) {
	p := &Presentation{}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// WithCredentials returns a PresentationOpt that adds credentials to a presentation.
func WithCredentials(credentials ...*Credential) PresentationOpt {
	return func(p *Presentation) {
		p.AddCredentials(credentials...)
	}
}

// typedIDsToJSON converts a slice of TypedID to JSON-compatible format.
func typedIDsToJSON(ids []TypedID) []JSONObject {
	result := make([]JSONObject, 0, len(ids))
	for _, id := range ids {
		obj := JSONObject{}
		if id.ID != "" {
			obj[JSONLDKeyID] = id.ID
		}
		if id.Type != "" {
			obj[JSONLDKeyType] = id.Type
		}
		result = append(result, obj)
	}
	return result
}
