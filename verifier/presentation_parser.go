package verifier

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	"github.com/hellofresh/health-go/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	cache "github.com/patrickmn/go-cache"
	"github.com/piprate/json-gold/ld"
)

// ldDocLoaderCacheTTL is the TTL for cached JSON-LD context documents.
const ldDocLoaderCacheTTL = 1 * time.Hour

// ldDocLoaderCacheCleanup is the interval for removing expired entries from
// the JSON-LD document loader cache.
const ldDocLoaderCacheCleanup = 10 * time.Minute

var ErrorInvalidSdJwt = errors.New("credential_is_not_sd_jwt")
var ErrorPresentationNoCredentials = errors.New("presentation_not_contains_credentials")
var ErrorInvalidProof = errors.New("invalid_vp_proof")
var ErrorVCNotArray = errors.New("verifiable_credential_not_array")
var ErrorInvalidJWTFormat = errors.New("invalid_jwt_format")
var ErrorCnfKeyMismatch = errors.New("cnf_key_does_not_match_vp_signer")

// ErrorUnsignedPresentation is returned when a JSON-LD Verifiable
// Presentation has no proof member. An unsigned VP cannot be trusted and
// must be rejected.
var ErrorUnsignedPresentation = errors.New("unsigned_presentation_not_accepted")

// ErrorUnsignedCredential is returned when a JSON-LD Verifiable Credential
// carries no Linked Data Proof. Accepting it would let anybody put arbitrary
// claims — under an arbitrary issuer — into an otherwise valid presentation.
var ErrorUnsignedCredential = errors.New("unsigned_credential_not_accepted")

// ErrorProofChallengeMismatch is returned when a JSON-LD VP proof's challenge
// field does not match the expected session nonce, indicating a potential
// replay attack.
var ErrorProofChallengeMismatch = errors.New("vp_proof_challenge_mismatch")

// ErrorProofDomainMismatch is returned when a JSON-LD VP proof's domain
// field does not match the expected verifier audience/client ID.
var ErrorProofDomainMismatch = errors.New("vp_proof_domain_mismatch")

// ErrorHolderBindingMissingKey is returned when holder binding is required
// but the JSON-LD VP has no holder key from LD-proof verification.
var ErrorHolderBindingMissingKey = errors.New("holder_binding_required_but_no_key_available")

// ErrorProofCreatedMissing is returned when a JSON-LD VP proof carries no
// `created` timestamp, so its age cannot be bounded.
var ErrorProofCreatedMissing = errors.New("vp_proof_created_missing")

// ErrorProofCreatedUnparseable is returned when a JSON-LD VP proof's
// `created` timestamp is not a valid RFC3339 date-time.
var ErrorProofCreatedUnparseable = errors.New("vp_proof_created_unparseable")

// ErrorProofCreatedInFuture is returned when a JSON-LD VP proof claims to
// have been created further in the future than the tolerated clock skew.
var ErrorProofCreatedInFuture = errors.New("vp_proof_created_in_future")

// ErrorProofNotFresh is returned when a JSON-LD VP proof is older than the
// configured freshness window, indicating a replayed presentation.
var ErrorProofNotFresh = errors.New("vp_proof_not_fresh")

// ErrorHolderSubjectMismatch is returned when a JSON-LD credential inside a
// presentation names a subject that is not the presentation's holder. Without
// this check a credential issued to somebody else could be replayed inside an
// attacker-signed presentation.
var ErrorHolderSubjectMismatch = errors.New("credential_subject_does_not_match_holder")

// ErrorIssClaimIssuerMismatch is returned when a vc+jwt credential carries
// both an `iss` JWT claim and an `issuer` payload field that disagree.
// VC-JOSE-COSE §3.3.1 requires them to be equal when both are present.
var ErrorIssClaimIssuerMismatch = errors.New("vc_jwt_iss_claim_does_not_match_issuer_field")

// ErrorEnvelopedCredentialMissingID is returned when an
// EnvelopedVerifiableCredential object has no "id" field or the "id" is not a
// string. The "id" must be a data: URI holding the compact JWS.
var ErrorEnvelopedCredentialMissingID = errors.New("enveloped_credential_missing_id")

// ErrorEnvelopedCredentialInvalidDataURI is returned when the "id" of an
// EnvelopedVerifiableCredential does not start with the expected
// "data:application/vc+jwt," prefix, or is empty after the prefix.
var ErrorEnvelopedCredentialInvalidDataURI = errors.New("enveloped_credential_invalid_data_uri")

// allow singleton access to the parser
var presentationParser PresentationParser

// allow singleton access to the parser
var sdJwtParser SdJwtParser

// globalProofChecker is the shared proof checker for deferred VP signature verification.
var globalProofChecker *JWTProofChecker

// globalLDProofChecker is the shared LD proof checker for JSON-LD VP/VC verification.
var globalLDProofChecker *LDProofChecker

// globalHttpsIssuerResolver is the shared resolver for HTTPS-based issuer
// identifiers. It is shared by every component that resolves issuer keys, so
// a single JWKS cache serves the JWT path, the JSON-LD proof path and
// status-list verification.
var globalHttpsIssuerResolver HttpsIssuerResolver

// parser interface
type PresentationParser interface {
	ParsePresentation(tokenBytes []byte) (*common.Presentation, error)
}

type SdJwtParser interface {
	Parse(tokenString string) (map[string]interface{}, error)
	ParseWithSdJwt(tokenBytes []byte) (presentation *common.Presentation, err error)
	ClaimsToCredential(claims map[string]interface{}) (credential *common.Credential, err error)
}

type ConfigurablePresentationParser struct {
	ProofChecker   *JWTProofChecker
	LDProofChecker *LDProofChecker
}

type ConfigurableSdJwtParser struct {
	ProofChecker *JWTProofChecker
}

/**
* Global singelton access to the parser
**/
func GetSdJwtParser() SdJwtParser {
	if sdJwtParser == nil {
		logging.Log().Error("SdJwtParser is not initialized.")
	}
	return sdJwtParser
}

// GetProofChecker returns the shared JWT proof checker for VP signature verification.
func GetProofChecker() *JWTProofChecker {
	return globalProofChecker
}

// GetLDProofChecker returns the shared LD proof checker for JSON-LD VP/VC verification.
func GetLDProofChecker() *LDProofChecker {
	return globalLDProofChecker
}

// GetHttpsIssuerResolver returns the shared resolver for HTTPS-based issuer
// identifiers, so components initialized after InitPresentationParser reuse
// its JWKS cache instead of building their own.
func GetHttpsIssuerResolver() HttpsIssuerResolver {
	return globalHttpsIssuerResolver
}

/**
* Global singelton access to the parser
**/
func GetPresentationParser() PresentationParser {
	if presentationParser == nil {
		logging.Log().Error("PresentationParser is not initialized.")
	}
	return presentationParser
}

// InitPresentationParser initialises the presentation parser from the
// given configuration. It sets up the DID registry, HTTPS issuer resolver,
// JWT proof checker and LD proof checker used for all subsequent VP/VC
// verification.
func InitPresentationParser(config *configModel.Configuration, healthCheck *health.Health) error {
	registry := did.NewRegistry(did.WithVDR(did.NewWebVDR()), did.WithVDR(did.NewKeyVDR()), did.WithVDR(did.NewJWKVDR()))

	// Create the HTTPS issuer resolver for metadata-based key discovery.
	// Uses a dedicated cache with the same cleanup pattern as other verifier caches.
	httpsResolverCache := cache.New(DefaultJwksCacheTTL, 2*DefaultJwksCacheTTL)
	httpsResolver := NewCachingHttpsIssuerResolver(httpsResolverCache, DefaultJwksCacheTTL).
		WithAllowedMetadataHosts(config.Verifier.HttpsIssuerAllowedHosts).
		WithAllowPrivateAddresses(config.Verifier.HttpsIssuerAllowPrivateNetworks)
	globalHttpsIssuerResolver = httpsResolver

	checker := NewJWTProofChecker(registry).WithHttpsResolver(httpsResolver)
	globalProofChecker = checker

	// Set up the document loader for JSON-LD context resolution and create
	// the LDProofChecker for verifying Linked Data Proofs on VPs/VCs. The
	// contexts that proof canonicalization depends on are served from the
	// binary, so a slow or hostile context host cannot influence — or block —
	// signature verification. Everything else is fetched and cached.
	docLoader := common.NewVerificationDocumentLoader(
		common.NewCachingDocumentLoader(
			ld.NewDefaultDocumentLoader(http.DefaultClient),
			ldDocLoaderCacheTTL,
			ldDocLoaderCacheCleanup,
		),
	)
	ldChecker := NewLDProofChecker(registry, docLoader).WithHttpsResolver(httpsResolver)
	globalLDProofChecker = ldChecker

	presentationParser = &ConfigurablePresentationParser{
		ProofChecker:   checker,
		LDProofChecker: ldChecker,
	}
	sdJwtParser = &ConfigurableSdJwtParser{
		ProofChecker: checker,
	}

	return nil
}
// ParsePresentation parses a VP from either JWT or JSON-LD format and
// verifies it. JWT VPs are verified via the configured JWTProofChecker,
// JSON-LD VPs via the configured LDProofChecker. Both paths are fail-closed:
// an unsigned presentation, an unsigned embedded credential, or a missing
// checker leads to rejection.
func (cpp *ConfigurablePresentationParser) ParsePresentation(tokenBytes []byte) (*common.Presentation, error) {
	trimmed := strings.TrimSpace(string(tokenBytes))
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return cpp.parseJSONLDPresentation([]byte(trimmed))
	}
	return cpp.parseJWTPresentation(tokenBytes)
}

// parseJWTPresentation parses a JWT-encoded VP, verifies the VP signature, and parses embedded VCs.
// If the JOSE typ header is "vp+jwt" (VC-JOSE-COSE), the JWT payload IS the presentation —
// there is no wrapping "vp" claim. Otherwise the classic JWT-VP 1.1 path is used,
// reading the presentation from the nested "vp" claim.
// If a VC contains a cnf (confirmation) claim, it is verified against the VP signer's key (RFC 7800).
func (cpp *ConfigurablePresentationParser) parseJWTPresentation(tokenBytes []byte) (*common.Presentation, error) {
	var payload []byte
	var holderKey jwk.Key
	var err error
	if cpp.ProofChecker != nil {
		payload, holderKey, err = cpp.ProofChecker.VerifyJWTAndReturnKey(tokenBytes)
	} else {
		payload, err = extractJWTPayload(tokenBytes)
	}
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	// Dispatch on the JOSE typ header: vp+jwt presentations carry the
	// presentation directly in the payload (no wrapping "vp" claim),
	// while classic JWT VPs use a nested "vp" object.
	typ := jwtMediaType(tokenBytes)
	if isVPJoseJWT(typ) {
		return cpp.parseVPJWTPresentation(claims, holderKey)
	}

	vpClaim, ok := claims[common.JWTClaimVP].(map[string]interface{})
	if !ok {
		return nil, ErrorPresentationNoCredentials
	}

	pres, _ := common.NewPresentation()
	if holderKey != nil {
		pres.SetHolderKey(holderKey)
	}

	// Holder from iss claim (standard JWT VP mapping)
	if iss, ok := claims[common.JWTClaimIss].(string); ok {
		pres.Holder = iss
	}

	vcsRaw, ok := vpClaim[common.VPKeyVerifiableCredential]
	if !ok {
		return pres, nil
	}

	vcList, ok := vcsRaw.([]interface{})
	if !ok {
		return nil, ErrorVCNotArray
	}

	for _, vc := range vcList {
		switch v := vc.(type) {
		case string:
			cred, err := cpp.parseJWTCredential([]byte(v))
			if err != nil {
				return nil, err
			}
			// Verify cryptographic holder binding (cnf) if present
			if holderKey != nil {
				if err := verifyCnfBinding(cred, holderKey); err != nil {
					return nil, err
				}
			}
			pres.AddCredentials(cred)
		case map[string]interface{}:
			// A JSON-LD credential inside a JWT VP still needs its own LD
			// proof verified — the VP signature says nothing about who
			// issued the credentials it carries.
			cred, err := cpp.parseAndVerifyJSONLDCredential(v, pres.Holder)
			if err != nil {
				return nil, err
			}
			pres.AddCredentials(cred)
		}
	}

	return pres, nil
}

// parseVPJWTPresentation parses a vp+jwt presentation (VC-JOSE-COSE §3.3.2).
// In a vp+jwt token the JWT payload IS the presentation: @context, type,
// holder, and verifiableCredential are top-level claims — there is no
// wrapping "vp" object.
//
// Claim mapping per VC-JOSE-COSE §3.3.2:
//   - "iss" maps to Holder (the presenter is the signer)
//   - "jti" maps to ID
//   - "@context", "type", "holder", "verifiableCredential" are read directly
//
// Each entry in verifiableCredential is handled as follows:
//   - string: a JWT VC (either vc+jwt or classic jwt_vc — parseJWTCredential
//     dispatches transparently)
//   - map with type "EnvelopedVerifiableCredential": the data: URI in "id"
//     is extracted and parsed as a vc+jwt credential
//   - map (other): a JSON-LD VC that carries its own Linked Data Proof
func (cpp *ConfigurablePresentationParser) parseVPJWTPresentation(claims map[string]interface{}, holderKey jwk.Key) (*common.Presentation, error) {
	pres, _ := common.NewPresentation()
	if holderKey != nil {
		pres.SetHolderKey(holderKey)
	}

	// Holder: payload "holder" takes precedence; "iss" is the fallback
	// (VC-JOSE-COSE §3.3.2 maps iss → holder).
	if holder, ok := claims[common.VPKeyHolder].(string); ok {
		pres.Holder = holder
	} else if iss, ok := claims[common.JWTClaimIss].(string); ok {
		pres.Holder = iss
	}

	// ID from jti, falling back to payload "id".
	if jti, ok := claims[common.JWTClaimJti].(string); ok {
		pres.ID = jti
	} else if id, ok := claims["id"].(string); ok {
		pres.ID = id
	}

	// Context and type directly from the payload.
	pres.Context = common.ToStringSlice(claims[common.JSONLDKeyContext])
	pres.Type = common.ToStringSlice(claims[common.JSONLDKeyType])

	// verifiableCredential is optional — a VP may carry zero credentials.
	vcsRaw, ok := claims[common.VPKeyVerifiableCredential]
	if !ok {
		return pres, nil
	}

	vcList, ok := vcsRaw.([]interface{})
	if !ok {
		return nil, ErrorVCNotArray
	}

	for _, vc := range vcList {
		cred, err := cpp.parseVPJWTCredentialEntry(vc, holderKey, pres.Holder)
		if err != nil {
			return nil, err
		}
		pres.AddCredentials(cred)
	}

	return pres, nil
}

// parseVPJWTCredentialEntry parses a single entry from the verifiableCredential
// array of a vp+jwt presentation. Entries may be:
//   - string: a JWT VC (vc+jwt or classic jwt_vc)
//   - map with type "EnvelopedVerifiableCredential": a VCDM 2.0 enveloped
//     credential whose "id" is a data:application/vc+jwt,<JWS> URI
//   - map (other): a JSON-LD VC with its own Linked Data Proof
func (cpp *ConfigurablePresentationParser) parseVPJWTCredentialEntry(vc interface{}, holderKey jwk.Key, presentationHolder string) (*common.Credential, error) {
	switch v := vc.(type) {
	case string:
		cred, err := cpp.parseJWTCredential([]byte(v))
		if err != nil {
			return nil, err
		}
		if holderKey != nil {
			if err := verifyCnfBinding(cred, holderKey); err != nil {
				return nil, err
			}
		}
		return cred, nil
	case map[string]interface{}:
		if isEnvelopedVerifiableCredential(v) {
			cred, err := cpp.parseEnvelopedCredential(v, holderKey)
			if err != nil {
				return nil, err
			}
			return cred, nil
		}
		// A JSON-LD credential inside a vp+jwt still needs its own LD
		// proof verified — the VP signature says nothing about who
		// issued the credentials it carries.
		cred, err := cpp.parseAndVerifyJSONLDCredential(v, presentationHolder)
		if err != nil {
			return nil, err
		}
		return cred, nil
	default:
		return nil, ErrorPresentationNoCredentials
	}
}

// isEnvelopedVerifiableCredential checks whether a JSON object represents an
// EnvelopedVerifiableCredential (VCDM 2.0 §4.13). Such objects have
// type "EnvelopedVerifiableCredential" and an "id" that is a data: URI.
func isEnvelopedVerifiableCredential(vcMap map[string]interface{}) bool {
	types := common.ToStringSlice(vcMap[common.JSONLDKeyType])
	for _, t := range types {
		if t == common.TypeEnvelopedVerifiableCredential {
			return true
		}
	}
	return false
}

// parseEnvelopedCredential extracts the JWT from an EnvelopedVerifiableCredential
// (VCDM 2.0 §4.13) and parses it as a vc+jwt credential.
//
// An EnvelopedVerifiableCredential is a JSON object with:
//   - "type": "EnvelopedVerifiableCredential"
//   - "id": "data:application/vc+jwt,<compact-JWS>"
//
// The data: URI must not have parameters (no ";base64," etc.).
func (cpp *ConfigurablePresentationParser) parseEnvelopedCredential(vcMap map[string]interface{}, holderKey jwk.Key) (*common.Credential, error) {
	id, ok := vcMap["id"].(string)
	if !ok || id == "" {
		return nil, ErrorEnvelopedCredentialMissingID
	}

	if !strings.HasPrefix(id, common.DataURISchemeVCJWT) {
		return nil, ErrorEnvelopedCredentialInvalidDataURI
	}

	// Extract the compact JWS from the data: URI.
	jws := id[len(common.DataURISchemeVCJWT):]
	if jws == "" {
		return nil, ErrorEnvelopedCredentialInvalidDataURI
	}

	cred, err := cpp.parseJWTCredential([]byte(jws))
	if err != nil {
		return nil, fmt.Errorf("enveloped credential: %w", err)
	}

	if holderKey != nil {
		if err := verifyCnfBinding(cred, holderKey); err != nil {
			return nil, err
		}
	}

	return cred, nil
}

// parseJWTCredential parses and verifies a JWT-encoded VC and sets the
// credential format. When the JOSE typ header is "vc+jwt" (VC-JOSE-COSE),
// the payload is parsed as a vc+jwt credential (format FormatVCJWT);
// otherwise the classic JWT-VC 1.1 path is used (format FormatJWTVC).
func (cpp *ConfigurablePresentationParser) parseJWTCredential(tokenBytes []byte) (*common.Credential, error) {
	var payload []byte
	var err error
	if cpp.ProofChecker != nil {
		payload, err = cpp.ProofChecker.VerifyJWT(tokenBytes)
	} else {
		payload, err = extractJWTPayload(tokenBytes)
	}
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	// Dispatch on the JOSE typ header: vc+jwt credentials carry the payload
	// directly (no wrapping "vc" claim), while classic JWT-VCs use a nested
	// "vc" object.
	typ := jwtMediaType(tokenBytes)
	if isVCJoseJWT(typ) {
		cred, err := vcJwtClaimsToCredential(claims)
		if err != nil {
			return nil, err
		}
		cred.SetFormat(common.FormatVCJWT)
		return cred, nil
	}

	cred, err := jwtClaimsToCredential(claims)
	if err != nil {
		return nil, err
	}
	cred.SetFormat(common.FormatJWTVC)
	return cred, nil
}

// jwtClaimsToCredential maps JWT VC claims to a common.Credential.
// Extracts standard JWT claims (iss, jti, nbf, iat, exp), VC-specific claims
// (type, @context, credentialSubject, credentialStatus), and the cnf claim
// for cryptographic holder binding verification.
func jwtClaimsToCredential(claims map[string]interface{}) (*common.Credential, error) {
	contents := common.CredentialContents{}

	if iss, ok := claims[common.JWTClaimIss].(string); ok {
		contents.Issuer = &common.Issuer{ID: iss}
	}
	if jti, ok := claims[common.JWTClaimJti].(string); ok {
		contents.ID = jti
	}

	customFields := common.CustomFields{}

	vcClaim, _ := claims[common.JWTClaimVC].(map[string]interface{})
	if vcClaim != nil {
		contents.Types = common.ToStringSlice(vcClaim[common.JSONLDKeyType])
		contents.Context = common.ToStringSlice(vcClaim[common.JSONLDKeyContext])
		if subject, ok := vcClaim[common.VCKeyCredentialSubject].(map[string]interface{}); ok {
			s := common.Subject{CustomFields: common.CustomFields{}}
			if id, ok := subject[common.JSONLDKeyID].(string); ok {
				s.ID = id
			}
			for k, v := range subject {
				if k != common.JSONLDKeyID {
					s.CustomFields[k] = v
				}
			}
			contents.Subject = []common.Subject{s}
		}

		// Extract credentialStatus for revocation checking (W3C VC Data Model 2.0 §7.1).
		if status, ok := vcClaim[common.VCKeyCredentialStatus].(map[string]interface{}); ok {
			contents.Status = &common.TypedID{
				ID:   stringFromMap(status, common.JSONLDKeyID),
				Type: stringFromMap(status, common.JSONLDKeyType),
			}
		}
	}

	if nbf, ok := claims[common.JWTClaimNbf].(float64); ok {
		t := time.Unix(int64(nbf), 0)
		contents.ValidFrom = &t
	} else if iat, ok := claims[common.JWTClaimIat].(float64); ok {
		t := time.Unix(int64(iat), 0)
		contents.ValidFrom = &t
	}
	if exp, ok := claims[common.JWTClaimExp].(float64); ok {
		t := time.Unix(int64(exp), 0)
		contents.ValidUntil = &t
	}
	// Fall back to issuanceDate/expirationDate embedded in the vc claim (JWT-VC 1.0 style,
	// used before nbf/exp became the standard mapping for validity dates).
	if vcClaim != nil {
		if contents.ValidFrom == nil || contents.ValidUntil == nil {
			legacyFrom, legacyUntil := common.ParseCredentialDates(vcClaim)
			if contents.ValidFrom == nil {
				contents.ValidFrom = legacyFrom
			}
			if contents.ValidUntil == nil {
				contents.ValidUntil = legacyUntil
			}
		}
	}

	// Preserve cnf (confirmation) claim for cryptographic holder binding (RFC 7800).
	if cnf, ok := claims[common.JWTClaimCnf]; ok {
		customFields[common.JWTClaimCnf] = cnf
	}

	cred, err := common.CreateCredential(contents, customFields)
	if err != nil {
		return nil, err
	}

	if vcClaim != nil {
		cred.SetRawJSON(vcClaim)
	}

	return cred, nil
}

// vcJwtClaimsToCredential maps VC-JOSE-COSE (vc+jwt) JWT claims to a
// common.Credential. In a vc+jwt token the JWT payload IS the credential —
// the top-level claims include @context, type, issuer, credentialSubject,
// validFrom, validUntil, etc. There is no wrapping "vc" claim.
//
// Claim mapping follows VC-JOSE-COSE §3.3.1:
//   - iss  → Issuer.ID  (takes precedence over the payload "issuer" field)
//   - jti  → ID
//   - sub  → credentialSubject[0].id  (takes precedence over embedded id)
//   - nbf/iat → ValidFrom, exp → ValidUntil  (JWT numeric dates)
//   - Payload-level validFrom/validUntil (RFC 3339 strings) are used as fallback
//   - @context, type, credentialSubject, credentialStatus are read directly
//     from the top-level payload
//   - cnf  → preserved in custom fields for holder binding
func vcJwtClaimsToCredential(claims map[string]interface{}) (*common.Credential, error) {
	contents := common.CredentialContents{}

	// --- Issuer: iss takes precedence, then payload "issuer" (string or object) ---
	// VC-JOSE-COSE §3.3.1 requires that when both iss and issuer are present
	// they MUST be equal; a mismatch makes the credential malformed.
	if iss, ok := claims[common.JWTClaimIss].(string); ok {
		contents.Issuer = &common.Issuer{ID: iss}

		// Verify consistency with the payload issuer field, if present.
		if payloadIssuerID := extractPayloadIssuerID(claims); payloadIssuerID != "" && payloadIssuerID != iss {
			return nil, fmt.Errorf("%w: iss=%q, issuer=%q", ErrorIssClaimIssuerMismatch, iss, payloadIssuerID)
		}
	} else if issuer, ok := claims[common.VCKeyIssuer]; ok {
		switch v := issuer.(type) {
		case string:
			contents.Issuer = &common.Issuer{ID: v}
		case map[string]interface{}:
			if id, ok := v[common.JSONLDKeyID].(string); ok {
				contents.Issuer = &common.Issuer{ID: id}
			}
		}
	}

	// --- Credential ID: jti claim ---
	if jti, ok := claims[common.JWTClaimJti].(string); ok {
		contents.ID = jti
	} else if id, ok := claims[common.JSONLDKeyID].(string); ok {
		contents.ID = id
	}

	// --- Context and types: read directly from the payload (no "vc" wrapper) ---
	contents.Context = common.ToStringSlice(claims[common.JSONLDKeyContext])
	contents.Types = common.ToStringSlice(claims[common.JSONLDKeyType])

	// --- Credential subject ---
	if cs, ok := claims[common.VCKeyCredentialSubject]; ok {
		contents.Subject = parseSubjectsFromClaims(cs)
	}

	// VC-JOSE-COSE §3.3.1: sub MUST only be set when the credential has a
	// single credentialSubject with an id property. When both are present,
	// sub takes precedence. We only apply sub when there is at most one
	// subject — a well-formed multi-subject vc+jwt will not carry sub.
	if sub, ok := claims[common.JWTClaimSub].(string); ok && len(contents.Subject) <= 1 {
		if len(contents.Subject) == 1 {
			contents.Subject[0].ID = sub
		} else {
			contents.Subject = []common.Subject{{ID: sub, CustomFields: common.CustomFields{}}}
		}
	}

	// --- Credential status ---
	// VCDM 2.0 allows credentialStatus to be a single object or an array.
	// Extract the first entry for contents.Status; the full value is still
	// available via ToRawJSON() for callers that need every entry.
	contents.Status = extractFirstCredentialStatus(claims[common.VCKeyCredentialStatus])

	// --- Validity dates: JWT numeric claims take precedence ---
	if nbf, ok := claims[common.JWTClaimNbf].(float64); ok {
		t := time.Unix(int64(nbf), 0)
		contents.ValidFrom = &t
	} else if iat, ok := claims[common.JWTClaimIat].(float64); ok {
		t := time.Unix(int64(iat), 0)
		contents.ValidFrom = &t
	}
	if exp, ok := claims[common.JWTClaimExp].(float64); ok {
		t := time.Unix(int64(exp), 0)
		contents.ValidUntil = &t
	}

	// Fall back to VCDM 2.0 string dates in the payload (validFrom/validUntil,
	// issuanceDate/expirationDate).
	if contents.ValidFrom == nil || contents.ValidUntil == nil {
		payloadFrom, payloadUntil := common.ParseCredentialDates(claims)
		if contents.ValidFrom == nil {
			contents.ValidFrom = payloadFrom
		}
		if contents.ValidUntil == nil {
			contents.ValidUntil = payloadUntil
		}
	}

	// --- Custom fields ---
	customFields := common.CustomFields{}

	// Preserve cnf (confirmation) claim for cryptographic holder binding (RFC 7800).
	if cnf, ok := claims[common.JWTClaimCnf]; ok {
		customFields[common.JWTClaimCnf] = cnf
	}

	cred, err := common.CreateCredential(contents, customFields)
	if err != nil {
		return nil, err
	}

	// For vc+jwt the entire payload IS the credential, so store the full
	// claims map as the raw JSON.
	cred.SetRawJSON(claims)

	return cred, nil
}

// parseSubjectsFromClaims parses the credentialSubject claim value into a
// slice of common.Subject. Handles both a single object and an array of
// objects. This is the vc+jwt counterpart of the inline subject extraction
// in jwtClaimsToCredential.
func parseSubjectsFromClaims(cs interface{}) []common.Subject {
	switch v := cs.(type) {
	case map[string]interface{}:
		return []common.Subject{parseOneSubjectFromClaims(v)}
	case []interface{}:
		subjects := make([]common.Subject, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				subjects = append(subjects, parseOneSubjectFromClaims(m))
			}
		}
		return subjects
	}
	return nil
}

// parseOneSubjectFromClaims parses a single credentialSubject map into a
// common.Subject, extracting the id and collecting remaining fields as
// custom fields.
func parseOneSubjectFromClaims(m map[string]interface{}) common.Subject {
	s := common.Subject{CustomFields: common.CustomFields{}}
	if id, ok := m[common.JSONLDKeyID].(string); ok {
		s.ID = id
	}
	for k, v := range m {
		if k != common.JSONLDKeyID {
			s.CustomFields[k] = v
		}
	}
	return s
}

// stringFromMap safely extracts a string value from a map.
func stringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// extractPayloadIssuerID returns the issuer identity string from the payload's
// "issuer" field (which may be a plain string or an {"id": ...} object).
// Returns "" when the field is absent or has an unrecognised shape.
func extractPayloadIssuerID(claims map[string]interface{}) string {
	issuer, ok := claims[common.VCKeyIssuer]
	if !ok {
		return ""
	}
	switch v := issuer.(type) {
	case string:
		return v
	case map[string]interface{}:
		if id, ok := v[common.JSONLDKeyID].(string); ok {
			return id
		}
	}
	return ""
}

// extractFirstCredentialStatus extracts the first credentialStatus entry as a
// *common.TypedID. The input may be a single map or an array of maps (VCDM 2.0
// allows both). Returns nil when no valid entry is found.
func extractFirstCredentialStatus(raw interface{}) *common.TypedID {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case map[string]interface{}:
		return &common.TypedID{
			ID:   stringFromMap(v, common.JSONLDKeyID),
			Type: stringFromMap(v, common.JSONLDKeyType),
		}
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				return &common.TypedID{
					ID:   stringFromMap(m, common.JSONLDKeyID),
					Type: stringFromMap(m, common.JSONLDKeyType),
				}
			}
		}
	}
	return nil
}

// parseJSONLDPresentation parses a JSON-LD Verifiable Presentation and
// verifies its Linked Data Proof(s) using the configured LDProofChecker.
//
// If the LDProofChecker is not configured, VPs with proofs are rejected
// (fail-closed). VPs without proofs are always rejected.
//
// Every embedded JSON-LD VC must carry its own LD proof, created by the
// credential's issuer — the VP signature says nothing about who issued the
// credentials it carries. JWT VCs embedded in a JSON-LD VP are verified via
// the JWTProofChecker.
func (cpp *ConfigurablePresentationParser) parseJSONLDPresentation(data []byte) (*common.Presentation, error) {
	var vpMap map[string]interface{}
	if err := json.Unmarshal(data, &vpMap); err != nil {
		return nil, err
	}

	// Extract VP-level proofs if present.
	proofRaw, hasProof := vpMap[common.VPKeyProof]
	if !hasProof {
		logging.Log().Warn("JSON-LD VP has no proof — unsigned presentations are not accepted")
		return nil, ErrorUnsignedPresentation
	}

	proofs, err := common.ParseLDProofs(proofRaw)
	if err != nil {
		logging.Log().Warnf("Failed to parse LD proofs on JSON-LD VP: %v", err)
		return nil, err
	}

	if len(proofs) == 0 {
		logging.Log().Warn("JSON-LD VP has empty proof array — unsigned presentations are not accepted")
		return nil, ErrorUnsignedPresentation
	}

	// Fail closed when no LDProofChecker is available.
	if cpp.LDProofChecker == nil {
		logging.Log().Warn("JSON-LD VP has a proof but LDProofChecker is not configured — rejecting")
		return nil, ErrorInvalidProof
	}

	// Build the document bytes WITHOUT the proof member for verification
	// (the proof is excluded from canonicalization input).
	vpWithoutProof := make(map[string]interface{}, len(vpMap))
	for k, v := range vpMap {
		if k != common.VPKeyProof {
			vpWithoutProof[k] = v
		}
	}
	vpDocBytes, err := json.Marshal(vpWithoutProof)
	if err != nil {
		return nil, err
	}

	pres, _ := common.NewPresentation()

	// The holder has to be known before the proofs are checked: the VP proof
	// is only meaningful when it was created by the holder it claims.
	if holder, ok := vpMap[common.VPKeyHolder].(string); ok {
		pres.Holder = holder
	}

	// Verify each VP-level proof and capture the signer key from the first
	// valid proof for downstream holder binding.
	var holderKey jwk.Key
	for _, proof := range proofs {
		key, verifyErr := cpp.LDProofChecker.VerifyPresentation(vpDocBytes, proof, pres.Holder)
		if verifyErr != nil {
			return nil, verifyErr
		}
		if holderKey == nil {
			holderKey = key
		}
	}
	if holderKey != nil {
		pres.SetHolderKey(holderKey)
	}
	pres.Proofs = proofs

	// Parse embedded VCs.
	vcsRaw, ok := vpMap[common.VPKeyVerifiableCredential]
	if !ok {
		return pres, nil
	}

	vcList, ok := vcsRaw.([]interface{})
	if !ok {
		return nil, ErrorVCNotArray
	}

	for _, vc := range vcList {
		switch v := vc.(type) {
		case string:
			// JWT VC embedded in a JSON-LD VP — verify via JWTProofChecker.
			cred, credErr := cpp.parseJWTCredential([]byte(v))
			if credErr != nil {
				return nil, credErr
			}
			if holderKey != nil {
				if bindErr := verifyCnfBinding(cred, holderKey); bindErr != nil {
					return nil, bindErr
				}
			}
			pres.AddCredentials(cred)
		case map[string]interface{}:
			cred, credErr := cpp.parseAndVerifyJSONLDCredential(v, pres.Holder)
			if credErr != nil {
				return nil, credErr
			}
			pres.AddCredentials(cred)
		}
	}

	return pres, nil
}

// parseAndVerifyJSONLDCredential parses a JSON-LD credential from its raw map
// and verifies every Linked Data Proof it carries against the credential's
// own issuer.
//
// The check is fail-closed in three ways: a credential without any proof is
// rejected (ErrorUnsignedCredential), a credential with a proof but no
// configured LDProofChecker is rejected (ErrorInvalidProof), and a proof that
// was not created by the claimed issuer is rejected by the checker.
//
// presentationHolder is the holder declared by the enclosing presentation, or
// "" when it declares none. It is used to bind the credential to the entity
// that presented it — the JSON-LD counterpart of the cnf binding enforced for
// JWT VCs.
func (cpp *ConfigurablePresentationParser) parseAndVerifyJSONLDCredential(vcMap map[string]interface{}, presentationHolder string) (*common.Credential, error) {
	cred, err := parseJSONLDCredential(vcMap)
	if err != nil {
		return nil, err
	}

	proofs := cred.Proofs()
	if len(proofs) == 0 {
		logging.Log().Warn("JSON-LD credential has no proof — unsigned credentials are not accepted")
		return nil, ErrorUnsignedCredential
	}

	if cpp.LDProofChecker == nil {
		logging.Log().Warn("JSON-LD credential has a proof but LDProofChecker is not configured — rejecting")
		return nil, ErrorInvalidProof
	}

	issuer := ""
	if credentialIssuer := cred.Contents().Issuer; credentialIssuer != nil {
		issuer = credentialIssuer.ID
	}

	// The proof is computed over the credential without its proof member.
	vcWithoutProof := make(map[string]interface{}, len(vcMap))
	for k, val := range vcMap {
		if k != common.VPKeyProof {
			vcWithoutProof[k] = val
		}
	}
	vcDocBytes, err := json.Marshal(vcWithoutProof)
	if err != nil {
		return nil, err
	}

	for _, vcProof := range proofs {
		if err := cpp.LDProofChecker.VerifyCredential(vcDocBytes, vcProof, issuer); err != nil {
			return nil, err
		}
	}

	// The holder binding is a semantic check on an authentic credential, so
	// it runs only once the proofs have been verified.
	if err := verifyJSONLDHolderBinding(cred, presentationHolder); err != nil {
		return nil, err
	}

	return cred, nil
}

// ldProofClockSkew is the tolerance applied on both ends of the proof
// freshness window. Holder and verifier clocks are independent, so a proof
// created a few seconds "in the future" is normal rather than suspicious.
const ldProofClockSkew = 30 * time.Second

// VerifyLDVPProofFreshness bounds the age of every Linked Data Proof on a
// presentation, using the proof's `created` timestamp.
//
// It is the only replay protection available on the grants that have no
// server-issued nonce (`vp_token` and token-exchange): without it a captured
// `ldp_vc` presentation stays valid for as long as the credentials it carries
// do. The check is fail-closed — a missing, unparseable or future-dated
// `created` is rejected rather than treated as "nothing to check".
//
// A maxAge of zero or less disables the check, as does a presentation without
// LD proofs (JWT and SD-JWT presentations are bound through their own
// mechanisms).
func VerifyLDVPProofFreshness(pres *common.Presentation, now time.Time, maxAge time.Duration) error {
	if len(pres.Proofs) == 0 || maxAge <= 0 {
		return nil
	}

	for _, proof := range pres.Proofs {
		if proof.Created == "" {
			logging.Log().Warn("VP proof has no created timestamp, its age cannot be bounded")
			return ErrorProofCreatedMissing
		}
		created, err := time.Parse(time.RFC3339, proof.Created)
		if err != nil {
			logging.Log().Warnf("VP proof created timestamp %q is not a valid RFC3339 date-time: %v", proof.Created, err)
			return ErrorProofCreatedUnparseable
		}
		if created.After(now.Add(ldProofClockSkew)) {
			logging.Log().Warnf("VP proof was created at %s, which is in the future", proof.Created)
			return ErrorProofCreatedInFuture
		}
		if age := now.Sub(created); age > maxAge+ldProofClockSkew {
			logging.Log().Warnf("VP proof was created at %s, %v ago, which exceeds the accepted maximum age of %v",
				proof.Created, age, maxAge)
			return ErrorProofNotFresh
		}
	}

	return nil
}

// verifyJSONLDHolderBinding requires an identified credential subject to be
// the holder of the presentation that carries the credential. It is the
// JSON-LD equivalent of verifyCnfBinding: the presentation proof establishes
// who is presenting, this check establishes that the credential was issued to
// them.
//
// The check is skipped when the presentation declares no holder — there is
// then nothing to bind against — and when no credential subject carries an
// id. A credential without an identified subject makes claims about nobody in
// particular, so replaying it does not transfer anybody's identity; rejecting
// it would break the many credentials that legitimately omit the id.
func verifyJSONLDHolderBinding(cred *common.Credential, presentationHolder string) error {
	if presentationHolder == "" {
		return nil
	}

	identifiedSubjects := 0
	for _, subject := range cred.Contents().Subject {
		if subject.ID == "" {
			continue
		}
		identifiedSubjects++
		if subject.ID == presentationHolder {
			return nil
		}
	}

	if identifiedSubjects == 0 {
		logging.Log().Debugf("JSON-LD credential %s has no identified subject, cannot bind it to holder %s",
			cred.Contents().ID, presentationHolder)
		return nil
	}

	logging.Log().Warnf("JSON-LD credential %s is not issued to the presentation holder %s",
		cred.Contents().ID, presentationHolder)
	return ErrorHolderSubjectMismatch
}

// VerifyLDVPProofBinding checks the semantic bindings of JSON-LD VP proofs:
// challenge (replay prevention via session nonce) and domain (audience binding).
//
// One and the same proof has to satisfy every expected binding. Tracking the
// bindings independently across the whole proof list would let a presentation
// with two proofs — one carrying the right challenge, the other the right
// domain — pass without any single signature binding this session to this
// verifier.
//
// An absent field counts as a mismatch rather than as "nothing to check": if
// expectedChallenge is non-empty the proof must carry exactly that challenge,
// and if expectedDomain is non-empty it must carry exactly that domain.
// Otherwise an attacker could opt out of either binding simply by omitting
// the field.
//
// Both fields are covered by the proof signature (see
// common.VerifyLinkedDataProof), so a captured presentation cannot be
// re-pointed at another session or another verifier.
//
// If the presentation has no LD proofs, the check is a no-op (returns nil) —
// JWT and SD-JWT presentations are bound through their own mechanisms.
func VerifyLDVPProofBinding(pres *common.Presentation, expectedChallenge, expectedDomain string) error {
	if len(pres.Proofs) == 0 {
		return nil
	}
	if expectedChallenge == "" && expectedDomain == "" {
		return nil
	}

	// A binding is "seen" once some proof carries the expected value, and
	// "fully bound" once one single proof carries all of them.
	challengeSeen := expectedChallenge == ""
	domainSeen := expectedDomain == ""
	fullyBound := false

	for _, proof := range pres.Proofs {
		// A proof that names a challenge or a domain has to name the right
		// one. A mismatching value is an active contradiction rather than a
		// missing binding, so it is rejected wherever in the list it appears.
		if expectedChallenge != "" && proof.Challenge != "" && proof.Challenge != expectedChallenge {
			logging.Log().Warnf("VP proof challenge %q does not match expected nonce %q", proof.Challenge, expectedChallenge)
			return ErrorProofChallengeMismatch
		}
		if expectedDomain != "" && proof.Domain != "" && proof.Domain != expectedDomain {
			logging.Log().Warnf("VP proof domain %q does not match expected domain %q", proof.Domain, expectedDomain)
			return ErrorProofDomainMismatch
		}

		challengeBound := expectedChallenge == "" || proof.Challenge == expectedChallenge
		domainBound := expectedDomain == "" || proof.Domain == expectedDomain
		challengeSeen = challengeSeen || challengeBound
		domainSeen = domainSeen || domainBound
		fullyBound = fullyBound || (challengeBound && domainBound)
	}

	if fullyBound {
		return nil
	}

	// Report the binding that no proof carried at all; when each was carried
	// only by a different proof, no signature binds this session to this
	// verifier and the challenge is the binding that is missing from the
	// proof that names the domain.
	if !challengeSeen {
		logging.Log().Warn("VP proof challenge expected but not found in any proof")
		return ErrorProofChallengeMismatch
	}
	if !domainSeen {
		logging.Log().Warnf("VP proof domain %q expected but not found in any proof", expectedDomain)
		return ErrorProofDomainMismatch
	}
	logging.Log().Warnf("No single VP proof carries both the expected challenge and the expected domain %q", expectedDomain)
	return ErrorProofChallengeMismatch
}

// extractJWTPayload decodes the payload from a JWT without signature verification.
func extractJWTPayload(token []byte) ([]byte, error) {
	parts := strings.SplitN(string(token), ".", 3)
	if len(parts) < 2 {
		return nil, ErrorInvalidJWTFormat
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}

// jwtMediaType reads the JOSE typ header from a compact JWT serialization and
// returns its value. It base64url-decodes the first dot-delimited segment,
// unmarshals it as JSON, and returns the "typ" field. When the token has no
// typ header, is malformed, or does not contain valid JSON in the header
// segment, an empty string is returned without error.
func jwtMediaType(token []byte) string {
	parts := strings.SplitN(string(token), ".", 3)
	if len(parts) < 2 {
		return ""
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return ""
	}
	typ, _ := header["typ"].(string)
	return typ
}

// isVCJoseJWT reports whether the given JWT typ header value identifies a
// VC-JOSE-COSE credential (typ: vc+jwt). The comparison is case-insensitive
// per RFC 7515 §4.1.9 (JOSE media type values are case-insensitive).
func isVCJoseJWT(typ string) bool {
	return strings.EqualFold(typ, common.JWTTypVCJWT)
}

// isVPJoseJWT reports whether the given JWT typ header value identifies a
// VC-JOSE-COSE presentation (typ: vp+jwt). The comparison is case-insensitive
// per RFC 7515 §4.1.9 (JOSE media type values are case-insensitive).
func isVPJoseJWT(typ string) bool {
	return strings.EqualFold(typ, common.JWTTypVPJWT)
}

// parseUnsignedJWTCredential extracts claims from a JWT VC without signature verification.
func parseUnsignedJWTCredential(tokenString string) (*common.Credential, error) {
	parts := strings.SplitN(tokenString, ".", 3)
	if len(parts) < 2 {
		return nil, ErrorInvalidJWTFormat
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	return jwtClaimsToCredential(claims)
}

// parseJSONLDCredential parses a JSON-LD VC from a map.
func parseJSONLDCredential(vcMap map[string]interface{}) (*common.Credential, error) {
	contents := common.CredentialContents{}

	if id, ok := vcMap[common.JSONLDKeyID].(string); ok {
		contents.ID = id
	}
	contents.Types = common.ToStringSlice(vcMap[common.JSONLDKeyType])
	contents.Context = common.ToStringSlice(vcMap[common.JSONLDKeyContext])

	switch issuer := vcMap[common.VCKeyIssuer].(type) {
	case string:
		contents.Issuer = &common.Issuer{ID: issuer}
	case map[string]interface{}:
		if id, ok := issuer[common.JSONLDKeyID].(string); ok {
			contents.Issuer = &common.Issuer{ID: id}
		}
	}

	contents.ValidFrom, contents.ValidUntil = common.ParseCredentialDates(vcMap)

	if subject, ok := vcMap[common.VCKeyCredentialSubject].(map[string]interface{}); ok {
		s := common.Subject{CustomFields: common.CustomFields{}}
		if id, ok := subject[common.JSONLDKeyID].(string); ok {
			s.ID = id
		}
		for k, v := range subject {
			if k != common.JSONLDKeyID {
				s.CustomFields[k] = v
			}
		}
		contents.Subject = []common.Subject{s}
	}

	// Extract credentialStatus for revocation checking.
	if status, ok := vcMap[common.VCKeyCredentialStatus].(map[string]interface{}); ok {
		contents.Status = &common.TypedID{
			ID:   stringFromMap(status, common.JSONLDKeyID),
			Type: stringFromMap(status, common.JSONLDKeyType),
		}
	}

	cred, err := common.CreateCredential(contents, common.CustomFields{})
	if err != nil {
		return nil, err
	}
	cred.SetRawJSON(vcMap)

	// Extract LD proofs from the credential, if present.
	if proofRaw, hasProof := vcMap[common.VPKeyProof]; hasProof {
		proofs, err := common.ParseLDProofs(proofRaw)
		if err != nil {
			logging.Log().Warnf("Failed to parse LD proofs on JSON-LD credential: %v", err)
			return nil, err
		}
		cred.SetProofs(proofs)
	}

	cred.SetFormat(common.FormatLDPVC)
	return cred, nil
}

func (sjp *ConfigurableSdJwtParser) Parse(tokenString string) (map[string]interface{}, error) {
	var verifyFunc func([]byte) ([]byte, error)
	if sjp.ProofChecker != nil {
		verifyFunc = sjp.ProofChecker.VerifyJWT
	}
	return common.ParseSDJWT(tokenString, verifyFunc)
}

func (sjp *ConfigurableSdJwtParser) ClaimsToCredential(claims map[string]interface{}) (credential *common.Credential, err error) {

	issuer, i_ok := claims[common.JWTClaimIss]
	vct, vct_ok := claims[common.JWTClaimVct]
	if !i_ok || !vct_ok {
		logging.Log().Warnf("Token does not contain issuer(%v) or vct(%v).", i_ok, vct_ok)
		return credential, ErrorInvalidSdJwt
	}
	dateClaims := map[string]bool{common.JWTClaimNbf: true, common.JWTClaimIat: true, common.JWTClaimExp: true}
	customFields := common.CustomFields{}
	for k, v := range claims {
		if k != common.JWTClaimIss && k != common.JWTClaimVct && !dateClaims[k] {
			customFields[k] = v
		}
	}
	subject := common.Subject{CustomFields: customFields}
	contents := common.CredentialContents{Issuer: &common.Issuer{ID: issuer.(string)}, Types: []string{vct.(string)}, Subject: []common.Subject{subject}}

	if nbf, ok := claims[common.JWTClaimNbf].(float64); ok {
		t := time.Unix(int64(nbf), 0)
		contents.ValidFrom = &t
	} else if iat, ok := claims[common.JWTClaimIat].(float64); ok {
		t := time.Unix(int64(iat), 0)
		contents.ValidFrom = &t
	}
	if exp, ok := claims[common.JWTClaimExp].(float64); ok {
		t := time.Unix(int64(exp), 0)
		contents.ValidUntil = &t
	}

	cred, err := common.CreateCredential(contents, common.CustomFields{})
	if err != nil {
		return nil, err
	}
	cred.SetFormat(common.FormatSDJWT)
	return cred, nil
}

func (sjp *ConfigurableSdJwtParser) ParseWithSdJwt(tokenBytes []byte) (presentation *common.Presentation, err error) {
	logging.Log().Debug("Parse with SD-Jwt")

	payloadBytes, err := extractJWTPayload(tokenBytes)
	if err != nil {
		logging.Log().Warnf("Failed to extract the VP payload: %v", err)
		return nil, err
	}

	var vpMap map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &vpMap); err != nil {
		logging.Log().Warnf("Failed to unmarshal VP payload: %v", err)
		return nil, err
	}

	vp, ok := vpMap[common.JWTClaimVP].(map[string]interface{})
	if !ok {
		logging.Log().Warn("VP token does not contain vp claim")
		return presentation, ErrorPresentationNoCredentials
	}

	vcs, ok := vp[common.VPKeyVerifiableCredential]
	if !ok {
		logging.Log().Warn("VP does not contain verifiableCredential")
		return presentation, ErrorPresentationNoCredentials
	}

	presentation, err = common.NewPresentation()
	if err != nil {
		return nil, err
	}

	// the holder is optional here, mirroring parseJSONLDPresentation and parseJWTPresentation. Holder binding
	// for sd-jwts is done via the kb-jwt, not via this claim, so a missing one must not reject the presentation.
	if holder, ok := vp[common.VPKeyHolder].(string); ok {
		presentation.Holder = holder
	}

	vcArray, ok := vcs.([]interface{})
	if !ok {
		logging.Log().Warn("The verifiableCredential entry is not an array")
		return nil, ErrorVCNotArray
	}

	// due to dcql, we only need to take care of presentations containing credentials of the same type.
	for _, vc := range vcArray {
		vcString, ok := vc.(string)
		if !ok {
			logging.Log().Warn("The presentation contains a credential that is not an sd-jwt string")
			return nil, ErrorInvalidSdJwt
		}
		logging.Log().Debugf("The vc %s", vcString)
		parsed, err := sjp.Parse(vcString)
		if err != nil {
			logging.Log().Warnf("Failed to parse SD-JWT VC: %v", err)
			return nil, err
		}
		credential, err := sjp.ClaimsToCredential(parsed)
		if err != nil {
			logging.Log().Warnf("Failed to create credential from SD-JWT claims: %v", err)
			return nil, err
		}
		// Extract and parse x5c certificates from the SD-JWT header so
		// downstream validators (e.g. eIDAS) can use the already-parsed
		// certificates directly. Not every SD-JWT carries an x5c header,
		// so extraction failures are silently ignored here.
		if x5cCerts := parseX5CCertificates([]byte(vcString)); len(x5cCerts) > 0 {
			credential.SetX5CCertificates(x5cCerts)
		}
		presentation.AddCredentials(credential)
	}

	// Store raw token for deferred VP signature verification.
	// Verification happens in GenerateToken only when holder binding is required by the service config.
	presentation.SetRawToken(tokenBytes)

	return presentation, nil
}

// verifyCnfBinding checks the cnf (confirmation) claim in a credential against the VP signer's key.
// Per RFC 7800, if the credential contains a cnf.jwk, the key must match the VP signer's public key.
// If no cnf claim is present, the check is skipped (no error).
func verifyCnfBinding(cred *common.Credential, holderKey jwk.Key) error {
	cnfRaw, ok := cred.CustomFields()[common.JWTClaimCnf]
	if !ok {
		return nil
	}

	cnfMap, ok := cnfRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	jwkRaw, ok := cnfMap[common.CnfKeyJWK]
	if !ok {
		return nil
	}

	jwkMap, ok := jwkRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	cnfKeyBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return ErrorCnfKeyMismatch
	}

	cnfKey, err := jwk.ParseKey(cnfKeyBytes)
	if err != nil {
		logging.Log().Warnf("Failed to parse cnf.jwk: %v", err)
		return ErrorCnfKeyMismatch
	}

	// Compare using JWK thumbprints (RFC 7638)
	if !jwk.Equal(cnfKey, holderKey) {
		logging.Log().Warn("CNF key does not match VP signer key")
		return ErrorCnfKeyMismatch
	}

	return nil
}

// parseX5CCertificates extracts and parses the x5c certificate chain from an
// SD-JWT token's header. Returns the parsed certificates (leaf first, then
// intermediates), or nil if the token has no x5c header or parsing fails.
// This function is intentionally lenient: it returns nil instead of an error
// because not every SD-JWT carries an x5c header.
func parseX5CCertificates(token []byte) []*x509.Certificate {
	x5cStrings, err := extractX5CFromToken(token)
	if err != nil || len(x5cStrings) == 0 {
		return nil
	}

	certs := make([]*x509.Certificate, 0, len(x5cStrings))
	for _, certB64 := range x5cStrings {
		cert, err := parseCertificate(certB64)
		if err != nil {
			logging.Log().Debugf("parseX5CCertificates: skipping unparseable certificate: %v", err)
			return nil
		}
		certs = append(certs, cert)
	}
	return certs
}
