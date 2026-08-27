package verifier

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/jades"
	"github.com/fiware/VCVerifier/logging"
	"github.com/hellofresh/health-go/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/piprate/json-gold/ld"
)

// ldDocLoaderCacheTTL is the TTL for cached JSON-LD context documents.
const ldDocLoaderCacheTTL = 1 * time.Hour

// ldDocLoaderCacheCleanup is the interval for removing expired entries from
// the JSON-LD document loader cache.
const ldDocLoaderCacheCleanup = 10 * time.Minute

var ErrorNoValidationEndpoint = errors.New("no_validation_endpoint_configured")
var ErrorNoValidationHost = errors.New("no_validation_host_configured")
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

// allow singleton access to the parser
var presentationParser PresentationParser

// allow singleton access to the parser
var sdJwtParser SdJwtParser

// globalProofChecker is the shared proof checker for deferred VP signature verification.
var globalProofChecker *JWTProofChecker

// globalLDProofChecker is the shared LD proof checker for JSON-LD VP/VC verification.
var globalLDProofChecker *LDProofChecker

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

/**
* Global singelton access to the parser
**/
func GetPresentationParser() PresentationParser {
	if presentationParser == nil {
		logging.Log().Error("PresentationParser is not initialized.")
	}
	return presentationParser
}

// init the presentation parser depending on the config, either with or without did:elsi support
func InitPresentationParser(config *configModel.Configuration, healthCheck *health.Health) error {
	elsiConfig := &config.Elsi
	err := validateConfig(elsiConfig)
	if err != nil {
		logging.Log().Warnf("No valid elsi configuration provided. Error: %v", err)
		return err
	}

	registry := did.NewRegistry(did.WithVDR(did.NewWebVDR()), did.WithVDR(did.NewKeyVDR()), did.WithVDR(did.NewJWKVDR()))

	var jAdESValidator jades.JAdESValidator
	if elsiConfig.Enabled {
		externalValidator := &jades.ExternalJAdESValidator{
			HttpClient:        &http.Client{},
			ValidationAddress: buildAddress(elsiConfig.ValidationEndpoint.Host, elsiConfig.ValidationEndpoint.ValidationPath),
			HealthAddress:     buildAddress(elsiConfig.ValidationEndpoint.Host, elsiConfig.ValidationEndpoint.HealthPath),
		}
		jAdESValidator = externalValidator

		if err := healthCheck.Register(health.Config{
			Name:      "JAdES-Validator",
			Timeout:   time.Second * 5,
			SkipOnErr: false,
			Check: func(ctx context.Context) error {
				return externalValidator.IsReady()
			},
		}); err != nil {
			logging.Log().Errorf("Failed to register JAdES-Validator health check: %v", err)
		}
	}

	checker := NewJWTProofChecker(registry, jAdESValidator)
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
	ldChecker := NewLDProofChecker(registry, docLoader)
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

func validateConfig(elsiConfig *configModel.Elsi) error {
	if !elsiConfig.Enabled {
		return nil
	}
	if elsiConfig.ValidationEndpoint == nil {
		return ErrorNoValidationEndpoint
	}
	if elsiConfig.ValidationEndpoint.Host == "" {
		return ErrorNoValidationHost
	}
	return nil
}

func buildAddress(host, path string) string {
	return strings.TrimSuffix(host, "/") + "/" + strings.TrimPrefix(path, "/")
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
			cred, err := cpp.parseAndVerifyJSONLDCredential(v)
			if err != nil {
				return nil, err
			}
			pres.AddCredentials(cred)
		}
	}

	return pres, nil
}

// parseJWTCredential parses and verifies a JWT-encoded VC.
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

	return jwtClaimsToCredential(claims)
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
		if types, ok := vcClaim[common.JSONLDKeyType].([]interface{}); ok {
			for _, t := range types {
				if s, ok := t.(string); ok {
					contents.Types = append(contents.Types, s)
				}
			}
		}
		if ctxs, ok := vcClaim[common.JSONLDKeyContext].([]interface{}); ok {
			for _, c := range ctxs {
				if s, ok := c.(string); ok {
					contents.Context = append(contents.Context, s)
				}
			}
		}
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

// stringFromMap safely extracts a string value from a map.
func stringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
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
			cred, credErr := cpp.parseAndVerifyJSONLDCredential(v)
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
func (cpp *ConfigurablePresentationParser) parseAndVerifyJSONLDCredential(vcMap map[string]interface{}) (*common.Credential, error) {
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

	return cred, nil
}

// VerifyLDVPProofBinding checks the semantic bindings of JSON-LD VP proofs:
// challenge (replay prevention via session nonce) and domain (audience binding).
//
// Both checks treat an absent field as a mismatch rather than as "nothing to
// check": if expectedChallenge is non-empty, at least one VP-level proof must
// carry exactly that challenge, and if expectedDomain is non-empty, at least
// one proof must carry exactly that domain. Otherwise an attacker could opt
// out of either binding simply by omitting the field.
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

	challengeMatched := false
	domainMatched := false
	for _, proof := range pres.Proofs {
		// Check challenge binding (replay prevention).
		if expectedChallenge != "" && proof.Challenge != "" {
			if proof.Challenge != expectedChallenge {
				logging.Log().Warnf("VP proof challenge %q does not match expected nonce %q", proof.Challenge, expectedChallenge)
				return ErrorProofChallengeMismatch
			}
			challengeMatched = true
		}

		// Check domain binding (audience verification).
		if expectedDomain != "" && proof.Domain != "" {
			if proof.Domain != expectedDomain {
				logging.Log().Warnf("VP proof domain %q does not match expected domain %q", proof.Domain, expectedDomain)
				return ErrorProofDomainMismatch
			}
			domainMatched = true
		}
	}

	// If a challenge was expected, at least one proof must have provided it.
	if expectedChallenge != "" && !challengeMatched {
		logging.Log().Warn("VP proof challenge expected but not found in any proof")
		return ErrorProofChallengeMismatch
	}

	// The same holds for the domain — an omitted domain is not a free pass.
	if expectedDomain != "" && !domainMatched {
		logging.Log().Warnf("VP proof domain %q expected but not found in any proof", expectedDomain)
		return ErrorProofDomainMismatch
	}

	return nil
}

// extractJWTPayload decodes the payload from a JWT without signature verification.
func extractJWTPayload(token []byte) ([]byte, error) {
	parts := strings.SplitN(string(token), ".", 3)
	if len(parts) < 2 {
		return nil, ErrorInvalidJWTFormat
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
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
	if types, ok := vcMap[common.JSONLDKeyType].([]interface{}); ok {
		for _, t := range types {
			if s, ok := t.(string); ok {
				contents.Types = append(contents.Types, s)
			}
		}
	}
	if ctxs, ok := vcMap[common.JSONLDKeyContext].([]interface{}); ok {
		for _, c := range ctxs {
			if s, ok := c.(string); ok {
				contents.Context = append(contents.Context, s)
			}
		}
	}

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

	return common.CreateCredential(contents, common.CustomFields{})
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
