package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	common "github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/gaiax"
	"github.com/fiware/VCVerifier/tir"
	"github.com/trustbloc/vc-go/verifiable"

	logging "github.com/fiware/VCVerifier/logging"

	client "github.com/fiware/dsba-pdp/http"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/patrickmn/go-cache"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/valyala/fasttemplate"
)

const REQUEST_MODE_BY_VALUE = "byValue"
const REQUEST_MODE_BY_REFERENCE = "byReference"
const REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"
const (
	CROSS_DEVICE_V1 = iota
	CROSS_DEVICE_V2
	SAME_DEVICE
)

const OPENID4VP_PROTOCOL = "openid4vp"
const REDIRECT_PROTOCOL = "redirect"

const DEFAULT_AUTHORIZATION_PATH = "/api/v1/authorization"
const DEFAULT_SERIVCE_AUTHORIZATION_TYPE = "FRONTEND_V2"

var ErrorNoDID = errors.New("no_did_configured")
var ErrorNoTIR = errors.New("no_tir_configured")
var ErrorUnsupportedKeyAlgorithm = errors.New("unsupported_key_algorithm")
var ErrorInvalidKeyConfig = errors.New("invalid_key_config")
var ErrorUnsupportedValidationMode = errors.New("unsupported_validation_mode")
var ErrorSupportedModesNotSet = errors.New("no_supported_request_mode_set")
var ErrorNoSigningKey = errors.New("no_signing_key_available")
var ErrorInvalidVC = errors.New("invalid_vc")
var ErrorNoSuchSession = errors.New("no_such_session")
var ErrorWrongGrantType = errors.New("wrong_grant_type")
var ErrorNoSuchCode = errors.New("no_such_code")
var ErrorRedirectUriMismatch = errors.New("redirect_uri_does_not_match")
var ErrorVerficationContextSetup = errors.New("no_valid_verification_context")
var ErrorTokenUnparsable = errors.New("unable_to_parse_token")
var ErrorRequiredCredentialNotProvided = errors.New("required_credential_not_provided")
var ErrorUnsupportedRequestMode = errors.New("unsupported_request_mode")
var ErrorNoExpiration = errors.New("no_jwt_expiration_set")
var ErrorNoKeyId = errors.New("no_key_id_available")
var ErrorNoRequestObject = errors.New("no_request_object_available")
var ErrorInvalidNonce = errors.New("invalid_nonce")

// Actual implementation of the verfifier functionality

// verifier interface
type Verifier interface {
	ReturnLoginQR(host string, protocol string, callback string, sessionId string, clientId string, nonce string, requestMode string) (qr string, err error)
	ReturnLoginQRV2(host string, protocol string, callback string, sessionId string, clientId string, scope string, nonce string, requestMode string) (qr string, err error)
	StartSiopFlow(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string) (connectionString string, err error)
	StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string, clientId string, nonce string, requestMode string, scope string, requestProtocol string) (authenticationRequest string, err error)
	GetToken(authorizationCode string, redirectUri string, validated bool) (jwtString string, expiration int64, err error)
	GetJWKS() jwk.Set
	AuthenticationResponse(state string, verifiablePresentation *verifiable.Presentation) (sameDevice Response, err error)
	GenerateToken(clientId, subject, audience string, scope []string, verifiablePresentation *verifiable.Presentation) (int64, string, error)
	GetOpenIDConfiguration(serviceIdentifier string) (metadata common.OpenIDProviderMetadata, err error)
	GetRequestObject(state string) (jwt string, err error)
	GetHost() string
	GetAuthorizationType(clientId string) string
	GetDefaultScope(serviceIdentifier string) (string, error)
}

type ValidationService interface {
	// Validates the given VC. FIXME Currently a positiv result is returned even when no policy was checked
	ValidateVC(verifiableCredential *verifiable.Credential, verificationContext ValidationContext) (result bool, err error)
}

// implementation of the verifier, using trustbloc and gaia-x compliance issuers registry as a validation backends.
type CredentialVerifier struct {
	// host of the verifier
	host string
	// did of the verifier
	did string
	// trusted-issuers-registry to be used for verification
	tirAddress string
	// key to sign the jwt's with
	signingKey jwk.Key
	// cache to be used for in-progress authentication sessions
	sessionCache common.Cache
	// cache to be used for jwt retrieval
	tokenCache common.Cache
	// nonce generator
	nonceGenerator NonceGenerator
	// provides the current time
	clock common.Clock
	// provides the capabilities to signt the jwt
	tokenSigner common.TokenSigner
	// provide the configuration to be used with the credentials
	credentialsConfig CredentialsConfig
	// Validation services to be used on the credentials
	validationServices []ValidationService
	// Algorithm to be used for signing the jwt
	signingAlgorithm string
	// request modes supported by this instance of the verifier
	supportedRequestModes []string
	// Key for signing the request objects
	requestSigningKey *jwk.Key
	// Client identification for signing the request objects
	clientIdentification configModel.ClientIdentification
	// config of the verifier
	verifierConfig configModel.Verifier
	// JWT token expiration time in minutes
	jwtExpiration time.Duration
}

// allow singleton access to the verifier
var verifier Verifier

// http client to be used
var httpClient = client.HttpClient()

// file accessor to be used
var localFileAccessor common.FileAccessor = common.DiskFileAccessor{}

// interfaces and default implementations

type ValidationContext interface{}

type TrustRegistriesValidationContext struct {
	trustedIssuersLists           map[string][]string
	trustedParticipantsRegistries map[string][]configModel.TrustedParticipantsList
}

func (trvc TrustRegistriesValidationContext) GetTrustedIssuersLists() map[string][]string {
	return trvc.trustedIssuersLists
}

func (trvc TrustRegistriesValidationContext) GetTrustedParticipantLists() map[string][]configModel.TrustedParticipantsList {
	return trvc.trustedParticipantsRegistries
}

func (trvc TrustRegistriesValidationContext) GetRequiredCredentialTypes() []string {
	requiredTypes := []string{}
	for credentialType := range trvc.trustedIssuersLists {
		requiredTypes = append(requiredTypes, credentialType)
	}
	for credentialType := range trvc.trustedParticipantsRegistries {
		requiredTypes = append(requiredTypes, credentialType)
	}
	return removeDuplicate(requiredTypes)
}

type HolderValidationContext struct {
	claim  string
	holder string
}

func (hvc HolderValidationContext) GetClaim() string {
	return hvc.claim
}

func (hvc HolderValidationContext) GetHolder() string {
	return hvc.holder
}

func removeDuplicate[T string | int](sliceList []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

type randomGenerator struct{}

type NonceGenerator interface {
	GenerateNonce() string
}

// generate a random nonce
func (r *randomGenerator) GenerateNonce() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	return nonce
}

// struct to represent a running login session
type loginSession struct {
	// callback to be notified after success
	callback string
	// sessionId to be included in the notification
	sessionId string
	// nonce used for the session
	nonce string
	// clientId provided for the session
	clientId string
	// requestObject created for the session
	requestObject string
	// inidicates if the cross device session is v1 or v2
	version int
	// scope requested for the session
	scope string
}

// struct to represent a token, accessible through the token endpoint
type tokenStore struct {
	token        jwt.Token
	redirect_uri string
}

// Response structure for successful same-device authentications
type Response struct {
	// version of the flow
	FlowVersion int
	// the redirect target to be informed
	RedirectTarget string
	// code of the siop flow
	Code string
	// session id provided by the client
	SessionId string
	// nonce provided by the client
	Nonce string
}

/**
* Global singelton access to the verifier
**/
func GetVerifier() Verifier {
	if verifier == nil {
		logging.Log().Error("Verifier is not initialized.")
	}
	return verifier
}

/**
* Initialize the verifier and all its components from the configuration
**/
func InitVerifier(config *configModel.Configuration) (err error) {

	logging.Log().Info("Init verifeir")

	err = verifyConfig(&config.Verifier)
	if err != nil {
		logging.Log().Warnf("Was not able to verify config. Err: %v", err)
		return
	}
	verifierConfig := &config.Verifier

	sessionCache := cache.New(time.Duration(verifierConfig.SessionExpiry)*time.Second, time.Duration(2*verifierConfig.SessionExpiry)*time.Second)
	tokenCache := cache.New(time.Duration(verifierConfig.SessionExpiry)*time.Second, time.Duration(2*verifierConfig.SessionExpiry)*time.Second)

	credentialsVerifier := TrustBlocValidator{validationMode: config.Verifier.ValidationMode}

	externalGaiaXValidator := InitGaiaXRegistryValidationService(verifierConfig)

	credentialsConfig, err := InitServiceBackedCredentialsConfig(&config.ConfigRepo)
	if err != nil {
		logging.Log().Errorf("Was not able to initiate the credentials config. Err: %v", err)
	}

	clock := common.RealClock{}

	var tokenProvider tir.TokenProvider
	if (&config.M2M).AuthEnabled {
		tokenProvider, err = tir.InitM2MTokenProvider(config, clock)
		if err != nil {
			logging.Log().Errorf("Was not able to instantiate the token provider. Err: %v", err)
			return err
		}
		logging.Log().Info("Successfully created token provider")
	} else {
		logging.Log().Infof("Auth disabled.")
	}

	tirClient, err := tir.NewTirHttpClient(tokenProvider, config.M2M, config.Verifier)
	if err != nil {
		logging.Log().Errorf("Was not able to instantiate the trusted-issuers-registry client. Err: %v", err)
		return err
	}
	gaiaXClient, _ := gaiax.NewGaiaXHttpClient()
	trustedParticipantVerificationService := TrustedParticipantValidationService{tirClient: tirClient, gaiaXClient: gaiaXClient}
	trustedIssuerVerificationService := TrustedIssuerValidationService{tirClient: tirClient}

	key, err := initPrivateKey(verifierConfig.KeyAlgorithm, verifierConfig.GenerateKey, verifierConfig.KeyPath)

	kid := verifierConfig.ClientIdentification.Id
	if verifierConfig.ClientIdentification.Kid != "" {
		kid = verifierConfig.ClientIdentification.Kid
	}
	if key != nil && !key.Has(jwk.KeyIDKey) {
		logging.Log().Infof("Adding kid='%s' to keyset", kid)
		key.Set(jwk.KeyIDKey, kid)
	}

	if err != nil {
		logging.Log().Errorf("Was not able to initiate a signing key. Err: %v", err)
		return err
	}

	didSigningKey, err := getRequestSigningKey(verifierConfig.ClientIdentification.KeyPath, verifierConfig.ClientIdentification.Id)
	if (slices.Contains(verifierConfig.SupportedModes, REQUEST_MODE_BY_VALUE) || slices.Contains(verifierConfig.SupportedModes, REQUEST_MODE_BY_REFERENCE)) && err != nil {
		logging.Log().Errorf("Was not able to get a signing key, despite mode %s supported. Err: %v", REQUEST_MODE_BY_VALUE, err)
		return err
	} else {
		err = nil
	}

	verifier = &CredentialVerifier{
		(&config.Server).Host,
		verifierConfig.Did,
		verifierConfig.TirAddress,
		key,
		sessionCache,
		tokenCache,
		&randomGenerator{},
		clock,
		common.JwtTokenSigner{},
		credentialsConfig,
		[]ValidationService{
			&credentialsVerifier,
			&externalGaiaXValidator,
			&trustedParticipantVerificationService,
			&trustedIssuerVerificationService,
		},
		verifierConfig.KeyAlgorithm,
		verifierConfig.SupportedModes,
		&didSigningKey,
		verifierConfig.ClientIdentification,
		*verifierConfig,
		time.Duration(verifierConfig.JwtExpiration) * time.Minute,
	}

	logging.Log().Debug("Successfully initalized the verifier")
	return
}

/**
*   Initializes the cross-device login flow and returns all neccessary information as a qr-code
**/
func (v *CredentialVerifier) ReturnLoginQR(host string, protocol string, callback string, sessionId string, clientId string, nonce string, requestMode string) (qr string, err error) {

	for _, v := range v.supportedRequestModes {
		logging.Log().Warnf("Supported: %s", v)
	}

	if !slices.Contains(v.supportedRequestModes, requestMode) {
		logging.Log().Infof("QR with mode %s was requested, but only %v is supported.", requestMode, v.supportedRequestModes)
		return qr, ErrorUnsupportedRequestMode
	}

	logging.Log().Debugf("Generate a login qr for %s.", callback)
	authenticationRequest, err := v.initSiopFlow(host, protocol, callback, sessionId, clientId, nonce, requestMode)

	if err != nil {
		return qr, err
	}

	png, err := qrcode.Encode(authenticationRequest, qrcode.Medium, 256)
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	return base64Img, err
}

/**
*   Initializes the cross-device login flow and returns all neccessary information as a qr-code
**/
func (v *CredentialVerifier) ReturnLoginQRV2(host string, protocol string, redircetUri string, sessionId string, clientId string, scope string, nonce string, requestMode string) (qr string, err error) {

	for _, v := range v.supportedRequestModes {
		logging.Log().Warnf("Supported: %s", v)
	}

	if !slices.Contains(v.supportedRequestModes, requestMode) {
		logging.Log().Infof("QR with mode %s was requested, but only %v is supported.", requestMode, v.supportedRequestModes)
		return qr, ErrorUnsupportedRequestMode
	}

	logging.Log().Debugf("Generate a login qr for %s.", redircetUri)
	authenticationRequest, err := v.initOid4VPCrossDevice(host, protocol, redircetUri, sessionId, clientId, scope, nonce, requestMode)

	if err != nil {
		return qr, err
	}

	png, err := qrcode.Encode(authenticationRequest, qrcode.Medium, 256)
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	return base64Img, err
}

/**
* Starts a siop-flow and returns the required connection information
**/
func (v *CredentialVerifier) StartSiopFlow(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string) (connectionString string, err error) {
	logging.Log().Debugf("Start a plain siop-flow for %s.", callback)

	return v.initSiopFlow(host, protocol, callback, state, clientId, nonce, requestMode)
}

/**
* Starts a same-device siop-flow and returns the required redirection information
**/
func (v *CredentialVerifier) StartSameDeviceFlow(host string, protocol string, state string, redirectPath string, clientId string, nonce string, requestMode string, scope string, requestProtocol string) (authenticationRequest string, err error) {
	logging.Log().Debugf("Initiate samedevice flow for %s - %s.", host, clientId)
	if nonce == "" {
		nonce = v.nonceGenerator.GenerateNonce()
	}

	loginSession := loginSession{callback: fmt.Sprintf("%s://%s%s", protocol, host, redirectPath), sessionId: state, nonce: nonce, clientId: clientId, version: SAME_DEVICE, scope: scope}
	err = v.sessionCache.Add(state, loginSession, cache.DefaultExpiration)
	if err != nil {
		logging.Log().Warnf("Was not able to store the login session %s in cache. Err: %v", logging.PrettyPrintObject(loginSession), err)
		return authenticationRequest, err
	}

	authResponseUri := fmt.Sprintf("%s://%s/api/v1/authentication_response", protocol, host)
	if requestProtocol == OPENID4VP_PROTOCOL {
		return v.generateAuthenticationRequest(requestProtocol+"://", clientId, scope, authResponseUri, state, nonce, loginSession, requestMode)
	} else {
		return v.generateAuthenticationRequest(protocol+"://"+host+redirectPath, clientId, scope, authResponseUri, state, nonce, loginSession, requestMode)
	}
}

/**
*   Returns an already generated jwt from the cache to properly authorized requests. Every token will only be returend once.
**/
func (v *CredentialVerifier) GetToken(authorizationCode string, redirectUri string, validated bool) (jwtString string, expiration int64, err error) {

	tokenSessionInterface, hit := v.tokenCache.Get(authorizationCode)
	if !hit {
		logging.Log().Infof("No such authorization code cached: %s.", authorizationCode)
		return jwtString, expiration, ErrorNoSuchCode
	}
	// we do only allow retrieval once.
	v.tokenCache.Delete(authorizationCode)

	tokenSession := tokenSessionInterface.(tokenStore)
	if !validated && tokenSession.redirect_uri != redirectUri {
		logging.Log().Infof("Redirect uri does not match for authorization %s. Was %s but is expected %s.", authorizationCode, redirectUri, tokenSession.redirect_uri)
		return jwtString, expiration, ErrorRedirectUriMismatch
	}

	var signatureAlgorithm jwa.SignatureAlgorithm

	switch v.signingAlgorithm {
	case "RS256":
		signatureAlgorithm = jwa.RS256()
	case "ES256":
		signatureAlgorithm = jwa.ES256()
	}

	jwtBytes, err := v.tokenSigner.Sign(tokenSession.token, jwt.WithKey(signatureAlgorithm, v.signingKey))
	if err != nil {
		logging.Log().Warnf("Was not able to sign the token. Err: %v", err)
		return jwtString, expiration, err
	}

	tokenExpiry, exists := tokenSession.token.Expiration()
	if !exists {
		logging.Log().Warn("Token does not have an expiration.")
		return jwtString, expiration, ErrorNoExpiration
	}

	expiration = tokenExpiry.Unix() - v.clock.Now().Unix()

	return string(jwtBytes), expiration, err
}

/**
* Return the JWKS used by the verifier to allow jwt verification
**/
func (v *CredentialVerifier) GetJWKS() jwk.Set {
	jwks := jwk.NewSet()
	publicKey, _ := v.signingKey.PublicKey()
	jwks.AddKey(publicKey)
	return jwks
}

func extractCredentialTypes(verifiablePresentation *verifiable.Presentation) (credentialsByType map[string][]*verifiable.Credential, credentialTypes []string) {

	js, _ := verifiablePresentation.MarshalJSON()
	logging.Log().Debugf("Presentation %s", js)
	credentialsByType = map[string][]*verifiable.Credential{}
	credentialTypes = []string{}
	for _, vc := range verifiablePresentation.Credentials() {
		logging.Log().Debugf("Contained credential %s", logging.PrettyPrintObject(vc))
		logging.Log().Debugf("Contained credential contents %s", logging.PrettyPrintObject(vc.Contents()))
		for _, credentialType := range vc.Contents().Types {
			if _, ok := credentialsByType[credentialType]; !ok {
				credentialsByType[credentialType] = []*verifiable.Credential{}
			}
			credentialsByType[credentialType] = append(credentialsByType[credentialType], vc)
		}
		credentialTypes = append(credentialTypes, vc.Contents().Types...)
	}
	return
}

func getCredentialsNeededForScope(verificationContext TrustRegistriesValidationContext, credentialsByType map[string][]*verifiable.Credential) []*verifiable.Credential {
	credentialTypesNeededForScope := verificationContext.GetRequiredCredentialTypes()
	credentialsNeededForScope := []*verifiable.Credential{}
	seen := make(map[*verifiable.Credential]bool)
	// prevent duplicate checks
	for _, credentialType := range credentialTypesNeededForScope {
		if cred, ok := credentialsByType[credentialType]; ok {
			for _, c := range cred {
				if !seen[c] {
					credentialsNeededForScope = append(credentialsNeededForScope, c)
					seen[c] = true
				}
			}
		}
	}
	return credentialsNeededForScope
}

func (v *CredentialVerifier) GenerateToken(clientId, subject, audience string, scopes []string, verifiablePresentation *verifiable.Presentation) (int64, string, error) {
	// collect all submitted credential types
	credentialsByType, credentialTypes := extractCredentialTypes(verifiablePresentation)

	holder := verifiablePresentation.Holder
	var credentialsToBeIncluded []map[string]interface{}
	flatClaims := false

	// Go through all requested scopes and create a verification context
	for _, scope := range scopes {
		verificationContext, err := v.getTrustRegistriesValidationContextFromScope(clientId, scope, credentialTypes)
		if err != nil {
			logging.Log().Warnf("Was not able to create a valid verification context. Credential will be rejected. Err: %v", err)
			return 0, "", ErrorVerficationContextSetup
		}
		credentialsNeededForScope := getCredentialsNeededForScope(verificationContext, credentialsByType)

		for _, credential := range credentialsNeededForScope {
			holderValidationContexts, err := v.getHolderValidationContext(clientId, scope, credentialTypes, holder)
			if err != nil {
				logging.Log().Warnf("Was not able to create the holder validation context. Credential will be rejected. Err: %v", err)
				return 0, "", ErrorVerficationContextSetup
			}
			holderValidationService := HolderValidationService{}
			for _, holderValidationContext := range holderValidationContexts {
				result, err := holderValidationService.ValidateVC(credential, holderValidationContext)
				if err != nil {
					logging.Log().Warnf("Failed to verify credential %s. Err: %v", logging.PrettyPrintObject(credential), err)
					return 0, "", err
				}
				if !result {
					logging.Log().Infof("VC %s is not valid.", logging.PrettyPrintObject(credential))
					return 0, "", ErrorInvalidVC
				}
			}
			for _, verificationService := range v.validationServices {
				result, err := verificationService.ValidateVC(credential, verificationContext)
				if err != nil {
					logging.Log().Warnf("Failed to verify credential %s. Err: %v", logging.PrettyPrintObject(credential), err)
					return 0, "", err
				}
				if !result {
					logging.Log().Infof("VC %s is not valid.", logging.PrettyPrintObject(credential))
					return 0, "", ErrorInvalidVC
				}
			}
			complianceValidationContexts, err := v.getComplianceValidationContext(clientId, scope, credential, verifiablePresentation)
			if err != nil {
				logging.Log().Warnf("Was not able to create the compliance validation context. Credential will be rejected. Err: %v", err)
				return 0, "", ErrorVerficationContextSetup
			}
			complianceValidationService := ComplianceValidationService{}
			for _, complianceValidationContext := range complianceValidationContexts {
				logging.Log().Debugf("Validate credential %v with context %v", credential, complianceValidationContext)
				result, err := complianceValidationService.ValidateVC(credential, complianceValidationContext)
				if err != nil {
					logging.Log().Warnf("Failed to verify credential %s. Err: %v", logging.PrettyPrintObject(credential), err)
					return 0, "", err
				}
				if !result {
					logging.Log().Infof("VC %s is not valid.", logging.PrettyPrintObject(credential))
					return 0, "", ErrorInvalidVC
				}
			}
			shouldBeIncluded, inclusionConfig := v.shouldBeIncluded(clientId, scope, credential.Contents().Types)
			if shouldBeIncluded {
				credentialsToBeIncluded = append(credentialsToBeIncluded, buildInclusion(credential, inclusionConfig))
			}
			flatClaims, _ = v.credentialsConfig.GetFlatClaims(clientId, scope)
		}
	}
	token, err := v.generateJWT(credentialsToBeIncluded, holder, audience, flatClaims)
	if err != nil {
		logging.Log().Warnf("Was not able to create the token. Err: %v", err)
		return 0, "", err
	}

	tokenExpiry, exists := token.Expiration()
	if !exists {
		logging.Log().Warn("Token does not have an expiration.")
		return 0, "", ErrorNoExpiration
	}

	expiration := tokenExpiry.Unix() - v.clock.Now().Unix()

	var signatureAlgorithm jwa.SignatureAlgorithm
	switch v.signingAlgorithm {
	case "RS256":
		signatureAlgorithm = jwa.RS256()
	case "ES256":
		signatureAlgorithm = jwa.ES256()
	}

	tokenBytes, err := v.tokenSigner.Sign(token, jwt.WithKey(signatureAlgorithm, v.signingKey))
	if err != nil {
		logging.Log().Warnf("Was not able to sign the token. Err: %v", err)
		return 0, "", err
	}
	return expiration, string(tokenBytes), nil
}

func buildInclusion(credential *verifiable.Credential, inclusionConfig configModel.JwtInclusion) (inclusion map[string]interface{}) {
	if inclusionConfig.FullInclusion {
		logging.Log().Debugf("Include the full credential: %s", logging.PrettyPrintObject(credential))
		return credential.ToRawJSON()
	}
	logging.Log().Debug("Include only some claims")

	inclusion = make(map[string]interface{})
	for _, claim := range inclusionConfig.ClaimsToInclude {
		pathParts := strings.Split(claim.OriginalKey, ".")
		if val, ok := getValueFromPath(credential.ToRawJSON(), pathParts); ok {
			if claim.NewKey != "" {
				setValueAtPath(inclusion, strings.Split(claim.NewKey, "."), val)
			} else {
				setValueAtPath(inclusion, strings.Split(claim.OriginalKey, "."), val)
			}
		}
	}
	return inclusion
}

// retrieve the value from  the given path in the map
func getValueFromPath(m map[string]interface{}, path []string) (interface{}, bool) {
	currentPosition := m
	for i, key := range path {
		if i == len(path)-1 {
			// end of the path, get the value
			val, ok := currentPosition[key]
			return val, ok
		}
		// get the sub-object
		next, ok := currentPosition[key].(map[string]interface{})
		if !ok {
			// nothing available at the given path
			return nil, false
		}
		currentPosition = next
	}
	return nil, false
}

// set the value at the given path in the map
func setValueAtPath(m map[string]interface{}, path []string, value interface{}) {
	currentPosition := m
	for i, key := range path {
		if i == len(path)-1 {
			// end of the path, set the value
			currentPosition[key] = value
			return
		}
		if _, ok := currentPosition[key]; !ok {
			// no sub-object exists in the given map, create a new one
			currentPosition[key] = make(map[string]interface{})
		}
		// get the sub-object
		next, ok := currentPosition[key].(map[string]interface{})
		if !ok {
			// the existing element is not a map, overwrite it
			next = make(map[string]interface{})
			currentPosition[key] = next
		}
		currentPosition = next
	}
}

func (v *CredentialVerifier) shouldBeIncluded(clientId string, scope string, credentialTypes []string) (enabled bool, inclusion configModel.JwtInclusion) {
	logging.Log().Debugf("Check inclusion %s", credentialTypes)
	for _, credentialType := range credentialTypes {
		inclusion, _ := v.credentialsConfig.GetJwtInclusion(clientId, scope, credentialType)
		if inclusion.Enabled {
			return true, inclusion
		}
	}
	return false, inclusion
}

func (v *CredentialVerifier) GetDefaultScope(serviceIdentifier string) (scope string, err error) {
	return v.credentialsConfig.GetDefaultScope(serviceIdentifier)
}

func (v *CredentialVerifier) GetOpenIDConfiguration(serviceIdentifier string) (metadata common.OpenIDProviderMetadata, err error) {

	scopes, err := v.credentialsConfig.GetScope(serviceIdentifier)
	if err != nil {
		return metadata, err
	}
	authorizationPath := v.credentialsConfig.GetAuthorizationPath(serviceIdentifier)

	if authorizationPath == "" {
		authorizationPath = v.verifierConfig.AuthorizationEndpoint
	}
	if authorizationPath == "" {
		// static default in case nothing is provided
		authorizationPath = DEFAULT_AUTHORIZATION_PATH
	}

	logging.Log().Debugf("Scopes %s for %s", scopes, serviceIdentifier)

	return common.OpenIDProviderMetadata{
		Issuer:                           v.host,
		AuthorizationEndpoint:            appendPath(v.host, authorizationPath),
		TokenEndpoint:                    v.host + "/services/" + serviceIdentifier + "/token",
		JwksUri:                          v.host + "/.well-known/jwks",
		GrantTypesSupported:              []string{"authorization_code", "vp_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		ResponseTypesSupported:           []string{"code"},
		ResponseModeSupported:            []string{"direct_post"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"EdDSA", "ES256"},
		ScopesSupported:                  scopes}, err
}

func (v *CredentialVerifier) GetAuthorizationType(serviceIdentifier string) string {
	authorizationType, err := v.credentialsConfig.GetAuthorizationType(serviceIdentifier)
	if err != nil {
		return DEFAULT_SERIVCE_AUTHORIZATION_TYPE
	}
	return authorizationType
}

func appendPath(host string, path string) string {
	host = strings.TrimSuffix(host, "/")
	path = strings.TrimPrefix(path, "/")
	return host + "/" + path
}

/**
* Receive credentials and verify them in the context of an already present login-session. Will return either an error if failed, a sameDevice response to be used for
* redirection or notify the original initiator(in case of a cross-device flow)
**/
func (v *CredentialVerifier) AuthenticationResponse(state string, verifiablePresentation *verifiable.Presentation) (sameDevice Response, err error) {

	logging.Log().Debugf("Authenticate presentation %v for session %s", logging.PrettyPrintObject(verifiablePresentation), state)

	loginSessionInterface, hit := v.sessionCache.Get(state)
	if !hit {
		logging.Log().Infof("Session %s is either expired or did never exist.", state)
		return sameDevice, ErrorNoSuchSession
	}
	loginSession := loginSessionInterface.(loginSession)

	// TODO extract into separate policy
	trustedChain, _ := verifyChain(verifiablePresentation.Credentials())

	for _, credential := range verifiablePresentation.Credentials() {

		verificationContext, err := v.getTrustRegistriesValidationContext(loginSession.clientId, credential.Contents().Types, loginSession.scope)
		if err != nil {
			logging.Log().Warnf("Was not able to create a valid verification context. Credential will be rejected. Err: %v", err)
			return sameDevice, ErrorVerficationContextSetup
		}
		//FIXME make it an error if no policy was checked at all( possible misconfiguration)
		for _, verificationService := range v.validationServices {
			if trustedChain {
				logging.Log().Debug("Credentials chain is trusted.")
				_, isTrustedParticipantVerificationService := verificationService.(*TrustedParticipantValidationService)
				_, isTrustedIssuerVerificationService := verificationService.(*TrustedIssuerValidationService)
				if isTrustedIssuerVerificationService || isTrustedParticipantVerificationService {
					logging.Log().Debug("Skip the tir services.")
					continue
				}
			}

			logging.Log().Debugf("Validate with context %v", verificationContext)
			result, err := verificationService.ValidateVC(credential, verificationContext)
			if err != nil {
				logging.Log().Warnf("Failed to verify credential %s. Err: %v", logging.PrettyPrintObject(credential), err)
				return sameDevice, err
			}
			if !result {
				logging.Log().Infof("VC %s is not valid.", logging.PrettyPrintObject(credential))
				return sameDevice, ErrorInvalidVC
			}
		}
	}

	// we ignore the error here, since the only consequence is that sub will be empty.
	hostname, _ := getHostName(loginSession.callback)

	//TODO: properly handle inclusion config

	var toBeIncluded []map[string]interface{}
	for _, credential := range verifiablePresentation.Credentials() {
		toBeIncluded = append(toBeIncluded, credential.ToRawJSON())
	}

	flatClaims, _ := v.credentialsConfig.GetFlatClaims(loginSession.clientId, loginSession.scope)
	token, err := v.generateJWT(toBeIncluded, verifiablePresentation.Holder, hostname, flatClaims)
	if err != nil {
		logging.Log().Warnf("Was not able to create a jwt for %s. Err: %v", state, err)
		return sameDevice, err
	}

	tokenStore := tokenStore{token, loginSession.callback}
	authorizationCode := v.nonceGenerator.GenerateNonce()
	// store for retrieval by token endpoint
	err = v.tokenCache.Add(authorizationCode, tokenStore, cache.DefaultExpiration)
	logging.Log().Infof("Stored token for %s.", authorizationCode)
	if err != nil {
		logging.Log().Warnf("Was not able to store the token %s in cache.", logging.PrettyPrintObject(tokenStore))
		return sameDevice, err
	}
	switch loginSession.version {
	case SAME_DEVICE:
		return Response{SAME_DEVICE, loginSession.callback, authorizationCode, loginSession.sessionId, loginSession.nonce}, err
	case CROSS_DEVICE_V1:
		return sameDevice, callbackToRequester(loginSession, authorizationCode)
	default:
		return Response{CROSS_DEVICE_V2, loginSession.callback, authorizationCode, loginSession.sessionId, loginSession.nonce}, err
	}
}

// returns the subject for all gaia-x compliancy credentials
func (v *CredentialVerifier) getComplianceSubjects(presentation *verifiable.Presentation) (complianceSubjects []ComplianceSubject) {
	for _, credential := range presentation.Credentials() {
		subject := credential.ToRawJSON()["credentialSubject"]
		switch typedSubject := subject.(type) {
		case []interface{}:
			for _, sub := range typedSubject {
				asMap := sub.(map[string]interface{})
				if asMap["type"] == GAIA_X_COMPLIANCE_SUBJECT_TYPE {
					complianceSubjects = append(complianceSubjects, toComplianceSubject(asMap))
				}
			}
		case map[string]interface{}:
			if typedSubject["type"] == GAIA_X_COMPLIANCE_SUBJECT_TYPE {
				complianceSubjects = append(complianceSubjects, toComplianceSubject(typedSubject))
			}
		}
	}
	return complianceSubjects
}

func toComplianceSubject(theMap map[string]interface{}) ComplianceSubject {
	return ComplianceSubject{
		Type:                   theMap["type"].(string),
		Id:                     theMap["id"].(string),
		Integrity:              theMap["gx:integrity"].(string),
		IntegrityNormalization: theMap["gx:integrityNormalization"].(string),
		GxType:                 theMap["gx:type"].(string),
	}
}

func (v *CredentialVerifier) getComplianceValidationContext(clientId string, scope string, credential *verifiable.Credential, presentation *verifiable.Presentation) (complianceContext []ComplianceValidationContext, err error) {
	credentialTypes := []string{}
	credentialTypes = append(credentialTypes, credential.Contents().Types...)

	complianceContexts := []ComplianceValidationContext{}
	complianceSubjects := v.getComplianceSubjects(presentation)
	for _, credentialType := range credentialTypes {
		isRequired, err := v.credentialsConfig.GetComplianceRequired(clientId, scope, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get valid compliance config for client %s, scope %s and type %s. Err: %v", clientId, scope, credentialType, err)
			return complianceContexts, err
		}
		if !isRequired {
			continue
		}
		complianceContexts = append(complianceContexts, ComplianceValidationContext{complianceSubjects})
	}
	return complianceContexts, err
}

func (v *CredentialVerifier) GetRequestObject(state string) (jwt string, err error) {

	logging.Log().Infof("Get session with id %s", state)
	loginSessionInterface, hit := v.sessionCache.Get(state)
	if !hit {
		logging.Log().Debugf("No cache entry for session with id %s", state)
		return jwt, ErrorNoRequestObject
	}

	loginSession := loginSessionInterface.(loginSession)

	if loginSession.requestObject == "" {
		logging.Log().Debugf("No request object for session with id %s", state)
		return jwt, ErrorNoRequestObject
	}

	return loginSession.requestObject, err
}

func (v *CredentialVerifier) getHolderValidationContext(clientId string, scope string, credentialTypes []string, holder string) (validationContext []HolderValidationContext, err error) {
	validationContexts := []HolderValidationContext{}
	for _, credentialType := range credentialTypes {
		isEnabled, claim, err := v.credentialsConfig.GetHolderVerification(clientId, scope, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get valid holder verification config for client %s, scope %s and type %s. Err: %v", clientId, scope, credentialType, err)
			return validationContext, err
		}
		if !isEnabled {
			continue
		}
		validationContexts = append(validationContext, HolderValidationContext{claim: claim, holder: holder})
	}
	return validationContexts, err
}

func (v *CredentialVerifier) getTrustRegistriesValidationContext(clientId string, credentialTypes []string, scope string) (verificationContext TrustRegistriesValidationContext, err error) {
	logging.Log().Debugf("Create trust registry validation context for client '%s', scope '%s' and credential types %s", clientId, scope, credentialTypes)
	trustedIssuersLists := map[string][]string{}
	trustedParticipantsRegistries := map[string][]configModel.TrustedParticipantsList{}

	for _, credentialType := range credentialTypes {
		issuersLists, err := v.credentialsConfig.GetTrustedIssuersLists(clientId, scope, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get valid trusted-issuers-lists for client %s and type %s. Err: %v", clientId, credentialType, err)
			return verificationContext, err
		}
		participantsLists, err := v.credentialsConfig.GetTrustedParticipantLists(clientId, scope, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get valid trusted-pariticpants-registries for client %s and type %s. Err: %v", clientId, credentialType, err)
			return verificationContext, err
		}
		trustedIssuersLists[credentialType] = issuersLists
		trustedParticipantsRegistries[credentialType] = participantsLists
	}
	context := TrustRegistriesValidationContext{trustedIssuersLists: trustedIssuersLists, trustedParticipantsRegistries: trustedParticipantsRegistries}
	return context, err
}

func (v *CredentialVerifier) getTrustRegistriesValidationContextFromScope(clientId string, scope string, credentialTypes []string) (verificationContext TrustRegistriesValidationContext, err error) {
	trustedIssuersLists := map[string][]string{}
	trustedParticipantsRegistries := map[string][]configModel.TrustedParticipantsList{}

	requiredCredentialTypes, err := v.credentialsConfig.RequiredCredentialTypes(clientId, scope)
	if err != nil {
		logging.Log().Warnf("Was not able to get required credential types for client %s and scope %s. Err: %v", clientId, scope, err)
		return verificationContext, err
	}

	// Check if all required credentials were presented
	for _, credentialType := range requiredCredentialTypes {
		if !slices.Contains(credentialTypes, credentialType) {
			logging.Log().Warnf("Required Credential of Type %s was not provided. Type was: %s", credentialType, credentialTypes)
			return verificationContext, ErrorRequiredCredentialNotProvided
		}
	}

	for _, credentialType := range requiredCredentialTypes {
		issuersLists, err := v.credentialsConfig.GetTrustedIssuersLists(clientId, scope, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get valid trusted-issuers-lists for client %s and type %s. Err: %v", clientId, credentialType, err)
			return verificationContext, err
		}
		participantsLists, err := v.credentialsConfig.GetTrustedParticipantLists(clientId, scope, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get valid trusted-pariticpants-registries for client %s and type %s. Err: %v", clientId, credentialType, err)
			return verificationContext, err
		}
		trustedIssuersLists[credentialType] = issuersLists
		trustedParticipantsRegistries[credentialType] = participantsLists
	}
	context := TrustRegistriesValidationContext{trustedIssuersLists: trustedIssuersLists, trustedParticipantsRegistries: trustedParticipantsRegistries}
	return context, err
}

// TODO Use more generic approach to validate that every credential is issued by a party that we trust
func verifyChain(vcs []*verifiable.Credential) (bool, error) {
	if len(vcs) != 3 {
		// TODO Simplification to be removed/replaced
		return false, nil
	}

	var legalEntity *verifiable.Credential
	var naturalEntity *verifiable.Credential
	var compliance *verifiable.Credential
	for _, vc := range vcs {
		types := vc.Contents().Types
		if slices.Contains(types, "gx:LegalParticipant") {
			legalEntity = vc
		}
		if slices.Contains(types, "gx:compliance") {
			compliance = vc
		}
		if slices.Contains(types, "gx:NaturalParticipant") {
			naturalEntity = vc
		}
	}

	// the expected credentials only have a single subject
	legalEntitySubjectID := legalEntity.Contents().Subject[0].ID
	complianceSubjectID := compliance.Contents().Subject[0].ID
	// Make sure that the compliance credential is issued for the given credential
	if legalEntitySubjectID != complianceSubjectID {
		return false, fmt.Errorf("compliance credential was not issued for the presented legal entity. Compliance VC subject id %s, legal VC id %s", complianceSubjectID, legalEntitySubjectID)
	}
	// Natural participientVC must be issued by the legal participient VC
	if legalEntitySubjectID != naturalEntity.Contents().Issuer.ID {
		return false, fmt.Errorf("natural participent credential was not issued by the presented legal entity. Legal Participant VC id %s, natural VC issuer %s", legalEntitySubjectID, naturalEntity.Contents().Issuer.ID)
	}
	return true, nil
}

// intialize the OID4VP cross device flow
func (v *CredentialVerifier) initOid4VPCrossDevice(host string, protocol string, redirectUri string, state string, clientId string, scope string, nonce string, requestMode string) (authenticationRequest string, err error) {

	loginSession := loginSession{redirectUri, state, nonce, clientId, "", CROSS_DEVICE_V2, scope}
	err = v.sessionCache.Add(state, loginSession, cache.DefaultExpiration)

	if err != nil {
		logging.Log().Warnf("Was not able to store the login session %s in cache.", logging.PrettyPrintObject(loginSession))
		return authenticationRequest, err
	}
	authResponseUri := fmt.Sprintf("%s://%s/api/v1/authentication_response", protocol, host)

	return v.generateAuthenticationRequest("openid4vp://", clientId, scope, authResponseUri, state, nonce, loginSession, requestMode)
}

// initializes the cross-device siop flow
func (v *CredentialVerifier) initSiopFlow(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string) (authenticationRequest string, err error) {

	if nonce == "" {
		logging.Log().Debugf("No nonce provided, generate one.")
		nonce = v.nonceGenerator.GenerateNonce()
	}
	loginSession := loginSession{callback, state, nonce, clientId, "", CROSS_DEVICE_V1, ""}
	err = v.sessionCache.Add(state, loginSession, cache.DefaultExpiration)

	if err != nil {
		logging.Log().Warnf("Was not able to store the login session %s in cache.", logging.PrettyPrintObject(loginSession))
		return authenticationRequest, err
	}
	redirectUri := fmt.Sprintf("%s://%s/api/v1/authentication_response", protocol, host)

	return v.generateAuthenticationRequest("openid4vp://", clientId, "", redirectUri, state, nonce, loginSession, requestMode)
}

func (v *CredentialVerifier) generateAuthenticationRequest(base string, clientId string, scope string, redirectUri string, state string, nonce string, loginSession loginSession, requestMode string) (authenticationRequest string, err error) {
	switch requestMode {
	case REQUEST_MODE_BY_VALUE:
		authenticationRequest, err = v.createAuthenticationRequestByValue(base, redirectUri, state, clientId, scope, nonce)
		if err != nil {
			logging.Log().Warnf("Was not able to create the authentication request by value. Error: %v", err)
		} else {
			logging.Log().Debugf("Authentication request is %s.", authenticationRequest)
		}
		return authenticationRequest, err
	case REQUEST_MODE_BY_REFERENCE:
		requestObject, err := v.createAuthenticationRequestObject(redirectUri, state, clientId, scope, nonce)

		if err != nil {
			logging.Log().Warnf("Was not able to create the authentication request by reference. Error: %v", err)
		} else {
			logging.Log().Debugf("Authentication request is %s.", authenticationRequest)
		}

		loginSession.requestObject = string(requestObject[:])

		logging.Log().Debugf("Store session with id %s", state)
		v.sessionCache.Set(state, loginSession, cache.DefaultExpiration)

		authenticationRequest = v.createAuthenticationRequestByReference(base, state)

		return authenticationRequest, err
	default:
		return authenticationRequest, ErrorUnsupportedRequestMode
	}
}

// generate a jwt, containing the credential and mandatory information as defined by the dsba-convergence
func (v *CredentialVerifier) generateJWT(credentials []map[string]interface{}, holder string, audience string, flatValues bool) (generatedJwt jwt.Token, err error) {

	jwtBuilder := jwt.NewBuilder().Issuer(v.GetHost()).Audience([]string{audience}).Expiration(v.clock.Now().Add(v.jwtExpiration))

	if holder != "" {
		jwtBuilder.Subject(holder)
	}

	if flatValues {
		appendClaims(jwtBuilder, credentials)
	} else if len(credentials) > 1 {
		jwtBuilder.Claim("verifiablePresentation", credentials)
	} else {
		logging.Log().Debugf("Credentials %s", logging.PrettyPrintObject(credentials))
		jwtBuilder.Claim("verifiableCredential", credentials[0])
	}

	token, err := jwtBuilder.Build()
	if err != nil {
		logging.Log().Warnf("Was not able to build a token. Err: %v", err)
		return generatedJwt, err
	}

	return token, err
}

func appendClaims(builder *jwt.Builder, claims []map[string]interface{}) {
	for _, claim := range claims {
		for key, value := range claim {
			builder.Claim(key, value)
		}
	}
}

// creates an authenticationRequest string from the given parameters
func (v *CredentialVerifier) createAuthenticationRequestByReference(base string, state string) string {

	// We use a template to generate the final string
	template := "{{base}}?client_id={{client_id}}" +
		"&request_uri={{host}}/api/v1/request/{{state}}" +
		"&request_uri_method=get"

	t := fasttemplate.New(template, "{{", "}}")
	authRequest := t.ExecuteString(map[string]interface{}{
		"base":      base,
		"client_id": v.clientIdentification.Id,
		"host":      v.host,
		"state":     state,
	})

	return authRequest
}

func (v *CredentialVerifier) createAuthenticationRequestObject(response_uri string, state string, clientId string, scope string, nonce string) (requestObject []byte, err error) {
	jwtBuilder := jwt.NewBuilder().Issuer(v.clientIdentification.Id)
	jwtBuilder.Claim("response_type", "vp_token")
	jwtBuilder.Claim("response_mode", "direct_post")
	jwtBuilder.Claim("client_id", v.clientIdentification.Id)
	jwtBuilder.Claim("response_uri", response_uri)
	jwtBuilder.Claim("state", state)
	if nonce != "" {
		jwtBuilder.Claim("nonce", nonce)
	}
	jwtBuilder.Expiration(v.clock.Now().Add(time.Second * 30))

	presentationDefinition, err := v.credentialsConfig.GetPresentationDefinition(clientId, scope)
	if err != nil {
		return
	}
	if presentationDefinition != nil {
		logging.Log().Debugf("The definition %s", logging.PrettyPrintObject(presentationDefinition))
		jwtBuilder.Claim("presentation_definition", &presentationDefinition)
	}

	dcql, err := v.credentialsConfig.GetDcqlQuery(clientId, scope)
	if err != nil {
		return
	}
	if dcql != nil {
		logging.Log().Debugf("The dcql %s", logging.PrettyPrintObject(dcql))
		jwtBuilder.Claim("dcql_query", &dcql)
	} else {
		logging.Log().Debugf("No dcql configured for %s - %s.", clientId, scope)
	}

	requestToken, err := jwtBuilder.Build()
	if err != nil {
		logging.Log().Errorf("Was not able to build a token. Err: %v", err)
		return requestObject, err
	}

	signingKeyAlgorithm := v.clientIdentification.KeyAlgorithm
	keyAlgorithm, err := jwa.KeyAlgorithmFrom(signingKeyAlgorithm)
	if err != nil {
		logging.Log().Errorf("Request signing key does not have a valid algorithm. Error: %v", err)
		return requestObject, ErrorNoSigningKey
	}

	headers := jws.NewHeaders()
	headers.Set("typ", REQUEST_OBJECT_TYP)
	if v.clientIdentification.CertificatePath != "" {
		certs, err := loadCertChainFromPEM(v.clientIdentification.CertificatePath)
		if err != nil {
			logging.Log().Errorf("Was not able to read the client certificate chain. Error: %v", err)
			return requestObject, err
		}

		x5cChain := cert.Chain{}
		for _, cert := range certs {
			x5cChain.AddString(base64.StdEncoding.EncodeToString(cert.Raw))
		}

		err = headers.Set("x5c", &x5cChain)
		if err != nil {
			logging.Log().Errorf("Was not able to set x5c. Error: %v", err)
			return requestObject, err
		}
	} else {
		logging.Log().Debug("No certificate chain for client identity")
	}
	var opts jwt.SignEncryptParseOption

	logging.Log().Debugf("Signing key algo: %s - key: %v", signingKeyAlgorithm, *v.requestSigningKey)

	if signingKeyAlgorithm == "ES256" || signingKeyAlgorithm == "ES256K" || signingKeyAlgorithm == "ES384" || signingKeyAlgorithm == "ES512" {
		convertedKey, _ := (*v.requestSigningKey).(jwk.ECDSAPrivateKey)
		logging.Log().Debug("Init with ECDSA key")
		opts = jwt.WithKey(keyAlgorithm, convertedKey, jws.WithProtectedHeaders(headers))
	} else {
		convertedKey, _ := (*v.requestSigningKey).(jwk.RSAPrivateKey)
		logging.Log().Debug("Init with RSA key")
		opts = jwt.WithKey(keyAlgorithm, convertedKey, jws.WithProtectedHeaders(headers))
	}

	t, err := v.tokenSigner.Sign(requestToken, opts)
	logging.Log().Debugf("The token object: %s", t)
	return t, err

}

// creates an authenticationRequest string from the given parameters
func (v *CredentialVerifier) createAuthenticationRequestByValue(base string, response_uri string, state string, clientId string, scope string, nonce string) (request string, err error) {

	// We use a template to generate the final string
	template := "{{base}}?client_id={{client_id}}" +
		"&request={{request}}"

	signedRequest, err := v.createAuthenticationRequestObject(response_uri, state, clientId, scope, nonce)

	t := fasttemplate.New(template, "{{", "}}")
	authRequest := t.ExecuteString(map[string]interface{}{
		"base":      base,
		"client_id": v.clientIdentification.Id,
		"request":   signedRequest,
	})

	return authRequest, err
}

// call back to the original initiator of the login-session, providing an authorization_code for token retrieval
func callbackToRequester(loginSession loginSession, authorizationCode string) error {
	callbackRequest, err := http.NewRequest("GET", loginSession.callback, nil)
	logging.Log().Infof("Try to callback %s", loginSession.callback)
	if err != nil {
		logging.Log().Warnf("Was not able to create callback request to %s. Err: %v", loginSession.callback, err)
		return err
	}
	q := callbackRequest.URL.Query()
	q.Add("state", loginSession.sessionId)
	q.Add("code", authorizationCode)
	callbackRequest.URL.RawQuery = q.Encode()

	_, err = httpClient.Do(callbackRequest)
	if err != nil {
		logging.Log().Warnf("Was not able to notify requestor %s. Err: %v", loginSession.callback, err)
		return err
	}
	return nil
}

// helper method to extract the hostname from a url
func getHostName(urlString string) (host string, err error) {
	url, err := url.Parse(urlString)
	if err != nil {
		logging.Log().Warnf("Was not able to extract the host from the redirect_url %s. Err: %v", urlString, err)
		return host, err
	}
	return url.Host, err
}

func loadKey(keyPath string) (key jwk.Key, err error) {
	// read key file
	rawKey, err := localFileAccessor.ReadFile(keyPath)
	if err != nil {
		logging.Log().Warnf("Was not able to read the key file from %s. err: %v", keyPath, err)
		return key, err
	} // parse key file

	key, err = jwk.ParseKey(rawKey, jwk.WithPEM(true))
	if err != nil {
		logging.Log().Warnf("Was not able to parse the key %s. err: %v", rawKey, err)
		return key, err
	}
	return
}

func getRequestSigningKey(keyPath string, clientId string) (key jwk.Key, err error) {
	key, err = loadKey(keyPath)
	if key != nil {
		key.Set("kid", clientId)
	}
	return
}

// Initialize the private key of the verifier. Might need to be persisted in future iterations.
func initPrivateKey(keyType string, generateKey bool, keyPath string) (key jwk.Key, err error) {
	var newKey interface{}
	if generateKey {
		switch keyType {
		case "RS256":
			newKey, err = rsa.GenerateKey(rand.Reader, 2048)
		case "ES256":
			newKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		default:
			return key, ErrorUnsupportedKeyAlgorithm
		}
		if err != nil {
			return key, err
		}
		key, err = jwk.Import(newKey)
		if err != nil {
			return nil, err
		}
		if err != jwk.AssignKeyID(key) {
			return nil, err
		}
		return key, err
	} else if keyPath != "" {
		return loadKey(keyPath)
	} else {
		return key, ErrorInvalidKeyConfig
	}
}

// verify the configuration
func verifyConfig(verifierConfig *configModel.Verifier) error {
	if verifierConfig.Did == "" {
		return ErrorNoDID
	}
	if verifierConfig.TirAddress == "" {
		return ErrorNoTIR
	}
	if !slices.Contains(SupportedModes, verifierConfig.ValidationMode) {
		return ErrorUnsupportedValidationMode
	}
	if len(verifierConfig.SupportedModes) == 0 {
		return ErrorSupportedModesNotSet
	}

	return nil
}

func loadCertChainFromPEM(path string) ([]*x509.Certificate, error) {
	data, err := localFileAccessor.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM file")
	}

	return certs, nil
}

func (v *CredentialVerifier) GetHost() string {
	return v.host
}
