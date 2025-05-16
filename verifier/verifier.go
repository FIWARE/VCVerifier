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

const REQUEST_MODE_URL_ENCODE = "urlEncoded"
const REQUEST_MODE_BY_VALUE = "byValue"
const REQUEST_MODE_BY_REFERENCE = "byReference"
const REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"

var ErrorNoDID = errors.New("no_did_configured")
var ErrorNoTIR = errors.New("no_tir_configured")
var ErrorUnsupportedKeyAlgorithm = errors.New("unsupported_key_algorithm")
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

// Actual implementation of the verfifier functionality

// verifier interface
type Verifier interface {
	ReturnLoginQR(host string, protocol string, callback string, sessionId string, clientId string, requestMode string) (qr string, err error)
	StartSiopFlow(host string, protocol string, callback string, sessionId string, clientId string, requestMode string) (connectionString string, err error)
	StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string, clientId string, requestMode string) (authenticationRequest string, err error)
	GetToken(authorizationCode string, redirectUri string) (jwtString string, expiration int64, err error)
	GetJWKS() jwk.Set
	AuthenticationResponse(state string, verifiablePresentation *verifiable.Presentation) (sameDevice SameDeviceResponse, err error)
	GenerateToken(clientId, subject, audience string, scope []string, verifiablePresentation *verifiable.Presentation) (int64, string, error)
	GetOpenIDConfiguration(serviceIdentifier string) (metadata common.OpenIDProviderMetadata, err error)
	GetRequestObject(state string) (jwt string, err error)
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
	// is it using the same-device flow?
	sameDevice bool
	// callback to be notified after success
	callback string
	// sessionId to be included in the notification
	sessionId string
	// clientId provided for the session
	clientId string
	// requestObject created for the session
	requestObject string
}

// struct to represent a token, accessible through the token endpoint
type tokenStore struct {
	token        jwt.Token
	redirect_uri string
}

// Response structure for successful same-device authentications
type SameDeviceResponse struct {
	// the redirect target to be informed
	RedirectTarget string
	// code of the siop flow
	Code string
	// session id provided by the client
	SessionId string
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

	err = verifyConfig(&config.Verifier)
	if err != nil {
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

	key, err := initPrivateKey(verifierConfig.KeyAlgorithm)

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

	logging.Log().Warnf("Initiated key %s.", logging.PrettyPrintObject(key))
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
	}

	logging.Log().Debug("Successfully initalized the verifier")
	return
}

/**
*   Initializes the cross-device login flow and returns all neccessary information as a qr-code
**/
func (v *CredentialVerifier) ReturnLoginQR(host string, protocol string, callback string, sessionId string, clientId string, requestMode string) (qr string, err error) {

	for _, v := range v.supportedRequestModes {
		logging.Log().Warnf("Supported: %s", v)
	}

	if !slices.Contains(v.supportedRequestModes, requestMode) {
		logging.Log().Infof("QR with mode %s was requested, but only %v is supported.", requestMode, v.supportedRequestModes)
		return qr, ErrorUnsupportedRequestMode
	}

	logging.Log().Debugf("Generate a login qr for %s.", callback)
	authenticationRequest, err := v.initSiopFlow(host, protocol, callback, sessionId, clientId, requestMode)

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
func (v *CredentialVerifier) StartSiopFlow(host string, protocol string, callback string, sessionId string, clientId string, requestMode string) (connectionString string, err error) {
	logging.Log().Debugf("Start a plain siop-flow for %s.", callback)

	return v.initSiopFlow(host, protocol, callback, sessionId, clientId, requestMode)
}

/**
* Starts a same-device siop-flow and returns the required redirection information
**/
func (v *CredentialVerifier) StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string, clientId string, requestMode string) (authenticationRequest string, err error) {
	logging.Log().Debugf("Initiate samedevice flow for %s.", host)
	state := v.nonceGenerator.GenerateNonce()

	loginSession := loginSession{true, fmt.Sprintf("%s://%s%s", protocol, host, redirectPath), sessionId, clientId, ""}
	err = v.sessionCache.Add(state, loginSession, cache.DefaultExpiration)
	if err != nil {
		logging.Log().Warnf("Was not able to store the login session %s in cache. Err: %v", logging.PrettyPrintObject(loginSession), err)
		return authenticationRequest, err
	}

	redirectUri := fmt.Sprintf("%s://%s/api/v1/authentication_response", protocol, host)

	return v.generateAuthenticationRequest(protocol+"://"+host+redirectPath, clientId, redirectUri, state, loginSession, requestMode)
}

/**
*   Returns an already generated jwt from the cache to properly authorized requests. Every token will only be returend once.
**/
func (v *CredentialVerifier) GetToken(authorizationCode string, redirectUri string) (jwtString string, expiration int64, err error) {

	tokenSessionInterface, hit := v.tokenCache.Get(authorizationCode)
	if !hit {
		logging.Log().Infof("No such authorization code cached: %s.", authorizationCode)
		return jwtString, expiration, ErrorNoSuchCode
	}
	// we do only allow retrieval once.
	v.tokenCache.Delete(authorizationCode)

	tokenSession := tokenSessionInterface.(tokenStore)
	if tokenSession.redirect_uri != redirectUri {
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

func (v *CredentialVerifier) GenerateToken(clientId, subject, audience string, scopes []string, verifiablePresentation *verifiable.Presentation) (int64, string, error) {
	// collect all submitted credential types
	credentialsByType := map[string][]*verifiable.Credential{}
	credentialTypes := []string{}
	holder := verifiablePresentation.Holder
	for _, vc := range verifiablePresentation.Credentials() {
		for _, credentialType := range vc.Contents().Types {
			if _, ok := credentialsByType[credentialType]; !ok {
				credentialsByType[credentialType] = []*verifiable.Credential{}
			}
			credentialsByType[credentialType] = append(credentialsByType[credentialType], vc)
		}
		credentialTypes = append(credentialTypes, vc.Contents().Types...)
	}

	// Go through all requested scopes and create a verification context
	for _, scope := range scopes {
		verificationContext, err := v.getTrustRegistriesValidationContextFromScope(clientId, scope, credentialTypes)
		if err != nil {
			logging.Log().Warnf("Was not able to create a valid verification context. Credential will be rejected. Err: %v", err)
			return 0, "", ErrorVerficationContextSetup
		}
		credentialTypesNeededForScope := verificationContext.GetRequiredCredentialTypes()
		credentialsNeededForScope := []*verifiable.Credential{}
		for _, credentialType := range credentialTypesNeededForScope {
			if cred, ok := credentialsByType[credentialType]; ok {
				credentialsNeededForScope = append(credentialsNeededForScope, cred...)
			}
		}
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
		}
	}
	// FIXME How shall we handle VCs that are not needed for the give scope? Just ignore them and not include in the token?
	token, err := v.generateJWT(verifiablePresentation, subject, audience)
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

func (v *CredentialVerifier) GetOpenIDConfiguration(serviceIdentifier string) (metadata common.OpenIDProviderMetadata, err error) {

	scopes, err := v.credentialsConfig.GetScope(serviceIdentifier)
	if err != nil {
		return metadata, err
	}

	return common.OpenIDProviderMetadata{
		Issuer:                           v.host,
		AuthorizationEndpoint:            v.host,
		TokenEndpoint:                    v.host + "/services/" + serviceIdentifier + "/token",
		JwksUri:                          v.host + "/.well-known/jwks",
		GrantTypesSupported:              []string{"authorization_code", "vp_token"},
		ResponseTypesSupported:           []string{"token"},
		ResponseModeSupported:            []string{"direct_post"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"EdDSA", "ES256"},
		ScopesSupported:                  scopes}, err
}

/**
* Receive credentials and verify them in the context of an already present login-session. Will return either an error if failed, a sameDevice response to be used for
* redirection or notify the original initiator(in case of a cross-device flow)
**/
func (v *CredentialVerifier) AuthenticationResponse(state string, verifiablePresentation *verifiable.Presentation) (sameDevice SameDeviceResponse, err error) {

	logging.Log().Debugf("Authenticate credential for session %s", state)

	loginSessionInterface, hit := v.sessionCache.Get(state)
	if !hit {
		logging.Log().Infof("Session %s is either expired or did never exist.", state)
		return sameDevice, ErrorNoSuchSession
	}
	loginSession := loginSessionInterface.(loginSession)

	// TODO extract into separate policy
	trustedChain, _ := verifyChain(verifiablePresentation.Credentials())

	for _, credential := range verifiablePresentation.Credentials() {

		verificationContext, err := v.getTrustRegistriesValidationContext(loginSession.clientId, credential.Contents().Types)
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

	token, err := v.generateJWT(verifiablePresentation, verifiablePresentation.Holder, hostname)
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
	if loginSession.sameDevice {
		return SameDeviceResponse{loginSession.callback, authorizationCode, loginSession.sessionId}, err
	} else {
		return sameDevice, callbackToRequester(loginSession, authorizationCode)
	}
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

func (v *CredentialVerifier) getTrustRegistriesValidationContext(clientId string, credentialTypes []string) (verificationContext TrustRegistriesValidationContext, err error) {
	trustedIssuersLists := map[string][]string{}
	trustedParticipantsRegistries := map[string][]configModel.TrustedParticipantsList{}

	for _, credentialType := range credentialTypes {
		issuersLists, err := v.credentialsConfig.GetTrustedIssuersLists(clientId, configModel.SERVICE_DEFAULT_SCOPE, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get valid trusted-issuers-lists for client %s and type %s. Err: %v", clientId, credentialType, err)
			return verificationContext, err
		}
		participantsLists, err := v.credentialsConfig.GetTrustedParticipantLists(clientId, configModel.SERVICE_DEFAULT_SCOPE, credentialType)
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
			logging.Log().Warnf("Required Credential of Type %s was not provided", credentialType)
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

// initializes the cross-device siop flow
func (v *CredentialVerifier) initSiopFlow(host string, protocol string, callback string, sessionId string, clientId string, requestMode string) (authenticationRequest string, err error) {

	state := v.nonceGenerator.GenerateNonce()

	loginSession := loginSession{false, callback, sessionId, clientId, ""}
	err = v.sessionCache.Add(state, loginSession, cache.DefaultExpiration)

	if err != nil {
		logging.Log().Warnf("Was not able to store the login session %s in cache.", logging.PrettyPrintObject(loginSession))
		return authenticationRequest, err
	}
	redirectUri := fmt.Sprintf("%s://%s/api/v1/authentication_response", protocol, host)

	return v.generateAuthenticationRequest("openid4vp://", clientId, redirectUri, state, loginSession, requestMode)
}

func (v *CredentialVerifier) generateAuthenticationRequest(base string, clientId string, redirectUri string, state string, loginSession loginSession, requestMode string) (authenticationRequest string, err error) {
	if requestMode == REQUEST_MODE_URL_ENCODE {
		authenticationRequest = v.createAuthenticationRequestUrlEncoded(base, redirectUri, state, clientId)
		logging.Log().Debugf("Authentication request is %s.", authenticationRequest)
		return authenticationRequest, err
	} else if requestMode == REQUEST_MODE_BY_VALUE {
		authenticationRequest, err = v.createAuthenticationRequestByValue(base, redirectUri, state, clientId)
		if err != nil {
			logging.Log().Warnf("Was not able to create the authentication request by value. Error: %v", err)
		} else {
			logging.Log().Debugf("Authentication request is %s.", authenticationRequest)
		}
		return authenticationRequest, err
	} else if requestMode == REQUEST_MODE_BY_REFERENCE {
		requestObject, err := v.createAuthenticationRequestObject(redirectUri, state, clientId)
		loginSession.requestObject = string(requestObject[:])

		logging.Log().Debugf("Store session with id %s", state)
		v.sessionCache.Set(state, loginSession, cache.DefaultExpiration)

		authenticationRequest = v.createAuthenticationRequestByReference(base, state)
		if err != nil {
			logging.Log().Warnf("Was not able to create the authentication request by reference. Error: %v", err)
		} else {
			logging.Log().Debugf("Authentication request is %s.", authenticationRequest)
		}

		return authenticationRequest, err
	} else {
		return authenticationRequest, ErrorUnsupportedRequestMode
	}
}

// generate a jwt, containing the credential and mandatory information as defined by the dsba-convergence
func (v *CredentialVerifier) generateJWT(presentation *verifiable.Presentation, holder string, audience string) (generatedJwt jwt.Token, err error) {

	jwtBuilder := jwt.NewBuilder().Issuer(v.did).Claim("client_id", v.did).Subject(holder).Audience([]string{audience}).Expiration(v.clock.Now().Add(time.Minute * 30))

	if len(presentation.Credentials()) > 1 {
		jwtBuilder.Claim("verifiablePresentation", presentation)
	} else {
		jwtBuilder.Claim("verifiableCredential", presentation.Credentials()[0].ToRawJSON())
	}

	token, err := jwtBuilder.Build()
	if err != nil {
		logging.Log().Warnf("Was not able to build a token. Err: %v", err)
		return generatedJwt, err
	}

	return token, err
}

// creates an authenticationRequest string from the given parameters
func (v *CredentialVerifier) createAuthenticationRequestUrlEncoded(base string, redirect_uri string, state string, clientId string) string {

	// We use a template to generate the final string
	template := "{{base}}?response_type=vp_token" +
		"&response_mode=direct_post" +
		"&client_id={{client_id}}" +
		"&redirect_uri={{redirect_uri}}" +
		"&state={{state}}" +
		"&nonce={{nonce}}"

	var scope string
	if clientId != "" {
		typesToBeRequested, err := v.credentialsConfig.GetScope(clientId)
		if err != nil {
			logging.Log().Warnf("Was not able to get the scope to be requested for client %s. Err: %v", clientId, err)
		} else {
			template = template + "&scope={{scope}}"
			scope = strings.Join(typesToBeRequested, ",")
		}
	}

	t := fasttemplate.New(template, "{{", "}}")
	authRequest := t.ExecuteString(map[string]interface{}{
		"base":         base,
		"scope":        scope,
		"client_id":    v.clientIdentification.Id,
		"redirect_uri": redirect_uri,
		"state":        state,
		"nonce":        v.nonceGenerator.GenerateNonce(),
	})

	return authRequest
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

func (v *CredentialVerifier) createAuthenticationRequestObject(redirect_uri string, state string, clientId string) (requestObject []byte, err error) {
	jwtBuilder := jwt.NewBuilder().Issuer(v.did)
	jwtBuilder.Claim("response_type", "vp_token")
	jwtBuilder.Claim("client_id", v.clientIdentification.Id)
	jwtBuilder.Claim("redirect_uri", redirect_uri)
	jwtBuilder.Claim("state", state)
	jwtBuilder.Claim("scope", "openid")
	jwtBuilder.Claim("nonce", v.nonceGenerator.GenerateNonce())
	jwtBuilder.Expiration(v.clock.Now().Add(time.Second * 30))

	// TODO: decide if more than the default scope should be supported.
	presentationDefinition, err := v.credentialsConfig.GetPresentationDefinition(clientId, "")
	if err != nil {
		logging.Log().Errorf("Was not able to get the presentationDefintion for %s. Err: %v", clientId, err)
		return requestObject, err
	}
	logging.Log().Debugf("The definition %s", logging.PrettyPrintObject(presentationDefinition))
	jwtBuilder.Claim("presentation_definition", presentationDefinition)

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

	if signingKeyAlgorithm == "ES256" || signingKeyAlgorithm == "ES256K" || signingKeyAlgorithm == "ES384" || signingKeyAlgorithm == "ES512" {
		convertedKey, _ := (*v.requestSigningKey).(jwk.ECDSAPrivateKey)
		opts = jwt.WithKey(keyAlgorithm, convertedKey, jws.WithProtectedHeaders(headers))
	} else {
		convertedKey, _ := (*v.requestSigningKey).(jwk.RSAPrivateKey)
		opts = jwt.WithKey(keyAlgorithm, convertedKey, jws.WithProtectedHeaders(headers))
	}

	t, err := v.tokenSigner.Sign(requestToken, opts)
	logging.Log().Debugf("The token object: %s", t)
	return t, err

}

// creates an authenticationRequest string from the given parameters
func (v *CredentialVerifier) createAuthenticationRequestByValue(base string, redirect_uri string, state string, clientId string) (request string, err error) {

	// We use a template to generate the final string
	template := "{{base}}?client_id={{client_id}}" +
		"&request={{request}}"

	signedRequest, err := v.createAuthenticationRequestObject(redirect_uri, state, clientId)

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

func getRequestSigningKey(keyPath string, clientId string) (key jwk.Key, err error) {
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

	key.Set("kid", clientId)

	return
}

// Initialize the private key of the verifier. Might need to be persisted in future iterations.
func initPrivateKey(keyType string) (key jwk.Key, err error) {
	var newKey interface{}
	if keyType == "RS256" {
		newKey, err = rsa.GenerateKey(rand.Reader, 2048)
	} else if keyType == "ES256" {
		newKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		return key, ErrorUnsupportedKeyAlgorithm
	}

	if err != nil {
		return nil, err
	}

	key, err = jwk.Import(newKey)
	if err != nil {
		return nil, err
	}
	if err != jwk.AssignKeyID(key) {
		return nil, err
	}
	return key, err
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

type RequestObject struct {
	Issuer       string `json:"iss"`
	ResponseType string `json:"response_type"`
	ClientId     string `json:"client_id"`
	RedirectUri  string `json:"redirect_uri"`
	Scope        string `json:"scope"`
	Nonce        string `json:"nonce"`
	State        string `json:"state"`
	//dcql_query to be supported in the future
}
