package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	"github.com/PaesslerAG/jsonpath"
	common "github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/database"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/eidas"
	"github.com/fiware/VCVerifier/gaiax"
	"github.com/fiware/VCVerifier/tir"
	"github.com/google/uuid"

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

const REQUEST_MODE_URL_ENCODED = "urlEncoded"
const REQUEST_MODE_BY_VALUE = "byValue"
const REQUEST_MODE_BY_REFERENCE = "byReference"
const REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"

// qrCodePixelsPerModule is the fixed size (in pixels) of a single QR code "module".
// Passed as a negative size to qrcode.Encode, it makes the rendered image grow with
// the content instead of scaling a fixed canvas, keeping modules scannable regardless
// of how large the encoded authentication request is.
const qrCodePixelsPerModule = 6
const (
	CROSS_DEVICE_V1 = iota
	CROSS_DEVICE_V2
	SAME_DEVICE
)

const OPENID4VP_PROTOCOL = "openid4vp"
const REDIRECT_PROTOCOL = "redirect"

// CLIENT_ID_REDIRECT_URI_PREFIX is the OIDC4VP client_id prefix for the "redirect_uri"
// client identifier scheme (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
const CLIENT_ID_REDIRECT_URI_PREFIX = "redirect_uri:"

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
var ErrorInvalidVCHolder = errors.New("invalid_vc_holder")
var ErrorNoSuchSession = errors.New("no_such_session")
var ErrorLoginPageSecretMismatch = errors.New("login_page_secret_mismatch")
var ErrorRedirectUriNotAllowed = errors.New("redirect_uri_not_allowed")
var ErrorInvalidRedirectPath = errors.New("invalid_redirect_path")

// ErrorLoginCompletionFailed wraps a failure on the verifier's side after the presentation was
// verified, so it is not reported as a rejected credential.
var ErrorLoginCompletionFailed = errors.New("login_completion_failed")
var ErrorCallbackRejected = errors.New("callback_rejected_by_requestor")
var ErrorInvalidClientCallbackTimeout = errors.New("invalid_client_callback_timeout")
var ErrorClientCallbackTimeoutExceedsWriteTimeout = errors.New("client_callback_timeout_not_below_server_write_timeout")
var ErrorWrongGrantType = errors.New("wrong_grant_type")
var ErrorNoSuchCode = errors.New("no_such_code")
var ErrorRedirectUriMismatch = errors.New("redirect_uri_does_not_match")
var ErrorClientIdHostMismatch = errors.New("client_id_host_does_not_match_response_uri")
var ErrorVerficationContextSetup = errors.New("no_valid_verification_context")
var ErrorTokenUnparsable = errors.New("unable_to_parse_token")
var ErrorRequiredCredentialNotProvided = errors.New("required_credential_not_provided")
var ErrorNoValidCredentialTypeProvided = errors.New("no_valid_credential_type_provided")
var ErrorUnsupportedRequestMode = errors.New("unsupported_request_mode")
var ErrorRequestModeNotSupported = errors.New("request_mode_not_in_supported_modes")
var ErrorNoExpiration = errors.New("no_jwt_expiration_set")
var ErrorNoKeyId = errors.New("no_key_id_available")
var ErrorNoRequestObject = errors.New("no_request_object_available")
var ErrorInvalidNonce = errors.New("invalid_nonce")
var ErrorRefreshTokenDisabled = errors.New("refresh_token_not_enabled")
var ErrorRefreshTokenExpired = errors.New("refresh_token_expired")
var ErrorRefreshTokenNotFound = errors.New("refresh_token_not_found")
var ErrorRefreshTokenInvalidSignature = errors.New("refresh_token_invalid_signature")
var ErrorUnsupportedVCDataModelVersion = errors.New("unsupported_vc_data_model_version")

// refreshTokenByteLength is the number of random bytes used to generate
// an opaque refresh token. 32 bytes → 43-character base64url string.
const refreshTokenByteLength = 32

// Actual implementation of the verfifier functionality

// Verifier QR Information
type QRLoginInfo struct {
	// SessionId is the verifier's own id for the login session the QR belongs to - the key
	// the frontend's WebSocket has to register under. Never the external client's state.
	SessionId             string
	QR                    string
	ExpireAt              time.Time
	TotalDuration         int
	AuthenticationRequest string
	// PageSecret authenticates the login page's WebSocket for the session (see
	// CheckLoginPageSecret). It is handed to the page that shows the QR and nowhere else: never
	// put it in the QR, a URL or a log.
	PageSecret string
}

// verifier interface
type Verifier interface {
	ReturnLoginQR(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string) (qr string, err error)
	ReturnLoginQRWithPKCE(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string, pkce PKCEChallenge) (qr string, err error)
	ReturnLoginQRV2(host string, protocol string, callback string, state string, clientId string, scope string, nonce string, requestMode string) (qrLoginInfo QRLoginInfo, err error)
	StartSiopFlow(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string) (connectionString string, err error)
	StartSiopFlowWithPKCE(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string, pkce PKCEChallenge) (connectionString string, err error)
	StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string, clientId string, nonce string, requestMode string, scope string, requestProtocol string) (authenticationRequest string, err error)
	GetToken(authorizationCode string, redirectUri string, validated bool) (jwtString string, expiration int64, refreshToken string, err error)
	StartSameDeviceFlowWithPKCE(host string, protocol string, sessionId string, redirectPath string, clientId string, nonce string, requestMode string, scope string, requestProtocol string, pkce PKCEChallenge) (authenticationRequest string, err error)
	// StartSameDeviceFlowForRedirectUri starts a same-device flow that sends its code to the
	// client's redirect_uri instead of a path on the verifier's host
	StartSameDeviceFlowForRedirectUri(host string, protocol string, state string, redirectUri string, clientId string, nonce string, requestMode string, scope string, pkce PKCEChallenge) (authenticationRequest string, err error)
	ReturnLoginQRV2WithPKCE(host string, protocol string, callback string, state string, clientId string, scope string, nonce string, requestMode string, pkce PKCEChallenge) (qrLoginInfo QRLoginInfo, err error)
	GetTokenWithCodeVerifier(authorizationCode string, redirectUri string, validated bool, codeVerifier string) (jwtString string, expiration int64, refreshToken string, err error)
	GetJWKS() jwk.Set
	AuthenticationResponse(state string, verifiablePresentation *common.Presentation) (sameDevice Response, err error)
	// HasLoginSession reports whether a login session is still open - not expired, not completed
	HasLoginSession(sessionId string) bool
	// CheckLoginPageSecret checks the secret a login page presents for its cross-device v2
	// session: ErrorNoSuchSession if the page may no longer wait on it (see AwaitsLoginPage),
	// ErrorLoginPageSecretMismatch if the secret is not the one handed to the page that started it
	CheckLoginPageSecret(sessionId string, secret string) error
	// CheckRedirectUri checks where a login of the client may send its authorization code:
	// ErrorRedirectUriNotAllowed if the client has allowedRedirectUris and the URI matches none
	CheckRedirectUri(clientId string, redirectUri string) error
	// ReleaseUndeliveredCode restores the login session of a cross-device v2 login whose code
	// could not be handed to the browser, unless the code was already redeemed
	ReleaseUndeliveredCode(sessionId string, authorizationCode string) bool
	// AwaitsLoginPage reports whether a login page may still wait on the session: it is open, or it
	// completed and its code was neither exchanged nor released yet
	AwaitsLoginPage(sessionId string) bool
	// PendingLogin returns the result of a completed cross-device v2 login whose code was neither
	// exchanged nor released yet
	PendingLogin(sessionId string) (pending PendingLogin, found bool)
	GenerateToken(clientId, subject, audience string, scope []string, verifiablePresentation *common.Presentation) (int64, string, error)
	GetOpenIDConfiguration(serviceIdentifier string) (metadata common.OpenIDProviderMetadata, err error)
	GetRequestObject(state string) (jwt string, err error)
	GetHost() string
	GetPathPrefix() string
	// GetRequestMode returns the request mode to use for flows where the caller has
	// no way to request one explicitly (e.g. the OIDC-bridging authorization endpoint).
	GetRequestMode() string
	GetAuthorizationType(clientId string) string
	GetDefaultScope(serviceIdentifier string) (string, error)
	// ExchangeRefreshToken atomically consumes a refresh token and returns a
	// new signed access token JWT, its expiration (seconds), and a rotated
	// refresh token. Returns ErrorRefreshTokenDisabled when the feature is off.
	ExchangeRefreshToken(refreshToken string) (jwtString string, expiration int64, newRefreshToken string, err error)
	// IsRefreshTokenEnabled reports whether the refresh token feature is active.
	IsRefreshTokenEnabled() bool
	// RefreshTokenExpiresIn returns the configured refresh token lifetime in seconds.
	RefreshTokenExpiresIn() int64
	// CreateRefreshToken generates a new opaque refresh token, stores the
	// full signed JWT in the database, and returns the token string.
	CreateRefreshToken(clientId string, signedJWT string) (string, error)
}

type ValidationService interface {
	// Validates the given VC. FIXME Currently a positiv result is returned even when no policy was checked
	ValidateVC(verifiableCredential *common.Credential, verificationContext ValidationContext) (result bool, err error)
}

// CredentialVerifier implements the Verifier interface using gaia-x compliance issuers registry as a validation backend.
type CredentialVerifier struct {
	// host of the verifier
	host string
	// path prefix to be prepended to server-built URLs that are not derived from host
	pathPrefix string
	// did of the verifier
	did string
	// trusted-issuers-registry to be used for verification
	tirAddress string
	// key to sign the jwt's with
	signingKey jwk.Key
	// cache to be used for in-progress authentication sessions
	sessionCache common.Cache
	// makes redeeming a login session (check that it still exists, then remove it) atomic, and
	// guards a session together with its pending login, so one of them is always found until the
	// code is exchanged or released
	sessionRedeemMutex sync.Mutex
	// results of completed cross-device v2 logins whose code was neither exchanged nor released yet,
	// by session id (see PendingLogin)
	pendingLogins common.Cache
	// cache to be used for jwt retrieval
	tokenCache common.Cache
	// authorization codes claimed at the token endpoint (see GetToken), so an undelivered code can
	// tell a requestor that redeemed it from one whose exchange failed. Without it, nothing can be
	// told apart and a login session whose code was not delivered is never restored.
	redeemedCodes common.Cache
	// makes claiming a code at the token endpoint and releasing an undelivered one mutually
	// exclusive, so a session is never restored for a code that is being exchanged. Taken before
	// sessionRedeemMutex where both are needed.
	codeMutex sync.Mutex
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
	// request mode used for flows where the caller has no way to request one explicitly
	fallbackRequestMode string
	// Key for signing the request objects
	requestSigningKey *jwk.Key
	// Client identification for signing the request objects
	clientIdentification configModel.ClientIdentification
	// config of the verifier
	verifierConfig configModel.Verifier
	// JWT token expiration time in minutes
	jwtExpiration time.Duration
	// Session duration in seconds
	sessionDuration time.Duration
	// ldProofMaxAge bounds the age of a Linked Data Proof on a presentation.
	// Zero disables the check.
	ldProofMaxAge time.Duration
	// refreshTokenEnabled indicates whether the refresh token feature is active.
	refreshTokenEnabled bool
	// refreshTokenExpiration is the lifetime of issued refresh tokens.
	refreshTokenExpiration time.Duration
	// refreshTokenRepo is the database-backed store for refresh tokens.
	// nil when refresh tokens are disabled.
	refreshTokenRepo database.RefreshTokenRepository
	// eidasConfig holds the global eIDAS trust list configuration, used to
	// supply global country filters to the eIDAS validation context.
	eidasConfig configModel.Eidas
}

// allow singleton access to the verifier
var verifier Verifier

// http client used to call the requestor's client_callback; InitVerifier gives it the configured
// verifier.clientCallbackTimeout
var httpClient = client.HttpClient()

// defaultClientCallbackTimeout applies when verifier.clientCallbackTimeout is not set
const defaultClientCallbackTimeout = 20

// file accessor to be used
var localFileAccessor common.FileAccessor = common.DiskFileAccessor{}

// interfaces and default implementations

type ValidationContext interface{}

type TrustRegistriesValidationContext struct {
	trustedIssuersLists           map[string][]configModel.TrustedIssuersList
	trustedParticipantsRegistries map[string][]configModel.TrustedParticipantsList
}

// GetTrustedIssuersLists returns the per-credential-type trusted issuers list configuration.
func (trvc TrustRegistriesValidationContext) GetTrustedIssuersLists() map[string][]configModel.TrustedIssuersList {
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
	_, _ = io.ReadFull(rand.Reader, b)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	return nonce
}

// struct to represent a running login session
type loginSession struct {
	// callback to be notified after success
	callback string
	// sessionId is generated by the verifier itself and used as the sessionCache key, as
	// the state embedded in the request sent to the wallet, and as the request_uri lookup
	// key for byReference requests. Never derived from externalState - an external OIDC
	// client that reuses the same state value across retries must not collide with, or be
	// able to attach to, a session it didn't create.
	sessionId string
	// externalState is the (optional) state value supplied by the external OIDC client at
	// /api/v1/authorization. It is opaque data as far as the verifier is concerned - it is
	// only ever echoed back verbatim to that client at the end of the flow, never used to
	// look anything up.
	externalState string
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
	pkce  PKCEChallenge
	// SHA-256 of the secret handed to the login page of a cross-device v2 session, which its
	// WebSocket has to present. Only the hash is kept, so a dump of the session cannot leak it.
	pageSecretHash [sha256.Size]byte
}

// struct to represent a token, accessible through the token endpoint
type tokenStore struct {
	token        jwt.Token
	redirect_uri string
	pkce         PKCEChallenge
	// clientId identifies the relying party for refresh token generation.
	clientId string
	// the redeemed login session the code was issued for and when it would have expired, so it can
	// be restored if the code cannot be delivered (see ReleaseUndeliveredCode)
	sessionId        string
	session          loginSession
	sessionExpiresAt time.Time
}

// PendingLogin is the result of a completed cross-device v2 login, kept until its code is exchanged
// at the token endpoint or released. The page's WebSocket may be gone when the wallet's response
// completes the login - typically on a phone, where opening the wallet sends the browser to the
// background - and only the page that started the login can collect it later (see
// CheckLoginPageSecret). It is not dropped once written to the page: a successful write only means
// the kernel took the bytes, and a socket that died in the background still takes them.
type PendingLogin struct {
	RedirectTarget string
	ExternalState  string
	Code           string
	// the hash of the page secret of the redeemed session, which no longer exists
	pageSecretHash [sha256.Size]byte
}

// Response structure for successful same-device authentications
type Response struct {
	// version of the flow
	FlowVersion int
	// the redirect target to be informed
	RedirectTarget string
	// code of the siop flow
	Code string
	// ExternalState is the state value the external OIDC client originally sent, echoed
	// back verbatim - not the verifier's own internal session id.
	ExternalState string
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

// InitVerifier initializes the verifier and all its components from the configuration.
// When repo is non-nil, the verifier uses a database-backed credentials config;
// otherwise it falls back to the HTTP-based or static config mode.
func InitVerifier(config *configModel.Configuration, repo database.ServiceRepository) (err error) {

	logging.Log().Info("Init verifeir")

	err = verifyConfig(&config.Verifier)
	if err != nil {
		logging.Log().Warnf("Was not able to verify config. Err: %v", err)
		return
	}
	verifierConfig := &config.Verifier

	// The wallet's authentication response waits for the v1 callback before it is answered, so a
	// callback allowed to run as long as the response may be written would make the wallet see a
	// dropped connection even when the login completed. 0 means no write timeout.
	if writeTimeout := config.Server.WriteTimeout; writeTimeout > 0 && verifierConfig.ClientCallbackTimeout >= writeTimeout {
		logging.Log().Errorf("verifier.clientCallbackTimeout (%ds) must be lower than server.writeTimeout (%ds): the wallet's authentication response waits for the callback and must still be written afterwards.", verifierConfig.ClientCallbackTimeout, writeTimeout)
		return ErrorClientCallbackTimeoutExceedsWriteTimeout
	}

	callbackTimeout := time.Duration(verifierConfig.ClientCallbackTimeout) * time.Second
	httpClient = &http.Client{
		Timeout: callbackTimeout,
		// A redirect answer means the requestor accepted the callback; following it would judge
		// the delivery by whatever page it leads to, fetched without the user's browser session.
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	logging.Log().Infof("Requestor callbacks (cross-device v1 flow) time out after %v.", callbackTimeout)

	sessionCache := cache.New(time.Duration(verifierConfig.SessionExpiry)*time.Second, time.Duration(2*verifierConfig.SessionExpiry)*time.Second)
	tokenCache := cache.New(time.Duration(verifierConfig.SessionExpiry)*time.Second, time.Duration(2*verifierConfig.SessionExpiry)*time.Second)
	redeemedCodes := cache.New(time.Duration(verifierConfig.SessionExpiry)*time.Second, time.Duration(2*verifierConfig.SessionExpiry)*time.Second)
	// same lifetime as the code a pending login carries
	pendingLogins := cache.New(time.Duration(verifierConfig.SessionExpiry)*time.Second, time.Duration(2*verifierConfig.SessionExpiry)*time.Second)
	pendingLogins.OnEvicted(logUncollectedLogin)

	clock := common.RealClock{}

	credentialsVerifier := CredentialValidator{
		validationMode:      config.Verifier.ValidationMode,
		clock:               clock,
		vcDataModelVersions: config.Verifier.VCDataModelVersions,
	}
	WarnDeprecatedMode(config.Verifier.ValidationMode)

	externalGaiaXValidator := InitGaiaXRegistryValidationService(verifierConfig)

	credentialsConfig, err := InitCredentialsConfig(&config.ConfigRepo, repo)
	if err != nil {
		logging.Log().Errorf("Was not able to initiate the credentials config. Err: %v", err)
	}
	WarnLDPVCFormat(config.ConfigRepo.Services, verifierConfig.ClientIdentification.Id)
	// an invalid entry would match nothing and refuse every login of its service
	if err = configModel.ValidateServicesAllowedRedirectUris(config.ConfigRepo.Services); err != nil {
		logging.Log().Errorf("Invalid configRepo.services allowedRedirectUris. Err: %v", err)
		return
	}
	for _, service := range config.ConfigRepo.Services {
		if len(service.AllowedRedirectUris) > 0 {
			logging.Log().Infof("Service %q sends authorization codes only to its %d allowedRedirectUris.", service.Id, len(service.AllowedRedirectUris))
		}
	}

	var tokenProvider tir.TokenProvider
	if (&config.M2M).AuthEnabled {
		tokenProvider, err = tir.InitM2MTokenProvider(config, clock)
		if err != nil {
			logging.Log().Errorf("Was not able to instantiate the token provider. Err: %v", err)
			return
		}
		logging.Log().Info("Successfully created token provider")
	} else {
		logging.Log().Infof("Auth disabled.")
	}

	tirClient, err := tir.NewTirHttpClient(tokenProvider, config.M2M, config.Verifier)
	if err != nil {
		logging.Log().Errorf("Was not able to instantiate the trusted-issuers-registry client. Err: %v", err)
		return
	}
	gaiaXClient, _ := gaiax.NewGaiaXHttpClient()
	trustedParticipantVerificationService := TrustedParticipantValidationService{tirClient: tirClient, gaiaXClient: gaiaXClient}
	trustedIssuerVerificationService := TrustedIssuerValidationService{tirClient: tirClient}

	// Construct the shared status-list credential client and the
	// CredentialStatusValidationService. The service is always appended to
	// the validation chain. When a credential has
	// CredentialStatus.IsEnabled() == false, the service's ValidateVC is a
	// no-op for that type.
	statusListHttpTimeout := time.Duration(verifierConfig.StatusListHttpTimeout) * time.Second
	statusListCacheExpiry := time.Duration(verifierConfig.StatusListCacheExpiry) * time.Second
	statusListDIDRegistry := did.NewRegistry(did.WithVDR(did.NewWebVDR()), did.WithVDR(did.NewKeyVDR()), did.WithVDR(did.NewJWKVDR()))
	// GetHttpsIssuerResolver() is populated by InitPresentationParser, so the
	// status-list path shares the JWKS cache with credential verification.
	statusListJWTVerifier := NewStatusListJWTVerifier(statusListDIDRegistry).
		WithHttpsResolver(GetHttpsIssuerResolver())
	// GetLDProofChecker() is populated by InitPresentationParser, which
	// main.go runs before InitVerifier.
	statusListClient := NewCachingStatusListClient(statusListHttpTimeout, statusListCacheExpiry, statusListJWTVerifier, GetLDProofChecker())
	ietfStatusListClient := NewCachingIETFStatusListClient(statusListHttpTimeout, statusListCacheExpiry, statusListJWTVerifier, clock)
	credentialStatusVerificationService := NewCredentialStatusValidationService(statusListClient, ietfStatusListClient, clock)

	// Construct the eIDAS validation service. When eIDAS is globally enabled,
	// create a TrustListFetcher with background refresh; otherwise leave the
	// service with a nil trust store so it acts as a pass-through (no HTTP
	// requests, no goroutines, no memory).
	var eidasValidationService EidasValidationService
	if config.Eidas.Enabled {
		opts := []eidas.FetcherOption{}
		if config.Eidas.LotlURL != "" {
			opts = append(opts, eidas.WithLOTLURL(config.Eidas.LotlURL))
		}
		if config.Eidas.RefreshInterval > 0 {
			opts = append(opts, eidas.WithRefreshInterval(time.Duration(config.Eidas.RefreshInterval)*time.Second))
		}
		if len(config.Eidas.Countries) > 0 {
			opts = append(opts, eidas.WithAllowedCountries(config.Eidas.Countries))
		}
		if config.Eidas.MaxWorkers > 0 {
			opts = append(opts, eidas.WithMaxWorkers(config.Eidas.MaxWorkers))
		}
		if config.Eidas.FetchTimeout > 0 {
			opts = append(opts, eidas.WithHTTPClient(&http.Client{
				Timeout: time.Duration(config.Eidas.FetchTimeout) * time.Second,
			}))
		}
		opts = append(opts, eidas.WithAllowStaleTrustLists(config.Eidas.AllowStaleTrustLists))
		if config.Eidas.AllowStaleTrustLists {
			logging.Log().Warn("eIDAS trust lists that have passed their NextUpdate time will be accepted (allowStaleTrustLists is set)")
		}
		fetcher := eidas.NewTrustListFetcher(opts...)
		fetcher.Start(context.Background())

		// Revocation status is published by the issuing CA, not by the trust
		// list, so chain validation consults OCSP/CRL separately.
		revocationChecker := eidas.NewRevocationChecker(
			eidas.WithRevocationMode(config.Eidas.RevocationCheck),
			eidas.WithRevocationCacheExpiry(time.Duration(config.Eidas.RevocationCacheExpiry)*time.Second),
			eidas.WithRevocationHTTPClient(&http.Client{
				Timeout: time.Duration(config.Eidas.RevocationTimeout) * time.Second,
			}),
		)
		if revocationChecker.Enabled() {
			logging.Log().Infof("eIDAS certificate revocation checking enabled in %q mode", config.Eidas.RevocationCheck)
		} else {
			logging.Log().Warn("eIDAS certificate revocation checking is disabled; a revoked issuer certificate stays valid until the trust list is updated")
		}

		eidasValidationService = EidasValidationService{trustStore: fetcher.Store(), revocationChecker: revocationChecker}
		// Inject the trust store into the global JWT proof checker so did:elsi
		// JWTs can be verified against the EU Trusted Lists.  WithTrustStore
		// mutates the receiver in place (same pattern as WithHttpsResolver),
		// so we don't need to reassign the global.
		GetProofChecker().WithTrustStore(fetcher.Store()).WithRevocationChecker(revocationChecker)
		logging.Log().Info("eIDAS trust list fetcher started with background refresh")
		logging.Log().Info("did:elsi support enabled via eIDAS trust store")
	} else {
		logging.Log().Debug("eIDAS trust list feature is disabled")
	}

	key, err := initPrivateKey(verifierConfig.KeyAlgorithm, verifierConfig.GenerateKey, verifierConfig.KeyPath)

	kid := verifierConfig.ClientIdentification.Id
	if verifierConfig.ClientIdentification.Kid != "" {
		kid = verifierConfig.ClientIdentification.Kid
	}
	if key != nil && !key.Has(jwk.KeyIDKey) {
		logging.Log().Infof("Adding kid='%s' to keyset", kid)
		_ = key.Set(jwk.KeyIDKey, kid)
	}

	if err != nil {
		logging.Log().Errorf("Was not able to initiate a signing key. Err: %v", err)
		return
	}

	didSigningKey, err := getRequestSigningKey(verifierConfig.ClientIdentification.KeyPath, verifierConfig.ClientIdentification.Id)
	if (slices.Contains(verifierConfig.SupportedModes, REQUEST_MODE_BY_VALUE) || slices.Contains(verifierConfig.SupportedModes, REQUEST_MODE_BY_REFERENCE)) && err != nil { //nolint:govet
		logging.Log().Errorf("Was not able to get a signing key, despite mode %s supported. Err: %v", REQUEST_MODE_BY_VALUE, err)
		return
	} else {
		err = nil
	}

	pathPrefix := config.Server.NormalizedPathPrefix()

	verifier = &CredentialVerifier{
		host:              strings.TrimSuffix((&config.Server).Host, "/") + pathPrefix,
		pathPrefix:        pathPrefix,
		did:               verifierConfig.Did,
		tirAddress:        verifierConfig.TirAddress,
		signingKey:        key,
		sessionCache:      sessionCache,
		tokenCache:        tokenCache,
		redeemedCodes:     redeemedCodes,
		pendingLogins:     pendingLogins,
		nonceGenerator:    &randomGenerator{},
		clock:             clock,
		tokenSigner:       common.JwtTokenSigner{},
		credentialsConfig: credentialsConfig,
		validationServices: initValidationServices(
			&credentialsVerifier,
			&externalGaiaXValidator,
			&trustedParticipantVerificationService,
			&trustedIssuerVerificationService,
			&credentialStatusVerificationService,
			&eidasValidationService,
			config.Eidas.Enabled,
		),
		signingAlgorithm:       verifierConfig.KeyAlgorithm,
		supportedRequestModes:  verifierConfig.SupportedModes,
		fallbackRequestMode:    verifierConfig.RequestMode,
		requestSigningKey:      &didSigningKey,
		clientIdentification:   verifierConfig.ClientIdentification,
		verifierConfig:         *verifierConfig,
		jwtExpiration:          time.Duration(verifierConfig.JwtExpiration) * time.Minute,
		sessionDuration:        time.Duration(verifierConfig.SessionExpiry),
		ldProofMaxAge:          time.Duration(verifierConfig.LdProofMaxAge) * time.Second,
		refreshTokenEnabled:    verifierConfig.RefreshToken.Enabled,
		refreshTokenExpiration: time.Duration(verifierConfig.RefreshToken.Expiration) * time.Minute,
		refreshTokenRepo:       nil, // set below when enabled
		eidasConfig:            config.Eidas,
	}

	logging.Log().Debug("Successfully initalized the verifier")
	if verifierConfig.RefreshToken.Enabled {
		logging.Log().Infof("Refresh tokens enabled (expiration: %d minutes)", verifierConfig.RefreshToken.Expiration)
	}
	return
}

// SetRefreshTokenRepo configures the database-backed refresh token
// repository. It must be called after InitVerifier when RefreshTokenEnabled
// is true. The verifier is stored as a package-level singleton, so this
// method updates that instance via a type assertion on the concrete
// CredentialVerifier.
func SetRefreshTokenRepo(repo database.RefreshTokenRepository) {
	if cv, ok := verifier.(*CredentialVerifier); ok && cv != nil {
		cv.refreshTokenRepo = repo
	}
}

/**
*   Initializes the cross-device login flow and returns all neccessary information as a qr-code
**/
func (v *CredentialVerifier) ReturnLoginQR(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string) (qr string, err error) {
	return v.ReturnLoginQRWithPKCE(host, protocol, callback, state, clientId, nonce, requestMode, PKCEChallenge{})
}

func (v *CredentialVerifier) ReturnLoginQRWithPKCE(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string, pkce PKCEChallenge) (qr string, err error) {

	for _, v := range v.supportedRequestModes {
		logging.Log().Warnf("Supported: %s", v)
	}

	if !slices.Contains(v.supportedRequestModes, requestMode) { //nolint:govet
		logging.Log().Infof("QR with mode %s was requested, but only %v is supported.", requestMode, v.supportedRequestModes)
		return qr, ErrorUnsupportedRequestMode
	}

	logging.Log().Debugf("Generate a login qr for %s.", callback)
	authenticationRequest, err := v.initSiopFlowWithPKCE(host, protocol, callback, state, clientId, nonce, requestMode, pkce)

	if err != nil {
		return qr, err
	}

	// A negative size tells go-qrcode to render at a fixed number of pixels per module
	// instead of scaling a fixed canvas, so the image grows with the content instead of
	// the modules shrinking below what a phone camera can resolve (relevant for
	// REQUEST_MODE_URL_ENCODED, whose inlined presentation_definition/dcql_query can push
	// the QR to a much higher version than byValue/byReference ever need).
	png, err := qrcode.Encode(authenticationRequest, qrcode.Medium, -qrCodePixelsPerModule)
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	return base64Img, err
}

/**
*   Initializes the cross-device login flow and returns all neccessary information as a qr-code
**/
func (v *CredentialVerifier) ReturnLoginQRV2(host string, protocol string, redircetUri string, state string, clientId string, scope string, nonce string, requestMode string) (qrInfo QRLoginInfo, err error) {
	return v.ReturnLoginQRV2WithPKCE(host, protocol, redircetUri, state, clientId, scope, nonce, requestMode, PKCEChallenge{})
}

func (v *CredentialVerifier) ReturnLoginQRV2WithPKCE(host string, protocol string, redircetUri string, state string, clientId string, scope string, nonce string, requestMode string, pkce PKCEChallenge) (qrInfo QRLoginInfo, err error) {

	for _, v := range v.supportedRequestModes {
		logging.Log().Warnf("Supported: %s", v)
	}

	if !slices.Contains(v.supportedRequestModes, requestMode) { //nolint:govet
		logging.Log().Infof("QR with mode %s was requested, but only %v is supported.", requestMode, v.supportedRequestModes)
		return qrInfo, ErrorUnsupportedRequestMode
	}

	logging.Log().Debugf("Generate a login qr for %s.", redircetUri)
	sessionId, pageSecret, authenticationRequest, err := v.initOid4VPCrossDevice(host, protocol, redircetUri, state, clientId, scope, nonce, requestMode, pkce)

	if err != nil {
		return qrInfo, err
	}

	// A negative size tells go-qrcode to render at a fixed number of pixels per module
	// instead of scaling a fixed canvas, so the image grows with the content instead of
	// the modules shrinking below what a phone camera can resolve (relevant for
	// REQUEST_MODE_URL_ENCODED, whose inlined presentation_definition/dcql_query can push
	// the QR to a much higher version than byValue/byReference ever need).
	png, err := qrcode.Encode(authenticationRequest, qrcode.Medium, -qrCodePixelsPerModule)
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	_, expireAt, _ := v.sessionCache.GetWithExpiration(sessionId)
	qrInfo = QRLoginInfo{
		SessionId:             sessionId,
		QR:                    base64Img,
		ExpireAt:              expireAt,
		TotalDuration:         int(v.sessionDuration),
		AuthenticationRequest: authenticationRequest,
		PageSecret:            pageSecret,
	}
	return qrInfo, err
}

/**
* Starts a siop-flow and returns the required connection information
**/
func (v *CredentialVerifier) StartSiopFlow(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string) (connectionString string, err error) {
	return v.StartSiopFlowWithPKCE(host, protocol, callback, state, clientId, nonce, requestMode, PKCEChallenge{})
}

func (v *CredentialVerifier) StartSiopFlowWithPKCE(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string, pkce PKCEChallenge) (connectionString string, err error) {
	logging.Log().Debugf("Start a plain siop-flow for %s.", callback)

	return v.initSiopFlowWithPKCE(host, protocol, callback, state, clientId, nonce, requestMode, pkce)
}

/**
* Starts a same-device siop-flow and returns the required redirection information
**/
func (v *CredentialVerifier) StartSameDeviceFlow(host string, protocol string, state string, redirectPath string, clientId string, nonce string, requestMode string, scope string, requestProtocol string) (authenticationRequest string, err error) {
	return v.StartSameDeviceFlowWithPKCE(host, protocol, state, redirectPath, clientId, nonce, requestMode, scope, requestProtocol, PKCEChallenge{})
}

func (v *CredentialVerifier) StartSameDeviceFlowWithPKCE(host string, protocol string, state string, redirectPath string, clientId string, nonce string, requestMode string, scope string, requestProtocol string, pkce PKCEChallenge) (authenticationRequest string, err error) {
	callback, err := sameDeviceCallback(protocol, host, redirectPath)
	if err != nil {
		logging.Log().Infof("Rejecting same-device flow for client %s: redirect path %q does not stay on host %s.", clientId, redirectPath, host)
		return authenticationRequest, err
	}
	return v.startSameDeviceFlow(host, protocol, state, callback, clientId, nonce, requestMode, scope, requestProtocol, pkce)
}

// StartSameDeviceFlowForRedirectUri starts the same-device flow of the OIDC authorization endpoint:
// the wallet is opened through an openid4vp:// link, and the code goes to the client's redirect_uri.
// Without a redirect_uri the code goes to the verifier's own host, as before redirect_uri was used.
func (v *CredentialVerifier) StartSameDeviceFlowForRedirectUri(host string, protocol string, state string, redirectUri string, clientId string, nonce string, requestMode string, scope string, pkce PKCEChallenge) (authenticationRequest string, err error) {
	if redirectUri == "" {
		logging.Log().Infof("Same-device flow for client %s has no redirect_uri, the code is sent to the verifier's host.", clientId)
		return v.StartSameDeviceFlowWithPKCE(host, protocol, state, "", clientId, nonce, requestMode, scope, OPENID4VP_PROTOCOL, pkce)
	}
	return v.startSameDeviceFlow(host, protocol, state, redirectUri, clientId, nonce, requestMode, scope, OPENID4VP_PROTOCOL, pkce)
}

func (v *CredentialVerifier) startSameDeviceFlow(host string, protocol string, state string, callback string, clientId string, nonce string, requestMode string, scope string, requestProtocol string, pkce PKCEChallenge) (authenticationRequest string, err error) {
	logging.Log().Debugf("Initiate samedevice flow for %s - %s.", host, clientId)
	pkce, err = validatePKCEChallenge(pkce, v.verifierConfig.AllowedCodeChallengeMethods)
	if err != nil {
		return authenticationRequest, err
	}
	if _, err = v.credentialsConfig.RequiredCredentialTypes(clientId, scope); err != nil {
		logging.Log().Infof("Rejecting same-device flow for unconfigured client %s and scope %s: %v", clientId, scope, err)
		return authenticationRequest, err
	}
	// the code is sent to the callback once the login completed
	if err = v.CheckRedirectUri(clientId, callback); err != nil {
		return authenticationRequest, err
	}
	if nonce == "" {
		nonce = v.nonceGenerator.GenerateNonce()
	}
	sessionId := v.nonceGenerator.GenerateNonce()

	loginSession := loginSession{callback: callback, sessionId: sessionId, externalState: state, nonce: nonce, clientId: clientId, version: SAME_DEVICE, scope: scope, pkce: pkce}
	err = v.sessionCache.Add(sessionId, loginSession, cache.DefaultExpiration)
	if err != nil {
		logging.Log().Warnf("Was not able to store the login session %s in cache. Err: %v", logging.PrettyPrintObject(loginSession), err)
		return authenticationRequest, err
	}
	logging.Log().Infof("Started same-device login session %s for client %s.", sessionId, clientId)

	authResponseUri := fmt.Sprintf("%s://%s%s/api/v1/authentication_response", protocol, host, v.pathPrefix)
	if requestProtocol == OPENID4VP_PROTOCOL {
		return v.generateAuthenticationRequest(requestProtocol+"://", clientId, scope, authResponseUri, sessionId, nonce, loginSession, requestMode)
	} else {
		return v.generateAuthenticationRequest(callback, clientId, scope, authResponseUri, sessionId, nonce, loginSession, requestMode)
	}
}

// sameDeviceCallback builds where a same-device login sends its code: the redirect path on the
// verifier's own host. The path is appended to the host as a string, so it has to be a path -
// "@evil.example" would turn the host into user info and ".evil.example" into a subdomain of
// another host.
func sameDeviceCallback(protocol string, host string, redirectPath string) (string, error) {
	if redirectPath != "" && (!strings.HasPrefix(redirectPath, "/") || strings.HasPrefix(redirectPath, "//") || strings.Contains(redirectPath, "\\")) {
		return "", ErrorInvalidRedirectPath
	}
	callback := fmt.Sprintf("%s://%s%s", protocol, host, redirectPath)
	parsed, err := url.Parse(callback)
	if err != nil || parsed.User != nil || !strings.EqualFold(parsed.Host, host) {
		return "", ErrorInvalidRedirectPath
	}
	return callback, nil
}

// GetToken returns an already generated jwt from the cache to properly
// authorized requests. Every token will only be returned once. When the
// refresh token feature is enabled, a refresh token is generated and
// returned alongside the access token; otherwise refreshToken is empty.
func (v *CredentialVerifier) GetToken(authorizationCode string, redirectUri string, validated bool) (jwtString string, expiration int64, refreshToken string, err error) {
	return v.GetTokenWithCodeVerifier(authorizationCode, redirectUri, validated, "")
}

func (v *CredentialVerifier) GetTokenWithCodeVerifier(authorizationCode string, redirectUri string, validated bool, codeVerifier string) (jwtString string, expiration int64, refreshToken string, err error) {

	tokenSession, err := v.claimCode(authorizationCode, redirectUri, validated, codeVerifier)
	if err != nil {
		return jwtString, expiration, "", err
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
		return jwtString, expiration, "", err
	}

	tokenExpiry, exists := tokenSession.token.Expiration()
	if !exists {
		logging.Log().Warn("Token does not have an expiration.")
		return jwtString, expiration, "", ErrorNoExpiration
	}

	expiration = tokenExpiry.Unix() - v.clock.Now().Unix()
	jwtString = string(jwtBytes)

	// Generate a refresh token if the feature is enabled.
	if v.refreshTokenEnabled {
		refreshToken, err = v.CreateRefreshToken(tokenSession.clientId, jwtString)
		if err != nil {
			logging.Log().Warnf("Failed to create refresh token for authorization code %s: %v", authorizationCode, err)
			return jwtString, expiration, "", err
		}
	}

	return jwtString, expiration, refreshToken, nil
}

// claimCode takes the authorization code out of the cache, so it is retrieved only once, and
// records it as redeemed once its redirect_uri matched. Both happen under codeMutex: a code
// claimed here can no longer be released by ReleaseUndeliveredCode, and one released there is
// gone here. An invalid PKCE proof leaves the code available for the legitimate client. Signing
// happens after claiming, so a signing failure still counts as a redeemed code.
func (v *CredentialVerifier) claimCode(authorizationCode string, redirectUri string, validated bool, codeVerifier string) (tokenSession tokenStore, err error) {
	v.codeMutex.Lock()
	defer v.codeMutex.Unlock()

	tokenSessionInterface, hit := v.tokenCache.Get(authorizationCode)
	if !hit {
		logging.Log().Infof("No such authorization code cached: %s.", authorizationCode)
		return tokenSession, ErrorNoSuchCode
	}
	tokenSession = tokenSessionInterface.(tokenStore)
	// A failed proof of possession must not let someone who only intercepted the
	// code invalidate it before the legitimate client can complete the exchange.
	if err = verifyPKCE(tokenSession.pkce, codeVerifier); err != nil {
		return tokenSession, err
	}
	// We only allow retrieval once.
	v.tokenCache.Delete(authorizationCode)
	// a page reconnecting later would only get a code that no longer works
	v.dropPendingLogin(tokenSession.sessionId, authorizationCode)
	if !validated && tokenSession.redirect_uri != redirectUri {
		logging.Log().Infof("Redirect uri does not match for authorization %s. Was %s but is expected %s.", authorizationCode, redirectUri, tokenSession.redirect_uri)
		return tokenSession, ErrorRedirectUriMismatch
	}
	if v.redeemedCodes != nil {
		v.redeemedCodes.Set(authorizationCode, true, cache.DefaultExpiration)
	}
	return tokenSession, nil
}

// wasCodeRedeemed reports whether the authorization code was claimed at the token endpoint.
// Callers hold codeMutex.
func (v *CredentialVerifier) wasCodeRedeemed(authorizationCode string) bool {
	_, redeemed := v.redeemedCodes.Get(authorizationCode)
	return redeemed
}

/**
* Return the JWKS used by the verifier to allow jwt verification
**/
func (v *CredentialVerifier) GetJWKS() jwk.Set {
	jwks := jwk.NewSet()
	publicKey, _ := v.signingKey.PublicKey()
	_ = jwks.AddKey(publicKey)
	return jwks
}

func extractCredentialTypes(verifiablePresentation *common.Presentation) (credentialsByType map[string][]*common.Credential, credentialTypes []string) {

	js, _ := verifiablePresentation.MarshalJSON()
	logging.Log().Debugf("Presentation %s", js)
	credentialsByType = map[string][]*common.Credential{}
	credentialTypes = []string{}
	for _, vc := range verifiablePresentation.Credentials() {
		logging.Log().Debugf("Contained credential %s", logging.PrettyPrintObject(vc))
		logging.Log().Debugf("Contained credential contents %s", logging.PrettyPrintObject(vc.Contents()))
		for _, credentialType := range vc.Contents().Types {
			if _, ok := credentialsByType[credentialType]; !ok {
				credentialsByType[credentialType] = []*common.Credential{}
			}
			credentialsByType[credentialType] = append(credentialsByType[credentialType], vc)
		}
		credentialTypes = append(credentialTypes, vc.Contents().Types...)
	}
	return
}

func getCredentialsNeededForScope(verificationContext TrustRegistriesValidationContext, credentialsByType map[string][]*common.Credential) []*common.Credential {
	credentialTypesNeededForScope := verificationContext.GetRequiredCredentialTypes()
	credentialsNeededForScope := []*common.Credential{}
	seen := make(map[*common.Credential]bool)
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

func (v *CredentialVerifier) GenerateToken(clientId, subject, audience string, scopes []string, verifiablePresentation *common.Presentation) (int64, string, error) {
	// collect all submitted credential types
	credentialsByType, credentialTypes := extractCredentialTypes(verifiablePresentation)

	holder := verifiablePresentation.Holder
	var credentialsToBeIncluded []map[string]interface{}
	flatClaims := false

	if err := v.verifyVPSignatureIfRequired(clientId, scopes, credentialTypes, verifiablePresentation); err != nil {
		return 0, "", err
	}

	// Audience binding for JSON-LD VPs. Unlike the authorization-code flow
	// there is no server-issued nonce for the vp_token and token-exchange
	// grants, so no challenge can be required here — the domain still has to
	// name this verifier.
	if bindErr := VerifyLDVPProofBinding(verifiablePresentation, "", v.clientIdentification.Id); bindErr != nil {
		logging.Log().Warnf("JSON-LD VP proof binding verification failed for client %s: %v", clientId, bindErr)
		return 0, "", bindErr
	}

	// With no challenge to bind against, the proof's age is what keeps a
	// captured presentation from being replayed here until its credentials
	// expire.
	if freshErr := VerifyLDVPProofFreshness(verifiablePresentation, v.clock.Now(), v.ldProofMaxAge); freshErr != nil {
		logging.Log().Warnf("JSON-LD VP proof freshness verification failed for client %s: %v", clientId, freshErr)
		return 0, "", freshErr
	}

	// Go through all requested scopes and create a verification context
	for _, scope := range scopes {
		verificationContext, err := v.getTrustRegistriesValidationContextFromScope(clientId, scope, credentialTypes)
		if err != nil {
			logging.Log().Warnf("Was not able to create a valid verification context. Credential will be rejected. Err: %v", err)
			return 0, "", ErrorVerficationContextSetup
		}
		statusValidationContext, err := v.getCredentialStatusValidationContext(clientId, scope, credentialTypes)
		if err != nil {
			logging.Log().Warnf("Was not able to create the credential-status validation context. Credential will be rejected. Err: %v", err)
			return 0, "", ErrorVerficationContextSetup
		}
		eidasValidationContext, err := v.getEidasValidationContext(clientId, scope, credentialTypes, v.eidasConfig)
		if err != nil {
			logging.Log().Warnf("Was not able to create the eIDAS validation context. Credential will be rejected. Err: %v", err)
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
					logging.Log().Infof("VC %s is not valid. Invalid holder", logging.PrettyPrintObject(credential))
					return 0, "", ErrorInvalidVCHolder
				}
			}
			for _, verificationService := range v.validationServices {
				ctx := selectValidationContext(verificationService, verificationContext, statusValidationContext, eidasValidationContext)
				result, err := verificationService.ValidateVC(credential, ctx)
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
	if len(credentialsToBeIncluded) == 0 {
		vcTypes := []string{}
		for k := range credentialsByType {
			vcTypes = append(vcTypes, k)
		}
		logging.Log().Warnf("No valid credential type was provided. Provided credential type: %v", vcTypes)
		return 0, "", ErrorNoValidCredentialTypeProvided
	}
	token, err := v.generateJWT(credentialsToBeIncluded, holder, audience, flatClaims, uuid.NewString())
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

func buildInclusion(credential *common.Credential, inclusionConfig configModel.JwtInclusion) (inclusion map[string]interface{}) {
	if inclusionConfig.FullInclusion {
		logging.Log().Debugf("Include the full credential: %s", logging.PrettyPrintObject(credential))
		return credential.ToRawJSON()
	}
	logging.Log().Debug("Include only some claims")

	inclusion = make(map[string]interface{})
	for _, claim := range inclusionConfig.ClaimsToInclude {
		if strings.HasPrefix(claim.OriginalKey, "$") {
			logging.Log().Debugf("Claim uses json path: %s from %s", claim.OriginalKey, logging.PrettyPrintObject(credential.ToRawJSON()))
			claimValues, err := jsonpath.Get(claim.OriginalKey, credential.ToRawJSON())

			if err != nil {
				logging.Log().Warnf("Was not able to evaluate path %s", claim.OriginalKey)
				continue
			}

			if claim.NewKey != "" {
				setValueAtPath(inclusion, strings.Split(claim.NewKey, "."), claimValues)
			} else {
				setValueAtPath(inclusion, strings.Split(claim.OriginalKey, "."), claimValues)
			}
		} else {
			pathParts := strings.Split(claim.OriginalKey, ".")
			if val, ok := getValueFromPath(credential.ToRawJSON(), pathParts); ok {
				if claim.NewKey != "" {
					setValueAtPath(inclusion, strings.Split(claim.NewKey, "."), val)
				} else {
					setValueAtPath(inclusion, strings.Split(claim.OriginalKey, "."), val)
				}
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
		// Skip the generic W3C base types: they have no inclusion config of
		// their own, and GetJwtInclusion returns a zero-value config whose
		// IsEnabled() defaults to true. Matching the base type first would
		// short-circuit with an empty inclusion (FullInclusion=false, no
		// claims), dropping the actual credential claims from the token.
		if baseCredentialTypes[credentialType] {
			continue
		}
		inclusion, _ := v.credentialsConfig.GetJwtInclusion(clientId, scope, credentialType)
		if inclusion.IsEnabled() {
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

	supportedAlgorithms := []string{}
	if v.signingAlgorithm != "" {
		supportedAlgorithms = append(supportedAlgorithms, v.signingAlgorithm)
	}

	return common.OpenIDProviderMetadata{
		Issuer:                           v.host,
		AuthorizationEndpoint:            appendPath(v.host, authorizationPath),
		TokenEndpoint:                    v.host + "/services/" + serviceIdentifier + "/token",
		JwksUri:                          v.host + "/.well-known/jwks",
		GrantTypesSupported:              []string{"authorization_code", "vp_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		ResponseTypesSupported:           []string{"code"},
		ResponseModeSupported:            []string{"direct_post"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: supportedAlgorithms,
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
func (v *CredentialVerifier) AuthenticationResponse(state string, verifiablePresentation *common.Presentation) (sameDevice Response, err error) {

	logging.Log().Debugf("Authenticate presentation %v for session %s", logging.PrettyPrintObject(verifiablePresentation), state)

	loginSessionInterface, sessionExpiresAt, hit := v.sessionCache.GetWithExpiration(state)
	if !hit {
		logging.Log().Infof("Session %s is either expired or did never exist.", state)
		return sameDevice, ErrorNoSuchSession
	}
	loginSession := loginSessionInterface.(loginSession)

	// Verify challenge/domain binding for JSON-LD VPs. The session nonce
	// must appear as proof.challenge (replay prevention), and the verifier's
	// client ID is checked against proof.domain (audience binding).
	if len(verifiablePresentation.Proofs) > 0 {
		if bindErr := VerifyLDVPProofBinding(verifiablePresentation, loginSession.nonce, v.clientIdentification.Id); bindErr != nil {
			logging.Log().Warnf("JSON-LD VP proof binding verification failed for session %s: %v", state, bindErr)
			return sameDevice, bindErr
		}
	}

	credentialsByType, credentialTypes := extractCredentialTypes(verifiablePresentation)
	configuredCredentialTypes, err := v.credentialsConfig.RequiredCredentialTypes(loginSession.clientId, loginSession.scope)
	if err != nil {
		logging.Log().Warnf("Was not able to get configured credential types for client %s and scope %s. Err: %v", loginSession.clientId, loginSession.scope, err)
		return sameDevice, ErrorVerficationContextSetup
	}
	configuredTypes := make(map[string]struct{}, len(configuredCredentialTypes))
	for _, credentialType := range configuredCredentialTypes {
		configuredTypes[credentialType] = struct{}{}
	}
	dcqlRequestIDs, descriptorIDs, presentationDefinitionID, queryConfigured, dcqlQuery, presentationDefinition, err := v.getPresentationRequestIDs(loginSession.clientId, loginSession.scope)
	if err != nil {
		logging.Log().Warnf("Was not able to get presentation query identifiers for client %s and scope %s. Err: %v", loginSession.clientId, loginSession.scope, err)
		return sameDevice, ErrorVerficationContextSetup
	}
	if !queryConfigured {
		presentedTypes := make(map[string]struct{}, len(credentialTypes))
		for _, credentialType := range credentialTypes {
			presentedTypes[credentialType] = struct{}{}
		}
		for _, credentialType := range configuredCredentialTypes {
			if _, ok := presentedTypes[credentialType]; !ok {
				logging.Log().Infof("Required credential type %s was not provided for client %s and scope %s.", credentialType, loginSession.clientId, loginSession.scope)
				return sameDevice, ErrorRequiredCredentialNotProvided
			}
		}
	}
	presentedDCQLIDs := make(map[string]struct{})
	presentedDescriptorIDs := make(map[string]struct{})
	presentedDCQLCredentialCounts := make(map[string]int)
	presentedConfiguredCredential := false
	for _, credential := range verifiablePresentation.Credentials() {
		configured := false
		for _, credentialType := range credential.Contents().Types {
			if _, ok := configuredTypes[credentialType]; ok {
				configured = true
				break
			}
		}
		associations := credential.RequestAssociations()
		if !configured && (!queryConfigured || len(associations) == 0) {
			logging.Log().Debugf("Ignoring unconfigured credential types %v.", credential.Contents().Types)
			continue
		}
		if configured {
			presentedConfiguredCredential = true
		}
		if queryConfigured {
			if len(associations) == 0 {
				logging.Log().Infof("Credential types %v were not associated with a configured presentation query for client %s and scope %s.", credential.Contents().Types, loginSession.clientId, loginSession.scope)
				return sameDevice, ErrorNoValidCredentialTypeProvided
			}
			for _, association := range associations {
				var configuredID bool
				switch association.Kind {
				case common.PresentationRequestDCQL:
					_, configuredID = dcqlRequestIDs[association.ID]
					if configuredID {
						matchedQuery := false
						for _, query := range dcqlQuery.Credentials {
							if query.Id == association.ID {
								matchedQuery = true
								if !matchesDCQLQuery(query, credential) {
									logging.Log().Infof("Credential associated with DCQL query %s does not satisfy its constraints.", association.ID)
									return sameDevice, ErrorNoValidCredentialTypeProvided
								}
								presentedDCQLCredentialCounts[association.ID]++
								if !query.Multiple && presentedDCQLCredentialCounts[association.ID] > 1 {
									logging.Log().Infof("More than one credential was associated with DCQL query %s, which does not allow multiple credentials.", association.ID)
									return sameDevice, ErrorNoValidCredentialTypeProvided
								}
								break
							}
						}
						configuredID = matchedQuery
					}
				case common.PresentationRequestDescriptor:
					_, configuredID = descriptorIDs[association.ID]
					if configuredID && (presentationDefinitionID == "" || verifiablePresentation.PresentationSubmissionDefinitionID() != presentationDefinitionID) {
						logging.Log().Infof("Presentation submission definition %s does not match configured definition %s for client %s and scope %s.", verifiablePresentation.PresentationSubmissionDefinitionID(), presentationDefinitionID, loginSession.clientId, loginSession.scope)
						return sameDevice, ErrorNoValidCredentialTypeProvided
					}
					if configuredID {
						matchedDescriptor := false
						for _, descriptor := range presentationDefinition.InputDescriptors {
							if descriptor.Id == association.ID {
								matchedDescriptor = true
								if !matchesPresentationDescriptor(descriptor, presentationDefinition, credential) {
									logging.Log().Infof("Credential associated with Presentation Exchange descriptor %s does not satisfy its constraints.", association.ID)
									return sameDevice, ErrorNoValidCredentialTypeProvided
								}
								break
							}
						}
						configuredID = matchedDescriptor
					}
				default:
					configuredID = false
				}
				if !configuredID {
					logging.Log().Infof("Presentation request association %s (%s) is not configured for client %s and scope %s.", association.ID, association.Kind, loginSession.clientId, loginSession.scope)
					return sameDevice, ErrorNoValidCredentialTypeProvided
				}
				if configured {
					switch association.Kind {
					case common.PresentationRequestDCQL:
						presentedDCQLIDs[association.ID] = struct{}{}
					case common.PresentationRequestDescriptor:
						presentedDescriptorIDs[association.ID] = struct{}{}
					}
				}
			}
		} else if len(associations) > 0 {
			logging.Log().Infof("Credential types %v were associated with a presentation request but no query is configured for client %s and scope %s.", credential.Contents().Types, loginSession.clientId, loginSession.scope)
			return sameDevice, ErrorNoValidCredentialTypeProvided
		}
	}
	if dcqlQuery != nil && !satisfiesDCQLCredentialSets(dcqlQuery, presentedDCQLIDs) {
		logging.Log().Infof("Presented credentials do not satisfy the configured DCQL credential sets for client %s and scope %s.", loginSession.clientId, loginSession.scope)
		return sameDevice, ErrorRequiredCredentialNotProvided
	}
	if presentationDefinition != nil && !satisfiesPresentationSubmissionRequirements(presentationDefinition, presentedDescriptorIDs) {
		logging.Log().Infof("Presented credentials do not satisfy the configured Presentation Exchange submission requirements for client %s and scope %s.", loginSession.clientId, loginSession.scope)
		return sameDevice, ErrorRequiredCredentialNotProvided
	}
	if !presentedConfiguredCredential {
		logging.Log().Infof("No configured credential was provided for client %s and scope %s.", loginSession.clientId, loginSession.scope)
		return sameDevice, ErrorNoValidCredentialTypeProvided
	}
	var credentialsToBeIncluded []map[string]interface{}

	flatClaims := false
	for _, credential := range verifiablePresentation.Credentials() {
		configured := false
		for _, credentialType := range credential.Contents().Types {
			if _, ok := configuredTypes[credentialType]; ok {
				configured = true
				break
			}
		}
		if !configured {
			logging.Log().Debugf("Ignoring unconfigured credential types %v for token inclusion.", credential.Contents().Types)
			continue
		}

		verificationContext, err := v.getTrustRegistriesValidationContext(loginSession.clientId, credential.Contents().Types, loginSession.scope)
		if err != nil {
			logging.Log().Warnf("Was not able to create a valid verification context. Credential will be rejected. Err: %v", err)
			return sameDevice, ErrorVerficationContextSetup
		}
		statusValidationContext, err := v.getCredentialStatusValidationContext(loginSession.clientId, loginSession.scope, credential.Contents().Types)
		if err != nil {
			logging.Log().Warnf("Was not able to create the credential-status validation context. Credential will be rejected. Err: %v", err)
			return sameDevice, ErrorVerficationContextSetup
		}
		eidasValidationContext, err := v.getEidasValidationContext(loginSession.clientId, loginSession.scope, credential.Contents().Types, v.eidasConfig)
		if err != nil {
			logging.Log().Warnf("Was not able to create the eIDAS validation context. Credential will be rejected. Err: %v", err)
			return sameDevice, ErrorVerficationContextSetup
		}
		//FIXME make it an error if no policy was checked at all( possible misconfiguration)
		for _, verificationService := range v.validationServices {
			logging.Log().Debugf("Validate with context %v", verificationContext)
			ctx := selectValidationContext(verificationService, verificationContext, statusValidationContext, eidasValidationContext)
			result, err := verificationService.ValidateVC(credential, ctx)
			if err != nil {
				logging.Log().Warnf("Failed to verify credential %s. Err: %v", logging.PrettyPrintObject(credential), err)
				return sameDevice, err
			}
			if !result {
				logging.Log().Infof("VC %s is not valid.", logging.PrettyPrintObject(credential))
				return sameDevice, ErrorInvalidVC
			}
		}
		shouldBeIncluded, inclusionConfig := v.shouldBeIncluded(loginSession.clientId, loginSession.scope, credential.Contents().Types)
		if shouldBeIncluded {
			credentialsToBeIncluded = append(credentialsToBeIncluded, buildInclusion(credential, inclusionConfig))
		}
		flatClaims, _ = v.credentialsConfig.GetFlatClaims(loginSession.clientId, loginSession.scope)
	}

	if len(credentialsToBeIncluded) == 0 {
		vcTypes := []string{}
		for k := range credentialsByType {
			vcTypes = append(vcTypes, k)
		}
		logging.Log().Warnf("No valid credential type was provided. Provided credential type: %v", vcTypes)
		return sameDevice, ErrorNoValidCredentialTypeProvided
	}

	token, err := v.generateJWT(credentialsToBeIncluded, verifiablePresentation.Holder, loginSession.clientId, flatClaims, loginSession.nonce)
	if err != nil {
		logging.Log().Warnf("Was not able to create a jwt for %s. Err: %v", state, err)
		return sameDevice, fmt.Errorf("%w: %w", ErrorLoginCompletionFailed, err)
	}

	tokenStore := tokenStore{token: token, redirect_uri: loginSession.callback, pkce: loginSession.pkce, clientId: loginSession.clientId,
		sessionId: state, session: loginSession, sessionExpiresAt: sessionExpiresAt}
	authorizationCode := v.nonceGenerator.GenerateNonce()
	// store for retrieval by token endpoint
	err = v.tokenCache.Add(authorizationCode, tokenStore, cache.DefaultExpiration)
	if err != nil {
		logging.Log().Warnf("Was not able to store the token %s in cache.", logging.PrettyPrintObject(tokenStore))
		return sameDevice, fmt.Errorf("%w: %w", ErrorLoginCompletionFailed, err)
	}
	logging.Log().Infof("Stored token for %s.", authorizationCode)
	// A session is single-use. Responses are verified concurrently and the first one to get here
	// redeems the session; any other that passed verification in the meantime finds it gone and
	// discards its code. Nothing is locked during verification, so a slow or malicious response
	// cannot hold up the legitimate one, and a rejected presentation never consumes the session.
	// A cross-device v2 login page collects its result over a WebSocket that may be gone right now,
	// so the result stays until its code is exchanged or released.
	var pending *PendingLogin
	if loginSession.version == CROSS_DEVICE_V2 {
		pending = &PendingLogin{RedirectTarget: loginSession.callback, ExternalState: loginSession.externalState, Code: authorizationCode, pageSecretHash: loginSession.pageSecretHash}
	}
	if !v.redeemSession(state, pending) {
		v.tokenCache.Delete(authorizationCode)
		logging.Log().Warnf("Discarded the code issued for session %s: the session was already redeemed by a concurrent response.", state)
		return sameDevice, ErrorNoSuchSession
	}
	logging.Log().Infof("Completed login session %s for client %s, scope %s, credential types %v.", state, loginSession.clientId, loginSession.scope, credentialTypes)

	switch loginSession.version {
	case SAME_DEVICE:
		return Response{FlowVersion: SAME_DEVICE, RedirectTarget: loginSession.callback, Code: authorizationCode, ExternalState: loginSession.externalState, Nonce: loginSession.nonce}, err
	case CROSS_DEVICE_V1:
		if err := callbackToRequester(loginSession, authorizationCode); err != nil {
			// A requestor commonly exchanges the code while handling the callback and may still
			// answer with an error status (e.g. no browser session on a server-to-server call). A
			// code that was exchanged for a token means the login did complete. A failed exchange
			// (e.g. a mismatching redirect_uri) also removes the code, but does not count.
			if v.releaseCode(state, loginSession, sessionExpiresAt, authorizationCode) == codeRedeemed {
				logging.Log().Infof("Requestor %s reported a failed callback for session %s but redeemed the code, the login is complete.", loginSession.callback, state)
				return sameDevice, nil
			}
			return sameDevice, err
		}
		return sameDevice, nil
	default:
		return Response{FlowVersion: CROSS_DEVICE_V2, RedirectTarget: loginSession.callback, Code: authorizationCode, ExternalState: loginSession.externalState, Nonce: loginSession.nonce}, err
	}
}

// returns the subject for all gaia-x compliancy credentials
func (v *CredentialVerifier) getComplianceSubjects(presentation *common.Presentation) (complianceSubjects []ComplianceSubject) {
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

func (v *CredentialVerifier) getComplianceValidationContext(clientId string, scope string, credential *common.Credential, presentation *common.Presentation) (complianceContext []ComplianceValidationContext, err error) {
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

// verifyVPSignatureIfRequired verifies the VP signature when the service config
// requires holder binding for at least one credential type in the presentation.
//
// For SD-JWT VPs (rawToken != nil), the JWT signature is verified via the global
// JWTProofChecker. For JSON-LD VPs (LD proofs present), the proof was already
// verified during parsing — this method checks that a holder key is available.
// For JWT VPs (neither rawToken nor LD proofs), the proof was already verified
// during parsing, so this is a no-op.
func (v *CredentialVerifier) verifyVPSignatureIfRequired(clientId string, scopes []string, credentialTypes []string, presentation *common.Presentation) error {
	rawToken := presentation.RawToken()
	hasLDProofs := len(presentation.Proofs) > 0

	// If there's no raw token and no LD proofs, the VP signature was already
	// verified during parsing (JWT VP path). Nothing more to do.
	if rawToken == nil && !hasLDProofs {
		return nil
	}

	holderRequired := false
outer:
	for _, scope := range scopes {
		for _, credentialType := range credentialTypes {
			isEnabled, _, err := v.credentialsConfig.GetHolderVerification(clientId, scope, credentialType)
			if err != nil {
				logging.Log().Warnf("Could not read holder verification config for client %s, scope %s, type %s: %v", clientId, scope, credentialType, err)
				return ErrorVerficationContextSetup
			}
			if isEnabled {
				holderRequired = true
				break outer
			}
		}
	}

	if !holderRequired {
		return nil
	}

	// JSON-LD VP path: parsing already required the VP proof to be created by
	// the DID named in `holder` (see LDProofChecker.VerifyPresentation), so a
	// holder key here means the presenter proved control of the holder DID.
	// Both the key and the holder itself must be present.
	if hasLDProofs {
		if presentation.HolderKey() == nil {
			logging.Log().Warn("Holder binding required but JSON-LD VP has no holder key from LD-proof verification")
			return ErrorHolderBindingMissingKey
		}
		if presentation.Holder == "" {
			logging.Log().Warn("Holder binding required but JSON-LD VP declares no holder")
			return ErrorHolderBindingMissingKey
		}
		return nil
	}

	// SD-JWT VP path: verify the VP JWT signature.
	_, _, err := GetProofChecker().VerifyJWTAndReturnKey(rawToken)
	if err != nil {
		logging.Log().Warnf("VP JWT holder binding verification failed: %v", err)
		return ErrorInvalidVCHolder
	}
	return nil
}

func (v *CredentialVerifier) getHolderValidationContext(clientId string, scope string, credentialTypes []string, holder string) (validationContexts []HolderValidationContext, err error) {
	validationContexts = []HolderValidationContext{}
	for _, credentialType := range credentialTypes {
		isEnabled, claim, err := v.credentialsConfig.GetHolderVerification(clientId, scope, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get valid holder verification config for client %s, scope %s and type %s. Err: %v", clientId, scope, credentialType, err)
			return nil, err
		}
		if !isEnabled {
			continue
		}
		validationContexts = append(validationContexts, HolderValidationContext{claim: claim, holder: holder})
	}
	return validationContexts, nil
}

func (v *CredentialVerifier) getTrustRegistriesValidationContext(clientId string, credentialTypes []string, scope string) (verificationContext TrustRegistriesValidationContext, err error) {
	logging.Log().Debugf("Create trust registry validation context for client '%s', scope '%s' and credential types %s", clientId, scope, credentialTypes)
	trustedIssuersLists := map[string][]configModel.TrustedIssuersList{}
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

// getCredentialStatusValidationContext assembles a
// CredentialStatusValidationContext for the given service / scope and the
// set of credential types observed in the incoming presentation.
//
// For each type, the per-credential CredentialStatus config (from Step 2's
// GetCredentialStatusConfig) is looked up and placed in the returned
// context's PerType map. Unknown types yield a zero-value entry, which
// the validation service treats as "feature off" — no network call is
// issued for credentials whose types are not opted in.
func (v *CredentialVerifier) getCredentialStatusValidationContext(clientId string, scope string, credentialTypes []string) (CredentialStatusValidationContext, error) {
	logging.Log().Debugf("Create credential-status validation context for client '%s', scope '%s' and credential types %s", clientId, scope, credentialTypes)
	perType := map[string]configModel.CredentialStatus{}
	for _, credentialType := range credentialTypes {
		statusConfig, err := v.credentialsConfig.GetCredentialStatusConfig(clientId, scope, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get credential-status config for client %s, scope %s and type %s. Err: %v", clientId, scope, credentialType, err)
			return CredentialStatusValidationContext{}, err
		}
		perType[credentialType] = statusConfig
	}
	return CredentialStatusValidationContext{PerType: perType}, nil
}

func (v *CredentialVerifier) getPresentationRequestIDs(clientId string, scope string) (map[string]struct{}, map[string]struct{}, string, bool, *configModel.DCQL, *configModel.PresentationDefinition, error) {
	dcqlRequestIDs := make(map[string]struct{})
	descriptorIDs := make(map[string]struct{})
	presentationDefinition, err := v.credentialsConfig.GetPresentationDefinition(clientId, scope)
	if err != nil {
		return nil, nil, "", false, nil, nil, err
	}
	dcql, err := v.credentialsConfig.GetDcqlQuery(clientId, scope)
	if err != nil {
		return nil, nil, "", false, nil, nil, err
	}
	if presentationDefinition != nil {
		for _, descriptor := range presentationDefinition.InputDescriptors {
			if descriptor.Id != "" {
				descriptorIDs[descriptor.Id] = struct{}{}
			}
		}
	}
	if dcql != nil {
		for _, query := range dcql.Credentials {
			if query.Id != "" {
				dcqlRequestIDs[query.Id] = struct{}{}
			}
		}
	}
	definitionID := ""
	if presentationDefinition != nil {
		definitionID = presentationDefinition.Id
	}
	return dcqlRequestIDs, descriptorIDs, definitionID, presentationDefinition != nil || dcql != nil, dcql, presentationDefinition, nil
}

func satisfiesDCQLCredentialSets(dcql *configModel.DCQL, presentedIDs map[string]struct{}) bool {
	if len(dcql.CredentialSets) == 0 {
		for _, credential := range dcql.Credentials {
			if credential.Id == "" {
				return false
			}
			if _, presented := presentedIDs[credential.Id]; !presented {
				return false
			}
		}
		return len(dcql.Credentials) > 0
	}

	for _, credentialSet := range dcql.CredentialSets {
		if !credentialSet.IsRequired() {
			continue
		}
		optionSatisfied := false
		for _, option := range credentialSet.Options {
			if len(option) == 0 {
				continue
			}
			allPresented := true
			for _, credentialID := range option {
				if _, presented := presentedIDs[credentialID]; !presented {
					allPresented = false
					break
				}
			}
			if allPresented {
				optionSatisfied = true
				break
			}
		}
		if !optionSatisfied {
			return false
		}
	}
	return true
}

func satisfiesPresentationSubmissionRequirements(definition *configModel.PresentationDefinition, presentedIDs map[string]struct{}) bool {
	descriptorGroups := make(map[string][]string)
	for _, descriptor := range definition.InputDescriptors {
		for _, group := range descriptor.Group {
			descriptorGroups[group] = append(descriptorGroups[group], descriptor.Id)
		}
	}
	if len(definition.SubmissionRequirements) == 0 {
		for _, descriptor := range definition.InputDescriptors {
			if descriptor.Id == "" {
				return false
			}
			if _, presented := presentedIDs[descriptor.Id]; !presented {
				return false
			}
		}
		return len(definition.InputDescriptors) > 0
	}
	for _, requirement := range definition.SubmissionRequirements {
		if !satisfiesSubmissionRequirement(requirement, descriptorGroups, presentedIDs) {
			return false
		}
	}
	return true
}

func satisfiesSubmissionRequirement(requirement configModel.SubmissionRequirement, descriptorGroups map[string][]string, presentedIDs map[string]struct{}) bool {
	total := 0
	selected := 0
	if requirement.From != "" {
		descriptors := descriptorGroups[requirement.From]
		if len(descriptors) == 0 {
			return false
		}
		total = len(descriptors)
		for _, descriptorID := range descriptors {
			if _, presented := presentedIDs[descriptorID]; presented {
				selected++
			}
		}
	} else if len(requirement.FromNested) > 0 {
		total = len(requirement.FromNested)
		for _, nested := range requirement.FromNested {
			if satisfiesSubmissionRequirement(nested, descriptorGroups, presentedIDs) {
				selected++
			}
		}
	} else {
		return false
	}

	minimum, maximum := 1, total
	if requirement.Count != nil {
		minimum, maximum = *requirement.Count, *requirement.Count
	}
	if requirement.Min != nil {
		minimum = *requirement.Min
	}
	if requirement.Max != nil {
		maximum = *requirement.Max
	}
	switch requirement.Rule {
	case "all":
		return selected == total
	case "pick":
		return selected >= minimum && selected <= maximum
	default:
		return false
	}
}

// initValidationServices builds the ordered slice of ValidationService
// instances used by the verifier. When eIDAS is globally disabled the
// EidasValidationService is omitted so that a nil trustStore can never be
// reached at runtime (defensive against per-credential eIDAS config being
// set while the global flag is off).
func initValidationServices(
	credentialsVerifier *CredentialValidator,
	gaiaXValidator *GaiaXRegistryValidationService,
	trustedParticipant *TrustedParticipantValidationService,
	trustedIssuer *TrustedIssuerValidationService,
	statusVerification *CredentialStatusValidationService,
	eidasValidation *EidasValidationService,
	eidasEnabled bool,
) []ValidationService {
	services := []ValidationService{
		credentialsVerifier,
		gaiaXValidator,
		trustedParticipant,
		trustedIssuer,
		statusVerification,
	}
	if eidasEnabled {
		services = append(services, eidasValidation)
	}
	return services
}

// selectValidationContext picks the ValidationContext that the given
// ValidationService expects. The verifier keeps a heterogeneous slice of
// services but each service consumes exactly one context shape, so we
// dispatch at call time rather than burden the ValidationService
// interface with a generic context type.
//
// The default branch returns trustContext so the pre-existing services
// (CredentialValidator, GaiaXRegistryValidationService,
// TrustedParticipantValidationService, TrustedIssuerValidationService)
// keep the exact behaviour they had before Step 6.
func selectValidationContext(service ValidationService, trustContext TrustRegistriesValidationContext, statusContext CredentialStatusValidationContext, eidasContext EidasValidationContext) ValidationContext {
	switch service.(type) {
	case *CredentialStatusValidationService:
		return statusContext
	case *EidasValidationService:
		return eidasContext
	default:
		return trustContext
	}
}

func (v *CredentialVerifier) getTrustRegistriesValidationContextFromScope(clientId string, scope string, credentialTypes []string) (verificationContext TrustRegistriesValidationContext, err error) {
	trustedIssuersLists := map[string][]configModel.TrustedIssuersList{}
	trustedParticipantsRegistries := map[string][]configModel.TrustedParticipantsList{}

	requiredCredentialTypes, err := v.credentialsConfig.RequiredCredentialTypes(clientId, scope)
	if err != nil {
		logging.Log().Warnf("Was not able to get required credential types for client %s and scope %s. Err: %v", clientId, scope, err)
		return verificationContext, err
	}

	// Check if all required credentials were presented
	for _, credentialType := range requiredCredentialTypes {
		if !slices.Contains(credentialTypes, credentialType) { //nolint:govet
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

// HasLoginSession reports whether a login session is still open, i.e. neither expired nor
// redeemed by a successful authentication response.
func (v *CredentialVerifier) HasLoginSession(sessionId string) bool {
	_, found := v.sessionCache.Get(sessionId)
	return found
}

// AwaitsLoginPage reports whether a login page may still wait on the session: it is open, or it
// completed and its code was neither exchanged nor released yet. Both are read under
// sessionRedeemMutex, which moves a session to its pending login in one step, so neither is missed
// in between.
func (v *CredentialVerifier) AwaitsLoginPage(sessionId string) bool {
	v.sessionRedeemMutex.Lock()
	defer v.sessionRedeemMutex.Unlock()

	if _, found := v.sessionCache.Get(sessionId); found {
		return true
	}
	_, found := v.getPendingLogin(sessionId)
	return found
}

// CheckLoginPageSecret checks the secret a login page presents for its session against the hash
// stored when the session was created, or kept with its pending login once the session completed.
// Comparing the fixed-size hashes in constant time leaks neither the secret nor its length. Only
// cross-device v2 sessions have a login page.
func (v *CredentialVerifier) CheckLoginPageSecret(sessionId string, secret string) error {
	pageSecretHash, err := v.loginPageSecretHash(sessionId)
	if err != nil {
		return err
	}
	if pageSecretHash == ([sha256.Size]byte{}) {
		return ErrorLoginPageSecretMismatch
	}
	presented := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(presented[:], pageSecretHash[:]) != 1 {
		return ErrorLoginPageSecretMismatch
	}
	return nil
}

// loginPageSecretHash returns the page secret hash of the open session, or of its pending login.
func (v *CredentialVerifier) loginPageSecretHash(sessionId string) (pageSecretHash [sha256.Size]byte, err error) {
	v.sessionRedeemMutex.Lock()
	defer v.sessionRedeemMutex.Unlock()

	if sessionInterface, found := v.sessionCache.Get(sessionId); found {
		session := sessionInterface.(loginSession)
		if session.version != CROSS_DEVICE_V2 {
			return pageSecretHash, ErrorLoginPageSecretMismatch
		}
		return session.pageSecretHash, nil
	}
	if pending, found := v.getPendingLogin(sessionId); found {
		return pending.pageSecretHash, nil
	}
	return pageSecretHash, ErrorNoSuchSession
}

// PendingLogin returns the result of a completed cross-device v2 login whose code was neither
// exchanged nor released yet. Whoever hands it to the page must have checked the page secret first.
func (v *CredentialVerifier) PendingLogin(sessionId string) (pending PendingLogin, found bool) {
	v.sessionRedeemMutex.Lock()
	defer v.sessionRedeemMutex.Unlock()
	return v.getPendingLogin(sessionId)
}

// droppedPendingLogin replaces a pending login whose code was exchanged or released. go-cache calls
// OnEvicted on Delete as well, so overwriting it is what lets logUncollectedLogin tell a result that
// nobody collected from one that was used.
type droppedPendingLogin struct{}

// logUncollectedLogin is the OnEvicted callback of pendingLogins: a pending login that expires was
// never redeemed at the token endpoint - its page did not come back or never got the result, or the
// client did not redeem the code it was redirected with. The wallet was told that the login
// succeeded, so this is what explains a user who did not get in. go-cache evicts on its cleanup
// interval, so this comes up to two session lifetimes after the code expired.
func logUncollectedLogin(sessionId string, value interface{}) {
	if _, uncollected := value.(PendingLogin); uncollected {
		logging.Log().Infof("Login session %s completed, but its code expired without being exchanged at the token endpoint: the login page did not collect the result, or the client did not redeem the code. The wallet was told that the login succeeded.", sessionId)
	}
}

// getPendingLogin reads the pending login of the session. Callers hold sessionRedeemMutex.
func (v *CredentialVerifier) getPendingLogin(sessionId string) (pending PendingLogin, found bool) {
	if v.pendingLogins == nil {
		return pending, false
	}
	pendingInterface, found := v.pendingLogins.Get(sessionId)
	if !found {
		return pending, false
	}
	pending, found = pendingInterface.(PendingLogin)
	return pending, found
}

// dropPendingLogin removes the pending login of the session if it carries the given code.
func (v *CredentialVerifier) dropPendingLogin(sessionId string, authorizationCode string) {
	v.sessionRedeemMutex.Lock()
	defer v.sessionRedeemMutex.Unlock()
	v.dropPendingLoginLocked(sessionId, authorizationCode)
}

// dropPendingLoginLocked is dropPendingLogin for callers that hold sessionRedeemMutex.
func (v *CredentialVerifier) dropPendingLoginLocked(sessionId string, authorizationCode string) {
	if pending, found := v.getPendingLogin(sessionId); found && pending.Code == authorizationCode {
		v.pendingLogins.Set(sessionId, droppedPendingLogin{}, cache.DefaultExpiration)
	}
}

// redeemSession removes the login session if it still exists and reports whether this call was
// the one that removed it. Like sessionCache itself, the guarantee holds within one process. A
// pending login, if given, takes the session's place in the same step.
func (v *CredentialVerifier) redeemSession(sessionId string, pending *PendingLogin) bool {
	v.sessionRedeemMutex.Lock()
	defer v.sessionRedeemMutex.Unlock()

	if _, exists := v.sessionCache.Get(sessionId); !exists {
		return false
	}
	if pending != nil && v.pendingLogins != nil {
		v.pendingLogins.Set(sessionId, *pending, cache.DefaultExpiration)
	}
	v.sessionCache.Delete(sessionId)
	return true
}

// codeRelease is the outcome of releasing a code that could not be delivered.
type codeRelease int

const (
	// the session was put back, so the wallet can retry
	sessionRestored codeRelease = iota
	// the requestor claimed the code at the token endpoint: the login did complete
	codeRedeemed
	// the session stays redeemed: it has expired meanwhile, or redemptions are not recorded
	sessionNotRestored
)

// releaseCode undoes redeemSession when the issued code could not be delivered: the code is
// discarded and the session is put back for the rest of its lifetime, so a retry by the wallet can
// complete the login. Only one code for the session is ever valid at a time. A code already
// claimed at the token endpoint completed the login and is left alone; see claimCode for why
// both run under codeMutex.
func (v *CredentialVerifier) releaseCode(sessionId string, session loginSession, expiresAt time.Time, authorizationCode string) codeRelease {
	v.codeMutex.Lock()
	defer v.codeMutex.Unlock()

	if v.redeemedCodes == nil {
		// a claimed code cannot be told from an unused one, and restoring the session for a
		// claimed code would let it be redeemed twice
		logging.Log().Warnf("Did not restore session %s after the failed delivery: redeemed codes are not recorded.", sessionId)
		return sessionNotRestored
	}
	if v.wasCodeRedeemed(authorizationCode) {
		return codeRedeemed
	}
	v.tokenCache.Delete(authorizationCode)

	// the pending login carries the discarded code; the session takes its place in the same step
	v.sessionRedeemMutex.Lock()
	defer v.sessionRedeemMutex.Unlock()
	v.dropPendingLoginLocked(sessionId, authorizationCode)

	ttl := cache.DefaultExpiration
	if !expiresAt.IsZero() {
		ttl = time.Until(expiresAt)
		if ttl <= 0 {
			logging.Log().Infof("Did not restore session %s after the failed delivery: it has expired meanwhile.", sessionId)
			return sessionNotRestored
		}
	}
	v.sessionCache.Set(sessionId, session, ttl)
	logging.Log().Infof("Restored session %s after its code could not be delivered, so the wallet can retry.", sessionId)
	return sessionRestored
}

// ReleaseUndeliveredCode is called when the code of a completed cross-device v2 login could not be
// handed to the browser. It discards the code and restores the login session, unless the code was
// already claimed at the token endpoint. It reports whether the session was restored.
func (v *CredentialVerifier) ReleaseUndeliveredCode(sessionId string, authorizationCode string) bool {
	tokenSessionInterface, found := v.tokenCache.Get(authorizationCode)
	if !found {
		// the code was exchanged meanwhile, which drops the pending login too, or expired with it;
		// dropping it here only makes sure no page waits for it
		v.dropPendingLogin(sessionId, authorizationCode)
		logging.Log().Infof("Did not restore session %s after the failed delivery: its code is no longer cached.", sessionId)
		return false
	}
	tokenSession := tokenSessionInterface.(tokenStore)
	if tokenSession.sessionId != sessionId {
		logging.Log().Warnf("Did not restore session %s after the failed delivery: the code was issued for another session.", sessionId)
		return false
	}
	return v.releaseCode(sessionId, tokenSession.session, tokenSession.sessionExpiresAt, authorizationCode) == sessionRestored
}

// CheckRedirectUri checks the URI a login of the client sends its authorization code to - the
// redirect_uri of the cross-device v2 and OIDC flows, the client_callback of the cross-device v1
// flow - against the client's allowedRedirectUris. A client without the list, or not configured at
// all, accepts any URI; an unconfigured client never gets a code, as its presentation fails
// verification. A failure to read the configuration is returned, so the login is refused rather
// than left unchecked.
func (v *CredentialVerifier) CheckRedirectUri(clientId string, redirectUri string) error {
	allowedRedirectUris, err := v.credentialsConfig.GetAllowedRedirectUris(clientId)
	if err != nil {
		logging.Log().Warnf("Was not able to read the allowed redirect URIs of client %s, refusing the login. Err: %v", clientId, err)
		return err
	}
	if len(allowedRedirectUris) == 0 || configModel.RedirectUriAllowed(allowedRedirectUris, redirectUri) {
		return nil
	}
	logging.Log().Infof("Refused a login for client %s: %q is not in its allowedRedirectUris.", clientId, redirectUri)
	return ErrorRedirectUriNotAllowed
}

// intialize the OID4VP cross device flow
// It returns the generated session id alongside the request, since the frontend needs it to
// address the session (WebSocket, expiry) - the external state is not a lookup key.
func (v *CredentialVerifier) initOid4VPCrossDevice(host string, protocol string, redirectUri string, state string, clientId string, scope string, nonce string, requestMode string, pkceOptions ...PKCEChallenge) (sessionId string, pageSecret string, authenticationRequest string, err error) {
	pkce := PKCEChallenge{}
	if len(pkceOptions) > 0 {
		pkce = pkceOptions[0]
	}

	if err = v.CheckRedirectUri(clientId, redirectUri); err != nil {
		return sessionId, "", authenticationRequest, err
	}

	sessionId = v.nonceGenerator.GenerateNonce()
	// The session id is in the QR, so anyone who sees the QR knows it. The page secret is what
	// tells the page that started the login apart from them.
	pageSecret = v.nonceGenerator.GenerateNonce()
	pkce, err = validatePKCEChallenge(pkce, v.verifierConfig.AllowedCodeChallengeMethods)
	if err != nil {
		return sessionId, "", authenticationRequest, err
	}
	loginSession := loginSession{callback: redirectUri, sessionId: sessionId, externalState: state, nonce: nonce, clientId: clientId, version: CROSS_DEVICE_V2, scope: scope, pageSecretHash: sha256.Sum256([]byte(pageSecret)), pkce: pkce}
	err = v.sessionCache.Add(sessionId, loginSession, cache.DefaultExpiration)

	if err != nil {
		logging.Log().Warnf("Was not able to store the login session %s in cache.", logging.PrettyPrintObject(loginSession))
		return sessionId, "", authenticationRequest, err
	}
	logging.Log().Infof("Started cross-device (v2) login session %s for client %s, scope %s.", sessionId, clientId, scope)
	authResponseUri := fmt.Sprintf("%s://%s%s/api/v1/authentication_response", protocol, host, v.pathPrefix)

	authenticationRequest, err = v.generateAuthenticationRequest("openid4vp://", clientId, scope, authResponseUri, sessionId, nonce, loginSession, requestMode)
	return sessionId, pageSecret, authenticationRequest, err
}

// initializes the cross-device siop flow
func (v *CredentialVerifier) initSiopFlow(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string) (authenticationRequest string, err error) {
	return v.initSiopFlowWithPKCE(host, protocol, callback, state, clientId, nonce, requestMode, PKCEChallenge{})
}

func (v *CredentialVerifier) initSiopFlowWithPKCE(host string, protocol string, callback string, state string, clientId string, nonce string, requestMode string, pkce PKCEChallenge) (authenticationRequest string, err error) {
	pkce, err = validatePKCEChallenge(pkce, v.verifierConfig.AllowedCodeChallengeMethods)
	if err != nil {
		return authenticationRequest, err
	}

	scope, err := v.credentialsConfig.GetDefaultScope(clientId)
	if err != nil {
		return authenticationRequest, err
	}
	if strings.TrimSpace(scope) == "" {
		return authenticationRequest, ErrorNoDefaultScope
	}

	// the verifier calls the callback itself once the login completed
	if err = v.CheckRedirectUri(clientId, callback); err != nil {
		return authenticationRequest, err
	}

	if nonce == "" {
		logging.Log().Debugf("No nonce provided, generate one.")
		nonce = v.nonceGenerator.GenerateNonce()
	}
	sessionId := v.nonceGenerator.GenerateNonce()
	loginSession := loginSession{callback: callback, sessionId: sessionId, externalState: state, nonce: nonce, clientId: clientId, version: CROSS_DEVICE_V1, scope: scope, pkce: pkce}
	err = v.sessionCache.Add(sessionId, loginSession, cache.DefaultExpiration)

	if err != nil {
		logging.Log().Warnf("Was not able to store the login session %s in cache.", logging.PrettyPrintObject(loginSession))
		return authenticationRequest, err
	}
	logging.Log().Infof("Started cross-device (v1) login session %s for client %s.", sessionId, clientId)
	redirectUri := fmt.Sprintf("%s://%s%s/api/v1/authentication_response", protocol, host, v.pathPrefix)

	return v.generateAuthenticationRequest("openid4vp://", clientId, scope, redirectUri, sessionId, nonce, loginSession, requestMode)
}

func (v *CredentialVerifier) generateAuthenticationRequest(base string, clientId string, scope string, redirectUri string, state string, nonce string, loginSession loginSession, requestMode string) (authenticationRequest string, err error) {
	switch requestMode {
	case REQUEST_MODE_URL_ENCODED:
		authenticationRequest, err = v.createAuthenticationRequestUrlEncoded(base, redirectUri, state, clientId, scope, nonce)
		if err != nil {
			logging.Log().Warnf("Was not able to create the url-encoded authentication request. Error: %v", err)
		} else {
			logging.Log().Debugf("Authentication request is %s.", authenticationRequest)
		}
		return authenticationRequest, err
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
func (v *CredentialVerifier) generateJWT(credentials []map[string]interface{}, holder string, audience string, flatValues bool, nonce string) (generatedJwt jwt.Token, err error) {

	jwtBuilder := jwt.NewBuilder().Issuer(v.GetHost()).Audience([]string{audience}).Expiration(v.clock.Now().Add(v.jwtExpiration)).IssuedAt(v.clock.Now())

	if holder != "" {
		jwtBuilder.Subject(holder)
	}

	if flatValues {
		appendClaims(jwtBuilder, credentials)
	} else if len(credentials) > 1 {
		jwtBuilder.Claim("verifiablePresentation", credentials)
	} else {
		jwtBuilder.Claim("verifiableCredential", credentials[0])
	}

	if nonce != "" {
		jwtBuilder.Claim("nonce", nonce)
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
	_ = headers.Set("typ", REQUEST_OBJECT_TYP)
	if v.clientIdentification.CertificatePath != "" {
		certs, err := loadCertChainFromPEM(v.clientIdentification.CertificatePath)
		if err != nil {
			logging.Log().Errorf("Was not able to read the client certificate chain. Error: %v", err)
			return requestObject, err
		}

		x5cChain := cert.Chain{}
		for _, cert := range certs {
			_ = x5cChain.AddString(base64.StdEncoding.EncodeToString(cert.Raw))
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
// createAuthenticationRequestUrlEncoded builds an unsigned authentication request, with all
// parameters(including presentation_definition/dcql_query) inlined as plain query parameters
// on the request URI, instead of wrapped in a signed JWT. This is the only valid transport for
// the "redirect_uri" client_id scheme, since that scheme cannot be used with signed requests
// (there is no certificate/DID for the wallet to verify the signature against). It produces a
// larger QR/URI than "byValue"/"byReference", since nothing is fetched separately or embedded
// as a compact JWT — see README.md for the resulting trade-off.
func (v *CredentialVerifier) createAuthenticationRequestUrlEncoded(base string, response_uri string, state string, clientId string, scope string, nonce string) (request string, err error) {
	oidcClientId, err := resolveRedirectUriClientId(v.clientIdentification.Id, response_uri)
	if err != nil {
		return request, err
	}

	values := url.Values{}
	values.Set("response_type", "vp_token")
	values.Set("response_mode", "direct_post")
	values.Set("client_id", oidcClientId)
	values.Set("response_uri", response_uri)
	values.Set("state", state)
	if nonce != "" {
		values.Set("nonce", nonce)
	}

	presentationDefinition, err := v.credentialsConfig.GetPresentationDefinition(clientId, scope)
	if err != nil {
		return request, err
	}
	if presentationDefinition != nil {
		pdJSON, err := json.Marshal(presentationDefinition)
		if err != nil {
			return request, err
		}
		values.Set("presentation_definition", string(pdJSON))
	}

	dcql, err := v.credentialsConfig.GetDcqlQuery(clientId, scope)
	if err != nil {
		return request, err
	}
	if dcql != nil {
		dcqlJSON, err := json.Marshal(dcql)
		if err != nil {
			return request, err
		}
		values.Set("dcql_query", string(dcqlJSON))
	} else {
		logging.Log().Debugf("No dcql configured for %s - %s.", clientId, scope)
	}

	return base + "?" + values.Encode(), nil
}

// resolveRedirectUriClientId determines the client_id to send for the unsigned "redirect_uri"
// scheme. Per OIDC4VP, the wallet's only trust check for this scheme is that response_uri
// equals the URI embedded in client_id, so:
//   - if no id is configured, it defaults to the actual response_uri, which is always consistent
//     since both are derived from the same request.
//   - if an id is configured, it must resolve to the same host as response_uri - a stale value
//     (e.g. after an ingress hostname or pathPrefix change) would otherwise send a client_id the
//     wallet is guaranteed to reject, instead of failing here with an actionable error.
//   - any other id scheme (e.g. did:..., x509_san_dns:...) is left untouched.
func resolveRedirectUriClientId(configuredId string, responseUri string) (clientId string, err error) {
	if configuredId == "" {
		return CLIENT_ID_REDIRECT_URI_PREFIX + responseUri, nil
	}
	if !strings.HasPrefix(configuredId, CLIENT_ID_REDIRECT_URI_PREFIX) {
		return configuredId, nil
	}

	configuredUri := strings.TrimPrefix(configuredId, CLIENT_ID_REDIRECT_URI_PREFIX)
	parsedConfigured, err := url.Parse(configuredUri)
	if err != nil {
		return clientId, err
	}
	parsedResponse, err := url.Parse(responseUri)
	if err != nil {
		return clientId, err
	}
	if parsedConfigured.Host != parsedResponse.Host {
		logging.Log().Warnf("Configured redirect_uri client_id host %s does not match the request's response_uri host %s.", parsedConfigured.Host, parsedResponse.Host)
		return clientId, ErrorClientIdHostMismatch
	}
	return configuredId, nil
}

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
	q.Add("state", loginSession.externalState)
	q.Add("code", authorizationCode)
	callbackRequest.URL.RawQuery = q.Encode()

	response, err := httpClient.Do(callbackRequest)
	if err != nil {
		logging.Log().Warnf("Was not able to notify requestor %s. Err: %v", loginSession.callback, err)
		return err
	}
	defer func() { _ = response.Body.Close() }()
	// 2xx and 3xx accept the callback - a redirect is not followed, see InitVerifier
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		logging.Log().Warnf("Requestor %s did not accept the callback, it answered with status %d.", loginSession.callback, response.StatusCode)
		return ErrorCallbackRejected
	}
	return nil
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
		_ = key.Set("kid", clientId)
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
	allowedPKCEMethods, err := validatePKCEConfiguration(verifierConfig.AllowedCodeChallengeMethods)
	if err != nil {
		return err
	}
	verifierConfig.AllowedCodeChallengeMethods = allowedPKCEMethods
	if !slices.Contains(SupportedModes, verifierConfig.ValidationMode) { //nolint:govet
		return ErrorUnsupportedValidationMode
	}
	if len(verifierConfig.SupportedModes) == 0 {
		return ErrorSupportedModesNotSet
	}
	// The "default:" struct tag only applies when the config is loaded from server.yaml
	// (via gookit/config); callers building configModel.Verifier directly (tests, or any
	// future caller) get the zero value. Fall back here so behaviour matches the documented
	// default regardless of how the config was constructed. Prefer "byReference" for backwards
	// compatibility, but only when it is actually supported - otherwise fall back to whichever
	// mode is supported, so a previously valid supportedModes-only config keeps booting.
	if verifierConfig.RequestMode == "" {
		if slices.Contains(verifierConfig.SupportedModes, REQUEST_MODE_BY_REFERENCE) { //nolint:govet
			verifierConfig.RequestMode = REQUEST_MODE_BY_REFERENCE
		} else {
			verifierConfig.RequestMode = verifierConfig.SupportedModes[0]
		}
	}
	if !slices.Contains(verifierConfig.SupportedModes, verifierConfig.RequestMode) { //nolint:govet
		return ErrorRequestModeNotSupported
	}
	// as above, a config built directly gets the zero value instead of the "default:" tag
	if verifierConfig.ClientCallbackTimeout == 0 {
		verifierConfig.ClientCallbackTimeout = defaultClientCallbackTimeout
	}
	if verifierConfig.ClientCallbackTimeout < 0 {
		return ErrorInvalidClientCallbackTimeout
	}

	// Default to accepting all recognized VC Data Model versions when the
	// config field is empty (either unset in YAML or zero-valued in tests).
	if len(verifierConfig.VCDataModelVersions) == 0 {
		verifierConfig.VCDataModelVersions = common.VCDataModelVersionAll()
	}
	// Normalize in place, so the configured versions can be compared against the
	// versions detected on a credential without repeating the aliasing per request.
	for i, v := range verifierConfig.VCDataModelVersions { //nolint:govet
		canonical, ok := common.NormalizeVCDataModelVersion(v)
		if !ok {
			return fmt.Errorf("%w: %q (supported: %v)", ErrorUnsupportedVCDataModelVersion,
				v, common.VCDataModelVersionAll())
		}
		verifierConfig.VCDataModelVersions[i] = canonical
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

func (v *CredentialVerifier) GetPathPrefix() string {
	return v.pathPrefix
}

// GetRequestMode returns the request mode to use for flows where the caller has
// no way to request one explicitly (e.g. the OIDC-bridging authorization endpoint).
func (v *CredentialVerifier) GetRequestMode() string {
	return v.fallbackRequestMode
}

// IsRefreshTokenEnabled reports whether the refresh token feature is active.
func (v *CredentialVerifier) IsRefreshTokenEnabled() bool {
	return v.refreshTokenEnabled
}

// RefreshTokenExpiresIn returns the configured refresh token lifetime in seconds.
func (v *CredentialVerifier) RefreshTokenExpiresIn() int64 {
	return int64(v.refreshTokenExpiration.Seconds())
}

// generateRefreshToken creates a cryptographically random opaque token
// encoded as a base64url string (no padding). The token is 32 random bytes
// which yields a 43-character string.
func (v *CredentialVerifier) generateRefreshToken() (string, error) {
	buf := make([]byte, refreshTokenByteLength)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// CreateRefreshToken generates a new opaque refresh token, stores the raw
// JWT claims (not the signed access token) in the database, and returns
// the token string. Returns ErrorRefreshTokenDisabled when the feature is off.
func (v *CredentialVerifier) CreateRefreshToken(clientId string, signedJWT string) (string, error) {
	if !v.refreshTokenEnabled {
		return "", ErrorRefreshTokenDisabled
	}

	token, err := v.generateRefreshToken()
	if err != nil {
		return "", err
	}

	// Extract the raw JSON claims from the JWT payload segment (base64url-encoded
	// middle part of the compact serialization). Storing only the claims avoids
	// persisting a usable bearer token in the database.
	parts := strings.SplitN(signedJWT, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 dot-separated segments")
	}
	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT claims segment: %w", err)
	}

	row := database.RefreshTokenRow{
		Token:     token,
		ClientID:  clientId,
		Claims:    string(rawClaims),
		ExpiresAt: v.clock.Now().Add(v.refreshTokenExpiration).Unix(),
	}

	if err := v.refreshTokenRepo.StoreRefreshToken(context.Background(), row); err != nil {
		logging.Log().Warnf("Failed to store refresh token: %v", err)
		return "", err
	}

	logging.Log().Debug("Created refresh token")
	return token, nil
}

// signToken signs a jwt.Token and returns the serialized JWT string.
// This is a helper to deduplicate signing logic across GetToken,
// GenerateToken, and ExchangeRefreshToken.
func (v *CredentialVerifier) signToken(token jwt.Token) (string, error) {
	var signatureAlgorithm jwa.SignatureAlgorithm
	switch v.signingAlgorithm {
	case "RS256":
		signatureAlgorithm = jwa.RS256()
	case "ES256":
		signatureAlgorithm = jwa.ES256()
	}

	jwtBytes, err := v.tokenSigner.Sign(token, jwt.WithKey(signatureAlgorithm, v.signingKey))
	if err != nil {
		logging.Log().Warnf("Was not able to sign the token. Err: %v", err)
		return "", err
	}
	return string(jwtBytes), nil
}

// ExchangeRefreshToken atomically consumes a refresh token and returns a
// new signed access token JWT, its expiration in seconds, and a rotated
// refresh token. Returns ErrorRefreshTokenDisabled when the feature is off,
// ErrorRefreshTokenNotFound when the token does not exist, and
// ErrorRefreshTokenExpired when the token has passed its expiry.
func (v *CredentialVerifier) ExchangeRefreshToken(refreshToken string) (jwtString string, expiration int64, newRefreshToken string, err error) {
	if !v.refreshTokenEnabled {
		return "", 0, "", ErrorRefreshTokenDisabled
	}

	// Atomically retrieve and delete (single-use). The repository verifies the
	// stored HMAC integrity and returns ErrRefreshTokenInvalidIntegrity on mismatch.
	row, err := v.refreshTokenRepo.GetAndDeleteRefreshToken(context.Background(), refreshToken)
	if err != nil {
		if errors.Is(err, database.ErrRefreshTokenNotFound) {
			return "", 0, "", ErrorRefreshTokenNotFound
		}
		if errors.Is(err, database.ErrRefreshTokenInvalidIntegrity) {
			return "", 0, "", ErrorRefreshTokenInvalidSignature
		}
		return "", 0, "", err
	}

	// Defence-in-depth: check expiry even though housekeeping may have
	// already cleaned up expired rows.
	if row.ExpiresAt < v.clock.Now().Unix() {
		return "", 0, "", ErrorRefreshTokenExpired
	}

	// Build a new token from the stored claims, updating only the
	// time-dependent fields (iat, exp).
	now := v.clock.Now()
	builder := jwt.NewBuilder().
		IssuedAt(now).
		Expiration(now.Add(v.jwtExpiration))

	var claimsMap map[string]interface{}
	if err := json.Unmarshal([]byte(row.Claims), &claimsMap); err != nil {
		return "", 0, "", fmt.Errorf("parse stored claims: %w", err)
	}
	for key, val := range claimsMap {
		if key == "iat" || key == "exp" {
			continue
		}
		builder = builder.Claim(key, val)
	}

	newToken, err := builder.Build()
	if err != nil {
		return "", 0, "", fmt.Errorf("build refreshed token: %w", err)
	}

	jwtString, err = v.signToken(newToken)
	if err != nil {
		return "", 0, "", err
	}

	expiration = now.Add(v.jwtExpiration).Unix() - now.Unix()

	// Rotate: generate a new refresh token storing the newly signed JWT.
	newRefreshToken, err = v.CreateRefreshToken(row.ClientID, jwtString)
	if err != nil {
		return "", 0, "", fmt.Errorf("rotate refresh token: %w", err)
	}

	return jwtString, expiration, newRefreshToken, nil
}
