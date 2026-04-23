package tir

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"

	common "github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	v5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
)

/**
 * Global file accessor
 */
var localFileAccessor common.FileAccessor = common.DiskFileAccessor{}

// Key type constants for M2M token signing.
const (
	KeyTypeRSAPS256 = "RSAPS256"
	KeyTypeRSARS256 = "RSARS256"
	AlgorithmPS256  = "PS256"
	AlgorithmRS256  = "RS256"
)

var (
	ErrorTokenProviderNoKey                = errors.New("no_key_configured")
	ErrorTokenProviderNoVC                 = errors.New("no_vc_configured")
	ErrorTokenProviderNoVerificationMethod = errors.New("no_verification_method_configured")
	ErrorBadPrivateKey                     = errors.New("bad_private_key_length")
	ErrorTokenProviderNoDid                = errors.New("no_did_configured")
)

type TokenProvider interface {
	GetToken(vc *common.Credential, audience string) (string, error)
	GetAuthCredential() (vc *common.Credential, err error)
}

type M2MTokenProvider struct {
	// encodes the token according to the configuration
	tokenEncoder TokenEncoder
	// the credential
	authCredential *common.Credential
	// the signing key
	signingKey *rsa.PrivateKey
	// clock to get issuance time from
	clock common.Clock
	// verification method to be used on the tokens
	verificationMethod string
	// signature type to be used
	signatureType string
	// type of the provided key
	keyType string
	// did of the token provider
	did string
}

type TokenEncoder interface {
	GetEncodedToken(vp *common.Presentation, audience string) (encodedToken string, err error)
}

type Base64TokenEncoder struct{}

func InitM2MTokenProvider(config *configModel.Configuration, clock common.Clock) (tokenProvider TokenProvider, err error) {
	m2mConfig := config.M2M

	if m2mConfig.KeyPath == "" {
		logging.Log().Warn("No private key configured, cannot provide m2m tokens.")
		return tokenProvider, ErrorTokenProviderNoKey
	}
	if m2mConfig.VerificationMethod == "" {
		logging.Log().Warn("No verification method configured, cannot provide m2m tokens.")
		return tokenProvider, ErrorTokenProviderNoVerificationMethod
	}

	privateKey, err := getSigningKey(m2mConfig.KeyPath)
	if err != nil {
		logging.Log().Warnf("Was not able to load the signing key. Err: %v", err)
		return tokenProvider, err
	}

	if m2mConfig.CredentialPath == "" {
		logging.Log().Warn("No credential path configured, cannot provide m2m tokens.")
		return tokenProvider, ErrorTokenProviderNoVC
	}
	if config.Verifier.Did == "" {
		logging.Log().Warn("No did for token provider")
		return tokenProvider, ErrorTokenProviderNoDid
	}

	vc, err := getCredential(m2mConfig.CredentialPath)
	if err != nil {
		logging.Log().Warnf("Was not able to load the credential. Err: %v", err)
		return tokenProvider, err
	}
	logging.Log().Debug("Successfully initialized the M2MTokenProvider.")
	return M2MTokenProvider{tokenEncoder: Base64TokenEncoder{}, authCredential: vc, signingKey: privateKey, did: config.Verifier.Did, clock: clock, verificationMethod: m2mConfig.VerificationMethod, keyType: config.M2M.KeyType, signatureType: config.M2M.SignatureType}, err
}

func (tokenProvider M2MTokenProvider) GetAuthCredential() (vc *common.Credential, err error) {
	return tokenProvider.authCredential, err
}

func (tokenProvider M2MTokenProvider) GetToken(vc *common.Credential, audience string) (token string, err error) {

	vp, err := tokenProvider.signVerifiablePresentation(vc)
	if err != nil {
		logging.Log().Warnf("Was not able to get a signed verifiable presentation. Err: %v", err)
		return token, err
	}
	return tokenProvider.tokenEncoder.GetEncodedToken(vp, audience)
}

func (base64TokenEncoder Base64TokenEncoder) GetEncodedToken(vp *common.Presentation, audience string) (encodedToken string, err error) {

	marshalledPayload, err := vp.MarshalJSON()
	if err != nil {
		logging.Log().Warnf("Was not able to marshal the token payload. Err: %v", err)
		return encodedToken, err
	}

	return base64.RawURLEncoding.EncodeToString(marshalledPayload), err
}

// keyTypeToAlgorithm maps the configured key type to a JWS algorithm name.
func keyTypeToAlgorithm(keyType string) string {
	switch keyType {
	case KeyTypeRSAPS256:
		return AlgorithmPS256
	case KeyTypeRSARS256:
		return AlgorithmRS256
	default:
		return AlgorithmPS256
	}
}

func (tp M2MTokenProvider) signVerifiablePresentation(authCredential *common.Credential) (vp *common.Presentation, err error) {
	vp, err = common.NewPresentation(common.WithCredentials(authCredential))
	if err != nil {
		logging.Log().Warnf("Was not able to create a presentation. Err: %v", err)
		return vp, err
	}
	vp.ID = "urn:uuid:" + uuid.NewString()
	vp.Holder = tp.did

	created := tp.clock.Now()
	err = vp.AddLinkedDataProof(&common.LinkedDataProofContext{
		Created:            &created,
		SignatureType:      tp.signatureType,
		Algorithm:          keyTypeToAlgorithm(tp.keyType),
		VerificationMethod: tp.verificationMethod,
		Signer:             NewRS256Signer(tp.signingKey),
		DocumentLoader:     ld.NewDefaultDocumentLoader(http.DefaultClient),
	})

	if err != nil {
		logging.Log().Warnf("Was not able to add an ld-proof. Err: %v", err)
		return vp, err
	}

	return vp, err
}

/**
* Read siging key from local filesystem
 */
func getSigningKey(keyPath string) (key *rsa.PrivateKey, err error) {
	// read key file
	rawKey, err := localFileAccessor.ReadFile(keyPath)
	if err != nil {
		logging.Log().Warnf("Was not able to read the key file from %s. err: %v", keyPath, err)
		return key, err
	} // parse key file
	key, err = v5.ParseRSAPrivateKeyFromPEM(rawKey)
	if err != nil {
		logging.Log().Warnf("Was not able to parse the key %s. err: %v", rawKey, err)
		return key, err
	}

	return
}

func getCredential(vcPath string) (vc *common.Credential, err error) {
	vcBytes, err := localFileAccessor.ReadFile(vcPath)
	if err != nil {
		logging.Log().Warnf("Was not able to read the vc file from %s. err: %v", vcPath, err)
		return vc, err
	}
	logging.Log().Debugf("Got bytes %v", string(vcBytes))

	vc, err = common.ParseCredentialJSON(vcBytes)
	if err != nil {
		logging.Log().Warnf("Was not able to unmarshal the credential. Err: %v", err)
		return vc, err
	}

	return vc, err
}

// NewRS256Signer creates RS256Signer.
func NewRS256Signer(privKey *rsa.PrivateKey) *RS256Signer {
	return &RS256Signer{
		privKey: privKey,
	}
}

// Sign data.
func (s RS256Signer) Sign(data []byte) ([]byte, error) {
	hash := crypto.SHA256.New()

	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}

	hashed := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, s.privKey, crypto.SHA256, hashed)
}

// RS256Signer is a Jose complient signer.
type RS256Signer struct {
	privKey *rsa.PrivateKey
}
