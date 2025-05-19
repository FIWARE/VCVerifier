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

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/proof/creator"
	"github.com/trustbloc/vc-go/proof/jwtproofs/ps256"
	"github.com/trustbloc/vc-go/proof/ldproofs/jsonwebsignature2020"
	"github.com/trustbloc/vc-go/verifiable"
)

/**
 * Global file accessor
 */
var localFileAccessor common.FileAccessor = common.DiskFileAccessor{}

var ErrorTokenProviderNoKey = errors.New("no_key_configured")
var ErrorTokenProviderNoVC = errors.New("no_vc_configured")
var ErrorTokenProviderNoVerificationMethod = errors.New("no_verification_method_configured")
var ErrorBadPrivateKey = errors.New("bad_private_key_length")
var ErrorTokenProviderNoDid = errors.New("no_did_configured")

type TokenProvider interface {
	GetToken(vc *verifiable.Credential, audience string) (string, error)
	GetAuthCredential() (vc *verifiable.Credential, err error)
}

type M2MTokenProvider struct {
	// encodes the token according to the configuration
	tokenEncoder TokenEncoder
	// the credential
	authCredential *verifiable.Credential
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
	GetEncodedToken(vp *verifiable.Presentation, audience string) (encodedToken string, err error)
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

func (tokenProvider M2MTokenProvider) GetAuthCredential() (vc *verifiable.Credential, err error) {
	return tokenProvider.authCredential, err
}

func (tokenProvider M2MTokenProvider) GetToken(vc *verifiable.Credential, audience string) (token string, err error) {

	vp, err := tokenProvider.signVerifiablePresentation(vc)
	if err != nil {
		logging.Log().Warnf("Was not able to get a signed verifiable presentation. Err: %v", err)
		return token, err
	}
	return tokenProvider.tokenEncoder.GetEncodedToken(vp, audience)
}

func (base64TokenEncoder Base64TokenEncoder) GetEncodedToken(vc *verifiable.Presentation, audience string) (encodedToken string, err error) {

	marshalledPayload, err := vc.MarshalJSON()
	if err != nil {
		logging.Log().Warnf("Was not able to marshal the token payload. Err: %v", err)
		return encodedToken, err
	}

	return base64.RawURLEncoding.EncodeToString(marshalledPayload), err
}

func (tp M2MTokenProvider) signVerifiablePresentation(authCredential *verifiable.Credential) (vp *verifiable.Presentation, err error) {
	vp, err = verifiable.NewPresentation(verifiable.WithCredentials(authCredential))
	if err != nil {
		logging.Log().Warnf("Was not able to create a presentation. Err: %v", err)
		return vp, err
	}
	vp.ID = "urn:uuid:" + uuid.NewString()
	vp.Holder = tp.did

	proofCreator := creator.New(creator.WithLDProofType(jsonwebsignature2020.New(), NewRS256Signer(tp.signingKey)), creator.WithJWTAlg(ps256.New(), NewRS256Signer(tp.signingKey)))

	created := tp.clock.Now()
	err = vp.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		Created:                 &created,
		SignatureType:           tp.signatureType,
		KeyType:                 kms.KeyType(tp.keyType),
		ProofCreator:            proofCreator,
		SignatureRepresentation: verifiable.SignatureJWS,
		VerificationMethod:      tp.verificationMethod,
	}, processor.WithDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient)))

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

func getCredential(vcPath string) (vc *verifiable.Credential, err error) {
	vcBytes, err := localFileAccessor.ReadFile(vcPath)
	if err != nil {
		logging.Log().Warnf("Was not able to read the vc file from %s. err: %v", vcPath, err)
		return vc, err
	}
	logging.Log().Warnf("Got bytes %v", string(vcBytes))

	vc, err = verifiable.ParseCredential(vcBytes, verifiable.WithJSONLDDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient)), verifiable.WithDisabledProofCheck())

	if err != nil {
		logging.Log().Warnf("Was not able to unmarshal the credential. Err: %v", err)
		return vc, err
	}
	c, _ := vc.MarshalJSON()
	logging.Log().Warnf("The cred %s", string(c))

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
