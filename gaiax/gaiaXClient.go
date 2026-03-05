package gaiax

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
)

const GAIAX_REGISTRY_TRUSTANCHOR_FILE = "/v2/api/trustAnchor/chain/file"

var ErrorUnresolvableDid = errors.New("unresolvable_did")

/**
* A client to retrieve infromation from EBSI-compatible TrustedIssuerRegistry APIs.
 */
type GaiaXClient interface {
	IsTrustedParticipant(registryEndpoint string, did string) (trusted bool)
}

// DIDResolver resolves DIDs to their documents.
type DIDResolver interface {
	Resolve(didStr string) (*did.DocResolution, error)
}

type GaiaXHttpClient struct {
	client      common.HttpClient
	didRegistry DIDResolver
}

func NewGaiaXHttpClient() (client GaiaXClient, err error) {
	return GaiaXHttpClient{client: &http.Client{}, didRegistry: did.NewRegistry(did.WithVDR(did.NewWebVDR()))}, nil
}

func (ghc GaiaXHttpClient) IsTrustedParticipant(registryEndpoint string, didStr string) (trusted bool) {

	logging.Log().Debugf("Verify participant %s at gaia-x registry %s.", didStr, registryEndpoint)

	// 1. get jwk from did
	didDocument, err := ghc.resolveIssuer(didStr)

	if err != nil {
		logging.Log().Warnf("Was not able to resolve the issuer %s. E: %v", didStr, err)
		return false
	}

	// 2. verify at the registry
	for _, verficationMethod := range didDocument.DIDDocument.VerificationMethod {
		if verficationMethod.ID == didStr || verficationMethod.Controller == didStr {
			logging.Log().Debugf("Verify the issuer %s.", didStr)
			return ghc.verifiyIssuer(registryEndpoint, verficationMethod)
		}
	}

	return false
}

func (ghc GaiaXHttpClient) verifiyIssuer(registryEndpoint string, verificationMethod did.VerificationMethod) (trusted bool) {
	jwkKey := verificationMethod.JSONWebKey()
	if jwkKey == nil {
		logging.Log().Debug("Verification method has no JWK key")
		return false
	}

	// Extract x5u (X.509 certificate URL) from the JWK
	var x5u string
	if err := jwkKey.Get("x5u", &x5u); err == nil && x5u != "" {
		return ghc.verifyFileChain(registryEndpoint, x5u)
	}
	// gaia-x did-json need to provide an x5u, thus x5c checks are not required.
	logging.Log().Debug("Verification method JWK has no x5u field")
	return false
}

func (ghc GaiaXHttpClient) verifyFileChain(registryEndpoint string, x5u string) (trusted bool) {
	requestBody := FileChainRequest{Uri: x5u}

	encodedRequest, err := json.Marshal(requestBody)
	if err != nil {
		logging.Log().Warnf("Was not able to build a valid certificate check bode. E: %v", err)
		return false
	}

	request, _ := http.NewRequest("POST", buildURL(registryEndpoint, GAIAX_REGISTRY_TRUSTANCHOR_FILE), bytes.NewBuffer(encodedRequest))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := ghc.client.Do(request)
	if err != nil {
		logging.Log().Infof("Was not able to check cert chain %s at %s. E: %v", x5u, registryEndpoint, err)
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		logging.Log().Infof("x5u %s was not verified to be a trust anchor at %s. Response: %v", x5u, registryEndpoint, response.StatusCode)
		return false
	}
	// according to the spec, all 200s are valid chains, thus no need to parse the body
	return true
}

func (ghc GaiaXHttpClient) resolveIssuer(didStr string) (didDocument *did.DocResolution, err error) {
	didDocument, err = ghc.didRegistry.Resolve(didStr)
	if err != nil {
		logging.Log().Warnf("Was not able to resolve the issuer %s.", didStr)
		return nil, ErrorUnresolvableDid
	}
	return didDocument, err
}

func buildURL(host, path string) string {
	return strings.TrimSuffix(host, "/") + "/" + strings.TrimPrefix(path, "/")
}

type FileChainRequest struct {
	Uri string `json:"uri"`
}

type CertChainRequest struct {
	Certs string `json:"certs"`
}

type VerificationResult struct {
	Result bool `json:"result"`
}
