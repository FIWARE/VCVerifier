package gaiax

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/method/web"
	"github.com/trustbloc/did-go/vdr"
)

const GAIAX_REGISTRY_TRUSTANCHOR_FILE = "/v2/api/trustAnchor/chain/file"

var ErrorUnresolvableDid = errors.New("unresolvable_did")

type GaiaXClient interface {
	IsTrustedParticipant(registryEndpoint string, did string) (trusted bool)
}

/**
* A client to retrieve infromation from EBSI-compatible TrustedIssuerRegistry APIs.
 */
type GaiaXHttpClient struct {
	client      common.HttpClient
	didRegistry *vdr.Registry
}

func NewGaiaXHttpClient() (client GaiaXClient, err error) {
	return GaiaXHttpClient{client: &http.Client{}, didRegistry: vdr.New(vdr.WithVDR(web.New()))}, nil
}

func (ghc GaiaXHttpClient) IsTrustedParticipant(registryEndpoint string, did string) (trusted bool) {

	logging.Log().Debug("Verify participant at gaia-x registry.")

	// 1. get jwk from did
	didDocument, err := ghc.resolveIssuer(did)

	if err != nil {
		logging.Log().Warnf("Was not able to resolve the issuer. E: %v", err)
		return false
	}
	logging.Log().Debug("Got did document.")

	// 2. verify at the registry
	for _, verficationMethod := range didDocument.DIDDocument.VerificationMethod {
		if verficationMethod.ID == did {
			logging.Log().Debug("Verify the issuer.")
			return ghc.verifiyIssuer(registryEndpoint, verficationMethod)
		}
	}

	return false
}

func (ghc GaiaXHttpClient) verifiyIssuer(registryEndpoint string, verificationMethod did.VerificationMethod) (trusted bool) {
	jwk := verificationMethod.JSONWebKey()

	if jwk.CertificatesURL != nil {
		return ghc.verifyFileChain(registryEndpoint, jwk.CertificatesURL.String())
	}
	// gaia-x did-json need to provide an x5u, thus x5c checks should not be required.
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
	// according to the doc, all 200s are valid chains, thus no need to parse the body
	return true
}

func (ghc GaiaXHttpClient) resolveIssuer(did string) (didDocument *did.DocResolution, err error) {
	didDocument, err = ghc.didRegistry.Resolve(did)
	if err != nil {
		logging.Log().Warnf("Was not able to resolve the issuer %s.", did)
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
