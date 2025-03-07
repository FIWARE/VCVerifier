package gaiax

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fiware/VCVerifier/logging"
)

var ErrorRegistry = errors.New("gaiax_registry_failed_to_answer_properly")

type RegistryClient interface {
	// Get the list of DIDs of the trustable issuers
	GetComplianceIssuers() ([]string, error)
}

type GaiaXRegistryClient struct {
	endpoint string
}

func InitGaiaXRegistryVerificationService(url string) RegistryClient {
	return &GaiaXRegistryClient{url}
}

// TODO Could propably cache the response very generously as new issuers are not added often
func (rc *GaiaXRegistryClient) GetComplianceIssuers() ([]string, error) {
	response, err := http.Get(rc.endpoint)

	if err != nil {
		logging.Log().Warnf("Did not receive a valid issuers list response. Err: %v", err)
		return []string{}, err
	}
	if response == nil {
		logging.Log().Warn("Did not receive any response from gaia-x registry.")
		return []string{}, ErrorRegistry
	}
	if response.StatusCode != 200 {
		logging.Log().Warnf("Did not receive an ok from the registry. Was %s", logging.PrettyPrintObject(response))
		return []string{}, ErrorRegistry
	}
	if response.Body == nil {
		logging.Log().Warn("Received an empty body for the issuers list.")
		return []string{}, ErrorRegistry
	}
	var issuers []string

	err = json.NewDecoder(response.Body).Decode(&issuers)
	if err != nil {
		logging.Log().Warnf("Was not able to decode the issuers list. Was %s", logging.PrettyPrintObject(response))
		return []string{}, err
	}
	logging.Log().Infof("%d issuer dids received.", len(issuers))
	logging.Log().Debugf("Issuers are %v", logging.PrettyPrintObject(issuers))
	return issuers, nil
}
