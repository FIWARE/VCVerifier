package verifier

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/jades"
	"github.com/fiware/VCVerifier/logging"
	"github.com/hellofresh/health-go/v5"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/verifiable"
)

var ErrorNoValidationEndpoint = errors.New("no_validation_endpoint_configured")
var ErrorNoValidationHost = errors.New("no_validation_host_configured")

var defaultPresentationOptions = []verifiable.PresentationOpt{
	verifiable.WithPresProofChecker(defaults.NewDefaultProofChecker(JWTVerfificationMethodResolver{})),
	verifiable.WithPresJSONLDDocumentLoader(NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient)))}

// allow singleton access to the parser
var presentationParser PresentationParser

// parser interface
type PresentationParser interface {
	ParsePresentation(tokenBytes []byte) (*verifiable.Presentation, error)
}

type ConfigurablePresentationParser struct {
	PresentationOpts []verifiable.PresentationOpt
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

func InitPresentationParser(config *configModel.Configuration, healthCheck *health.Health) error {
	elsiConfig := &config.Elsi
	err := validateConfig(elsiConfig)
	if err != nil {
		logging.Log().Warnf("No valid elsi configuration provided. Error: %v", err)
		return err
	}
	if elsiConfig.Enabled {
		jAdESValidator := &jades.ExternalJAdESValidator{
			HttpClient:        &http.Client{},
			ValidationAddress: buildAddress(elsiConfig.ValidationEndpoint.Host, elsiConfig.ValidationEndpoint.ValidationPath),
			HealthAddress:     buildAddress(elsiConfig.ValidationEndpoint.Host, elsiConfig.ValidationEndpoint.HealthPath)}

		elsiProofChecker := &ElsiProofChecker{
			defaultChecker: defaults.NewDefaultProofChecker(JWTVerfificationMethodResolver{}),
			jAdESValidator: jAdESValidator,
		}

		healthCheck.Register(health.Config{
			Name:      "JAdES-Validator",
			Timeout:   time.Second * 5,
			SkipOnErr: false,
			Check: func(ctx context.Context) error {
				return jAdESValidator.IsReady()
			},
		})

		presentationParser = &ConfigurablePresentationParser{PresentationOpts: []verifiable.PresentationOpt{
			verifiable.WithPresProofChecker(elsiProofChecker),
			verifiable.WithPresJSONLDDocumentLoader(NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient)))}}
	} else {
		presentationParser = &ConfigurablePresentationParser{PresentationOpts: defaultPresentationOptions}
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

func (cpp *ConfigurablePresentationParser) ParsePresentation(tokenBytes []byte) (*verifiable.Presentation, error) {
	return verifiable.ParsePresentation(tokenBytes, cpp.PresentationOpts...)
}
