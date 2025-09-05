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
	sdv "github.com/trustbloc/vc-go/sdjwt/verifier"
	"github.com/trustbloc/vc-go/verifiable"
)

var ErrorNoValidationEndpoint = errors.New("no_validation_endpoint_configured")
var ErrorNoValidationHost = errors.New("no_validation_host_configured")

var defaultPresentationOptions = []verifiable.PresentationOpt{
	verifiable.WithPresProofChecker(defaults.NewDefaultProofChecker(JWTVerfificationMethodResolver{})),
	verifiable.WithPresJSONLDDocumentLoader(NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient)))}

var defaultSdJwtParserOptions = []sdv.ParseOpt{
	sdv.WithSignatureVerifier(defaults.NewDefaultProofChecker(JWTVerfificationMethodResolver{})),
	sdv.WithHolderVerificationRequired(false),
	sdv.WithHolderSigningAlgorithms([]string{"ES256", "PS256"}),
	sdv.WithIssuerSigningAlgorithms([]string{"ES256", "PS256"}),
}

// allow singleton access to the parser
var presentationParser PresentationParser

// allow singleton access to the parser
var sdJwtParser SdJwtParser

// parser interface
type PresentationParser interface {
	ParsePresentation(tokenBytes []byte) (*verifiable.Presentation, error)
}

type SdJwtParser interface {
	Parse(tokenString string) (map[string]interface{}, error)
}

type ConfigurablePresentationParser struct {
	PresentationOpts []verifiable.PresentationOpt
}

type ConfigurableSdJwtParser struct {
	ParserOpts []sdv.ParseOpt
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
	sdJwtParser = &ConfigurableSdJwtParser{ParserOpts: defaultSdJwtParserOptions}

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

func (sjp *ConfigurableSdJwtParser) Parse(tokenString string) (map[string]interface{}, error) {
	return sdv.Parse(tokenString, sjp.ParserOpts...)
}
