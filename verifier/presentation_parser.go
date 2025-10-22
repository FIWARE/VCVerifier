package verifier

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/jades"
	"github.com/fiware/VCVerifier/logging"
	"github.com/hellofresh/health-go/v5"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/defaults"
	sdv "github.com/trustbloc/vc-go/sdjwt/verifier"
	"github.com/trustbloc/vc-go/verifiable"
)

var ErrorNoValidationEndpoint = errors.New("no_validation_endpoint_configured")
var ErrorNoValidationHost = errors.New("no_validation_host_configured")
var ErrorInvalidSdJwt = errors.New("credential_is_not_sd_jwt")
var ErrorPresentationNoCredentials = errors.New("presentation_not_contains_credentials")
var ErrorInvalidProof = errors.New("invalid_vp_proof")

var proofChecker = defaults.NewDefaultProofChecker(JWTVerfificationMethodResolver{})
var defaultPresentationOptions = []verifiable.PresentationOpt{
	verifiable.WithPresProofChecker(proofChecker),
	verifiable.WithPresJSONLDDocumentLoader(NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient)))}

var defaultSdJwtParserOptions = []sdv.ParseOpt{
	sdv.WithSignatureVerifier(proofChecker),
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
	ParseWithSdJwt(tokenBytes []byte) (presentation *verifiable.Presentation, err error)
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

		proofChecker := &ElsiProofChecker{
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
			verifiable.WithPresProofChecker(proofChecker),
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

func (sjp *ConfigurableSdJwtParser) ClaimsToCredential(claims map[string]interface{}) (credential *verifiable.Credential, err error) {

	issuer, i_ok := claims["iss"]
	vct, vct_ok := claims["vct"]
	if !i_ok || !vct_ok {
		logging.Log().Infof("Token does not contain issuer(%v) or vct(%v).", i_ok, vct_ok)
		return credential, ErrorInvalidSdJwt
	}
	customFields := verifiable.CustomFields{}
	for k, v := range claims {
		if k != "iss" && k != "vct" {
			customFields[k] = v
		}
	}
	subject := verifiable.Subject{CustomFields: customFields}
	contents := verifiable.CredentialContents{Issuer: &verifiable.Issuer{ID: issuer.(string)}, Types: []string{vct.(string)}, Subject: []verifiable.Subject{subject}}
	return verifiable.CreateCredential(contents, verifiable.CustomFields{})
}

func (sjp *ConfigurableSdJwtParser) ParseWithSdJwt(tokenBytes []byte) (presentation *verifiable.Presentation, err error) {
	logging.Log().Debug("Parse with SD-Jwt")

	tokenString := string(tokenBytes)
	payloadString := strings.Split(tokenString, ".")[1]
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(payloadString)

	var vpMap map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &vpMap); err != nil {
		return nil, err
	}

	vp, ok := vpMap["vp"].(map[string]interface{})
	if !ok {
		return presentation, ErrorPresentationNoCredentials
	}

	vcs, ok := vp["verifiableCredential"]
	if !ok {
		return presentation, ErrorPresentationNoCredentials
	}

	presentation, err = verifiable.NewPresentation()
	if err != nil {
		return nil, err
	}

	presentation.Holder = vp["holder"].(string)

	// due to dcql, we only need to take care of presentations containing credentials of the same type.
	for _, vc := range vcs.([]interface{}) {
		logging.Log().Debugf("The vc %s", vc.(string))
		parsed, err := sjp.Parse(vc.(string))
		if err != nil {
			return nil, err
		}
		credential, err := sjp.ClaimsToCredential(parsed)
		if err != nil {
			return nil, err
		}
		presentation.AddCredentials(credential)
	}

	err = jwt.CheckProof(string(tokenBytes), proofChecker, nil, nil)
	if err != nil {
		return nil, ErrorInvalidProof
	}

	return presentation, nil
}
