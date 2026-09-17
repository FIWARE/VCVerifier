package config

import (
	"fmt"

	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yaml"
	"github.com/mitchellh/mapstructure"
)

const (
	// DefaultLotlURL is the official EU List of Trusted Lists (LOTL) URL,
	// used as the default when no explicit lotlUrl is configured.
	DefaultLotlURL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
	// DefaultEidasRefreshInterval is the default interval in seconds between
	// background trust list refreshes (24 hours).
	DefaultEidasRefreshInterval = 86400
	// DefaultEidasRevocationTimeout is the default HTTP timeout in seconds for
	// a single OCSP or CRL request.
	DefaultEidasRevocationTimeout = 10
	// DefaultEidasRevocationCacheExpiry is the default lifetime in seconds of a
	// cached revocation status.
	DefaultEidasRevocationCacheExpiry = 3600
)

// read the config from the config file
func ReadConfig(configFile string) (configuration Configuration, err error) {
	config.WithOptions(func(opt *config.Options) {
		opt.ParseDefault = true
		opt.ParseEnv = true
		opt.TagName = "mapstructure"
		// Compose a custom decode hook for TrustedIssuersLists backward
		// compatibility (plain string array → structured entries) with the
		// default gookit/config hooks for env-var and time-duration parsing.
		opt.DecoderConfig = &mapstructure.DecoderConfig{
			TagName:          "mapstructure",
			WeaklyTypedInput: true,
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				TrustedIssuersListsDecodeHook(),
				config.ValDecodeHookFunc(true, false),
			),
		}
	})
	config.AddDriver(yaml.Driver)

	if err = config.LoadFiles(configFile); err != nil {
		return
	}

	// pass 1: apply defaults & env vars
	if err = config.BindStruct("", &configuration); err != nil {
		return
	}

	if err = ApplyEnvOverrides(&configuration); err != nil {
		return
	}

	applyEidasDefaults(&configuration)

	if err = validateEidasConfig(&configuration); err != nil {
		return
	}

	return configuration, nil
}

// validateEidasConfig rejects global eIDAS settings that cannot be honoured.
// An unrecognised statusEvaluation is an error rather than a silent fallback:
// it changes whether a credential from a withdrawn CA is accepted, so guessing
// would hide a misconfiguration behind a trust decision.
func validateEidasConfig(cfg *Configuration) error {
	switch cfg.Eidas.StatusEvaluation {
	case StatusEvaluationCurrent, StatusEvaluationIssuance:
	default:
		return fmt.Errorf("invalid eidas.statusEvaluation %q, expected %q or %q",
			cfg.Eidas.StatusEvaluation, StatusEvaluationCurrent, StatusEvaluationIssuance)
	}

	switch cfg.Eidas.RevocationCheck {
	case RevocationCheckOff, RevocationCheckSoft, RevocationCheckHard:
	default:
		return fmt.Errorf("invalid eidas.revocationCheck %q, expected %q, %q or %q",
			cfg.Eidas.RevocationCheck, RevocationCheckOff, RevocationCheckSoft, RevocationCheckHard)
	}

	return nil
}

// applyEidasDefaults sets programmatic defaults for the global eIDAS
// configuration. gookit/config and mapstructure do not honour Go default
// struct tags, so values that must differ from the zero value are applied here
// after the configuration has been parsed.
func applyEidasDefaults(cfg *Configuration) {
	if cfg.Eidas.LotlURL == "" {
		cfg.Eidas.LotlURL = DefaultLotlURL
	}
	if cfg.Eidas.RefreshInterval == 0 {
		cfg.Eidas.RefreshInterval = DefaultEidasRefreshInterval
	}
	if cfg.Eidas.StatusEvaluation == "" {
		cfg.Eidas.StatusEvaluation = StatusEvaluationCurrent
	}
	if cfg.Eidas.RevocationCheck == "" {
		cfg.Eidas.RevocationCheck = RevocationCheckSoft
	}
	if cfg.Eidas.RevocationTimeout == 0 {
		cfg.Eidas.RevocationTimeout = DefaultEidasRevocationTimeout
	}
	if cfg.Eidas.RevocationCacheExpiry == 0 {
		cfg.Eidas.RevocationCacheExpiry = DefaultEidasRevocationCacheExpiry
	}
}
