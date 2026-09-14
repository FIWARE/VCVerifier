package config

import (
	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yaml"
	"github.com/mitchellh/mapstructure"
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

	return configuration, nil
}

// applyEidasDefaults sets programmatic defaults for the global eIDAS
// configuration. gookit/config and mapstructure do not honour Go default
// struct tags, so values that must differ from the zero value are applied here
// after the configuration has been parsed.
func applyEidasDefaults(cfg *Configuration) {
	if cfg.Eidas.LotlURL == "" {
		cfg.Eidas.LotlURL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
	}
	if cfg.Eidas.RefreshInterval == 0 {
		cfg.Eidas.RefreshInterval = 86400 // 24 hours in seconds
	}
}
