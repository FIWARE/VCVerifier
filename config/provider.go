package config

import (
	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yaml"
)

// read the config from the config file
func ReadConfig(configFile string) (configuration Configuration, err error) {
	config.WithOptions(func(opt *config.Options) {
		opt.ParseDefault = true
		opt.ParseEnv = true
		opt.TagName = "mapstructure"
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

	return configuration, nil
}
