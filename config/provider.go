package config

import (
	"fmt"
	"reflect"

	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yaml"
	"github.com/mitchellh/mapstructure"
)

// read the config from the config file
func ReadConfig(configFile string) (configuration Configuration, err error) {
	config.WithOptions(config.ParseDefault)
	config.AddDriver(yaml.Driver)

	if err = config.LoadFiles(configFile); err != nil {
		return
	}

	// pass 1: apply defaults & env vars
	if err = config.BindStruct("", &configuration); err != nil {
		return
	}

	raw := config.Data()
	normalized := forceStringKeys(raw)

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "mapstructure",
		Result:  &configuration,
	})
	if err != nil {
		return
	}
	if err = decoder.Decode(normalized); err != nil {
		return
	}

	return
}

func forceStringKeys(m interface{}) interface{} {
	switch v := m.(type) {
	case map[interface{}]interface{}:
		newMap := make(map[string]interface{})
		for key, val := range v {
			newMap[fmt.Sprintf("%v", key)] = forceStringKeys(val)
		}
		return newMap
	case map[string]interface{}:
		newMap := make(map[string]interface{})
		for key, val := range v {
			newMap[key] = forceStringKeys(val)
		}
		return newMap
	case []interface{}:
		for i := range v {
			v[i] = forceStringKeys(v[i])
		}
		return v
	default:
		return v
	}
}

func autoAllocHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		// If target type is a pointer to struct, and source is a map,
		// allocate the target before decoding.
		if to.Kind() == reflect.Ptr && to.Elem().Kind() == reflect.Struct {
			v := reflect.New(to.Elem())
			return v.Interface(), nil
		}
		return data, nil
	}
}
