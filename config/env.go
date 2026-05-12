package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// EnvPrefix is the prefix used for environment variable names that override
// configuration values. For example, VCVERIFIER_DATABASE_PASSWORD overrides
// the database.password config field.
const EnvPrefix = "VCVERIFIER"

// ApplyEnvOverrides walks the Configuration struct and overrides field values
// with matching environment variables. Variable names are derived from the
// mapstructure tag path, converted to UPPER_SNAKE_CASE with the EnvPrefix.
//
// Examples:
//
//	database.password  → VCVERIFIER_DATABASE_PASSWORD
//	server.port        → VCVERIFIER_SERVER_PORT
//	server.readTimeout → VCVERIFIER_SERVER_READ_TIMEOUT
//	m2m.authEnabled    → VCVERIFIER_M2M_AUTH_ENABLED
//
// Only scalar fields (string, int, int64, bool) are overridden. Slices, maps,
// and other complex types must be configured via the YAML file.
func ApplyEnvOverrides(cfg *Configuration) error {
	return applyEnvOverrides(reflect.ValueOf(cfg).Elem(), EnvPrefix)
}

func applyEnvOverrides(v reflect.Value, prefix string) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldVal := v.Field(i)

		tag := field.Tag.Get("mapstructure")
		if tag == "" {
			continue
		}

		envName := prefix + "_" + CamelToUpperSnake(tag)

		switch fieldVal.Kind() {
		case reflect.Struct:
			if err := applyEnvOverrides(fieldVal, envName); err != nil {
				return err
			}
		case reflect.Pointer:
			if fieldVal.Type().Elem().Kind() == reflect.Struct {
				if hasEnvVarWithPrefix(fieldVal.Type().Elem(), envName) {
					if fieldVal.IsNil() {
						fieldVal.Set(reflect.New(fieldVal.Type().Elem()))
					}
					if err := applyEnvOverrides(fieldVal.Elem(), envName); err != nil {
						return err
					}
				}
			}
		case reflect.String:
			if val, ok := os.LookupEnv(envName); ok {
				fieldVal.SetString(val)
			}
		case reflect.Int, reflect.Int64:
			if val, ok := os.LookupEnv(envName); ok {
				intVal, err := strconv.ParseInt(val, 10, 64)
				if err != nil {
					return fmt.Errorf("env %s: expected integer value: %w", envName, err)
				}
				fieldVal.SetInt(intVal)
			}
		case reflect.Bool:
			if val, ok := os.LookupEnv(envName); ok {
				boolVal, err := strconv.ParseBool(val)
				if err != nil {
					return fmt.Errorf("env %s: expected boolean value: %w", envName, err)
				}
				fieldVal.SetBool(boolVal)
			}
		}
	}
	return nil
}

// hasEnvVarWithPrefix checks whether any environment variable matching a
// scalar field in the given struct type (under the given prefix) is set.
// Used to decide whether a nil pointer-to-struct should be allocated.
func hasEnvVarWithPrefix(t reflect.Type, prefix string) bool {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("mapstructure")
		if tag == "" {
			continue
		}
		envName := prefix + "_" + CamelToUpperSnake(tag)
		switch field.Type.Kind() {
		case reflect.Struct:
			if hasEnvVarWithPrefix(field.Type, envName) {
				return true
			}
		case reflect.Pointer:
			if field.Type.Elem().Kind() == reflect.Struct {
				if hasEnvVarWithPrefix(field.Type.Elem(), envName) {
					return true
				}
			}
		default:
			if _, ok := os.LookupEnv(envName); ok {
				return true
			}
		}
	}
	return false
}

// CamelToUpperSnake converts a camelCase string to UPPER_SNAKE_CASE.
// Consecutive uppercase letters are kept together except before a lowercase
// transition (e.g. "sslMode" → "SSL_MODE", "readTimeout" → "READ_TIMEOUT").
func CamelToUpperSnake(s string) string {
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			if !unicode.IsUpper(prev) {
				b.WriteByte('_')
			} else if i+1 < len(runes) && unicode.IsLower(runes[i+1]) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}
