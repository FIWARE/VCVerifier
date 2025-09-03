package verifier

import (
	"testing"

	configModel "github.com/fiware/VCVerifier/config"
)

func TestValidateConfig(t *testing.T) {
	type test struct {
		testName      string
		elsiConfig    *configModel.Elsi
		expectedError error
	}

	tests := []test{
		{
			testName:      "ELSI disabled",
			elsiConfig:    &configModel.Elsi{Enabled: false},
			expectedError: nil,
		},
		{
			testName: "ELSI enabled with valid config",
			elsiConfig: &configModel.Elsi{
				Enabled: true,
				ValidationEndpoint: &configModel.ValidationEndpoint{
					Host: "http://localhost:8080",
				},
			},
			expectedError: nil,
		},
		{
			testName:      "ELSI enabled with no validation endpoint",
			elsiConfig:    &configModel.Elsi{Enabled: true},
			expectedError: ErrorNoValidationEndpoint,
		},
		{
			testName: "ELSI enabled with no validation host",
			elsiConfig: &configModel.Elsi{
				Enabled:            true,
				ValidationEndpoint: &configModel.ValidationEndpoint{},
			},
			expectedError: ErrorNoValidationHost,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			err := validateConfig(tc.elsiConfig)

			if err != tc.expectedError {
				t.Errorf("Expected error %v, but got %v", tc.expectedError, err)
			}
		})
	}
}

func TestBuildAddress(t *testing.T) {
	type test struct {
		testName       string
		host           string
		path           string
		expectedResult string
	}

	tests := []test{
		{
			testName:       "Both with slashes",
			host:           "http://localhost:8080/",
			path:           "/validate",
			expectedResult: "http://localhost:8080/validate",
		},
		{
			testName:       "Host with slash",
			host:           "http://localhost:8080/",
			path:           "validate",
			expectedResult: "http://localhost:8080/validate",
		},
		{
			testName:       "Path with slash",
			host:           "http://localhost:8080",
			path:           "/validate",
			expectedResult: "http://localhost:8080/validate",
		},
		{
			testName:       "Both without slashes",
			host:           "http://localhost:8080",
			path:           "validate",
			expectedResult: "http://localhost:8080/validate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			result := buildAddress(tc.host, tc.path)

			if result != tc.expectedResult {
				t.Errorf("Expected result %v, but got %v", tc.expectedResult, result)
			}
		})
	}
}
