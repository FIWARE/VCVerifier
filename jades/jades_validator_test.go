package jades

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"testing"
)

type MockClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

func TestValidateSignature(t *testing.T) {
	type test struct {
		testName       string
		signature      string
		mockResponse   *http.Response
		mockError      error
		expectedResult bool
		expectedError  error
	}

	tests := []test{
		{
			testName:  "Successful validation",
			signature: "valid_signature",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body: ioutil.NopCloser(bytes.NewBufferString(`{"simpleReport":{"signaturesCount":1,"validSignaturesCount":1}}`)),
			},
			mockError:      nil,
			expectedResult: true,
			expectedError:  nil,
		},
		{
			testName:  "Invalid signature",
			signature: "invalid_signature",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{"simpleReport":{"signaturesCount":1,"validSignaturesCount":0}}`)),
			},
			mockError:      nil,
			expectedResult: false,
			expectedError:  nil,
		},
		{
			testName:  "No signatures",
			signature: "no_signatures",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{"simpleReport":{"signaturesCount":0,"validSignaturesCount":0}}`)),
			},
			mockError:      nil,
			expectedResult: false,
			expectedError:  nil,
		},
		{
			testName:       "Bad response from validation endpoint",
			signature:      "bad_response",
			mockResponse:   &http.Response{StatusCode: http.StatusInternalServerError, Body: ioutil.NopCloser(bytes.NewBufferString(""))},
			mockError:      nil,
			expectedResult: false,
			expectedError:  ErrorBadResponse,
		},
		{
			testName:       "Empty body in response",
			signature:      "empty_body",
			mockResponse:   &http.Response{StatusCode: http.StatusOK, Body: nil},
			mockError:      nil,
			expectedResult: false,
			expectedError:  ErrorEmptyBodyResponse,
		},
		{
			testName:       "Error from HTTP client",
			signature:      "http_error",
			mockResponse:   nil,
			mockError:      errors.New("http client error"),
			expectedResult: false,
			expectedError:  errors.New("http client error"),
		},
		{
			testName:  "Error decoding response body",
			signature: "decode_error",
			mockResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{"simpleReport":`)),
			},
			mockError:      nil,
			expectedResult: false,
			expectedError:  &json.SyntaxError{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			mockClient := &MockClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return tc.mockResponse, tc.mockError
				},
			}

			validator := &ExternalJAdESValidator{
				HttpClient:        mockClient,
				ValidationAddress: "http://localhost/validate",
			}

			result, err := validator.ValidateSignature(tc.signature)

			if result != tc.expectedResult {
				t.Errorf("Expected result %v, but got %v", tc.expectedResult, result)
			}

			if tc.expectedError != nil {
				if err == nil {
					t.Errorf("Expected error %v, but got nil", tc.expectedError)
				} else if err.Error() != tc.expectedError.Error() && tc.expectedError.Error() != (&json.SyntaxError{}).Error() {
					t.Errorf("Expected error %v, but got %v", tc.expectedError, err)
				}
			} else if err != nil {
				t.Errorf("Expected no error, but got %v", err)
			}
		})
	}
}

func TestIsReady(t *testing.T) {
	type test struct {
		testName      string
		mockResponse  *http.Response
		mockError     error
		expectedError error
	}

	tests := []test{
		{
			testName:      "Service is ready",
			mockResponse:  &http.Response{StatusCode: http.StatusOK},
			mockError:     nil,
			expectedError: nil,
		},
		{
			testName:      "Service is not ready",
			mockResponse:  &http.Response{StatusCode: http.StatusInternalServerError},
			mockError:     nil,
			expectedError: ErrorValidationServiceNotReady,
		},
		{
			testName:      "Error from HTTP client",
			mockResponse:  nil,
			mockError:     errors.New("http client error"),
			expectedError: errors.New("http client error"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			mockClient := &MockClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return tc.mockResponse, tc.mockError
				},
			}

			validator := &ExternalJAdESValidator{
				HttpClient:    mockClient,
				HealthAddress: "http://localhost/health",
			}

			err := validator.IsReady()

			if tc.expectedError != nil {
				if err == nil {
					t.Errorf("Expected error %v, but got nil", tc.expectedError)
				} else if err.Error() != tc.expectedError.Error() {
					t.Errorf("Expected error %v, but got %v", tc.expectedError, err)
				}
			} else if err != nil {
				t.Errorf("Expected no error, but got %v", err)
			}
		})
	}
}
