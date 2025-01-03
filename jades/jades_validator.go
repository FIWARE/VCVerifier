package jades

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
)

const TOKEN_EXTRACTION_STRATEGY = "NONE"
const DOCUMENT_NAME = "RemoteDocument"

var ErrorBadResponse = errors.New("bad_response_from_validation_endpoint")
var ErrorEmptyBodyResponse = errors.New("empty_body_response_from_validation_endpoint")
var ErrorValidationServiceNotReady = errors.New("validation_service_not_ready")

type JAdESValidator interface {
	ValidateSignature(signature string) (bool, error)
}

type ExternalJAdESValidator struct {
	HttpClient        common.HttpClient
	ValidationAddress string
	HealthAddress     string
}

type SignedDocument struct {
	Bytes string `json:"bytes"`
	Name  string `json:"name"`
}

type ValidationRequest struct {
	SignedDocument          SignedDocument `json:"signedDocument"`
	TokenExtractionStrategy string         `json:"tokenExtractionStrategy"`
}

type SimpleReport struct {
	DocumentName string `json:"documentName"`
	// we only need to see that all signatures are valid, then nothing else has to be mapped
	ValidSignaturesCount int `json:"validSignaturesCount"`
	SignaturesCount      int `json:"signaturesCount"`
}

type ValidationResponse struct {
	SimpleReport SimpleReport `json:"simpleReport"`
}

func (v *ExternalJAdESValidator) ValidateSignature(signature string) (success bool, err error) {
	validationRequest := ValidationRequest{
		SignedDocument:          SignedDocument{Bytes: signature, Name: DOCUMENT_NAME},
		TokenExtractionStrategy: TOKEN_EXTRACTION_STRATEGY,
	}

	requestBody, err := json.Marshal(validationRequest)
	if err != nil {
		logging.Log().Warnf("Was not able to marshal the validation request. Error: %v", err)
		return success, err
	}

	validationHttpRequest, err := http.NewRequest("POST", v.ValidationAddress, bytes.NewBuffer(requestBody))
	if err != nil {
		logging.Log().Warnf("Was not able to create validation request. Err: %v", err)
		return success, err
	}
	validationHttpRequest.Header.Set("Content-Type", "application/json")
	validationHttpRequest.Header.Set("Accept", "application/json")
	validationHttpResponse, err := v.HttpClient.Do(validationHttpRequest)
	if err != nil {
		logging.Log().Warnf("Did not receive a valid validation response. Err: %v", err)
		return false, err
	}
	if validationHttpResponse.StatusCode != 200 {
		logging.Log().Warnf("Did not receive an OK from the validation endpoint. Was: %v", validationHttpResponse)
		return false, ErrorBadResponse
	}

	if validationHttpResponse.Body == nil {
		logging.Log().Warnf("Received an empty body from the validation endpoint.")
		return false, ErrorEmptyBodyResponse
	}

	validationResponse := &ValidationResponse{}
	err = json.NewDecoder(validationHttpResponse.Body).Decode(validationResponse)
	if err != nil {
		logging.Log().Warnf("Was not able to decode the validation response. Error: %v", err)
		return false, err
	}
	if validationResponse.SimpleReport.SignaturesCount == 0 ||
		(validationResponse.SimpleReport.SignaturesCount != validationResponse.SimpleReport.ValidSignaturesCount) {
		logging.Log().Infof("Signature was invalid.")
		logging.Log().Debugf("Validation report is %s", logging.PrettyPrintObject(validationResponse.SimpleReport))
		return false, err
	}
	return true, err
}

func (v *ExternalJAdESValidator) IsReady() error {
	healthRequest, err := http.NewRequest("GET", v.HealthAddress, nil)
	if err != nil {
		return err
	}
	response, err := v.HttpClient.Do(healthRequest)
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return ErrorValidationServiceNotReady
	}
	return nil
}
