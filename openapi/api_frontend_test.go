package openapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fiware/VCVerifier/logging"

	"github.com/foolin/goview/supports/ginview"
	"github.com/gin-gonic/gin"
)

func TestVerifierPageDisplayQRSIOP(t *testing.T) {

	logging.Configure(LOGGING_CONFIG)

	type test struct {
		testName           string
		testState          string
		testCallback       string
		testAddress        string
		mockQR             string
		mockError          error
		expectedStatusCode int
		expectedError      ErrorMessage
	}

	tests := []test{
		{"If all parameters are present, a siop flow should be started.", "my-state", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", nil, 200, ErrorMessage{}},
		{"If no state is present, a 400 should be returned.", "", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", nil, 400, ErrorMessageNoState},
		{"If no callback is present, a 400 should be returned.", "my-state", "", "http://my-verifier.org", "openid://mockConnectionString", nil, 400, ErrorMessageNoCallback},
		{"If the verifier cannot start the flow, a 500 should be returend.", "my-state", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", errors.New("verifier_failure"), 500, ErrorMessageNoState},
	}

	for _, tc := range tests {

		logging.Log().Info("TestVerifierPageDisplayQRSIOP +++++++++++++++++ Running test: ", tc.testName)

		recorder := httptest.NewRecorder()
		testContext, engine := gin.CreateTestContext(recorder)

		engine.HTMLRender = ginview.Default()

		frontendVerifier = &mockVerifier{mockQR: tc.mockQR, mockError: tc.mockError}

		testParameters := []string{}
		if tc.testState != "" {
			testParameters = append(testParameters, "state="+tc.testState)
		}
		if tc.testCallback != "" {
			testParameters = append(testParameters, "client_callback="+tc.testCallback)
		}

		testContext.Request, _ = http.NewRequest("GET", tc.testAddress+"/?"+strings.Join(testParameters, "&"), nil)
		VerifierPageDisplayQRSIOP(testContext)

		if recorder.Code != tc.expectedStatusCode {
			t.Errorf("%s - Expected code %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
			continue
		}
		if tc.expectedStatusCode == 500 {
			// something internal, we dont care about the details
			continue
		}

		if tc.expectedStatusCode == 400 {
			errorBody, _ := io.ReadAll(recorder.Body)
			errorMessage := ErrorMessage{}
			json.Unmarshal(errorBody, &errorMessage)
			if errorMessage != tc.expectedError {
				t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
				continue
			}
			continue
		}
	}
}
