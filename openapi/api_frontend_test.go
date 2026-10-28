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
	"github.com/fiware/VCVerifier/verifier"
	"github.com/foolin/goview"

	"github.com/foolin/goview/supports/ginview"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
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
			if err := json.Unmarshal(errorBody, &errorMessage); err != nil {
				t.Fatalf("Failed to unmarshal error response: %v", err)
			}
			if errorMessage != tc.expectedError {
				t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
				continue
			}
			continue
		}
	}
}

func TestVerifierPageDisplayQRSIOP_PassesPKCE(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	recorder := httptest.NewRecorder()
	testContext, engine := gin.CreateTestContext(recorder)
	engine.HTMLRender = ginview.Default()

	expectedPKCE := verifier.PKCEChallenge{
		Value:        strings.Repeat("a", 43),
		Method:       verifier.PKCES256,
		ChallengeSet: true,
		MethodSet:    true,
	}
	mock := &mockVerifier{mockQR: "openid://mockConnectionString"}
	frontendVerifier = mock
	t.Cleanup(func() { frontendVerifier = nil })

	testContext.Request, _ = http.NewRequest(
		"GET",
		"https://verifier.org/api/v1/loginQR?state=state&client_callback=https://rp.example/callback&code_challenge="+expectedPKCE.Value+"&code_challenge_method="+expectedPKCE.Method,
		nil,
	)
	VerifierPageDisplayQRSIOP(testContext)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, expectedPKCE, mock.mockReceivedPKCE)
}

// TestVerifierLoginQr_HandsThePageItsSecret checks that the v2 login page carries the secret its
// WebSocket authenticates with, and that no cache may keep the page.
func TestVerifierLoginQr_HandsThePageItsSecret(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	recorder := httptest.NewRecorder()
	testContext, engine := gin.CreateTestContext(recorder)
	engine.HTMLRender = ginview.New(goview.Config{Root: "../views", Extension: ".html", DisableCache: true})

	pkce := verifier.PKCEChallenge{Value: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", Method: verifier.PKCES256, ChallengeSet: true, MethodSet: true}
	frontendVerifier = &mockVerifier{mockHost: "https://verifier.org", mockRequestMode: "urlEncoded",
		mockQRInfo: &verifier.QRLoginInfo{SessionId: "the-session", PageSecret: "the-page-secret", QR: "data:image/png;base64,"}}
	t.Cleanup(func() { frontendVerifier = nil })

	testContext.Request, _ = http.NewRequest("GET", "https://verifier.org/api/v2/loginQR?state=my-state&redirect_uri=https://rp.example/callback&client_id=client&code_challenge="+pkce.Value+"&code_challenge_method="+pkce.Method, nil)
	VerifierLoginQr(testContext)

	if recorder.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	assert.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
	assert.Contains(t, recorder.Body.String(), `<meta name="wsSecret" content="the-page-secret">`)
	assert.Contains(t, recorder.Body.String(), `<meta name="wsUrl" content="https://verifier.org/ws?state=the-session">`)
	assert.Equal(t, pkce, frontendVerifier.(*mockVerifier).mockReceivedPKCE)
}
