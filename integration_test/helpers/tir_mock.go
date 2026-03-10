package helpers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

// TrustedIssuer mirrors the EBSI TrustedIssuer JSON structure returned by the TIR API.
type TrustedIssuer struct {
	Did        string            `json:"did"`
	Attributes []IssuerAttribute `json:"attributes"`
}

// IssuerAttribute mirrors the EBSI IssuerAttribute JSON structure.
type IssuerAttribute struct {
	Hash       string `json:"hash"`
	Body       string `json:"body"`
	IssuerType string `json:"issuerType"`
	Tao        string `json:"tao"`
	RootTao    string `json:"rootTao"`
}

// TIRCredentialConfig is the JSON structure encoded in the attribute body,
// defining what credential types and claims an issuer is allowed to issue.
type TIRCredentialConfig struct {
	ValidFor        TIRTimeRange `json:"validFor"`
	CredentialsType string       `json:"credentialsType"`
	Claims          []TIRClaim   `json:"claims"`
}

// TIRTimeRange defines a validity time range for issuer credentials.
type TIRTimeRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// TIRClaim defines a claim constraint in the TIR issuer attribute.
type TIRClaim struct {
	Name          string        `json:"name,omitempty"`
	Path          string        `json:"path,omitempty"`
	AllowedValues []interface{} `json:"allowedValues,omitempty"`
}

// BuildIssuerAttribute creates a properly base64-encoded IssuerAttribute
// for the given credential type. Claims can be empty for unrestricted issuers.
func BuildIssuerAttribute(credentialType string, claims []TIRClaim) IssuerAttribute {
	config := TIRCredentialConfig{
		ValidFor: TIRTimeRange{
			From: "2020-01-01T00:00:00Z",
			To:   "2030-12-31T23:59:59Z",
		},
		CredentialsType: credentialType,
		Claims:          claims,
	}

	bodyJSON, _ := json.Marshal(config)
	bodyB64 := base64.StdEncoding.EncodeToString(bodyJSON)

	return IssuerAttribute{
		Hash:       "",
		Body:       bodyB64,
		IssuerType: "legal",
		Tao:        "",
		RootTao:    "",
	}
}

// NewMockTIR creates an httptest.Server that mocks the EBSI Trusted Issuers Registry API.
// The issuers map keys are DIDs and values are the TrustedIssuer responses.
// The mock handles:
//   - GET /v4/issuers/<did> — returns the TrustedIssuer JSON or 404
//   - GET /v3/issuers/<did> — same as v4 (fallback path)
func NewMockTIR(issuers map[string]TrustedIssuer) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Handle v4/issuers/<did> and v3/issuers/<did>
		var did string
		if strings.HasPrefix(path, "/v4/issuers/") {
			did = strings.TrimPrefix(path, "/v4/issuers/")
		} else if strings.HasPrefix(path, "/v3/issuers/") {
			did = strings.TrimPrefix(path, "/v3/issuers/")
		} else {
			http.NotFound(w, r)
			return
		}

		issuer, exists := issuers[did]
		if !exists {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(issuer); err != nil {
			http.Error(w, fmt.Sprintf("encoding issuer response: %v", err), http.StatusInternalServerError)
		}
	})

	return httptest.NewServer(handler)
}
