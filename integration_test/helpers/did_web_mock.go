package helpers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
)

// DIDDocument represents a minimal DID document for did:web resolution.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication"`
	AssertionMethod    []string             `json:"assertionMethod"`
}

// VerificationMethod represents a public key entry in a DID document.
type VerificationMethod struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Controller   string                 `json:"controller"`
	PublicKeyJwk map[string]interface{} `json:"publicKeyJwk"`
}

// NewDidWebServer creates an httptest.Server that serves a DID document for did:web resolution.
// The server responds to GET /.well-known/did.json with the identity's DID document.
// Returns the server. The caller should use the server's URL host (without scheme)
// to construct the did:web DID via GenerateDidWebIdentity.
func NewDidWebServer(identity *TestIdentity) *httptest.Server {
	// Convert the public key JWK to a map for embedding in the DID document.
	jwkBytes, err := json.Marshal(identity.PublicKeyJWK)
	if err != nil {
		panic(fmt.Sprintf("marshaling public key JWK: %v", err))
	}
	var jwkMap map[string]interface{}
	if err := json.Unmarshal(jwkBytes, &jwkMap); err != nil {
		panic(fmt.Sprintf("unmarshaling public key JWK: %v", err))
	}

	didDoc := DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID: identity.DID,
		VerificationMethod: []VerificationMethod{
			{
				ID:           identity.KeyID,
				Type:         "JsonWebKey2020",
				Controller:   identity.DID,
				PublicKeyJwk: jwkMap,
			},
		},
		Authentication:  []string{identity.KeyID},
		AssertionMethod: []string{identity.KeyID},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/did.json" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(didDoc); err != nil {
			http.Error(w, fmt.Sprintf("encoding DID document: %v", err), http.StatusInternalServerError)
		}
	})

	return httptest.NewServer(handler)
}
