package helpers

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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

// DidWebTLSServer wraps an HTTPS httptest.Server with the CA certificate path
// needed for the verifier process to trust the server's TLS certificate.
type DidWebTLSServer struct {
	// Server is the running HTTPS test server.
	Server *httptest.Server
	// CACertPath is the path to a PEM file containing the server's certificate,
	// suitable for use as SSL_CERT_FILE environment variable.
	CACertPath string
}

// Close shuts down the TLS server and removes the temporary CA certificate file.
func (s *DidWebTLSServer) Close() {
	s.Server.Close()
	if s.CACertPath != "" {
		os.Remove(s.CACertPath)
	}
}

// NewDidWebTLSServer creates an HTTPS httptest.Server that serves a DID document for did:web resolution.
// The verifier's did:web resolver uses HTTPS by default, so this TLS variant is required for integration tests.
// The server's self-signed certificate is exported to a temporary PEM file accessible via CACertPath.
// Pass "SSL_CERT_FILE=<CACertPath>" as an extra env var to StartVerifier so the verifier trusts this server.
func NewDidWebTLSServer(identity *TestIdentity) *DidWebTLSServer {
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

	server := httptest.NewTLSServer(handler)

	// Export the server's certificate as a PEM file so the verifier process can trust it.
	cert := server.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	certFile, err := os.CreateTemp("", "did-web-ca-*.pem")
	if err != nil {
		panic(fmt.Sprintf("creating temp cert file: %v", err))
	}
	if _, err := certFile.Write(certPEM); err != nil {
		panic(fmt.Sprintf("writing cert PEM: %v", err))
	}
	certFile.Close()

	return &DidWebTLSServer{
		Server:     server,
		CACertPath: certFile.Name(),
	}
}

// HostFromURL extracts the host:port from an httptest.Server URL (e.g., "https://127.0.0.1:12345" -> "127.0.0.1:12345").
func HostFromURL(serverURL string) string {
	// Strip the scheme (http:// or https://)
	for _, prefix := range []string{"https://", "http://"} {
		if len(serverURL) > len(prefix) && serverURL[:len(prefix)] == prefix {
			return serverURL[len(prefix):]
		}
	}
	return serverURL
}

// SetupDidWebTLSIdentity creates a did:web identity and a matching TLS server in a single step.
// This solves the chicken-and-egg problem: the DID contains the server's host:port, but the
// server needs the identity to serve the DID document. It uses a dynamic handler that is
// updated after the server starts and the host is known.
func SetupDidWebTLSIdentity() (*TestIdentity, *DidWebTLSServer) {
	// Use a dynamic DID document that is set after we know the server's URL.
	var didDocBytes []byte

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/did.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(didDocBytes)
	})

	server := httptest.NewTLSServer(handler)
	host := HostFromURL(server.URL)

	identity, err := GenerateDidWebIdentity(host)
	if err != nil {
		server.Close()
		panic(fmt.Sprintf("generating did:web identity: %v", err))
	}

	// Build the DID document now that we have the identity.
	didDocBytes = buildDIDDocumentJSON(identity)

	// Export the server's certificate as a PEM file.
	cert := server.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	certFile, err := os.CreateTemp("", "did-web-ca-*.pem")
	if err != nil {
		server.Close()
		panic(fmt.Sprintf("creating temp cert file: %v", err))
	}
	if _, err := certFile.Write(certPEM); err != nil {
		server.Close()
		panic(fmt.Sprintf("writing cert PEM: %v", err))
	}
	certFile.Close()

	return identity, &DidWebTLSServer{
		Server:     server,
		CACertPath: certFile.Name(),
	}
}

// buildDIDDocumentJSON constructs the DID document JSON for the given identity.
func buildDIDDocumentJSON(identity *TestIdentity) []byte {
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

	docBytes, err := json.Marshal(didDoc)
	if err != nil {
		panic(fmt.Sprintf("marshaling DID document: %v", err))
	}
	return docBytes
}
