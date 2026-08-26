package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Well-known endpoint paths for HTTPS-based issuer metadata discovery.
const (
	// WellKnownJwtVcIssuerPath is the path for SD-JWT VC Issuer Metadata.
	WellKnownJwtVcIssuerPath = "/.well-known/jwt-vc-issuer"

	// WellKnownOIDCCredentialIssuerPath is the path for OpenID4VCI Credential Issuer Metadata.
	WellKnownOIDCCredentialIssuerPath = "/.well-known/openid-credential-issuer"

	// WellKnownOAuthAuthzServerPath is the path for OAuth 2.0 Authorization Server Metadata.
	WellKnownOAuthAuthzServerPath = "/.well-known/oauth-authorization-server"

	// JwksPath is the default path for serving the JSON Web Key Set.
	JwksPath = "/jwks"
)

// HttpsIssuerIdentity holds the key material and DID-less identity for an HTTPS-based
// issuer. Unlike DID-based identities, the issuer is identified by its HTTPS URL.
type HttpsIssuerIdentity struct {
	// PrivateKey is the ECDSA private key for signing credentials.
	PrivateKey *ecdsa.PrivateKey
	// PublicKeyJWK is the public key in JWK format (lestrrat-go/jwx).
	PublicKeyJWK jwk.Key
	// IssuerURL is the HTTPS URL identifying this issuer (set after the test server starts).
	IssuerURL string
	// KeyID is the key identifier used in the JWKS and JWT headers.
	KeyID string
}

// GenerateHttpsIssuerIdentity creates a new ECDSA P-256 key pair for an HTTPS-based issuer.
// The IssuerURL is left empty and must be set after the test server starts.
func GenerateHttpsIssuerIdentity() (*HttpsIssuerIdentity, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA P-256 key: %w", err)
	}

	jwxKey, err := jwk.Import(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("importing public key to jwx JWK: %w", err)
	}
	if err := jwk.AssignKeyID(jwxKey); err != nil {
		return nil, fmt.Errorf("assigning key ID: %w", err)
	}

	keyID, _ := jwxKey.KeyID()

	return &HttpsIssuerIdentity{
		PrivateKey:   privateKey,
		PublicKeyJWK: jwxKey,
		KeyID:        keyID,
	}, nil
}

// HttpsIssuerServer wraps an httptest.Server configured to serve HTTPS issuer
// metadata (/.well-known/jwt-vc-issuer) and a JWKS endpoint.
type HttpsIssuerServer struct {
	// Server is the running HTTP test server.
	Server *httptest.Server
	// Identity holds the issuer's key material with IssuerURL populated.
	Identity *HttpsIssuerIdentity
}

// Close shuts down the test server.
func (s *HttpsIssuerServer) Close() {
	s.Server.Close()
}

// URL returns the base URL of the test server (the issuer URL).
func (s *HttpsIssuerServer) URL() string {
	return s.Server.URL
}

// NewHttpsIssuerServer creates an httptest.Server that serves SD-JWT VC issuer
// metadata at /.well-known/jwt-vc-issuer (with jwks_uri pointing to /jwks)
// and a JWKS endpoint at /jwks. This simulates the primary metadata resolution
// path for HTTPS-based credential issuers.
func NewHttpsIssuerServer(identity *HttpsIssuerIdentity) *HttpsIssuerServer {
	// We need a dynamic handler because the server URL is not known until it starts.
	var issuerURL string
	var jwksBytes []byte

	mux := http.NewServeMux()

	mux.HandleFunc(WellKnownJwtVcIssuerPath, func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]interface{}{
			"issuer":   issuerURL,
			"jwks_uri": issuerURL + JwksPath,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	mux.HandleFunc(JwksPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBytes)
	})

	server := httptest.NewServer(mux)
	issuerURL = server.URL
	identity.IssuerURL = issuerURL

	// Build JWKS containing the issuer's public key.
	keySet := jwk.NewSet()
	keySet.AddKey(identity.PublicKeyJWK)
	jwksBytes, _ = json.Marshal(keySet)

	return &HttpsIssuerServer{
		Server:   server,
		Identity: identity,
	}
}

// NewHttpsIssuerServerWithInlineJWKS creates an httptest.Server that serves SD-JWT VC
// issuer metadata at /.well-known/jwt-vc-issuer with inline jwks (no jwks_uri).
// This tests the inline JWKS resolution path.
func NewHttpsIssuerServerWithInlineJWKS(identity *HttpsIssuerIdentity) *HttpsIssuerServer {
	var issuerURL string

	keySet := jwk.NewSet()
	keySet.AddKey(identity.PublicKeyJWK)
	jwksBytes, _ := json.Marshal(keySet)

	mux := http.NewServeMux()

	mux.HandleFunc(WellKnownJwtVcIssuerPath, func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]interface{}{
			"issuer": issuerURL,
			"jwks":   json.RawMessage(jwksBytes),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	server := httptest.NewServer(mux)
	issuerURL = server.URL
	identity.IssuerURL = issuerURL

	return &HttpsIssuerServer{
		Server:   server,
		Identity: identity,
	}
}

// OidcIssuerServer wraps an httptest.Server configured to serve OpenID4VCI credential
// issuer metadata (/.well-known/openid-credential-issuer) with authorization_servers,
// and a companion OAuth authorization server metadata endpoint.
type OidcIssuerServer struct {
	// IssuerServer is the credential issuer server.
	IssuerServer *httptest.Server
	// AuthServer is the OAuth authorization server (may be the same as IssuerServer).
	AuthServer *httptest.Server
	// Identity holds the issuer's key material with IssuerURL populated.
	Identity *HttpsIssuerIdentity
}

// Close shuts down both test servers.
func (s *OidcIssuerServer) Close() {
	s.IssuerServer.Close()
	if s.AuthServer != s.IssuerServer {
		s.AuthServer.Close()
	}
}

// URL returns the base URL of the credential issuer server.
func (s *OidcIssuerServer) URL() string {
	return s.IssuerServer.URL
}

// NewOidcIssuerServer creates test servers simulating the OpenID4VCI fallback path:
//   - The credential issuer server serves /.well-known/openid-credential-issuer with
//     authorization_servers pointing to the auth server.
//   - The auth server serves /.well-known/oauth-authorization-server with jwks_uri
//     and /jwks with the issuer's public key.
//
// This simulates the fallback metadata resolution path for HTTPS-based credential issuers.
func NewOidcIssuerServer(identity *HttpsIssuerIdentity) *OidcIssuerServer {
	var authServerURL string
	var jwksBytes []byte

	// Auth server: serves OAuth metadata and JWKS
	authMux := http.NewServeMux()

	authMux.HandleFunc(WellKnownOAuthAuthzServerPath, func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]interface{}{
			"issuer":   authServerURL,
			"jwks_uri": authServerURL + JwksPath,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	authMux.HandleFunc(JwksPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBytes)
	})

	authServer := httptest.NewServer(authMux)
	authServerURL = authServer.URL

	// Build JWKS
	keySet := jwk.NewSet()
	keySet.AddKey(identity.PublicKeyJWK)
	jwksBytes, _ = json.Marshal(keySet)

	// Credential issuer server: serves OpenID credential issuer metadata
	var issuerURL string
	issuerMux := http.NewServeMux()

	issuerMux.HandleFunc(WellKnownOIDCCredentialIssuerPath, func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]interface{}{
			"issuer":                issuerURL,
			"authorization_servers": []string{authServerURL},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	issuerServer := httptest.NewServer(issuerMux)
	issuerURL = issuerServer.URL
	identity.IssuerURL = issuerURL

	return &OidcIssuerServer{
		IssuerServer: issuerServer,
		AuthServer:   authServer,
		Identity:     identity,
	}
}

// SignJWTWithHttpsIssuer signs a JWT token using the HTTPS issuer's private key.
// The JWT header uses the issuer's key ID and the iss claim is set to the issuer URL.
func SignJWTWithHttpsIssuer(token jwt.Token, identity *HttpsIssuerIdentity) (string, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, identity.KeyID); err != nil {
		return "", fmt.Errorf("setting kid header: %w", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), identity.PrivateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("signing JWT with HTTPS issuer: %w", err)
	}

	return string(signed), nil
}

// CreateJWTVCWithHttpsIssuer creates a signed JWT-VC (Verifiable Credential in JWT format)
// where the issuer is an HTTPS URL instead of a DID. The iss claim is set to the issuer's
// HTTPS URL, and the JWT is signed with the issuer's private key.
func CreateJWTVCWithHttpsIssuer(identity *HttpsIssuerIdentity, credType string, subject map[string]interface{}) (string, error) {
	now := time.Now()

	credentialSubject := make(map[string]interface{}, len(subject))
	for k, v := range subject {
		credentialSubject[k] = v
	}

	vcClaim := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1",
		},
		"type":              []string{"VerifiableCredential", credType},
		"credentialSubject": credentialSubject,
	}

	builder := jwt.NewBuilder().
		Issuer(identity.IssuerURL).
		IssuedAt(now).
		Expiration(now.Add(24 * time.Hour))
	builder.Claim("vc", vcClaim)

	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("building JWT-VC token: %w", err)
	}

	return SignJWTWithHttpsIssuer(token, identity)
}
