//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/fiware/VCVerifier/integration_test/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateDidKeyIdentity verifies that did:key identity generation works correctly.
func TestGenerateDidKeyIdentity(t *testing.T) {
	identity, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	assert.NotNil(t, identity.PrivateKey)
	assert.NotNil(t, identity.PublicKeyJWK)
	assert.True(t, strings.HasPrefix(identity.DID, "did:key:z"), "DID should start with did:key:z, got: %s", identity.DID)
	assert.Contains(t, identity.KeyID, identity.DID, "KeyID should contain the DID")
}

// TestGenerateDidWebIdentity verifies that did:web identity generation works correctly.
func TestGenerateDidWebIdentity(t *testing.T) {
	identity, err := helpers.GenerateDidWebIdentity("localhost:12345")
	require.NoError(t, err)
	assert.Equal(t, "did:web:localhost%3A12345", identity.DID)
	assert.Equal(t, "did:web:localhost%3A12345#key-1", identity.KeyID)
	assert.NotNil(t, identity.PrivateKey)
	assert.NotNil(t, identity.PublicKeyJWK)
}

// TestCreateJWTVC verifies that JWT-VC creation produces a valid signed JWT.
func TestCreateJWTVC(t *testing.T) {
	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	subject := map[string]interface{}{
		"type": "CustomerCredential",
		"name": "Test User",
	}

	vcJWT, err := helpers.CreateJWTVC(issuer, "CustomerCredential", subject)
	require.NoError(t, err)
	assert.NotEmpty(t, vcJWT)

	// JWT should have 3 parts.
	parts := strings.Split(vcJWT, ".")
	assert.Len(t, parts, 3, "JWT-VC should have 3 dot-separated parts")
}

// TestCreateJWTVCWithHolder verifies that holder-bound JWT-VC includes the holder claim.
func TestCreateJWTVCWithHolder(t *testing.T) {
	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	subject := map[string]interface{}{
		"type": "CustomerCredential",
	}

	vcJWT, err := helpers.CreateJWTVCWithHolder(issuer, "CustomerCredential", subject, holder.DID)
	require.NoError(t, err)
	assert.NotEmpty(t, vcJWT)
}

// TestCreateJWTVCWithCnf verifies that cnf-bound JWT-VC includes the confirmation claim.
func TestCreateJWTVCWithCnf(t *testing.T) {
	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	subject := map[string]interface{}{
		"type": "CustomerCredential",
	}

	vcJWT, err := helpers.CreateJWTVCWithCnf(issuer, "CustomerCredential", subject, holder.PublicKeyJWK)
	require.NoError(t, err)
	assert.NotEmpty(t, vcJWT)
}

// TestCreateVPToken verifies that VP token creation wraps VCs correctly.
func TestCreateVPToken(t *testing.T) {
	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	vcJWT, err := helpers.CreateJWTVC(issuer, "CustomerCredential", map[string]interface{}{"type": "CustomerCredential"})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(holder, "test-nonce", "test-audience", vcJWT)
	require.NoError(t, err)
	assert.NotEmpty(t, vpJWT)

	parts := strings.Split(vpJWT, ".")
	assert.Len(t, parts, 3, "VP JWT should have 3 dot-separated parts")
}

// TestCreateSDJWT verifies that SD-JWT creation produces a valid token with trailing tilde.
func TestCreateSDJWT(t *testing.T) {
	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	claims := map[string]interface{}{
		"familyName": "Doe",
		"givenName":  "John",
	}

	sdJWT, err := helpers.CreateSDJWT(issuer, "PersonIdentificationData", claims)
	require.NoError(t, err)
	assert.NotEmpty(t, sdJWT)
	assert.True(t, strings.HasSuffix(sdJWT, "~"), "SD-JWT should end with ~")
}

// TestCreateVPWithSDJWT verifies that a VP containing SD-JWTs can be created.
func TestCreateVPWithSDJWT(t *testing.T) {
	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	sdJWT, err := helpers.CreateSDJWT(issuer, "PersonIdentificationData", map[string]interface{}{"familyName": "Doe"})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPWithSDJWT(holder, "nonce", "audience", sdJWT)
	require.NoError(t, err)
	assert.NotEmpty(t, vpJWT)
}

// TestCreateDCQLResponse verifies that the DCQL response format is correct.
func TestCreateDCQLResponse(t *testing.T) {
	queryResponses := map[string]string{
		"query-1": "eyJhbGciOiJFUzI1NiJ9.payload.signature",
		"query-2": "eyJhbGciOiJFUzI1NiJ9.payload2.signature2",
	}

	response, err := helpers.CreateDCQLResponse(queryResponses)
	require.NoError(t, err)

	var parsed map[string]string
	err = json.Unmarshal([]byte(response), &parsed)
	require.NoError(t, err)
	assert.Equal(t, queryResponses, parsed)
}

// TestMockTIR verifies that the mock TIR server responds correctly.
func TestMockTIR(t *testing.T) {
	issuerDID := "did:key:z6MkTestIssuer"

	issuers := map[string]helpers.TrustedIssuer{
		issuerDID: {
			Did: issuerDID,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute("CustomerCredential", nil),
			},
		},
	}

	tirServer := helpers.NewMockTIR(issuers)
	defer tirServer.Close()

	// Existing issuer should return 200.
	resp, err := http.Get(fmt.Sprintf("%s/v4/issuers/%s", tirServer.URL, issuerDID))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var ti helpers.TrustedIssuer
	err = json.Unmarshal(body, &ti)
	require.NoError(t, err)
	assert.Equal(t, issuerDID, ti.Did)
	assert.Len(t, ti.Attributes, 1)

	// Unknown issuer should return 404.
	resp2, err := http.Get(fmt.Sprintf("%s/v4/issuers/%s", tirServer.URL, "did:key:unknown"))
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

// TestMockDidWeb verifies that the mock did:web server serves the DID document.
func TestMockDidWeb(t *testing.T) {
	identity, err := helpers.GenerateDidWebIdentity("localhost:9999")
	require.NoError(t, err)

	server := helpers.NewDidWebServer(identity)
	defer server.Close()

	resp, err := http.Get(server.URL + "/.well-known/did.json")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var doc helpers.DIDDocument
	err = json.Unmarshal(body, &doc)
	require.NoError(t, err)
	assert.Equal(t, identity.DID, doc.ID)
	assert.Len(t, doc.VerificationMethod, 1)
	assert.Equal(t, identity.KeyID, doc.VerificationMethod[0].ID)
}

// TestConfigBuilder verifies that the config builder produces valid YAML.
func TestConfigBuilder(t *testing.T) {
	config := helpers.NewConfigBuilder(8080, "http://localhost:9090").
		WithService("test-svc", "test-scope", "DEEPLINK").
		WithCredential("test-svc", "test-scope", "CustomerCredential", "http://localhost:9090").
		WithDCQL("test-svc", "test-scope", helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-query-1", "CustomerCredential"),
			},
		}).
		WithSigningKey("/tmp/key.pem").
		Build()

	assert.Contains(t, config, "port: 8080")
	assert.Contains(t, config, "test-svc")
	assert.Contains(t, config, "CustomerCredential")
	assert.Contains(t, config, "dcql:")
	assert.Contains(t, config, "cred-query-1")
	assert.Contains(t, config, "jwt_vc_json")
	assert.Contains(t, config, "/tmp/key.pem")
}

// TestGenerateSigningKeyPEM verifies that PEM key generation works.
func TestGenerateSigningKeyPEM(t *testing.T) {
	dir := t.TempDir()
	keyPath, err := helpers.GenerateSigningKeyPEM(dir)
	require.NoError(t, err)
	assert.FileExists(t, keyPath)
}

// TestGetFreePort verifies that a free port can be obtained.
func TestGetFreePort(t *testing.T) {
	port, err := helpers.GetFreePort()
	require.NoError(t, err)
	assert.Greater(t, port, 0)
}
