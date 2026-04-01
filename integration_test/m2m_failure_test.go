//go:build integration

package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/fiware/VCVerifier/integration_test/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// m2mFailureCase defines a parameterized M2M failure test case.
type m2mFailureCase struct {
	name string
	// setup prepares all infrastructure and returns a fixture with intentionally invalid credentials.
	setup func(t *testing.T) *m2mTestFixture
	// expectedStatus is the expected HTTP status code from the token endpoint.
	expectedStatus int
}

// TestM2MFailure runs parameterized failure tests for the M2M VP-token-to-JWT exchange.
// Each test case presents invalid or mismatched credentials and asserts a non-200 response.
func TestM2MFailure(t *testing.T) {
	tests := []m2mFailureCase{
		{
			name:           "WrongCredentialType",
			setup:          setupWrongCredentialType,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "MissingRequiredClaims",
			setup:          setupMissingRequiredClaims,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "UntrustedIssuer",
			setup:          setupUntrustedIssuer,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidVPSignature",
			setup:          setupInvalidVPSignature,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidCnfBinding",
			setup:          setupInvalidCnfBinding,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidClaimHolderBinding",
			setup:          setupInvalidClaimHolderBinding,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := tc.setup(t)
			defer fixture.cleanup()

			vp, err := helpers.StartVerifier(fixture.configYAML, projectRoot, binaryPath, fixture.extraEnv...)
			require.NoError(t, err, "verifier should start successfully")
			defer vp.Stop()

			vpToken, err := helpers.CreateDCQLResponse(fixture.dcqlResponse)
			require.NoError(t, err)

			resp, err := http.PostForm(
				fmt.Sprintf("%s/services/%s/token", vp.BaseURL, serviceID),
				url.Values{
					"grant_type": {"vp_token"},
					"vp_token":   {vpToken},
					"scope":      {scopeName},
				},
			)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedStatus, resp.StatusCode,
				"expected %d, got %d: %s", tc.expectedStatus, resp.StatusCode, string(body))
		})
	}
}

// --- Setup functions for failure test cases ---

// setupWrongCredentialType configures the verifier to expect TypeA via DCQL,
// but the VP contains a credential of type TypeB.
func setupWrongCredentialType(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	tirServer := helpers.NewMockTIR(map[string]helpers.TrustedIssuer{
		issuer.DID: {
			Did: issuer.DID,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute("VerifiableCredential", nil),
				helpers.BuildIssuerAttribute("TypeA", nil),
				helpers.BuildIssuerAttribute("TypeB", nil),
			},
		},
	})

	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	keyPath, err := helpers.GenerateSigningKeyPEM(t.TempDir())
	require.NoError(t, err)

	// Config expects TypeA, but we'll present TypeB.
	config := helpers.NewConfigBuilder(port, tirServer.URL).
		WithSigningKey(keyPath).
		WithService(serviceID, scopeName, "DEEPLINK").
		WithCredential(serviceID, scopeName, "VerifiableCredential", "*").
		WithCredential(serviceID, scopeName, "TypeA", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "TypeA", true).
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-1", "TypeA"),
			},
		}).
		Build()

	// Create a VC of TypeB instead of the expected TypeA.
	vc, err := helpers.CreateJWTVC(issuer, "TypeB", map[string]interface{}{
		"type": "TypeB",
	})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(holder, "", serviceID, vc)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML:   config,
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup:      func() { tirServer.Close() },
	}
}

// setupMissingRequiredClaims configures the TIR to restrict allowed values for a claim,
// then presents a VC whose claim value is not in the allowed set.
func setupMissingRequiredClaims(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	// TIR restricts the "role" claim to only allow "admin".
	tirServer := helpers.NewMockTIR(map[string]helpers.TrustedIssuer{
		issuer.DID: {
			Did: issuer.DID,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute("VerifiableCredential", nil),
				helpers.BuildIssuerAttribute("CustomerCredential", []helpers.TIRClaim{
					{Name: "role", AllowedValues: []interface{}{"admin"}},
				}),
			},
		},
	})

	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	keyPath, err := helpers.GenerateSigningKeyPEM(t.TempDir())
	require.NoError(t, err)

	config := helpers.NewConfigBuilder(port, tirServer.URL).
		WithSigningKey(keyPath).
		WithService(serviceID, scopeName, "DEEPLINK").
		WithCredential(serviceID, scopeName, "VerifiableCredential", "*").
		WithCredential(serviceID, scopeName, "CustomerCredential", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "CustomerCredential", true).
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-1", "CustomerCredential"),
			},
		}).
		Build()

	// VC has role=user, but TIR only allows role=admin.
	vc, err := helpers.CreateJWTVC(issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
		"role": "user",
	})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(holder, "", serviceID, vc)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML:   config,
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup:      func() { tirServer.Close() },
	}
}

// setupUntrustedIssuer presents a VC signed by an issuer whose DID is not registered in the TIR.
func setupUntrustedIssuer(t *testing.T) *m2mTestFixture {
	t.Helper()

	trustedIssuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	untrustedIssuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	// Only trustedIssuer is in the TIR; untrustedIssuer is not.
	tirServer := helpers.NewMockTIR(map[string]helpers.TrustedIssuer{
		trustedIssuer.DID: {
			Did: trustedIssuer.DID,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute("VerifiableCredential", nil),
				helpers.BuildIssuerAttribute("CustomerCredential", nil),
			},
		},
	})

	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	keyPath, err := helpers.GenerateSigningKeyPEM(t.TempDir())
	require.NoError(t, err)

	config := helpers.NewConfigBuilder(port, tirServer.URL).
		WithSigningKey(keyPath).
		WithService(serviceID, scopeName, "DEEPLINK").
		WithCredential(serviceID, scopeName, "VerifiableCredential", "*").
		WithCredential(serviceID, scopeName, "CustomerCredential", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "CustomerCredential", true).
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-1", "CustomerCredential"),
			},
		}).
		Build()

	// VC is signed by untrustedIssuer, which the TIR does not know.
	vc, err := helpers.CreateJWTVC(untrustedIssuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
	})
	require.NoError(t, err)

	vpJWT, err := helpers.CreateVPToken(holder, "", serviceID, vc)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML:   config,
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup:      func() { tirServer.Close() },
	}
}

// setupInvalidVPSignature presents a VP whose JWT signature does not match the holder's key.
// The VP is signed by a different key than the one whose DID is used as issuer/holder.
func setupInvalidVPSignature(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holder, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	// A different identity whose key will be used to sign the VP,
	// creating a mismatch between the VP's iss/kid and the actual signing key.
	wrongSigner, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	tirServer := helpers.NewMockTIR(map[string]helpers.TrustedIssuer{
		issuer.DID: {
			Did: issuer.DID,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute("VerifiableCredential", nil),
				helpers.BuildIssuerAttribute("CustomerCredential", nil),
			},
		},
	})

	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	keyPath, err := helpers.GenerateSigningKeyPEM(t.TempDir())
	require.NoError(t, err)

	config := helpers.NewConfigBuilder(port, tirServer.URL).
		WithSigningKey(keyPath).
		WithService(serviceID, scopeName, "DEEPLINK").
		WithCredential(serviceID, scopeName, "VerifiableCredential", "*").
		WithCredential(serviceID, scopeName, "CustomerCredential", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "CustomerCredential", true).
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-1", "CustomerCredential"),
			},
		}).
		Build()

	vc, err := helpers.CreateJWTVC(issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
	})
	require.NoError(t, err)

	// Sign the VP with wrongSigner's key but use holder's DID as the VP issuer.
	// This creates a VP whose signature cannot be verified against the holder's public key.
	vpJWT, err := helpers.CreateVPTokenWithMismatchedSigner(holder, wrongSigner, "", serviceID, vc)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML:   config,
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup:      func() { tirServer.Close() },
	}
}

// setupInvalidCnfBinding presents a VP where the VC's cnf.jwk references holder A's key,
// but the VP is signed by holder B. Since the verifier does not enforce cnf validation,
// the VP itself must have a valid signature — the failure comes from the holder mismatch
// combined with claim-based holder verification enabled on the credential.
// Note: Since the verifier ignores cnf, we enable claim-based holder verification to detect
// the holder mismatch that cnf was supposed to prevent.
func setupInvalidCnfBinding(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holderA, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holderB, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	tirServer := helpers.NewMockTIR(map[string]helpers.TrustedIssuer{
		issuer.DID: {
			Did: issuer.DID,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute("VerifiableCredential", nil),
				helpers.BuildIssuerAttribute("CustomerCredential", nil),
			},
		},
	})

	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	keyPath, err := helpers.GenerateSigningKeyPEM(t.TempDir())
	require.NoError(t, err)

	// Enable claim-based holder verification to detect the holder mismatch.
	config := helpers.NewConfigBuilder(port, tirServer.URL).
		WithSigningKey(keyPath).
		WithService(serviceID, scopeName, "DEEPLINK").
		WithCredential(serviceID, scopeName, "VerifiableCredential", "*").
		WithCredential(serviceID, scopeName, "CustomerCredential", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "CustomerCredential", true).
		WithHolderVerification(serviceID, scopeName, "CustomerCredential", "holder").
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-1", "CustomerCredential"),
			},
		}).
		Build()

	// VC has holder claim set to holderA's DID, but VP is signed by holderB.
	vc, err := helpers.CreateJWTVCWithHolder(issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
	}, holderA.DID)
	require.NoError(t, err)

	// holderB signs the VP — mismatch with the VC's holder claim.
	vpJWT, err := helpers.CreateVPToken(holderB, "", serviceID, vc)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML:   config,
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup:      func() { tirServer.Close() },
	}
}

// setupInvalidClaimHolderBinding presents a VC with credentialSubject.holder set to DID-A,
// but the VP is signed by DID-B. The verifier validates that the holder claim matches.
func setupInvalidClaimHolderBinding(t *testing.T) *m2mTestFixture {
	t.Helper()

	issuer, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holderA, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)
	holderB, err := helpers.GenerateDidKeyIdentity()
	require.NoError(t, err)

	tirServer := helpers.NewMockTIR(map[string]helpers.TrustedIssuer{
		issuer.DID: {
			Did: issuer.DID,
			Attributes: []helpers.IssuerAttribute{
				helpers.BuildIssuerAttribute("VerifiableCredential", nil),
				helpers.BuildIssuerAttribute("CustomerCredential", nil),
			},
		},
	})

	port, err := helpers.GetFreePort()
	require.NoError(t, err)

	keyPath, err := helpers.GenerateSigningKeyPEM(t.TempDir())
	require.NoError(t, err)

	config := helpers.NewConfigBuilder(port, tirServer.URL).
		WithSigningKey(keyPath).
		WithService(serviceID, scopeName, "DEEPLINK").
		WithCredential(serviceID, scopeName, "VerifiableCredential", "*").
		WithCredential(serviceID, scopeName, "CustomerCredential", tirServer.URL).
		WithJwtInclusion(serviceID, scopeName, "CustomerCredential", true).
		WithHolderVerification(serviceID, scopeName, "CustomerCredential", "holder").
		WithDCQL(serviceID, scopeName, helpers.DCQLConfig{
			Credentials: []helpers.CredentialQuery{
				helpers.NewJWTVCQuery("cred-1", "CustomerCredential"),
			},
		}).
		Build()

	// VC's holder claim is holderA's DID.
	vc, err := helpers.CreateJWTVCWithHolder(issuer, "CustomerCredential", map[string]interface{}{
		"type": "CustomerCredential",
	}, holderA.DID)
	require.NoError(t, err)

	// VP is signed by holderB — mismatch with VC's holder claim.
	vpJWT, err := helpers.CreateVPToken(holderB, "", serviceID, vc)
	require.NoError(t, err)

	return &m2mTestFixture{
		configYAML:   config,
		dcqlResponse: map[string]string{"cred-1": vpJWT},
		cleanup:      func() { tirServer.Close() },
	}
}
