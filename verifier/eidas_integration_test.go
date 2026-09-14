package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/eidas"
	"github.com/fiware/VCVerifier/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Integration tests for the full eIDAS validation flow ---
//
// These tests exercise the complete pipeline: SD-JWT presentation with an
// issuer certificate → EidasValidationService → TrustStore lookup →
// pass/reject. They use self-signed certificate hierarchies and a
// pre-populated trust store to simulate real trust list data.

// integrationCA creates a self-signed CA certificate suitable for trust list
// registration. The CA certificate is valid for 24 hours.
func integrationCA(t *testing.T, country, commonName string) (testCA, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
			Country:    []string{country},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return testCA{cert: cert, certDER: certDER, key: key}, cert
}

// integrationLeaf creates a leaf certificate signed by the given CA.
func integrationLeaf(t *testing.T, ca testCA) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject: pkix.Name{
			CommonName: "Credential Issuer",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// buildMultiCountryTrustStore creates a TrustStore with trusted services from
// multiple countries. Each entry maps a country code to a CA certificate and
// service type/status.
type trustEntry struct {
	countryCode   string
	tspName       string
	serviceName   string
	serviceType   string
	serviceStatus string
	caCert        *x509.Certificate
}

// buildTrustStoreFromEntries creates a trust store populated from the given
// entries, grouped by country code.
func buildTrustStoreFromEntries(t *testing.T, entries []trustEntry) *eidas.TrustStore {
	t.Helper()
	store := eidas.NewTrustStore()

	byCountry := map[string][]eidas.TrustedService{}
	for _, e := range entries {
		svc := eidas.TrustedService{
			CountryCode:   e.countryCode,
			TSPName:       e.tspName,
			ServiceName:   e.serviceName,
			ServiceType:   e.serviceType,
			ServiceStatus: e.serviceStatus,
			Certificates:  []*x509.Certificate{e.caCert},
		}
		byCountry[e.countryCode] = append(byCountry[e.countryCode], svc)
	}
	for cc, services := range byCountry {
		store.Update(cc, services)
	}
	return store
}

// eidasCredentialType is the credential type used in integration tests.
const eidasCredentialType = "EidasVerifiableCredential"

// TestEidasIntegration covers the full eIDAS validation flow with table-driven
// tests. Each test case sets up a trust store, constructs a credential with
// specific certificates and format, and verifies the expected outcome.
func TestEidasIntegration(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	// --- Certificate setup ---
	// German qualified CA.
	deCA, deCACert := integrationCA(t, "DE", "German Qualified CA")
	deLeaf, _ := integrationLeaf(t, deCA)

	// French qualified CA.
	frCA, frCACert := integrationCA(t, "FR", "French Qualified CA")
	frLeaf, _ := integrationLeaf(t, frCA)

	// Spanish non-qualified CA.
	esCA, esCACert := integrationCA(t, "ES", "Spanish Non-Qualified CA")
	esLeaf, _ := integrationLeaf(t, esCA)

	// Italian qualified CA (for withdrawn status testing).
	itCA, itCACert := integrationCA(t, "IT", "Italian Qualified CA")
	itLeaf, _ := integrationLeaf(t, itCA)

	// Untrusted CA — not registered in any trust list.
	untrustedCA, _ := integrationCA(t, "XX", "Untrusted CA")
	untrustedLeaf, _ := integrationLeaf(t, untrustedCA)

	// Multi-country trust store used by most tests.
	multiCountryStore := buildTrustStoreFromEntries(t, []trustEntry{
		{
			countryCode:   "DE",
			tspName:       "German TSP GmbH",
			serviceName:   "German QC CA",
			serviceType:   eidas.ServiceTypeCAQC,
			serviceStatus: eidas.ServiceStatusGranted,
			caCert:        deCACert,
		},
		{
			countryCode:   "FR",
			tspName:       "French TSP SAS",
			serviceName:   "French QC CA",
			serviceType:   eidas.ServiceTypeCAQC,
			serviceStatus: eidas.ServiceStatusGranted,
			caCert:        frCACert,
		},
		{
			countryCode:   "ES",
			tspName:       "Spanish TSP SA",
			serviceName:   "Spanish Non-Qualified CA",
			serviceType:   eidas.ServiceTypeCA,
			serviceStatus: eidas.ServiceStatusGranted,
			caCert:        esCACert,
		},
		{
			countryCode:   "IT",
			tspName:       "Italian TSP SpA",
			serviceName:   "Italian QC CA (Withdrawn)",
			serviceType:   eidas.ServiceTypeCAQC,
			serviceStatus: eidas.ServiceStatusWithdrawn,
			caCert:        itCACert,
		},
	})

	tests := []struct {
		name           string
		store          *eidas.TrustStore
		credTypes      []string
		credFormat     string
		x5cCerts       []*x509.Certificate
		eidasPerType   map[string]*configModel.EidasConfig
		globalCountries []string
		expectAccepted bool
		expectError    error
	}{
		{
			name:       "valid SD-JWT credential with matching trusted service accepted",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{deLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled:          true,
					AllowedCountries: []string{"DE"},
				},
			},
			expectAccepted: true,
			expectError:    nil,
		},
		{
			name:       "valid SD-JWT credential with no matching country rejected",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{deLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled:          true,
					AllowedCountries: []string{"FR"}, // DE leaf won't match FR trust list
				},
			},
			expectAccepted: false,
			expectError:    ErrorEidasUntrustedIssuer,
		},
		{
			name:       "valid SD-JWT credential with withdrawn service status rejected",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{itLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled:          true,
					AllowedCountries: []string{"IT"},
				},
			},
			expectAccepted: false,
			expectError:    ErrorEidasUntrustedIssuer,
		},
		{
			name:       "JSON-LD credential with eIDAS config rejected (format enforcement)",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatLDPVC,
			x5cCerts:   []*x509.Certificate{deLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled:          true,
					AllowedCountries: []string{"DE"},
				},
			},
			expectAccepted: false,
			expectError:    ErrorEidasSDJWTRequired,
		},
		{
			name:       "JWT credential with eIDAS config rejected (format enforcement)",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatJWTVC,
			x5cCerts:   []*x509.Certificate{deLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled:          true,
					AllowedCountries: []string{"DE"},
				},
			},
			expectAccepted: false,
			expectError:    ErrorEidasSDJWTRequired,
		},
		{
			name:       "credential type without eIDAS config passes through",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", "RegularCredential"},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{untrustedLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				// No eIDAS config for any type
			},
			expectAccepted: true,
			expectError:    nil,
		},
		{
			name:       "eIDAS with requireQualified true rejects non-qualified service",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{esLeaf}, // ES has non-qualified CA only
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled:          true,
					RequireQualified: boolPtr(true),
					AllowedCountries: []string{"ES"},
				},
			},
			expectAccepted: false,
			expectError:    ErrorEidasUntrustedIssuer,
		},
		{
			name:       "eIDAS with requireQualified false accepts non-qualified service",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{esLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled:          true,
					RequireQualified: boolPtr(false),
					AllowedCountries: []string{"ES"},
				},
			},
			expectAccepted: true,
			expectError:    nil,
		},
		{
			name:       "multiple allowed countries - service found in second country",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{frLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled:          true,
					AllowedCountries: []string{"DE", "FR"}, // FR is second
				},
			},
			expectAccepted: true,
			expectError:    nil,
		},
		{
			name:       "no allowed countries (empty list) searches all countries",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{deLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled: true,
					// No AllowedCountries → search all
				},
			},
			globalCountries: nil, // Also no global countries
			expectAccepted:  true,
			expectError:     nil,
		},
		{
			name:       "untrusted issuer certificate rejected across all countries",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{untrustedLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled: true,
				},
			},
			expectAccepted: false,
			expectError:    ErrorEidasUntrustedIssuer,
		},
		{
			name:       "credential with no x5c certificates rejected",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   nil,
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled: true,
				},
			},
			expectAccepted: false,
			expectError:    ErrorEidasNoCertificates,
		},
		{
			name:       "global country fallback when per-credential has no countries",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{frLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled: true,
					// No AllowedCountries on per-credential
				},
			},
			globalCountries: []string{"FR"},
			expectAccepted:  true,
			expectError:     nil,
		},
		{
			name:       "global country restricts when per-credential has no countries",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{deLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled: true,
					// No AllowedCountries on per-credential → falls back to global
				},
			},
			globalCountries: []string{"FR"}, // Global says only FR, but cert is from DE
			expectAccepted:  false,
			expectError:     ErrorEidasUntrustedIssuer,
		},
		{
			name:       "disabled eIDAS config passes through even with certificates",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{deLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled: false, // Explicitly disabled
				},
			},
			expectAccepted: true,
			expectError:    nil,
		},
		{
			name:       "requireQualified nil defaults to true - rejects non-qualified",
			store:      multiCountryStore,
			credTypes:  []string{"VerifiableCredential", eidasCredentialType},
			credFormat: common.FormatSDJWT,
			x5cCerts:   []*x509.Certificate{esLeaf},
			eidasPerType: map[string]*configModel.EidasConfig{
				eidasCredentialType: {
					Enabled:          true,
					RequireQualified: nil, // nil defaults to true via IsRequireQualified()
					AllowedCountries: []string{"ES"},
				},
			},
			expectAccepted: false,
			expectError:    ErrorEidasUntrustedIssuer,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &EidasValidationService{trustStore: tc.store}

			ctx := EidasValidationContext{
				PerType:         tc.eidasPerType,
				GlobalCountries: tc.globalCountries,
			}

			cred := makeEidasTestCredential(tc.credTypes, tc.credFormat, tc.x5cCerts)

			result, err := service.ValidateVC(cred, ctx)
			assert.Equal(t, tc.expectAccepted, result, "unexpected validation result")
			if tc.expectError != nil {
				assert.ErrorIs(t, err, tc.expectError, "expected error %v", tc.expectError)
			} else {
				assert.NoError(t, err, "expected no error")
			}
		})
	}
}

// TestEidasIntegration_IntermediateCertificateChain tests the full chain
// validation with root CA → intermediate CA → leaf certificate. The root CA
// is registered in the trust store, and the intermediate + leaf are in the
// x5c header.
func TestEidasIntegration_IntermediateCertificateChain(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	// Build three-level chain: root CA → intermediate CA → leaf.
	rootCA, rootCACert := integrationCA(t, "DE", "Root CA DE")

	// Create intermediate CA signed by root.
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: "Intermediate CA DE",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCA.cert, &intermediateKey.PublicKey, rootCA.key)
	require.NoError(t, err)
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	require.NoError(t, err)

	// Create leaf signed by intermediate.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject: pkix.Name{
			CommonName: "Credential Issuer Leaf",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// Trust store only has the root CA.
	store := buildTrustStoreFromEntries(t, []trustEntry{
		{
			countryCode:   "DE",
			tspName:       "German Root TSP",
			serviceName:   "German Root CA",
			serviceType:   eidas.ServiceTypeCAQC,
			serviceStatus: eidas.ServiceStatusGranted,
			caCert:        rootCACert,
		},
	})

	service := &EidasValidationService{trustStore: store}
	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			eidasCredentialType: {
				Enabled:          true,
				AllowedCountries: []string{"DE"},
			},
		},
	}

	// x5c chain: leaf + intermediate. Root is the trust anchor in the store.
	cred := makeEidasTestCredential(
		[]string{"VerifiableCredential", eidasCredentialType},
		common.FormatSDJWT,
		[]*x509.Certificate{leafCert, intermediateCert},
	)

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err, "should pass with valid intermediate chain")
	assert.True(t, result, "leaf → intermediate → root should be accepted")
}

// TestEidasIntegration_MultipleTypesOnlyOneEnabled verifies that when a
// credential carries multiple types and only one has eIDAS enabled, the
// validation correctly activates for that type.
func TestEidasIntegration_MultipleTypesOnlyOneEnabled(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca, caCert := integrationCA(t, "DE", "German QC CA")
	leaf, _ := integrationLeaf(t, ca)

	store := buildTrustStoreFromEntries(t, []trustEntry{
		{
			countryCode:   "DE",
			tspName:       "German TSP",
			serviceName:   "German QC CA",
			serviceType:   eidas.ServiceTypeCAQC,
			serviceStatus: eidas.ServiceStatusGranted,
			caCert:        caCert,
		},
	})

	service := &EidasValidationService{trustStore: store}
	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"VerifiableCredential":   nil,                            // No eIDAS config
			"RegularType":            {Enabled: false},               // Disabled
			eidasCredentialType:      {Enabled: true, AllowedCountries: []string{"DE"}}, // Active
		},
	}

	cred := makeEidasTestCredential(
		[]string{"VerifiableCredential", "RegularType", eidasCredentialType},
		common.FormatSDJWT,
		[]*x509.Certificate{leaf},
	)

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should find and use the enabled eIDAS type")
}

// TestEidasIntegration_EmptyTrustStoreRejectsAll verifies that when the trust
// store is empty (e.g., trust lists haven't been fetched yet), all credentials
// requiring eIDAS validation are rejected.
func TestEidasIntegration_EmptyTrustStoreRejectsAll(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca, _ := integrationCA(t, "DE", "Any CA")
	leaf, _ := integrationLeaf(t, ca)

	emptyStore := eidas.NewTrustStore()
	service := &EidasValidationService{trustStore: emptyStore}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			eidasCredentialType: {Enabled: true},
		},
	}

	cred := makeEidasTestCredential(
		[]string{"VerifiableCredential", eidasCredentialType},
		common.FormatSDJWT,
		[]*x509.Certificate{leaf},
	)

	result, err := service.ValidateVC(cred, ctx)
	assert.False(t, result, "should reject when trust store is empty")
	assert.ErrorIs(t, err, ErrorEidasUntrustedIssuer)
}
