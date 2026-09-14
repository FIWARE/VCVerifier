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

// --- test helpers for certificate generation ---

// testCA holds a self-signed CA certificate and its private key.
type testCA struct {
	cert    *x509.Certificate
	certDER []byte
	key     *ecdsa.PrivateKey
}

// testLeaf holds a leaf certificate signed by a CA and its private key.
type testLeaf struct {
	cert    *x509.Certificate
	certDER []byte
	key     *ecdsa.PrivateKey
}

// generateTestCA creates a self-signed CA certificate for testing.
func generateTestCA(t *testing.T, country string) testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
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

	return testCA{cert: cert, certDER: certDER, key: key}
}

// generateTestLeaf creates a leaf certificate signed by the given CA.
func generateTestLeaf(t *testing.T, ca testCA) testLeaf {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Leaf Issuer",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return testLeaf{cert: cert, certDER: certDER, key: key}
}

// setupTrustStore creates a TrustStore populated with the given services for
// a specific country code.
func setupTrustStore(t *testing.T, countryCode string, services []eidas.TrustedService) *eidas.TrustStore {
	t.Helper()
	store := eidas.NewTrustStore()
	store.Update(countryCode, services)
	return store
}

// makeEidasTestCredential creates a Credential with the given types, format,
// and optional pre-parsed x5c certificates. The certificates are set directly
// on the credential — the same way the presentation parser populates them
// during SD-JWT parsing.
func makeEidasTestCredential(types []string, format string, certs []*x509.Certificate) *common.Credential {
	cred, err := common.CreateCredential(common.CredentialContents{
		Types: types,
	}, nil)
	if err != nil {
		panic("makeEidasTestCredential: " + err.Error())
	}
	cred.SetFormat(format)
	if len(certs) > 0 {
		cred.SetX5CCertificates(certs)
	}
	return cred
}

// --- tests ---

func TestEidasValidation_PassThroughNoConfig(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	service := &EidasValidationService{trustStore: eidas.NewTrustStore()}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "SomeType"}, common.FormatSDJWT, nil)

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should pass through when no eIDAS config is set for credential types")
}

func TestEidasValidation_PassThroughDisabledConfig(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	service := &EidasValidationService{trustStore: eidas.NewTrustStore()}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"SomeType": {Enabled: false},
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "SomeType"}, common.FormatSDJWT, nil)

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should pass through when eIDAS config is disabled for the credential type")
}

func TestEidasValidation_PassThroughNilConfig(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	service := &EidasValidationService{trustStore: eidas.NewTrustStore()}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"SomeType": nil,
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "SomeType"}, common.FormatSDJWT, nil)

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should pass through when eIDAS config is nil for the credential type")
}

// TestEidasValidation_FormatRejection verifies that credentials not in SD-JWT
// format are rejected with a descriptive error when eIDAS is enabled.
func TestEidasValidation_FormatRejection(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	tests := []struct {
		name   string
		format string
	}{
		{"JWT format rejected", "jwt_vc"},
		{"JSON-LD format rejected", "ldp_vc"},
		{"empty format rejected", ""},
		{"unknown format rejected", "some_other_format"},
	}

	service := &EidasValidationService{trustStore: eidas.NewTrustStore()}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {Enabled: true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, tc.format, nil)

			result, err := service.ValidateVC(cred, ctx)
			assert.False(t, result, "should reject non-SD-JWT format")
			assert.ErrorIs(t, err, ErrorEidasSDJWTRequired)
		})
	}
}

func TestEidasValidation_NoCertificates(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	service := &EidasValidationService{trustStore: eidas.NewTrustStore()}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {Enabled: true},
		},
	}

	// SD-JWT format but no x5c certificates set (simulates a token without x5c header).
	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, nil)

	result, err := service.ValidateVC(cred, ctx)
	assert.False(t, result)
	assert.ErrorIs(t, err, ErrorEidasNoCertificates)
}

// TestEidasValidation_CertificateChainSuccess verifies the happy path: a leaf
// certificate signed by a trusted CA in the trust list passes validation.
func TestEidasValidation_CertificateChainSuccess(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca := generateTestCA(t, "DE")
	leaf := generateTestLeaf(t, ca)

	trustedService := eidas.TrustedService{
		CountryCode:   "DE",
		TSPName:       "Test TSP",
		ServiceName:   "Test Qualified CA",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{ca.cert},
	}

	store := setupTrustStore(t, "DE", []eidas.TrustedService{trustedService})
	service := &EidasValidationService{trustStore: store}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {Enabled: true, AllowedCountries: []string{"DE"}},
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should pass when leaf cert chains to trusted CA")
}

// TestEidasValidation_UntrustedIssuer verifies that a certificate not chaining
// to any trusted service is rejected.
func TestEidasValidation_UntrustedIssuer(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	// Create two unrelated CAs — one trusted, one that signs the leaf.
	trustedCA := generateTestCA(t, "DE")
	untrustedCA := generateTestCA(t, "DE")
	leaf := generateTestLeaf(t, untrustedCA)

	trustedService := eidas.TrustedService{
		CountryCode:   "DE",
		TSPName:       "Trusted TSP",
		ServiceName:   "Trusted Qualified CA",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{trustedCA.cert},
	}

	store := setupTrustStore(t, "DE", []eidas.TrustedService{trustedService})
	service := &EidasValidationService{trustStore: store}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {Enabled: true, AllowedCountries: []string{"DE"}},
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.False(t, result)
	assert.ErrorIs(t, err, ErrorEidasUntrustedIssuer)
}

// TestEidasValidation_QualifiedOnlyFilter verifies that when RequireQualified
// is true, only qualified service types are checked.
func TestEidasValidation_QualifiedOnlyFilter(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca := generateTestCA(t, "FR")
	leaf := generateTestLeaf(t, ca)

	// Register the CA only under a non-qualified service type.
	nonQualifiedService := eidas.TrustedService{
		CountryCode:   "FR",
		TSPName:       "Test TSP",
		ServiceName:   "Non-Qualified CA",
		ServiceType:   eidas.ServiceTypeCA,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{ca.cert},
	}

	store := setupTrustStore(t, "FR", []eidas.TrustedService{nonQualifiedService})
	service := &EidasValidationService{trustStore: store}

	// RequireQualified: true (default from IsRequireQualified() on nil/zero value)
	eidasCfg := &configModel.EidasConfig{
		Enabled:          true,
		RequireQualified: boolPtr(true),
		AllowedCountries: []string{"FR"},
	}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": eidasCfg,
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.False(t, result, "should reject when only non-qualified services exist but RequireQualified is true")
	assert.ErrorIs(t, err, ErrorEidasUntrustedIssuer)
}

// TestEidasValidation_NonQualifiedAllowed verifies that when RequireQualified
// is false, non-qualified service types are also accepted.
func TestEidasValidation_NonQualifiedAllowed(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca := generateTestCA(t, "FR")
	leaf := generateTestLeaf(t, ca)

	nonQualifiedService := eidas.TrustedService{
		CountryCode:   "FR",
		TSPName:       "Test TSP",
		ServiceName:   "Non-Qualified CA",
		ServiceType:   eidas.ServiceTypeCA,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{ca.cert},
	}

	store := setupTrustStore(t, "FR", []eidas.TrustedService{nonQualifiedService})
	service := &EidasValidationService{trustStore: store}

	eidasCfg := &configModel.EidasConfig{
		Enabled:          true,
		RequireQualified: boolPtr(false),
		AllowedCountries: []string{"FR"},
	}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": eidasCfg,
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should accept when RequireQualified is false and non-qualified service has the CA")
}

// TestEidasValidation_CountryFilter verifies that only services from allowed
// countries are consulted.
func TestEidasValidation_CountryFilter(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca := generateTestCA(t, "IT")
	leaf := generateTestLeaf(t, ca)

	// Register the CA under Italy.
	italyService := eidas.TrustedService{
		CountryCode:   "IT",
		TSPName:       "Italian TSP",
		ServiceName:   "Italian Qualified CA",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{ca.cert},
	}

	store := setupTrustStore(t, "IT", []eidas.TrustedService{italyService})
	service := &EidasValidationService{trustStore: store}

	// Config only allows Germany — Italy should not be checked.
	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {Enabled: true, AllowedCountries: []string{"DE"}},
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.False(t, result, "should reject when trusted CA is in a non-allowed country")
	assert.ErrorIs(t, err, ErrorEidasUntrustedIssuer)
}

// TestEidasValidation_GlobalCountryFallback verifies that the global country
// filter is used when the per-credential config has no AllowedCountries.
func TestEidasValidation_GlobalCountryFallback(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca := generateTestCA(t, "ES")
	leaf := generateTestLeaf(t, ca)

	spainService := eidas.TrustedService{
		CountryCode:   "ES",
		TSPName:       "Spanish TSP",
		ServiceName:   "Spanish CA",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{ca.cert},
	}

	store := setupTrustStore(t, "ES", []eidas.TrustedService{spainService})
	service := &EidasValidationService{trustStore: store}

	// Per-credential config has no AllowedCountries → falls back to global.
	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {Enabled: true},
		},
		GlobalCountries: []string{"ES"},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should use global country filter as fallback")
}

// TestEidasValidation_NoCountryFilterSearchesAll verifies that when both
// per-credential and global countries are empty, all countries are searched.
func TestEidasValidation_NoCountryFilterSearchesAll(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca := generateTestCA(t, "NL")
	leaf := generateTestLeaf(t, ca)

	nlService := eidas.TrustedService{
		CountryCode:   "NL",
		TSPName:       "Dutch TSP",
		ServiceName:   "Dutch CA",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{ca.cert},
	}

	store := setupTrustStore(t, "NL", []eidas.TrustedService{nlService})
	service := &EidasValidationService{trustStore: store}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {Enabled: true},
		},
		// No global countries either.
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should search all countries when no filter is set")
}

// TestEidasValidation_IntermediateCertificates verifies that intermediate
// certificates from the x5c chain are used during PKIX validation.
func TestEidasValidation_IntermediateCertificates(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	// Build a three-level chain: root CA → intermediate CA → leaf.
	rootCA := generateTestCA(t, "AT")

	// Create an intermediate CA signed by root.
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject: pkix.Name{
			CommonName: "Test Intermediate CA",
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

	// Create a leaf signed by intermediate.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(20),
		Subject: pkix.Name{
			CommonName: "Test Leaf",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	require.NoError(t, err)

	trustedService := eidas.TrustedService{
		CountryCode:   "AT",
		TSPName:       "Austrian TSP",
		ServiceName:   "Austrian Root CA",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{rootCA.cert},
	}

	store := setupTrustStore(t, "AT", []eidas.TrustedService{trustedService})
	service := &EidasValidationService{trustStore: store}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {Enabled: true, AllowedCountries: []string{"AT"}},
		},
	}

	// x5c chain: leaf + intermediate (root is the trust anchor in the store).
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leafCert, intermediateCert})

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should pass when intermediate certificate completes the chain to root CA")
}

// TestEidasValidation_WrongContextType verifies graceful recovery when the
// validation context is not an EidasValidationContext.
func TestEidasValidation_WrongContextType(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	service := &EidasValidationService{trustStore: eidas.NewTrustStore()}
	cred := makeEidasTestCredential([]string{"VerifiableCredential"}, common.FormatSDJWT, nil)

	// Pass a TrustRegistriesValidationContext instead of EidasValidationContext.
	wrongCtx := TrustRegistriesValidationContext{}

	result, err := service.ValidateVC(cred, wrongCtx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrorCannotConverContext)
	assert.False(t, result)
}

// TestEidasValidation_SelectValidationContext verifies that
// selectValidationContext routes the EidasValidationService to the
// EidasValidationContext.
func TestEidasValidation_SelectValidationContext(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	eidasService := &EidasValidationService{}
	trustCtx := TrustRegistriesValidationContext{}
	statusCtx := CredentialStatusValidationContext{}
	eidasCtx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"TestType": {Enabled: true},
		},
	}

	result := selectValidationContext(eidasService, trustCtx, statusCtx, eidasCtx)
	_, ok := result.(EidasValidationContext)
	assert.True(t, ok, "selectValidationContext should return EidasValidationContext for EidasValidationService")

	// Other services should still get trust context.
	otherService := &TrustedIssuerValidationService{}
	result = selectValidationContext(otherService, trustCtx, statusCtx, eidasCtx)
	_, ok = result.(TrustRegistriesValidationContext)
	assert.True(t, ok, "selectValidationContext should return TrustRegistriesValidationContext for other services")
}

// TestEidasValidation_MultipleCredentialTypes verifies that when a credential
// has multiple types and only one has eIDAS enabled, validation runs for that
// type.
func TestEidasValidation_MultipleCredentialTypes(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca := generateTestCA(t, "BE")
	leaf := generateTestLeaf(t, ca)

	trustedService := eidas.TrustedService{
		CountryCode:   "BE",
		TSPName:       "Belgian TSP",
		ServiceName:   "Belgian CA",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{ca.cert},
	}

	store := setupTrustStore(t, "BE", []eidas.TrustedService{trustedService})
	service := &EidasValidationService{trustStore: store}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"VerifiableCredential": nil, // not configured
			"SpecificType":         {Enabled: true, AllowedCountries: []string{"BE"}},
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "SpecificType"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should validate using the eIDAS-enabled type even when other types have no config")
}

// TestEidasValidation_EmptyTrustStore verifies that an empty trust store
// rejects the credential.
func TestEidasValidation_EmptyTrustStore(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca := generateTestCA(t, "PL")
	leaf := generateTestLeaf(t, ca)

	// Empty trust store — no services registered.
	store := eidas.NewTrustStore()
	service := &EidasValidationService{trustStore: store}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {Enabled: true, AllowedCountries: []string{"PL"}},
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.False(t, result)
	assert.ErrorIs(t, err, ErrorEidasUntrustedIssuer)
}
