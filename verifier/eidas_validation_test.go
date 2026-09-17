package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

// oidQCStatementsExtension is id-pe-qcStatements (RFC 3739 §3.2.6).
var oidQCStatementsExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

// oidQcComplianceStatement is id-etsi-qcs-QcCompliance (ETSI EN 319 412-5 §4.2.1).
var oidQcComplianceStatement = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}

// qcCompliantExtension builds a qcStatements extension declaring QcCompliance,
// i.e. marking the certificate as a qualified certificate.
func qcCompliantExtension(t *testing.T) pkix.Extension {
	t.Helper()

	type statement struct {
		StatementID asn1.ObjectIdentifier
	}
	value, err := asn1.Marshal([]statement{{StatementID: oidQcComplianceStatement}})
	require.NoError(t, err)

	return pkix.Extension{Id: oidQCStatementsExtension, Value: value}
}

// generateTestLeaf creates a leaf certificate signed by the given CA. The
// certificate declares QcCompliance, so it passes a requireQualified check.
func generateTestLeaf(t *testing.T, ca testCA) testLeaf {
	return generateTestLeafWithQCStatements(t, ca, true)
}

// generateTestLeafWithQCStatements creates a leaf certificate signed by the
// given CA, with or without a QcCompliance statement.
func generateTestLeafWithQCStatements(t *testing.T, ca testCA, qualified bool) testLeaf {
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
	if qualified {
		template.ExtraExtensions = []pkix.Extension{qcCompliantExtension(t)}
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
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{qcCompliantExtension(t)},
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

// TestEidasValidation_WithdrawnServiceStatus verifies that a certificate
// signed by a CA whose trust service status is "withdrawn" is rejected.
func TestEidasValidation_WithdrawnServiceStatus(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca := generateTestCA(t, "IT")
	leaf := generateTestLeaf(t, ca)

	withdrawnService := eidas.TrustedService{
		CountryCode:   "IT",
		TSPName:       "Italian TSP SpA",
		ServiceName:   "Italian QC CA (Withdrawn)",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusWithdrawn,
		Certificates:  []*x509.Certificate{ca.cert},
	}

	store := setupTrustStore(t, "IT", []eidas.TrustedService{withdrawnService})
	service := &EidasValidationService{trustStore: store}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {Enabled: true, AllowedCountries: []string{"IT"}},
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.False(t, result, "should reject when trusted service status is withdrawn")
	assert.ErrorIs(t, err, ErrorEidasUntrustedIssuer)
}

// TestEidasValidation_MultipleAllowedCountries verifies that the validation
// iterates through multiple allowed countries and finds a match even when it
// is not in the first country.
func TestEidasValidation_MultipleAllowedCountries(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	deCA := generateTestCA(t, "DE")
	frCA := generateTestCA(t, "FR")
	frLeaf := generateTestLeaf(t, frCA)

	store := eidas.NewTrustStore()
	store.Update("DE", []eidas.TrustedService{{
		CountryCode:   "DE",
		TSPName:       "German TSP",
		ServiceName:   "German QC CA",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{deCA.cert},
	}})
	store.Update("FR", []eidas.TrustedService{{
		CountryCode:   "FR",
		TSPName:       "French TSP",
		ServiceName:   "French QC CA",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{frCA.cert},
	}})

	service := &EidasValidationService{trustStore: store}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {
				Enabled:          true,
				AllowedCountries: []string{"DE", "FR"}, // FR is second
			},
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{frLeaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.NoError(t, err)
	assert.True(t, result, "should find matching CA in second allowed country")
}

// TestEidasValidation_GlobalCountryRestricts verifies that the global country
// filter acts as a restriction (not just a fallback) when the per-credential
// config has no AllowedCountries.
func TestEidasValidation_GlobalCountryRestricts(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	deCA := generateTestCA(t, "DE")
	deLeaf := generateTestLeaf(t, deCA)

	store := setupTrustStore(t, "DE", []eidas.TrustedService{{
		CountryCode:   "DE",
		TSPName:       "German TSP",
		ServiceName:   "German QC CA",
		ServiceType:   eidas.ServiceTypeCAQC,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{deCA.cert},
	}})

	service := &EidasValidationService{trustStore: store}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {
				Enabled: true,
				// No AllowedCountries on per-credential → falls back to global
			},
		},
		GlobalCountries: []string{"FR"}, // Global says only FR, but cert is from DE
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{deLeaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.False(t, result, "should reject when global country filter excludes the trusted CA's country")
	assert.ErrorIs(t, err, ErrorEidasUntrustedIssuer)
}

// TestEidasValidation_RequireQualifiedNilDefaultsToTrue verifies that when
// RequireQualified is nil, IsRequireQualified() defaults to true and rejects
// non-qualified services.
func TestEidasValidation_RequireQualifiedNilDefaultsToTrue(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	ca := generateTestCA(t, "ES")
	leaf := generateTestLeaf(t, ca)

	// Register under a non-qualified service type.
	nonQualifiedService := eidas.TrustedService{
		CountryCode:   "ES",
		TSPName:       "Spanish TSP",
		ServiceName:   "Spanish Non-Qualified CA",
		ServiceType:   eidas.ServiceTypeCA,
		ServiceStatus: eidas.ServiceStatusGranted,
		Certificates:  []*x509.Certificate{ca.cert},
	}

	store := setupTrustStore(t, "ES", []eidas.TrustedService{nonQualifiedService})
	service := &EidasValidationService{trustStore: store}

	ctx := EidasValidationContext{
		PerType: map[string]*configModel.EidasConfig{
			"EidasCredential": {
				Enabled:          true,
				RequireQualified: nil, // nil defaults to true via IsRequireQualified()
				AllowedCountries: []string{"ES"},
			},
		},
	}

	cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

	result, err := service.ValidateVC(cred, ctx)
	assert.False(t, result, "should reject non-qualified service when RequireQualified is nil (defaults to true)")
	assert.ErrorIs(t, err, ErrorEidasUntrustedIssuer)
}

// TestEidasValidation_LeafQualifiedStatus verifies that requireQualified is
// enforced against the leaf certificate's own QcCompliance statement, not only
// against the issuing CA's trust-list service type. A CA listed under CA/QC may
// also issue non-qualified certificates.
func TestEidasValidation_LeafQualifiedStatus(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	requireQualified := true
	allowNonQualified := false

	tests := []struct {
		name             string
		leafQualified    bool
		requireQualified *bool
		expectedResult   bool
		expectedError    error
	}{
		{
			name:             "qualified leaf under a qualified CA",
			leafQualified:    true,
			requireQualified: &requireQualified,
			expectedResult:   true,
		},
		{
			name:             "non-qualified leaf under a qualified CA is rejected",
			leafQualified:    false,
			requireQualified: &requireQualified,
			expectedResult:   false,
			expectedError:    ErrorEidasCertificateNotQualified,
		},
		{
			name:             "non-qualified leaf is accepted when qualification is not required",
			leafQualified:    false,
			requireQualified: &allowNonQualified,
			expectedResult:   true,
		},
		{
			name:             "requireQualified defaults to true and rejects a non-qualified leaf",
			leafQualified:    false,
			requireQualified: nil,
			expectedResult:   false,
			expectedError:    ErrorEidasCertificateNotQualified,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := generateTestCA(t, "DE")
			leaf := generateTestLeafWithQCStatements(t, ca, tc.leafQualified)

			// The CA is registered under a qualified service type in both cases,
			// so only the leaf's own statement can make the difference.
			qualifiedService := eidas.TrustedService{
				CountryCode:   "DE",
				TSPName:       "German TSP",
				ServiceName:   "German Qualified CA",
				ServiceType:   eidas.ServiceTypeCAQC,
				ServiceStatus: eidas.ServiceStatusGranted,
				Certificates:  []*x509.Certificate{ca.cert},
			}

			store := setupTrustStore(t, "DE", []eidas.TrustedService{qualifiedService})
			service := &EidasValidationService{trustStore: store}

			ctx := EidasValidationContext{
				PerType: map[string]*configModel.EidasConfig{
					"EidasCredential": {
						Enabled:          true,
						RequireQualified: tc.requireQualified,
						AllowedCountries: []string{"DE"},
					},
				},
			}

			cred := makeEidasTestCredential([]string{"VerifiableCredential", "EidasCredential"}, common.FormatSDJWT, []*x509.Certificate{leaf.cert})

			result, err := service.ValidateVC(cred, ctx)
			assert.Equal(t, tc.expectedResult, result)
			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
