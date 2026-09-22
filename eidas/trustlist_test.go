package eidas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdataDir returns the absolute path to the testdata directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("testdata")
	require.NoError(t, err)
	return dir
}

// readTestdata reads a file from the testdata directory.
func readTestdata(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir(t), filename))
	require.NoError(t, err)
	return data
}

// generateTestCertificate creates a self-signed X.509 certificate for testing.
// Returns the certificate and its base64-encoded DER representation.
func generateTestCertificate(t *testing.T, cn string, isCA bool) (*x509.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC),
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: isCA,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	return cert, base64.StdEncoding.EncodeToString(derBytes)
}

func TestParseTrustList_LOTLMinimal(t *testing.T) {
	data := readTestdata(t, "lotl_minimal.xml")
	tl, err := ParseTrustList(data)
	require.NoError(t, err)
	require.NotNil(t, tl)

	// Verify root element
	assert.Equal(t, "TrustServiceStatusList", tl.XMLName.Local)
	assert.Equal(t, "lotl-1", tl.ID)

	// Verify scheme information
	si := tl.SchemeInformation
	assert.Equal(t, 5, si.TSLVersionIdentifier)
	assert.Equal(t, 42, si.TSLSequenceNumber)
	assert.Equal(t, TSLTypeEUListOfTheLists, si.TSLType)
	assert.Equal(t, "European Commission", si.SchemeOperatorName.GetEnglish())
	assert.Equal(t, "EU Trusted Lists", si.SchemeName.GetEnglish())
	assert.Equal(t, "EU", si.SchemeTerritory)

	// Verify LOTL detection
	assert.True(t, tl.IsLOTL())

	// Verify no TSPs in LOTL
	assert.Nil(t, tl.TrustServiceProviderList)
}

func TestParseTrustList_NationalTL_DE(t *testing.T) {
	data := readTestdata(t, "national_tl_de.xml")
	tl, err := ParseTrustList(data)
	require.NoError(t, err)
	require.NotNil(t, tl)

	// Verify it's a national TL, not a LOTL
	assert.Equal(t, TSLTypeEUGeneric, tl.SchemeInformation.TSLType)
	assert.False(t, tl.IsLOTL())
	assert.Equal(t, "DE", tl.SchemeInformation.SchemeTerritory)

	// Verify multilingual names
	assert.Equal(t, "Germany Federal Network Agency", tl.SchemeInformation.SchemeOperatorName.GetEnglish())

	// Verify TSPs
	require.NotNil(t, tl.TrustServiceProviderList)
	tsps := tl.TrustServiceProviderList.TrustServiceProviders
	require.Len(t, tsps, 2)

	// First TSP
	tsp1 := tsps[0]
	assert.Equal(t, "Test TSP GmbH", tsp1.TSPInformation.TSPName.GetEnglish())
	require.Len(t, tsp1.TSPServices.TSPService, 2)

	// First service - Qualified CA with certificate
	svc1 := tsp1.TSPServices.TSPService[0].ServiceInformation
	assert.Equal(t, ServiceTypeCAQC, svc1.ServiceTypeIdentifier)
	assert.Equal(t, "Test Qualified CA", svc1.ServiceName.GetEnglish())
	assert.Equal(t, ServiceStatusGranted, svc1.ServiceStatus)
	assert.Equal(t, "2021-01-15T00:00:00Z", svc1.StatusStartingTime)

	// Verify digital identity has both cert and subject name
	require.Len(t, svc1.ServiceDigitalIdentity.DigitalIds, 2)
	assert.NotEmpty(t, svc1.ServiceDigitalIdentity.DigitalIds[0].X509Certificate)
	assert.NotEmpty(t, svc1.ServiceDigitalIdentity.DigitalIds[1].X509SubjectName)

	// Second service - Withdrawn timestamp service
	svc2 := tsp1.TSPServices.TSPService[1].ServiceInformation
	assert.Equal(t, ServiceTypeQTST, svc2.ServiceTypeIdentifier)
	assert.Equal(t, ServiceStatusWithdrawn, svc2.ServiceStatus)

	// Second TSP - Non-qualified CA
	tsp2 := tsps[1]
	assert.Equal(t, "Another TSP AG", tsp2.TSPInformation.TSPName.GetEnglish())
	require.Len(t, tsp2.TSPServices.TSPService, 1)
	assert.Equal(t, ServiceTypeCA, tsp2.TSPServices.TSPService[0].ServiceInformation.ServiceTypeIdentifier)
}

func TestParseTrustList_NationalTL_FR(t *testing.T) {
	data := readTestdata(t, "national_tl_fr.xml")
	tl, err := ParseTrustList(data)
	require.NoError(t, err)
	require.NotNil(t, tl)

	assert.Equal(t, "FR", tl.SchemeInformation.SchemeTerritory)
	assert.False(t, tl.IsLOTL())

	require.NotNil(t, tl.TrustServiceProviderList)
	tsps := tl.TrustServiceProviderList.TrustServiceProviders
	require.Len(t, tsps, 1)
	assert.Equal(t, "French TSP SARL", tsps[0].TSPInformation.TSPName.GetEnglish())
}

func TestParseTrustList_EmptyTL(t *testing.T) {
	data := readTestdata(t, "empty_tl.xml")
	tl, err := ParseTrustList(data)
	require.NoError(t, err)
	require.NotNil(t, tl)

	assert.Equal(t, "XX", tl.SchemeInformation.SchemeTerritory)
	assert.False(t, tl.IsLOTL())
	assert.Nil(t, tl.TrustServiceProviderList)

	// GetTrustServices should return nil for empty TL
	services, err := tl.GetTrustServices()
	require.NoError(t, err)
	assert.Nil(t, services)
}

func TestParseTrustList_InvalidXML(t *testing.T) {
	tests := []struct {
		name    string
		xmlData []byte
		errMsg  string
	}{
		{
			name:    "empty input",
			xmlData: []byte{},
			errMsg:  "failed to parse trust list XML",
		},
		{
			name:    "malformed XML",
			xmlData: []byte("<TrustServiceStatusList><unclosed"),
			errMsg:  "failed to parse trust list XML",
		},
		{
			name:    "wrong root element",
			xmlData: []byte("<WrongRoot></WrongRoot>"),
			errMsg:  "failed to parse trust list XML",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tl, err := ParseTrustList(tc.xmlData)
			assert.Nil(t, tl)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

func TestGetDistributionPoints(t *testing.T) {
	data := readTestdata(t, "lotl_minimal.xml")
	tl, err := ParseTrustList(data)
	require.NoError(t, err)

	points := tl.GetDistributionPoints()
	// Should only include EUgeneric pointers, not the EUlistofthelists pivot pointer
	require.Len(t, points, 2)

	assert.Equal(t, "https://tl.example.de/tl.xml", points[0].TSLLocation)
	assert.Equal(t, "DE", points[0].SchemeTerritory)

	assert.Equal(t, "https://tl.example.fr/tl.xml", points[1].TSLLocation)
	assert.Equal(t, "FR", points[1].SchemeTerritory)
}

func TestGetDistributionPoints_NoPointers(t *testing.T) {
	data := readTestdata(t, "empty_tl.xml")
	tl, err := ParseTrustList(data)
	require.NoError(t, err)

	points := tl.GetDistributionPoints()
	assert.Nil(t, points)
}

func TestGetTrustServices_DE(t *testing.T) {
	data := readTestdata(t, "national_tl_de.xml")
	tl, err := ParseTrustList(data)
	require.NoError(t, err)

	services, err := tl.GetTrustServices()
	require.NoError(t, err)
	require.Len(t, services, 3)

	// First service: qualified CA with certificate
	svc1 := services[0]
	assert.Equal(t, "DE", svc1.CountryCode)
	assert.Equal(t, "Test TSP GmbH", svc1.TSPName)
	assert.Equal(t, "Test Qualified CA", svc1.ServiceName)
	assert.Equal(t, ServiceTypeCAQC, svc1.ServiceType)
	assert.Equal(t, ServiceStatusGranted, svc1.ServiceStatus)
	assert.True(t, svc1.IsQualified())
	assert.True(t, svc1.IsGranted())
	require.Len(t, svc1.Certificates, 1)
	assert.Equal(t, "Test CA for eIDAS Trust List", svc1.Certificates[0].Subject.CommonName)
	assert.Equal(t, time.Date(2021, 1, 15, 0, 0, 0, 0, time.UTC), svc1.StatusStartingTime)

	// Second service: withdrawn timestamp (qualified)
	svc2 := services[1]
	assert.Equal(t, ServiceTypeQTST, svc2.ServiceType)
	assert.Equal(t, ServiceStatusWithdrawn, svc2.ServiceStatus)
	assert.True(t, svc2.IsQualified())
	assert.False(t, svc2.IsGranted())
	assert.Empty(t, svc2.Certificates) // Only has X509SubjectName, no cert

	// Third service: non-qualified CA
	svc3 := services[2]
	assert.Equal(t, "Another TSP AG", svc3.TSPName)
	assert.Equal(t, ServiceTypeCA, svc3.ServiceType)
	assert.False(t, svc3.IsQualified())
	assert.True(t, svc3.IsGranted())
}

func TestGetTrustServices_FR(t *testing.T) {
	data := readTestdata(t, "national_tl_fr.xml")
	tl, err := ParseTrustList(data)
	require.NoError(t, err)

	services, err := tl.GetTrustServices()
	require.NoError(t, err)
	require.Len(t, services, 1)

	svc := services[0]
	assert.Equal(t, "FR", svc.CountryCode)
	assert.Equal(t, "French TSP SARL", svc.TSPName)
	assert.Equal(t, ServiceTypeCAQC, svc.ServiceType)
	assert.True(t, svc.IsQualified())
	assert.True(t, svc.IsGranted())
	require.Len(t, svc.Certificates, 1)
	assert.Equal(t, "French Test CA", svc.Certificates[0].Subject.CommonName)
}

func TestExtractServiceCertificates(t *testing.T) {
	_, b64Cert := generateTestCertificate(t, "Test Cert", true)

	tests := []struct {
		name           string
		identity       ServiceDigitalIdentity
		wantCount      int
		wantSkipped    int
		wantSkipReason string
	}{
		{
			name: "single certificate",
			identity: ServiceDigitalIdentity{
				DigitalIds: []DigitalId{
					{X509Certificate: b64Cert},
				},
			},
			wantCount: 1,
		},
		{
			name: "certificate with subject name",
			identity: ServiceDigitalIdentity{
				DigitalIds: []DigitalId{
					{X509Certificate: b64Cert},
					{X509SubjectName: "CN=Test"},
				},
			},
			wantCount: 1, // Only the cert, subject name is skipped
		},
		{
			name: "no certificates, only subject name",
			identity: ServiceDigitalIdentity{
				DigitalIds: []DigitalId{
					{X509SubjectName: "CN=Test"},
				},
			},
			wantCount: 0,
		},
		{
			name: "empty digital identity",
			identity: ServiceDigitalIdentity{
				DigitalIds: nil,
			},
			wantCount: 0,
		},
		{
			name: "invalid base64 certificate",
			identity: ServiceDigitalIdentity{
				DigitalIds: []DigitalId{
					{X509Certificate: "not-valid-base64!!!"},
				},
			},
			wantSkipped:    1,
			wantSkipReason: "certificate at index 0",
		},
		{
			name: "valid base64 but invalid DER",
			identity: ServiceDigitalIdentity{
				DigitalIds: []DigitalId{
					{X509Certificate: base64.StdEncoding.EncodeToString([]byte("not a certificate"))},
				},
			},
			wantSkipped:    1,
			wantSkipReason: "certificate at index 0",
		},
		{
			name: "a broken certificate does not discard the usable ones",
			identity: ServiceDigitalIdentity{
				DigitalIds: []DigitalId{
					{X509Certificate: base64.StdEncoding.EncodeToString([]byte("not a certificate"))},
					{X509Certificate: b64Cert},
				},
			},
			wantCount:      1,
			wantSkipped:    1,
			wantSkipReason: "certificate at index 0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certs, skipped := ExtractServiceCertificates(tc.identity)
			assert.Len(t, certs, tc.wantCount)
			require.Len(t, skipped, tc.wantSkipped)
			if tc.wantSkipReason != "" {
				assert.Contains(t, skipped[0].Error(), tc.wantSkipReason)
			}
		})
	}
}

func TestExtractServiceCertificates_WhitespaceInBase64(t *testing.T) {
	data := readTestdata(t, "cert_with_whitespace.xml")
	tl, err := ParseTrustList(data)
	require.NoError(t, err)

	// Get the service with whitespace-formatted certificate
	require.NotNil(t, tl.TrustServiceProviderList)
	require.Len(t, tl.TrustServiceProviderList.TrustServiceProviders, 1)
	svc := tl.TrustServiceProviderList.TrustServiceProviders[0].TSPServices.TSPService[0]

	certs, skipped := ExtractServiceCertificates(svc.ServiceInformation.ServiceDigitalIdentity)
	require.Empty(t, skipped)
	require.Len(t, certs, 1)
	assert.Equal(t, "Test CA for eIDAS Trust List", certs[0].Subject.CommonName)
}

func TestExtractServiceCertificates_FromParsedTrustList(t *testing.T) {
	data := readTestdata(t, "national_tl_de.xml")
	tl, err := ParseTrustList(data)
	require.NoError(t, err)

	// Extract certificates from first service of first TSP
	svc := tl.TrustServiceProviderList.TrustServiceProviders[0].TSPServices.TSPService[0]
	certs, skipped := ExtractServiceCertificates(svc.ServiceInformation.ServiceDigitalIdentity)
	require.Empty(t, skipped)
	require.Len(t, certs, 1)

	cert := certs[0]
	assert.Equal(t, "Test CA for eIDAS Trust List", cert.Subject.CommonName)
	assert.Equal(t, "Test TSP GmbH", cert.Subject.Organization[0])
	assert.Equal(t, "DE", cert.Subject.Country[0])
	assert.True(t, cert.IsCA)
}

func TestInternationalNames_GetEnglish(t *testing.T) {
	tests := []struct {
		name   string
		names  InternationalNames
		expect string
	}{
		{
			name: "english name present",
			names: InternationalNames{
				Names: []InternationalName{
					{Lang: "de", Value: "German Name"},
					{Lang: "en", Value: "English Name"},
				},
			},
			expect: "English Name",
		},
		{
			name: "english name case insensitive",
			names: InternationalNames{
				Names: []InternationalName{
					{Lang: "EN", Value: "Uppercase English"},
				},
			},
			expect: "Uppercase English",
		},
		{
			name: "no english name, fallback to first",
			names: InternationalNames{
				Names: []InternationalName{
					{Lang: "de", Value: "German Name"},
					{Lang: "fr", Value: "French Name"},
				},
			},
			expect: "German Name",
		},
		{
			name:   "no names at all",
			names:  InternationalNames{Names: nil},
			expect: "",
		},
		{
			name:   "empty names slice",
			names:  InternationalNames{Names: []InternationalName{}},
			expect: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, tc.names.GetEnglish())
		})
	}
}

func TestOtherTSLPointer_GetSchemeTerritory(t *testing.T) {
	ptr := OtherTSLPointer{
		AdditionalInformation: AdditionalInformation{
			OtherInformation: []OtherInformation{
				{TSLType: TSLTypeEUGeneric},
				{SchemeTerritory: "DE"},
			},
		},
	}
	assert.Equal(t, "DE", ptr.GetSchemeTerritory())
}

func TestOtherTSLPointer_GetSchemeTerritory_NotPresent(t *testing.T) {
	ptr := OtherTSLPointer{
		AdditionalInformation: AdditionalInformation{
			OtherInformation: []OtherInformation{
				{TSLType: TSLTypeEUGeneric},
			},
		},
	}
	assert.Equal(t, "", ptr.GetSchemeTerritory())
}

func TestOtherTSLPointer_GetTSLType(t *testing.T) {
	ptr := OtherTSLPointer{
		AdditionalInformation: AdditionalInformation{
			OtherInformation: []OtherInformation{
				{TSLType: TSLTypeEUGeneric},
			},
		},
	}
	assert.Equal(t, TSLTypeEUGeneric, ptr.GetTSLType())
}

func TestOtherTSLPointer_GetTSLType_NotPresent(t *testing.T) {
	ptr := OtherTSLPointer{
		AdditionalInformation: AdditionalInformation{
			OtherInformation: []OtherInformation{
				{SchemeTerritory: "DE"},
			},
		},
	}
	assert.Equal(t, "", ptr.GetTSLType())
}

func TestTrustedService_IsQualified(t *testing.T) {
	tests := []struct {
		name        string
		serviceType string
		qualified   bool
	}{
		{name: "CA/QC is qualified", serviceType: ServiceTypeCAQC, qualified: true},
		{name: "QTST is qualified", serviceType: ServiceTypeQTST, qualified: true},
		{name: "NationalRootCA-QC is qualified", serviceType: ServiceTypeNationalRootCAQC, qualified: true},
		{name: "EDS/Q is qualified", serviceType: ServiceTypeEDS, qualified: true},
		{name: "EDS/REM/Q is qualified", serviceType: ServiceTypeREMD, qualified: true},
		{name: "CA is not qualified", serviceType: ServiceTypeCA, qualified: false},
		{name: "TSA is not qualified", serviceType: ServiceTypeTSA, qualified: false},
		{name: "IdV is not qualified", serviceType: ServiceTypeIdV, qualified: false},
		{name: "unknown type is not qualified", serviceType: "http://example.com/unknown", qualified: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := TrustedService{ServiceType: tc.serviceType}
			assert.Equal(t, tc.qualified, svc.IsQualified())
		})
	}
}

func TestTrustedService_IsGranted(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		granted bool
	}{
		{name: "granted", status: ServiceStatusGranted, granted: true},
		{name: "withdrawn", status: ServiceStatusWithdrawn, granted: false},
		{name: "recognised at national level", status: ServiceStatusRecognisedAtNationalLevel, granted: false},
		{name: "empty status", status: "", granted: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := TrustedService{ServiceStatus: tc.status}
			assert.Equal(t, tc.granted, svc.IsGranted())
		})
	}
}

func TestParseDateTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Time
		wantErr bool
	}{
		{
			name:  "RFC 3339 with Z",
			input: "2024-06-01T00:00:00Z",
			want:  time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:  "RFC 3339 with offset",
			input: "2024-06-01T12:30:00+02:00",
			want:  time.Date(2024, 6, 1, 12, 30, 0, 0, time.FixedZone("", 7200)),
		},
		{
			name:  "ISO 8601 without timezone",
			input: "2024-06-01T00:00:00",
			want:  time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid format",
			input:   "not-a-date",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDateTime(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.True(t, tc.want.Equal(got), "expected %v, got %v", tc.want, got)
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify namespace and tag constants are correct
	assert.Equal(t, "http://uri.etsi.org/02231/v2#", TrustListNamespace)
	assert.Equal(t, "http://uri.etsi.org/19612/TSLTag", TSLTag)

	// Verify service type URIs follow ETSI conventions
	assert.Contains(t, ServiceTypeCAQC, "http://uri.etsi.org/TrstSvc/Svctype/")
	assert.Contains(t, ServiceTypeQTST, "http://uri.etsi.org/TrstSvc/Svctype/")
	assert.Contains(t, ServiceTypeCA, "http://uri.etsi.org/TrstSvc/Svctype/")

	// Verify service status URIs follow ETSI conventions
	assert.Contains(t, ServiceStatusGranted, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/")
	assert.Contains(t, ServiceStatusWithdrawn, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/")

	// Verify TSL type URIs
	assert.Contains(t, TSLTypeEUGeneric, "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/")
	assert.Contains(t, TSLTypeEUListOfTheLists, "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/")
}

func TestGetTrustServices_WithMultipleCertsPerService(t *testing.T) {
	// Test that multiple certificates per DigitalId are handled
	cert1, b64Cert1 := generateTestCertificate(t, "Cert 1", true)
	cert2, b64Cert2 := generateTestCertificate(t, "Cert 2", true)

	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    <SchemeOperatorName><Name xml:lang="en">Test</Name></SchemeOperatorName>
    <SchemeName><Name xml:lang="en">Test</Name></SchemeName>
    <SchemeInformationURI><URI xml:lang="en">https://example.com</URI></SchemeInformationURI>
    <StatusDeterminationApproach>test</StatusDeterminationApproach>
    <SchemeTerritory>TE</SchemeTerritory>
    <HistoricalInformationPeriod>0</HistoricalInformationPeriod>
    <ListIssueDateTime>2024-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2025-01-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">Multi-Cert TSP</Name></TSPName>
        <TSPTradeName/>
        <TSPInformationURI><URI xml:lang="en">https://example.com</URI></TSPInformationURI>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Multi-Cert Service</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>` + b64Cert1 + `</X509Certificate></DigitalId>
              <DigitalId><X509Certificate>` + b64Cert2 + `</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

	tl, err := ParseTrustList([]byte(xmlData))
	require.NoError(t, err)

	services, err := tl.GetTrustServices()
	require.NoError(t, err)
	require.Len(t, services, 1)

	svc := services[0]
	require.Len(t, svc.Certificates, 2)
	assert.Equal(t, cert1.Subject.CommonName, svc.Certificates[0].Subject.CommonName)
	assert.Equal(t, cert2.Subject.CommonName, svc.Certificates[1].Subject.CommonName)
}

func TestGetTrustServices_InvalidCertificate(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    <SchemeOperatorName><Name xml:lang="en">Test</Name></SchemeOperatorName>
    <SchemeName><Name xml:lang="en">Test</Name></SchemeName>
    <SchemeInformationURI><URI xml:lang="en">https://example.com</URI></SchemeInformationURI>
    <StatusDeterminationApproach>test</StatusDeterminationApproach>
    <SchemeTerritory>TE</SchemeTerritory>
    <HistoricalInformationPeriod>0</HistoricalInformationPeriod>
    <ListIssueDateTime>2024-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2025-01-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">Bad Cert TSP</Name></TSPName>
        <TSPTradeName/>
        <TSPInformationURI><URI xml:lang="en">https://example.com</URI></TSPInformationURI>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Bad Cert Service</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>dGhpcyBpcyBub3QgYSBjZXJ0aWZpY2F0ZQ==</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

	tl, err := ParseTrustList([]byte(xmlData))
	require.NoError(t, err)

	// The unparseable certificate is dropped, but it does not cost the list its
	// other entries — published national lists reliably carry a few of these.
	services, err := tl.GetTrustServices()
	require.NoError(t, err)
	require.Len(t, services, 1)
	assert.Empty(t, services[0].Certificates, "the unparseable certificate is not kept")
	assert.Equal(t, "Bad Cert Service", services[0].ServiceName)
}

func TestIsLOTL(t *testing.T) {
	tests := []struct {
		name    string
		tslType string
		isLOTL  bool
	}{
		{
			name:    "LOTL type",
			tslType: TSLTypeEUListOfTheLists,
			isLOTL:  true,
		},
		{
			name:    "generic type",
			tslType: TSLTypeEUGeneric,
			isLOTL:  false,
		},
		{
			name:    "empty type",
			tslType: "",
			isLOTL:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tl := &TrustServiceStatusList{
				SchemeInformation: SchemeInformation{TSLType: tc.tslType},
			}
			assert.Equal(t, tc.isLOTL, tl.IsLOTL())
		})
	}
}

// statusStartingTimeTL renders a minimal national trust list carrying a single
// granted CA/QC service with the given StatusStartingTime value.
func statusStartingTimeTL(t *testing.T, statusStartingTime string) string {
	t.Helper()
	_, b64Cert := generateTestCertificate(t, "Status Time CA", true)
	return `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    <SchemeOperatorName><Name xml:lang="en">Test</Name></SchemeOperatorName>
    <SchemeName><Name xml:lang="en">Test</Name></SchemeName>
    <SchemeInformationURI><URI xml:lang="en">https://example.com</URI></SchemeInformationURI>
    <SchemeTerritory>TE</SchemeTerritory>
    <ListIssueDateTime>2024-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2025-01-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">Test TSP</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Test Service</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>` + b64Cert + `</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>` + statusStartingTime + `</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`
}

// TestGetTrustServices_StatusStartingTime verifies that a service whose
// StatusStartingTime cannot be parsed is dropped rather than silently defaulting
// to the zero time, which would misplace it on the status timeline. The rest of
// the list is kept.
func TestGetTrustServices_StatusStartingTime(t *testing.T) {
	tests := []struct {
		name               string
		statusStartingTime string
		expectSkipped      bool
		expectedTime       time.Time
	}{
		{
			name:               "RFC 3339 with timezone",
			statusStartingTime: "2021-01-15T00:00:00Z",
			expectedTime:       time.Date(2021, 1, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			name:               "ISO 8601 without timezone",
			statusStartingTime: "2021-01-15T00:00:00",
			expectedTime:       time.Date(2021, 1, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			name:               "unparseable value drops the entry",
			statusStartingTime: "not-a-timestamp",
			expectSkipped:      true,
		},
		{
			name:               "empty value drops the entry",
			statusStartingTime: "",
			expectSkipped:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tl, err := ParseTrustList([]byte(statusStartingTimeTL(t, tc.statusStartingTime)))
			require.NoError(t, err)

			services, err := tl.GetTrustServices()
			require.NoError(t, err)
			if tc.expectSkipped {
				assert.Empty(t, services, "an entry that cannot be placed on the timeline is dropped")
				return
			}
			require.Len(t, services, 1)
			assert.Equal(t, tc.expectedTime, services[0].StatusStartingTime)
		})
	}
}

// TestStatusDeterminationApproach verifies that the declared status
// determination approach is normalised to its final path segment and that only
// the EU approaches are reported as EU-determined.
func TestStatusDeterminationApproach(t *testing.T) {
	tests := []struct {
		name         string
		approach     string
		expectedKind string
		expectedEU   bool
	}{
		{
			name:         "EU appropriate",
			approach:     "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate",
			expectedKind: StatusDetnEUAppropriate,
			expectedEU:   true,
		},
		{
			name:         "EU appropriate over https",
			approach:     "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate",
			expectedKind: StatusDetnEUAppropriate,
			expectedEU:   true,
		},
		{
			name:         "EU list of the lists",
			approach:     "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUlistofthelists",
			expectedKind: StatusDetnEUListOfTheLists,
			expectedEU:   true,
		},
		{
			name:         "third country determination",
			approach:     "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/CCdetermination",
			expectedKind: StatusDetnCCDetermination,
			expectedEU:   false,
		},
		{
			name:         "trailing slash is ignored",
			approach:     "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate/",
			expectedKind: StatusDetnEUAppropriate,
			expectedEU:   true,
		},
		{
			name:         "unknown approach",
			approach:     "http://example.com/whatever",
			expectedKind: "whatever",
			expectedEU:   false,
		},
		{
			name:         "no approach declared",
			approach:     "",
			expectedKind: "",
			expectedEU:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			si := SchemeInformation{StatusDeterminationApproach: tc.approach}
			assert.Equal(t, tc.expectedKind, si.StatusDeterminationKind())
			assert.Equal(t, tc.expectedEU, si.IsEUStatusDetermination())
		})
	}
}

// TestValidateFreshness verifies that a trust list is judged against its own
// ListIssueDateTime and NextUpdate, with a tolerance for clock skew.
func TestValidateFreshness(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name              string
		listIssueDateTime string
		nextUpdate        string
		expectedError     error
	}{
		{
			name:              "fresh list",
			listIssueDateTime: "2026-05-01T00:00:00Z",
			nextUpdate:        "2026-07-01T00:00:00Z",
		},
		{
			name:              "next update passed",
			listIssueDateTime: "2026-01-01T00:00:00Z",
			nextUpdate:        "2026-05-01T00:00:00Z",
			expectedError:     ErrorTrustListStale,
		},
		{
			name:              "next update just passed within skew tolerance",
			listIssueDateTime: "2026-01-01T00:00:00Z",
			nextUpdate:        "2026-06-01T11:58:00Z",
		},
		{
			name:              "no next update declared",
			listIssueDateTime: "2026-01-01T00:00:00Z",
			nextUpdate:        "",
		},
		{
			name:              "issued in the future",
			listIssueDateTime: "2026-08-01T00:00:00Z",
			nextUpdate:        "2026-09-01T00:00:00Z",
			expectedError:     ErrorTrustListNotYetIssued,
		},
		{
			name:              "issued slightly ahead within skew tolerance",
			listIssueDateTime: "2026-06-01T12:02:00Z",
			nextUpdate:        "2026-07-01T00:00:00Z",
		},
		{
			name:              "unparseable next update",
			listIssueDateTime: "2026-01-01T00:00:00Z",
			nextUpdate:        "soon",
			expectedError:     ErrorInvalidTrustListTimestamp,
		},
		{
			name:              "unparseable issue date",
			listIssueDateTime: "yesterday",
			nextUpdate:        "2026-07-01T00:00:00Z",
			expectedError:     ErrorInvalidTrustListTimestamp,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tl := &TrustServiceStatusList{
				SchemeInformation: SchemeInformation{
					ListIssueDateTime: tc.listIssueDateTime,
					NextUpdate:        NextUpdate{DateTime: tc.nextUpdate},
				},
			}

			err := tl.ValidateFreshness(now)
			if tc.expectedError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedError)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// TestHasNextUpdate verifies detection of lists that cannot be checked for
// staleness because they declare no NextUpdate.
func TestHasNextUpdate(t *testing.T) {
	tests := []struct {
		name       string
		nextUpdate string
		expected   bool
	}{
		{name: "declared", nextUpdate: "2026-07-01T00:00:00Z", expected: true},
		{name: "empty", nextUpdate: "", expected: false},
		{name: "whitespace only", nextUpdate: "   ", expected: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tl := &TrustServiceStatusList{
				SchemeInformation: SchemeInformation{NextUpdate: NextUpdate{DateTime: tc.nextUpdate}},
			}
			assert.Equal(t, tc.expected, tl.HasNextUpdate())
		})
	}
}

// TestRecordAt verifies that a trust service's status and type are resolved
// from its history as of a given point in time.
func TestRecordAt(t *testing.T) {
	granted2020 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	withdrawn2024 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	service := TrustedService{
		ServiceType:        ServiceTypeCA,
		ServiceStatus:      ServiceStatusWithdrawn,
		StatusStartingTime: withdrawn2024,
		History: []ServiceStatusRecord{
			{
				ServiceType:        ServiceTypeCAQC,
				ServiceStatus:      ServiceStatusGranted,
				StatusStartingTime: granted2020,
			},
		},
	}

	tests := []struct {
		name            string
		at              time.Time
		expectFound     bool
		expectedStatus  string
		expectedType    string
		expectedGranted bool
	}{
		{
			name:            "zero time evaluates the current entry",
			at:              time.Time{},
			expectFound:     true,
			expectedStatus:  ServiceStatusWithdrawn,
			expectedType:    ServiceTypeCA,
			expectedGranted: false,
		},
		{
			name:            "before the first known status",
			at:              time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
			expectFound:     false,
			expectedGranted: false,
		},
		{
			name:            "while granted",
			at:              time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC),
			expectFound:     true,
			expectedStatus:  ServiceStatusGranted,
			expectedType:    ServiceTypeCAQC,
			expectedGranted: true,
		},
		{
			name:            "exactly at the status starting time",
			at:              granted2020,
			expectFound:     true,
			expectedStatus:  ServiceStatusGranted,
			expectedType:    ServiceTypeCAQC,
			expectedGranted: true,
		},
		{
			name:            "after withdrawal",
			at:              time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			expectFound:     true,
			expectedStatus:  ServiceStatusWithdrawn,
			expectedType:    ServiceTypeCA,
			expectedGranted: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			record, found := service.RecordAt(tc.at)
			assert.Equal(t, tc.expectFound, found)
			if tc.expectFound {
				assert.Equal(t, tc.expectedStatus, record.ServiceStatus)
				assert.Equal(t, tc.expectedType, record.ServiceType)
			}
			assert.Equal(t, tc.expectedGranted, service.IsGrantedAt(tc.at))
		})
	}
}

// TestRecordAt_NoHistory verifies that a service without history falls back to
// its current entry, and is unknown before that entry started.
func TestRecordAt_NoHistory(t *testing.T) {
	service := TrustedService{
		ServiceType:        ServiceTypeCAQC,
		ServiceStatus:      ServiceStatusGranted,
		StatusStartingTime: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	_, found := service.RecordAt(time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC))
	assert.False(t, found, "service was not yet listed")
	assert.False(t, service.IsGrantedAt(time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)))

	record, found := service.RecordAt(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	require.True(t, found)
	assert.Equal(t, ServiceStatusGranted, record.ServiceStatus)
}

// TestHasServiceTypeAt verifies that the service type filter is applied to the
// entry in effect at the given time.
func TestHasServiceTypeAt(t *testing.T) {
	service := TrustedService{
		ServiceType:        ServiceTypeCA,
		ServiceStatus:      ServiceStatusGranted,
		StatusStartingTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		History: []ServiceStatusRecord{
			{
				ServiceType:        ServiceTypeCAQC,
				ServiceStatus:      ServiceStatusGranted,
				StatusStartingTime: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	qualified := map[string]struct{}{CanonicalETSIURI(ServiceTypeCAQC): {}}

	assert.True(t, service.HasServiceTypeAt(time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC), qualified),
		"service was qualified in 2022")
	assert.False(t, service.HasServiceTypeAt(time.Time{}, qualified),
		"service is no longer qualified today")
	assert.True(t, service.HasServiceTypeAt(time.Time{}, nil),
		"an empty type filter matches any type")
}

// TestGetTrustServices_ParsesServiceHistory verifies that ServiceHistory
// entries are extracted onto the trust service and are ordered oldest first.
func TestGetTrustServices_ParsesServiceHistory(t *testing.T) {
	_, b64Cert := generateTestCertificate(t, "History CA", true)

	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    <SchemeTerritory>TE</SchemeTerritory>
    <ListIssueDateTime>2024-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">History TSP</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">History Service</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>` + b64Cert + `</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
            <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
          <ServiceHistory>
            <ServiceHistoryInstance>
              <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
              <ServiceName><Name xml:lang="en">History Service</Name></ServiceName>
              <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
              <StatusStartingTime>2022-01-01T00:00:00Z</StatusStartingTime>
            </ServiceHistoryInstance>
            <ServiceHistoryInstance>
              <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
              <ServiceName><Name xml:lang="en">History Service</Name></ServiceName>
              <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision</ServiceStatus>
              <StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>
            </ServiceHistoryInstance>
          </ServiceHistory>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

	tl, err := ParseTrustList([]byte(xmlData))
	require.NoError(t, err)

	services, err := tl.GetTrustServices()
	require.NoError(t, err)
	require.Len(t, services, 1)

	history := services[0].History
	require.Len(t, history, 2, "both history instances should be extracted")
	assert.Equal(t, ServiceStatusUnderSupervision, history[0].ServiceStatus, "history is ordered oldest first")
	assert.Equal(t, ServiceStatusGranted, history[1].ServiceStatus)

	assert.True(t, services[0].IsGrantedAt(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
		"service was granted in 2023")
	assert.False(t, services[0].IsGrantedAt(time.Time{}), "service is withdrawn today")
}

// TestCanonicalETSIURI verifies that ETSI identifiers compare equal regardless
// of the URI scheme they are spelled with. The published EU lists use http,
// while documents written against the specification text often use https.
func TestCanonicalETSIURI(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		areEqual bool
	}{
		{
			name:     "identical http URIs",
			a:        "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
			b:        "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
			areEqual: true,
		},
		{
			name:     "http and https spellings of the same identifier",
			a:        "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
			b:        "https://uri.etsi.org/TrstSvc/Svctype/CA/QC",
			areEqual: true,
		},
		{
			name:     "uppercase scheme",
			a:        "HTTP://uri.etsi.org/TrstSvc/Svctype/CA/QC",
			b:        "https://uri.etsi.org/TrstSvc/Svctype/CA/QC",
			areEqual: true,
		},
		{
			name:     "trailing slash and whitespace are ignored",
			a:        "  http://uri.etsi.org/TrstSvc/Svctype/CA/QC/ ",
			b:        "https://uri.etsi.org/TrstSvc/Svctype/CA/QC",
			areEqual: true,
		},
		{
			name:     "different identifiers stay different",
			a:        "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
			b:        "https://uri.etsi.org/TrstSvc/Svctype/CA",
			areEqual: false,
		},
		{
			name:     "the path is case sensitive",
			a:        "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
			b:        "http://uri.etsi.org/trstsvc/svctype/ca/qc",
			areEqual: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.areEqual, equalETSIURI(tc.a, tc.b))
		})
	}
}

// TestTrustList_HttpsSpelledURIs verifies that a trust list written with https
// spellings of the ETSI identifiers is understood exactly like the published
// http ones: the list type, the service type and the granted status all match.
func TestTrustList_HttpsSpelledURIs(t *testing.T) {
	_, b64Cert := generateTestCertificate(t, "Https Spelled CA", true)

	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="https://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLType>https://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    <SchemeTerritory>TE</SchemeTerritory>
    <ListIssueDateTime>2024-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">Https Spelled TSP</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>https://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Https Spelled Service</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509Certificate>` + b64Cert + `</X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2024-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

	tl, err := ParseTrustList([]byte(xmlData))
	require.NoError(t, err)
	assert.False(t, tl.IsLOTL(), "an EUgeneric list is not a LOTL")

	services, err := tl.GetTrustServices()
	require.NoError(t, err)
	require.Len(t, services, 1)

	assert.True(t, services[0].IsGranted(), "the https-spelled granted status must match")
	assert.True(t, services[0].IsQualified(), "the https-spelled CA/QC type must match")

	// The store filters on the canonical form, so an http-spelled filter finds
	// the https-spelled entry.
	store := NewTrustStore()
	store.Update("TE", services)
	assert.Len(t, store.GetTrustedServices("TE", []string{ServiceTypeCAQC}, true), 1)
}

// TestGetDistributionPoints_MediaTypeFilter verifies that only the machine
// readable representation is followed. Every EU territory publishes its list
// twice under the same TSLType: once as XML and once as a human readable PDF.
func TestGetDistributionPoints_MediaTypeFilter(t *testing.T) {
	pointer := func(location, mimeType string) string {
		mimeElement := ""
		if mimeType != "" {
			mimeElement = "<OtherInformation><MimeType>" + mimeType + "</MimeType></OtherInformation>"
		}
		return `<OtherTSLPointer>
          <TSLLocation>` + location + `</TSLLocation>
          <AdditionalInformation>
            <OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType></OtherInformation>
            <OtherInformation><SchemeTerritory>TE</SchemeTerritory></OtherInformation>
            ` + mimeElement + `
          </AdditionalInformation>
        </OtherTSLPointer>`
	}

	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType>
    <SchemeTerritory>EU</SchemeTerritory>
    <PointersToOtherTSL>` +
		pointer("https://example.test/tl.pdf", "application/pdf") +
		pointer("https://example.test/tl.xml", MimeTypeTSL) +
		pointer("https://example.test/legacy.xml", "") +
		`</PointersToOtherTSL>
  </SchemeInformation>
</TrustServiceStatusList>`

	tl, err := ParseTrustList([]byte(xmlData))
	require.NoError(t, err)
	require.True(t, tl.IsLOTL())

	points := tl.GetDistributionPoints()
	require.Len(t, points, 2, "the PDF representation must be skipped")

	locations := []string{points[0].TSLLocation, points[1].TSLLocation}
	assert.Contains(t, locations, "https://example.test/tl.xml")
	assert.Contains(t, locations, "https://example.test/legacy.xml",
		"a pointer declaring no media type is kept")
}
