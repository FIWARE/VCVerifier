package eidas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed X.509 certificate for testing.
func generateTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)
	return cert
}

func init() {
	// Ensure logging is initialized for tests.
	initTestLogging()
}

func TestNewTrustStore(t *testing.T) {
	store := NewTrustStore()
	assert.NotNil(t, store)
	assert.Empty(t, store.CountryCodesLoaded())
	assert.Equal(t, 0, store.ServiceCount())
}

func TestTrustStore_Update(t *testing.T) {
	store := NewTrustStore()

	services := []TrustedService{
		{
			CountryCode:   "DE",
			TSPName:       "Test TSP",
			ServiceName:   "Test Service",
			ServiceType:   ServiceTypeCAQC,
			ServiceStatus: ServiceStatusGranted,
		},
		{
			CountryCode:   "DE",
			TSPName:       "Test TSP",
			ServiceName:   "Another Service",
			ServiceType:   ServiceTypeCA,
			ServiceStatus: ServiceStatusWithdrawn,
		},
	}

	store.Update("DE", services)

	assert.Equal(t, 2, store.ServiceCount())
	assert.Contains(t, store.CountryCodesLoaded(), "DE")
}

func TestTrustStore_Update_ReplacesExisting(t *testing.T) {
	store := NewTrustStore()

	original := []TrustedService{
		{CountryCode: "DE", ServiceName: "Original"},
	}
	store.Update("DE", original)
	assert.Equal(t, 1, store.ServiceCount())

	replacement := []TrustedService{
		{CountryCode: "DE", ServiceName: "Replacement 1"},
		{CountryCode: "DE", ServiceName: "Replacement 2"},
	}
	store.Update("DE", replacement)
	assert.Equal(t, 2, store.ServiceCount())

	all := store.GetTrustedServices("DE", nil, false)
	assert.Len(t, all, 2)
	assert.Equal(t, "Replacement 1", all[0].ServiceName)
}

func TestTrustStore_Clear(t *testing.T) {
	store := NewTrustStore()
	store.Update("DE", []TrustedService{{CountryCode: "DE", ServiceName: "S1"}})
	store.Update("FR", []TrustedService{{CountryCode: "FR", ServiceName: "S2"}})
	assert.Equal(t, 2, store.ServiceCount())

	store.Clear()
	assert.Equal(t, 0, store.ServiceCount())
	assert.Empty(t, store.CountryCodesLoaded())
}

func TestTrustStore_RemoveCountriesNotIn(t *testing.T) {
	store := NewTrustStore()
	store.Update("DE", []TrustedService{{CountryCode: "DE", ServiceName: "S1"}})
	store.Update("FR", []TrustedService{{CountryCode: "FR", ServiceName: "S2"}})
	store.Update("ES", []TrustedService{{CountryCode: "ES", ServiceName: "S3"}})
	assert.Equal(t, 3, store.ServiceCount())

	// Keep only DE and ES.
	keep := map[string]struct{}{"DE": {}, "ES": {}}
	store.RemoveCountriesNotIn(keep)

	assert.Equal(t, 2, store.ServiceCount())
	assert.ElementsMatch(t, []string{"DE", "ES"}, store.CountryCodesLoaded())
	assert.Empty(t, store.GetTrustedServices("FR", nil, false))
}

func TestTrustStore_RemoveCountriesNotIn_EmptyKeepRemovesAll(t *testing.T) {
	store := NewTrustStore()
	store.Update("DE", []TrustedService{{CountryCode: "DE", ServiceName: "S1"}})
	store.Update("FR", []TrustedService{{CountryCode: "FR", ServiceName: "S2"}})

	store.RemoveCountriesNotIn(map[string]struct{}{})
	assert.Equal(t, 0, store.ServiceCount())
	assert.Empty(t, store.CountryCodesLoaded())
}

func TestTrustStore_GetTrustedServices_ByCountry(t *testing.T) {
	store := NewTrustStore()
	store.Update("DE", []TrustedService{
		{CountryCode: "DE", ServiceName: "DE Service", ServiceType: ServiceTypeCAQC, ServiceStatus: ServiceStatusGranted},
	})
	store.Update("FR", []TrustedService{
		{CountryCode: "FR", ServiceName: "FR Service", ServiceType: ServiceTypeCA, ServiceStatus: ServiceStatusGranted},
	})

	tests := []struct {
		name        string
		countryCode string
		wantNames   []string
	}{
		{
			name:        "specific country DE",
			countryCode: "DE",
			wantNames:   []string{"DE Service"},
		},
		{
			name:        "specific country FR",
			countryCode: "FR",
			wantNames:   []string{"FR Service"},
		},
		{
			name:        "empty country returns all",
			countryCode: "",
			wantNames:   []string{"DE Service", "FR Service"},
		},
		{
			name:        "unknown country returns empty",
			countryCode: "XX",
			wantNames:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.GetTrustedServices(tt.countryCode, nil, false)
			var names []string
			for _, s := range result {
				names = append(names, s.ServiceName)
			}
			if tt.wantNames == nil {
				assert.Empty(t, result)
			} else {
				assert.ElementsMatch(t, tt.wantNames, names)
			}
		})
	}
}

func TestTrustStore_GetTrustedServices_ByServiceType(t *testing.T) {
	store := NewTrustStore()
	store.Update("DE", []TrustedService{
		{CountryCode: "DE", ServiceName: "QC CA", ServiceType: ServiceTypeCAQC, ServiceStatus: ServiceStatusGranted},
		{CountryCode: "DE", ServiceName: "Plain CA", ServiceType: ServiceTypeCA, ServiceStatus: ServiceStatusGranted},
		{CountryCode: "DE", ServiceName: "TSA", ServiceType: ServiceTypeTSA, ServiceStatus: ServiceStatusGranted},
	})

	tests := []struct {
		name         string
		serviceTypes []string
		wantNames    []string
	}{
		{
			name:         "filter single type",
			serviceTypes: []string{ServiceTypeCAQC},
			wantNames:    []string{"QC CA"},
		},
		{
			name:         "filter multiple types",
			serviceTypes: []string{ServiceTypeCAQC, ServiceTypeTSA},
			wantNames:    []string{"QC CA", "TSA"},
		},
		{
			name:         "empty types returns all",
			serviceTypes: nil,
			wantNames:    []string{"QC CA", "Plain CA", "TSA"},
		},
		{
			name:         "no matching type",
			serviceTypes: []string{ServiceTypeQTST},
			wantNames:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.GetTrustedServices("DE", tt.serviceTypes, false)
			var names []string
			for _, s := range result {
				names = append(names, s.ServiceName)
			}
			if tt.wantNames == nil {
				assert.Empty(t, result)
			} else {
				assert.ElementsMatch(t, tt.wantNames, names)
			}
		})
	}
}

func TestTrustStore_GetTrustedServices_OnlyGranted(t *testing.T) {
	store := NewTrustStore()
	store.Update("DE", []TrustedService{
		{CountryCode: "DE", ServiceName: "Granted", ServiceStatus: ServiceStatusGranted},
		{CountryCode: "DE", ServiceName: "Withdrawn", ServiceStatus: ServiceStatusWithdrawn},
		{CountryCode: "DE", ServiceName: "Under Supervision", ServiceStatus: ServiceStatusUnderSupervision},
	})

	tests := []struct {
		name        string
		onlyGranted bool
		wantNames   []string
	}{
		{
			name:        "only granted",
			onlyGranted: true,
			wantNames:   []string{"Granted"},
		},
		{
			name:        "all statuses",
			onlyGranted: false,
			wantNames:   []string{"Granted", "Withdrawn", "Under Supervision"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.GetTrustedServices("DE", nil, tt.onlyGranted)
			var names []string
			for _, s := range result {
				names = append(names, s.ServiceName)
			}
			assert.ElementsMatch(t, tt.wantNames, names)
		})
	}
}

func TestTrustStore_GetTrustedServices_CombinedFilters(t *testing.T) {
	store := NewTrustStore()
	store.Update("DE", []TrustedService{
		{CountryCode: "DE", ServiceName: "DE QC Granted", ServiceType: ServiceTypeCAQC, ServiceStatus: ServiceStatusGranted},
		{CountryCode: "DE", ServiceName: "DE QC Withdrawn", ServiceType: ServiceTypeCAQC, ServiceStatus: ServiceStatusWithdrawn},
		{CountryCode: "DE", ServiceName: "DE CA Granted", ServiceType: ServiceTypeCA, ServiceStatus: ServiceStatusGranted},
	})
	store.Update("FR", []TrustedService{
		{CountryCode: "FR", ServiceName: "FR QC Granted", ServiceType: ServiceTypeCAQC, ServiceStatus: ServiceStatusGranted},
	})

	// Country=DE, Type=CAQC, OnlyGranted=true
	result := store.GetTrustedServices("DE", []string{ServiceTypeCAQC}, true)
	require.Len(t, result, 1)
	assert.Equal(t, "DE QC Granted", result[0].ServiceName)
}

func TestTrustStore_IsTrustedService(t *testing.T) {
	cert1 := generateTestCert(t, "Test Cert 1")
	cert2 := generateTestCert(t, "Test Cert 2")

	store := NewTrustStore()
	store.Update("DE", []TrustedService{
		{
			CountryCode:   "DE",
			ServiceName:   "Test Service",
			ServiceType:   ServiceTypeCAQC,
			ServiceStatus: ServiceStatusGranted,
			Certificates:  []*x509.Certificate{cert1},
		},
	})

	tests := []struct {
		name        string
		cert        *x509.Certificate
		countryCode string
		types       []string
		want        bool
	}{
		{
			name:        "matching certificate",
			cert:        cert1,
			countryCode: "DE",
			types:       []string{ServiceTypeCAQC},
			want:        true,
		},
		{
			name:        "non-matching certificate",
			cert:        cert2,
			countryCode: "DE",
			types:       []string{ServiceTypeCAQC},
			want:        false,
		},
		{
			name:        "wrong country",
			cert:        cert1,
			countryCode: "FR",
			types:       []string{ServiceTypeCAQC},
			want:        false,
		},
		{
			name:        "wrong service type",
			cert:        cert1,
			countryCode: "DE",
			types:       []string{ServiceTypeCA},
			want:        false,
		},
		{
			name:        "nil certificate",
			cert:        nil,
			countryCode: "DE",
			types:       nil,
			want:        false,
		},
		{
			name:        "empty country searches all",
			cert:        cert1,
			countryCode: "",
			types:       nil,
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := store.IsTrustedService(tt.cert, tt.countryCode, tt.types)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTrustStore_IsTrustedService_OnlyGrantedServices(t *testing.T) {
	cert := generateTestCert(t, "Withdrawn Cert")

	store := NewTrustStore()
	store.Update("DE", []TrustedService{
		{
			CountryCode:   "DE",
			ServiceName:   "Withdrawn Service",
			ServiceType:   ServiceTypeCAQC,
			ServiceStatus: ServiceStatusWithdrawn,
			Certificates:  []*x509.Certificate{cert},
		},
	})

	// IsTrustedService only checks granted services.
	assert.False(t, store.IsTrustedService(cert, "DE", nil))
}

func TestTrustStore_ConcurrentAccess(t *testing.T) {
	store := NewTrustStore()
	cert := generateTestCert(t, "Concurrent Cert")

	const numGoroutines = 50
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			cc := "C" + string(rune('A'+id%26))
			for j := 0; j < numOperations; j++ {
				switch j % 3 {
				case 0:
					// Writer.
					store.Update(cc, []TrustedService{
						{
							CountryCode:   cc,
							ServiceName:   "Service",
							ServiceType:   ServiceTypeCAQC,
							ServiceStatus: ServiceStatusGranted,
							Certificates:  []*x509.Certificate{cert},
						},
					})
				case 1:
					// Reader - GetTrustedServices.
					_ = store.GetTrustedServices(cc, nil, false)
				default:
					// Reader - IsTrustedService.
					_ = store.IsTrustedService(cert, cc, nil)
				}
			}
		}(i)
	}

	wg.Wait()
	// No race condition detected means the test passes.
	assert.Greater(t, store.ServiceCount(), 0)
}

func TestTrustStore_CountryCodesLoaded(t *testing.T) {
	store := NewTrustStore()
	store.Update("DE", []TrustedService{{CountryCode: "DE"}})
	store.Update("FR", []TrustedService{{CountryCode: "FR"}})
	store.Update("ES", []TrustedService{{CountryCode: "ES"}})

	codes := store.CountryCodesLoaded()
	assert.Len(t, codes, 3)
	assert.ElementsMatch(t, []string{"DE", "FR", "ES"}, codes)
}

func TestTrustStore_ServiceCount(t *testing.T) {
	store := NewTrustStore()
	assert.Equal(t, 0, store.ServiceCount())

	store.Update("DE", []TrustedService{
		{CountryCode: "DE", ServiceName: "S1"},
		{CountryCode: "DE", ServiceName: "S2"},
	})
	assert.Equal(t, 2, store.ServiceCount())

	store.Update("FR", []TrustedService{
		{CountryCode: "FR", ServiceName: "S3"},
	})
	assert.Equal(t, 3, store.ServiceCount())
}
