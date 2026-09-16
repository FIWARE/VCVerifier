package eidas

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	initTestLogging()
}

// --- LOTL and national TL XML templates for httptest ---

// lotlTemplate produces a minimal LOTL XML with dynamic distribution point URLs.
// Use %s placeholders for the national TL URLs (DE, FR).
const lotlTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="https://uri.etsi.org/02231/v2#" Id="test-lotl" TSLTag="https://uri.etsi.org/19612/TSLTag">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <TSLType>https://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType>
    <SchemeOperatorName>
      <Name xml:lang="en">Test LOTL Operator</Name>
    </SchemeOperatorName>
    <SchemeName>
      <Name xml:lang="en">Test LOTL</Name>
    </SchemeName>
    <SchemeInformationURI>
      <URI xml:lang="en">https://example.com/lotl</URI>
    </SchemeInformationURI>
    <StatusDeterminationApproach>https://uri.etsi.org/TrstSvc/TrustedList/TSLType/StatusDetn/EUappropriate</StatusDeterminationApproach>
    <SchemeTerritory>EU</SchemeTerritory>
    <HistoricalInformationPeriod>65535</HistoricalInformationPeriod>
    <ListIssueDateTime>2024-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate>
      <dateTime>2025-01-01T00:00:00Z</dateTime>
    </NextUpdate>
    <PointersToOtherTSL>
      %s
    </PointersToOtherTSL>
  </SchemeInformation>
</TrustServiceStatusList>`

// pointerTemplate produces a single OtherTSLPointer XML element.
const pointerTemplate = `<OtherTSLPointer>
        <ServiceDigitalIdentities>
          <ServiceDigitalIdentity>
            <DigitalId><X509SubjectName>CN=%s TL Signer</X509SubjectName></DigitalId>
          </ServiceDigitalIdentity>
        </ServiceDigitalIdentities>
        <TSLLocation>%s</TSLLocation>
        <AdditionalInformation>
          <OtherInformation>
            <TSLType>https://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
          </OtherInformation>
          <OtherInformation>
            <SchemeTerritory>%s</SchemeTerritory>
          </OtherInformation>
        </AdditionalInformation>
      </OtherTSLPointer>`

// nationalTLTemplate produces a minimal national TL XML with one TSP.
const nationalTLTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="https://uri.etsi.org/02231/v2#" Id="tl-%s" TSLTag="https://uri.etsi.org/19612/TSLTag">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <TSLType>https://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    <SchemeOperatorName><Name xml:lang="en">%s Operator</Name></SchemeOperatorName>
    <SchemeName><Name xml:lang="en">%s Trusted List</Name></SchemeName>
    <SchemeInformationURI><URI xml:lang="en">https://example.com/tl/%s</URI></SchemeInformationURI>
    <StatusDeterminationApproach>https://uri.etsi.org/TrstSvc/TrustedList/TSLType/StatusDetn/EUappropriate</StatusDeterminationApproach>
    <SchemeTerritory>%s</SchemeTerritory>
    <HistoricalInformationPeriod>65535</HistoricalInformationPeriod>
    <ListIssueDateTime>2024-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2025-01-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">%s TSP</Name></TSPName>
        <TSPTradeName><Name xml:lang="en">%s TSP</Name></TSPTradeName>
        <TSPInformationURI><URI xml:lang="en">https://tsp.example.%s</URI></TSPInformationURI>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>%s</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">%s QC CA</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId><X509SubjectName>CN=%s QC CA</X509SubjectName></DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>%s</ServiceStatus>
            <StatusStartingTime>2023-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

// makeNationalTLXML builds a national TL XML string for the given country code.
func makeNationalTLXML(cc, serviceType, status string) string {
	lcc := strings.ToLower(cc)
	return fmt.Sprintf(nationalTLTemplate,
		lcc, cc, cc, lcc, cc, cc, cc, lcc, serviceType, cc, cc, status)
}

// --- Tests ---

func TestNewTrustListFetcher_Defaults(t *testing.T) {
	f := NewTrustListFetcher()
	assert.Equal(t, DefaultLOTLURL, f.lotlURL)
	assert.Equal(t, DefaultRefreshInterval, f.refreshInterval)
	assert.Equal(t, DefaultMaxWorkers, f.maxWorkers)
	assert.NotNil(t, f.store)
	assert.NotNil(t, f.httpClient)
}

func TestNewTrustListFetcher_WithOptions(t *testing.T) {
	store := NewTrustStore()
	client := &http.Client{Timeout: 10 * time.Second}

	f := NewTrustListFetcher(
		WithLOTLURL("https://custom.example.com/lotl.xml"),
		WithRefreshInterval(2*time.Hour),
		WithAllowedCountries([]string{"DE", "FR"}),
		WithHTTPClient(client),
		WithMaxWorkers(10),
		WithTrustStore(store),
	)

	assert.Equal(t, "https://custom.example.com/lotl.xml", f.lotlURL)
	assert.Equal(t, 2*time.Hour, f.refreshInterval)
	assert.Len(t, f.allowedCountries, 2)
	assert.Contains(t, f.allowedCountries, "DE")
	assert.Contains(t, f.allowedCountries, "FR")
	assert.Equal(t, client, f.httpClient)
	assert.Equal(t, 10, f.maxWorkers)
	assert.Equal(t, store, f.store)
}

func TestWithRefreshInterval_Clamping(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected time.Duration
	}{
		{"below min", 1 * time.Minute, MinRefreshInterval},
		{"at min", MinRefreshInterval, MinRefreshInterval},
		{"normal", 6 * time.Hour, 6 * time.Hour},
		{"at max", MaxRefreshInterval, MaxRefreshInterval},
		{"above max", 30 * 24 * time.Hour, MaxRefreshInterval},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewTrustListFetcher(WithRefreshInterval(tt.input))
			assert.Equal(t, tt.expected, f.refreshInterval)
		})
	}
}

func TestWithMaxWorkers_IgnoresNonPositive(t *testing.T) {
	f := NewTrustListFetcher(WithMaxWorkers(0))
	assert.Equal(t, DefaultMaxWorkers, f.maxWorkers)

	f = NewTrustListFetcher(WithMaxWorkers(-1))
	assert.Equal(t, DefaultMaxWorkers, f.maxWorkers)
}

func TestWithAllowedCountries_NormalizesCase(t *testing.T) {
	f := NewTrustListFetcher(WithAllowedCountries([]string{"de", "Fr", "ES"}))
	assert.Contains(t, f.allowedCountries, "DE")
	assert.Contains(t, f.allowedCountries, "FR")
	assert.Contains(t, f.allowedCountries, "ES")
}

func TestTrustListFetcher_Refresh_FullHierarchy(t *testing.T) {
	// Set up httptest servers for LOTL and national TLs.
	deTL := makeNationalTLXML("DE", ServiceTypeCAQC, ServiceStatusGranted)
	frTL := makeNationalTLXML("FR", ServiceTypeCA, ServiceStatusGranted)

	// National TL servers.
	deServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, deTL)
	}))
	defer deServer.Close()

	frServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, frTL)
	}))
	defer frServer.Close()

	// Build LOTL with dynamic URLs.
	dePointer := fmt.Sprintf(pointerTemplate, "DE", deServer.URL, "DE")
	frPointer := fmt.Sprintf(pointerTemplate, "FR", frServer.URL, "FR")
	lotlXML := fmt.Sprintf(lotlTemplate, dePointer+"\n"+frPointer)

	lotlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer lotlServer.Close()

	store := NewTrustStore()
	f := NewTrustListFetcher(
		WithLOTLURL(lotlServer.URL),
		WithHTTPClient(lotlServer.Client()),
		WithTrustStore(store),
	)

	err := f.Refresh(context.Background())
	require.NoError(t, err)

	// Verify the store was populated.
	assert.Equal(t, 2, store.ServiceCount())
	assert.ElementsMatch(t, []string{"DE", "FR"}, store.CountryCodesLoaded())

	deServices := store.GetTrustedServices("DE", nil, false)
	require.Len(t, deServices, 1)
	assert.Equal(t, "DE QC CA", deServices[0].ServiceName)
	assert.Equal(t, ServiceTypeCAQC, deServices[0].ServiceType)
	assert.Equal(t, ServiceStatusGranted, deServices[0].ServiceStatus)

	frServices := store.GetTrustedServices("FR", nil, false)
	require.Len(t, frServices, 1)
	assert.Equal(t, "FR QC CA", frServices[0].ServiceName)
	assert.Equal(t, ServiceTypeCA, frServices[0].ServiceType)
}

func TestTrustListFetcher_Refresh_WithCountryFilter(t *testing.T) {
	deTL := makeNationalTLXML("DE", ServiceTypeCAQC, ServiceStatusGranted)
	frTL := makeNationalTLXML("FR", ServiceTypeCA, ServiceStatusGranted)

	deServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, deTL)
	}))
	defer deServer.Close()

	frServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, frTL)
	}))
	defer frServer.Close()

	dePointer := fmt.Sprintf(pointerTemplate, "DE", deServer.URL, "DE")
	frPointer := fmt.Sprintf(pointerTemplate, "FR", frServer.URL, "FR")
	lotlXML := fmt.Sprintf(lotlTemplate, dePointer+"\n"+frPointer)

	lotlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer lotlServer.Close()

	store := NewTrustStore()
	f := NewTrustListFetcher(
		WithLOTLURL(lotlServer.URL),
		WithHTTPClient(lotlServer.Client()),
		WithTrustStore(store),
		WithAllowedCountries([]string{"DE"}),
	)

	err := f.Refresh(context.Background())
	require.NoError(t, err)

	// Only DE should be fetched.
	assert.Equal(t, 1, store.ServiceCount())
	assert.Contains(t, store.CountryCodesLoaded(), "DE")
	assert.NotContains(t, store.CountryCodesLoaded(), "FR")
}

func TestTrustListFetcher_Refresh_LOTLFetchError(t *testing.T) {
	lotlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer lotlServer.Close()

	f := NewTrustListFetcher(
		WithLOTLURL(lotlServer.URL),
		WithHTTPClient(lotlServer.Client()),
	)

	err := f.Refresh(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code 500")
}

func TestTrustListFetcher_Refresh_InvalidLOTLXML(t *testing.T) {
	lotlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "not xml")
	}))
	defer lotlServer.Close()

	f := NewTrustListFetcher(
		WithLOTLURL(lotlServer.URL),
		WithHTTPClient(lotlServer.Client()),
	)

	err := f.Refresh(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse LOTL")
}

func TestTrustListFetcher_Refresh_NotALOTL(t *testing.T) {
	// Serve a national TL (EUgeneric) where a LOTL is expected.
	nationalXML := makeNationalTLXML("DE", ServiceTypeCAQC, ServiceStatusGranted)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, nationalXML)
	}))
	defer server.Close()

	f := NewTrustListFetcher(
		WithLOTLURL(server.URL),
		WithHTTPClient(server.Client()),
	)

	err := f.Refresh(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a LOTL")
}

func TestTrustListFetcher_Refresh_NoDistributionPoints(t *testing.T) {
	// LOTL with no pointers.
	lotlXML := fmt.Sprintf(lotlTemplate, "") // empty pointers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer server.Close()

	store := NewTrustStore()
	f := NewTrustListFetcher(
		WithLOTLURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTrustStore(store),
	)

	err := f.Refresh(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, store.ServiceCount())
}

func TestTrustListFetcher_Refresh_NationalTLFetchError(t *testing.T) {
	// DE server returns 500, FR works fine.
	frTL := makeNationalTLXML("FR", ServiceTypeCA, ServiceStatusGranted)

	deServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer deServer.Close()

	frServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, frTL)
	}))
	defer frServer.Close()

	dePointer := fmt.Sprintf(pointerTemplate, "DE", deServer.URL, "DE")
	frPointer := fmt.Sprintf(pointerTemplate, "FR", frServer.URL, "FR")
	lotlXML := fmt.Sprintf(lotlTemplate, dePointer+"\n"+frPointer)

	lotlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer lotlServer.Close()

	store := NewTrustStore()
	f := NewTrustListFetcher(
		WithLOTLURL(lotlServer.URL),
		WithHTTPClient(lotlServer.Client()),
		WithTrustStore(store),
	)

	// Refresh should succeed overall; the failing national TL is logged and skipped.
	err := f.Refresh(context.Background())
	require.NoError(t, err)

	// Only FR should be loaded.
	assert.Equal(t, 1, store.ServiceCount())
	assert.Contains(t, store.CountryCodesLoaded(), "FR")
}

func TestTrustListFetcher_Refresh_NationalTLInvalidXML(t *testing.T) {
	deServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "invalid xml garbage")
	}))
	defer deServer.Close()

	dePointer := fmt.Sprintf(pointerTemplate, "DE", deServer.URL, "DE")
	lotlXML := fmt.Sprintf(lotlTemplate, dePointer)

	lotlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer lotlServer.Close()

	store := NewTrustStore()
	f := NewTrustListFetcher(
		WithLOTLURL(lotlServer.URL),
		WithHTTPClient(lotlServer.Client()),
		WithTrustStore(store),
	)

	err := f.Refresh(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, store.ServiceCount())
}

func TestTrustListFetcher_Refresh_ContextCancelled(t *testing.T) {
	// Ensure context cancellation stops the fetch.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	f := NewTrustListFetcher(
		WithLOTLURL("http://should-not-reach.example.com"),
	)

	err := f.Refresh(ctx)
	assert.Error(t, err)
}

func TestTrustListFetcher_StartStop(t *testing.T) {
	var fetchCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		// Return a valid LOTL with no distribution points.
		lotlXML := fmt.Sprintf(lotlTemplate, "")
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer server.Close()

	f := NewTrustListFetcher(
		WithLOTLURL(server.URL),
		WithHTTPClient(server.Client()),
		WithRefreshInterval(MinRefreshInterval), // Use minimum interval.
	)

	f.Start(context.Background())

	// Wait for the initial fetch.
	require.Eventually(t, func() bool {
		return fetchCount.Load() >= 1
	}, 5*time.Second, 50*time.Millisecond, "initial fetch should complete")

	f.Stop()

	// After stop, no more fetches should occur.
	countAfterStop := fetchCount.Load()
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, countAfterStop, fetchCount.Load(), "no fetches should occur after Stop()")
}

func TestTrustListFetcher_StartIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lotlXML := fmt.Sprintf(lotlTemplate, "")
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer server.Close()

	f := NewTrustListFetcher(
		WithLOTLURL(server.URL),
		WithHTTPClient(server.Client()),
	)

	f.Start(context.Background())
	f.Start(context.Background()) // Second call should be a no-op.

	// Wait for the initial fetch to complete.
	time.Sleep(200 * time.Millisecond)
	f.Stop()
}

func TestTrustListFetcher_StartAfterStop(t *testing.T) {
	var fetchCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		lotlXML := fmt.Sprintf(lotlTemplate, "")
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer server.Close()

	f := NewTrustListFetcher(
		WithLOTLURL(server.URL),
		WithHTTPClient(server.Client()),
		WithRefreshInterval(MinRefreshInterval),
	)

	// First lifecycle: start and stop.
	f.Start(context.Background())
	require.Eventually(t, func() bool {
		return fetchCount.Load() >= 1
	}, 5*time.Second, 50*time.Millisecond, "first start: initial fetch should complete")
	f.Stop()

	countAfterFirstStop := fetchCount.Load()

	// Second lifecycle: start again after stop — must not panic.
	f.Start(context.Background())
	require.Eventually(t, func() bool {
		return fetchCount.Load() > countAfterFirstStop
	}, 5*time.Second, 50*time.Millisecond, "second start: initial fetch should complete")
	f.Stop()
}

func TestTrustListFetcher_StopIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lotlXML := fmt.Sprintf(lotlTemplate, "")
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer server.Close()

	f := NewTrustListFetcher(
		WithLOTLURL(server.URL),
		WithHTTPClient(server.Client()),
	)

	f.Start(context.Background())
	time.Sleep(200 * time.Millisecond)
	f.Stop()
	f.Stop() // Second call should not panic.
}

func TestTrustListFetcher_Store(t *testing.T) {
	store := NewTrustStore()
	f := NewTrustListFetcher(WithTrustStore(store))
	assert.Equal(t, store, f.Store())
}

func TestTrustListFetcher_Store_DefaultCreation(t *testing.T) {
	f := NewTrustListFetcher()
	assert.NotNil(t, f.Store())
}

func TestTrustListFetcher_ConcurrentNationalTLFetch(t *testing.T) {
	// Verify concurrent fetching with multiple countries.
	const numCountries = 8
	servers := make([]*httptest.Server, numCountries)
	var pointers []string

	countryCodes := []string{"DE", "FR", "ES", "IT", "NL", "BE", "AT", "PT"}

	for i, cc := range countryCodes {
		ccLocal := cc
		tlXML := makeNationalTLXML(ccLocal, ServiceTypeCAQC, ServiceStatusGranted)
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, tlXML)
		}))
		defer servers[i].Close()

		pointers = append(pointers, fmt.Sprintf(pointerTemplate, ccLocal, servers[i].URL, ccLocal))
	}

	lotlXML := fmt.Sprintf(lotlTemplate, strings.Join(pointers, "\n"))
	lotlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer lotlServer.Close()

	store := NewTrustStore()
	f := NewTrustListFetcher(
		WithLOTLURL(lotlServer.URL),
		WithHTTPClient(lotlServer.Client()),
		WithTrustStore(store),
		WithMaxWorkers(3), // Test bounded concurrency.
	)

	err := f.Refresh(context.Background())
	require.NoError(t, err)

	assert.Equal(t, numCountries, store.ServiceCount())
	assert.ElementsMatch(t, countryCodes, store.CountryCodesLoaded())
}

func TestTrustListFetcher_Refresh_UpdatesExistingData(t *testing.T) {
	// First refresh loads data, second refresh with different data replaces it.
	var version atomic.Int32

	deServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := version.Load()
		var status string
		if v == 0 {
			status = ServiceStatusGranted
		} else {
			status = ServiceStatusWithdrawn
		}
		tlXML := makeNationalTLXML("DE", ServiceTypeCAQC, status)
		_, _ = fmt.Fprint(w, tlXML)
	}))
	defer deServer.Close()

	dePointer := fmt.Sprintf(pointerTemplate, "DE", deServer.URL, "DE")
	lotlXML := fmt.Sprintf(lotlTemplate, dePointer)

	lotlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, lotlXML)
	}))
	defer lotlServer.Close()

	store := NewTrustStore()
	f := NewTrustListFetcher(
		WithLOTLURL(lotlServer.URL),
		WithHTTPClient(lotlServer.Client()),
		WithTrustStore(store),
	)

	// First refresh: granted.
	err := f.Refresh(context.Background())
	require.NoError(t, err)
	services := store.GetTrustedServices("DE", nil, false)
	require.Len(t, services, 1)
	assert.Equal(t, ServiceStatusGranted, services[0].ServiceStatus)

	// Second refresh: withdrawn.
	version.Store(1)
	err = f.Refresh(context.Background())
	require.NoError(t, err)
	services = store.GetTrustedServices("DE", nil, false)
	require.Len(t, services, 1)
	assert.Equal(t, ServiceStatusWithdrawn, services[0].ServiceStatus)
}

func TestTrustListFetcher_Refresh_PrunesStaleCountries(t *testing.T) {
	// First refresh loads DE and FR. Second refresh only includes DE.
	// FR should be pruned from the store after the second refresh.
	deTL := makeNationalTLXML("DE", ServiceTypeCAQC, ServiceStatusGranted)
	frTL := makeNationalTLXML("FR", ServiceTypeCA, ServiceStatusGranted)

	deServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, deTL)
	}))
	defer deServer.Close()

	frServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, frTL)
	}))
	defer frServer.Close()

	// Build two LOTL versions: one with DE+FR, one with only DE.
	dePointer := fmt.Sprintf(pointerTemplate, "DE", deServer.URL, "DE")
	frPointer := fmt.Sprintf(pointerTemplate, "FR", frServer.URL, "FR")
	lotlWithBoth := fmt.Sprintf(lotlTemplate, dePointer+"\n"+frPointer)
	lotlWithDE := fmt.Sprintf(lotlTemplate, dePointer)

	var currentLOTL atomic.Value
	currentLOTL.Store(lotlWithBoth)

	lotlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, currentLOTL.Load().(string))
	}))
	defer lotlServer.Close()

	store := NewTrustStore()
	f := NewTrustListFetcher(
		WithLOTLURL(lotlServer.URL),
		WithHTTPClient(lotlServer.Client()),
		WithTrustStore(store),
	)

	// First refresh: both DE and FR loaded.
	err := f.Refresh(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, store.ServiceCount())
	assert.ElementsMatch(t, []string{"DE", "FR"}, store.CountryCodesLoaded())

	// Switch LOTL to only include DE.
	currentLOTL.Store(lotlWithDE)

	// Second refresh: FR should be pruned.
	err = f.Refresh(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, store.ServiceCount())
	assert.Contains(t, store.CountryCodesLoaded(), "DE")
	assert.NotContains(t, store.CountryCodesLoaded(), "FR")
}

// --- Cache-Control max-age parsing tests ---

func TestParseCacheControlMaxAge(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{
			name:   "empty header",
			header: "",
			want:   0,
		},
		{
			name:   "max-age only",
			header: "max-age=3600",
			want:   3600 * time.Second,
		},
		{
			name:   "max-age with other directives",
			header: "public, max-age=86400, no-transform",
			want:   86400 * time.Second,
		},
		{
			name:   "max-age=0",
			header: "max-age=0",
			want:   0,
		},
		{
			name:   "no max-age",
			header: "no-cache, no-store",
			want:   0,
		},
		{
			name:   "invalid max-age value",
			header: "max-age=abc",
			want:   0,
		},
		{
			name:   "negative max-age",
			header: "max-age=-1",
			want:   0,
		},
		{
			name:   "max-age with spaces",
			header: " max-age=7200 ",
			want:   7200 * time.Second,
		},
		{
			name:   "Max-Age case insensitive",
			header: "Max-Age=1800",
			want:   1800 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCacheControlMaxAge(tt.header)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClampDuration(t *testing.T) {
	tests := []struct {
		name     string
		d        time.Duration
		min, max time.Duration
		want     time.Duration
	}{
		{"within range", 5 * time.Hour, time.Hour, 24 * time.Hour, 5 * time.Hour},
		{"below min", 30 * time.Minute, time.Hour, 24 * time.Hour, time.Hour},
		{"above max", 48 * time.Hour, time.Hour, 24 * time.Hour, 24 * time.Hour},
		{"at min", time.Hour, time.Hour, 24 * time.Hour, time.Hour},
		{"at max", 24 * time.Hour, time.Hour, 24 * time.Hour, 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampDuration(tt.d, tt.min, tt.max)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTrustListFetcher_FetchURL_CacheControlHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=7200")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "test body")
	}))
	defer server.Close()

	f := NewTrustListFetcher(WithHTTPClient(server.Client()))
	body, maxAge, err := f.fetchURL(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, []byte("test body"), body)
	assert.Equal(t, 7200*time.Second, maxAge)
}

func TestTrustListFetcher_FetchURL_NoCacheControl(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "test body")
	}))
	defer server.Close()

	f := NewTrustListFetcher(WithHTTPClient(server.Client()))
	_, maxAge, err := f.fetchURL(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), maxAge)
}

func TestTrustListFetcher_FetchURL_ErrorStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"404", http.StatusNotFound},
		{"500", http.StatusInternalServerError},
		{"403", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			f := NewTrustListFetcher(WithHTTPClient(server.Client()))
			_, _, err := f.fetchURL(context.Background(), server.URL)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("unexpected status code %d", tt.statusCode))
		})
	}
}
