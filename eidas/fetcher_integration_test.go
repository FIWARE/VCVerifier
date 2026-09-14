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

// --- Integration tests for the TrustListFetcher ---
//
// These tests exercise the full LOTL → national TL resolution pipeline using
// httptest servers. Unlike the unit tests in fetcher_test.go, which test
// individual methods and edge cases, these integration tests verify the
// end-to-end behaviour of the fetcher in realistic scenarios.

func init() {
	initTestLogging()
}

// --- LOTL and national TL server helpers ---

// testTLInfra bundles httptest servers for a LOTL and national TLs.
type testTLInfra struct {
	lotlServer    *httptest.Server
	nationalTLs   map[string]*httptest.Server
	lotlXML       *atomic.Value
	nationalXMLs  map[string]*atomic.Value
}

// newTestTLInfra creates a test infrastructure with LOTL and national TL
// servers for the given country codes. Each national TL serves one TSP with
// a qualified CA service in granted status by default.
func newTestTLInfra(t *testing.T, countryCodes []string) *testTLInfra {
	t.Helper()

	infra := &testTLInfra{
		nationalTLs:  make(map[string]*httptest.Server),
		nationalXMLs: make(map[string]*atomic.Value),
		lotlXML:      &atomic.Value{},
	}

	// Set up national TL servers.
	for _, cc := range countryCodes {
		xmlStore := &atomic.Value{}
		xmlStore.Store(makeNationalTLXML(cc, ServiceTypeCAQC, ServiceStatusGranted))
		infra.nationalXMLs[cc] = xmlStore

		srv := httptest.NewServer(http.HandlerFunc(func(store *atomic.Value) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, store.Load().(string))
			}
		}(xmlStore)))
		infra.nationalTLs[cc] = srv
	}

	// Build LOTL XML pointing to national TL servers.
	var pointers []string
	for _, cc := range countryCodes {
		pointers = append(pointers, fmt.Sprintf(pointerTemplate, cc, infra.nationalTLs[cc].URL, cc))
	}
	lotlXML := fmt.Sprintf(lotlTemplate, strings.Join(pointers, "\n"))
	infra.lotlXML.Store(lotlXML)

	infra.lotlServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, infra.lotlXML.Load().(string))
	}))

	return infra
}

// close shuts down all httptest servers.
func (infra *testTLInfra) close() {
	infra.lotlServer.Close()
	for _, srv := range infra.nationalTLs {
		srv.Close()
	}
}

// updateNationalTL replaces the XML served by the national TL for the given
// country code.
func (infra *testTLInfra) updateNationalTL(cc, serviceType, status string) {
	if xmlStore, ok := infra.nationalXMLs[cc]; ok {
		xmlStore.Store(makeNationalTLXML(cc, serviceType, status))
	}
}

// rebuildLOTL updates the LOTL XML to point only to the given countries.
// This simulates a country being removed from the LOTL.
func (infra *testTLInfra) rebuildLOTL(countryCodes []string) {
	var pointers []string
	for _, cc := range countryCodes {
		if srv, ok := infra.nationalTLs[cc]; ok {
			pointers = append(pointers, fmt.Sprintf(pointerTemplate, cc, srv.URL, cc))
		}
	}
	infra.lotlXML.Store(fmt.Sprintf(lotlTemplate, strings.Join(pointers, "\n")))
}

// --- Integration tests ---

// TestFetcherIntegration_LOTLToNationalTLResolution tests the full LOTL →
// national TL resolution: the fetcher downloads the LOTL, discovers national
// TL endpoints, fetches them in parallel, and populates the trust store.
func TestFetcherIntegration_LOTLToNationalTLResolution(t *testing.T) {
	countries := []string{"DE", "FR", "ES"}
	infra := newTestTLInfra(t, countries)
	defer infra.close()

	store := NewTrustStore()
	fetcher := NewTrustListFetcher(
		WithLOTLURL(infra.lotlServer.URL),
		WithHTTPClient(infra.lotlServer.Client()),
		WithTrustStore(store),
	)

	err := fetcher.Refresh(context.Background())
	require.NoError(t, err, "refresh should complete successfully")

	// All three countries should be loaded.
	assert.Equal(t, 3, store.ServiceCount(), "should have 3 services (one per country)")
	assert.ElementsMatch(t, countries, store.CountryCodesLoaded(),
		"all countries should be present in the store")

	// Each country should have one service with the expected name.
	for _, cc := range countries {
		services := store.GetTrustedServices(cc, nil, false)
		require.Len(t, services, 1, "country %s should have 1 service", cc)
		assert.Equal(t, cc+" QC CA", services[0].ServiceName)
		assert.Equal(t, ServiceTypeCAQC, services[0].ServiceType)
		assert.True(t, services[0].IsGranted(), "service should be granted")
	}
}

// TestFetcherIntegration_BackgroundRefreshPicksUpChanges verifies that the
// background refresh loop detects changes in the national TLs.
func TestFetcherIntegration_BackgroundRefreshPicksUpChanges(t *testing.T) {
	infra := newTestTLInfra(t, []string{"DE"})
	defer infra.close()

	store := NewTrustStore()
	fetcher := NewTrustListFetcher(
		WithLOTLURL(infra.lotlServer.URL),
		WithHTTPClient(infra.lotlServer.Client()),
		WithTrustStore(store),
		WithRefreshInterval(MinRefreshInterval),
	)

	// Initial manual refresh — granted.
	err := fetcher.Refresh(context.Background())
	require.NoError(t, err)

	services := store.GetTrustedServices("DE", nil, false)
	require.Len(t, services, 1)
	assert.Equal(t, ServiceStatusGranted, services[0].ServiceStatus,
		"initial status should be granted")

	// Change national TL to withdrawn.
	infra.updateNationalTL("DE", ServiceTypeCAQC, ServiceStatusWithdrawn)

	// Second refresh picks up the change.
	err = fetcher.Refresh(context.Background())
	require.NoError(t, err)

	services = store.GetTrustedServices("DE", nil, false)
	require.Len(t, services, 1)
	assert.Equal(t, ServiceStatusWithdrawn, services[0].ServiceStatus,
		"status should be updated to withdrawn after refresh")
}

// TestFetcherIntegration_CacheExpiryAndRefresh verifies that the trust store
// is correctly updated after a re-fetch, including pruning of stale countries.
func TestFetcherIntegration_CacheExpiryAndRefresh(t *testing.T) {
	infra := newTestTLInfra(t, []string{"DE", "FR"})
	defer infra.close()

	store := NewTrustStore()
	fetcher := NewTrustListFetcher(
		WithLOTLURL(infra.lotlServer.URL),
		WithHTTPClient(infra.lotlServer.Client()),
		WithTrustStore(store),
	)

	// Initial fetch: both DE and FR.
	err := fetcher.Refresh(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, store.ServiceCount())
	assert.ElementsMatch(t, []string{"DE", "FR"}, store.CountryCodesLoaded())

	// Remove FR from the LOTL (simulates country removal or LOTL update).
	infra.rebuildLOTL([]string{"DE"})

	// Re-fetch: FR should be pruned.
	err = fetcher.Refresh(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, store.ServiceCount(), "only DE should remain")
	assert.Contains(t, store.CountryCodesLoaded(), "DE")
	assert.NotContains(t, store.CountryCodesLoaded(), "FR",
		"FR should be pruned after being removed from LOTL")
}

// TestFetcherIntegration_ErrorHandling_UnavailableLOTL verifies that a
// completely unavailable LOTL returns an error and does not corrupt the store.
func TestFetcherIntegration_ErrorHandling_UnavailableLOTL(t *testing.T) {
	// Server that always returns 503.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	store := NewTrustStore()
	fetcher := NewTrustListFetcher(
		WithLOTLURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTrustStore(store),
	)

	err := fetcher.Refresh(context.Background())
	assert.Error(t, err, "should return an error when LOTL is unavailable")
	assert.Contains(t, err.Error(), "503")
	assert.Equal(t, 0, store.ServiceCount(), "store should remain empty")
}

// TestFetcherIntegration_ErrorHandling_MalformedLOTLXML verifies that
// malformed XML from the LOTL is handled gracefully.
func TestFetcherIntegration_ErrorHandling_MalformedLOTLXML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, "<invalid><xml>>>{{{not closed")
	}))
	defer server.Close()

	store := NewTrustStore()
	fetcher := NewTrustListFetcher(
		WithLOTLURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTrustStore(store),
	)

	err := fetcher.Refresh(context.Background())
	assert.Error(t, err, "should return an error for malformed XML")
	assert.Equal(t, 0, store.ServiceCount(), "store should remain empty")
}

// TestFetcherIntegration_ErrorHandling_UnreachableNationalTL verifies that
// a failing national TL does not prevent other national TLs from loading.
func TestFetcherIntegration_ErrorHandling_UnreachableNationalTL(t *testing.T) {
	// Create infrastructure with DE and FR.
	infra := newTestTLInfra(t, []string{"DE", "FR"})
	defer infra.close()

	// Replace DE server with one that returns errors.
	infra.nationalTLs["DE"].Close()
	failingDE := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failingDE.Close()

	// Rebuild LOTL with the failing DE server.
	dePointer := fmt.Sprintf(pointerTemplate, "DE", failingDE.URL, "DE")
	frPointer := fmt.Sprintf(pointerTemplate, "FR", infra.nationalTLs["FR"].URL, "FR")
	infra.lotlXML.Store(fmt.Sprintf(lotlTemplate, dePointer+"\n"+frPointer))

	store := NewTrustStore()
	fetcher := NewTrustListFetcher(
		WithLOTLURL(infra.lotlServer.URL),
		WithHTTPClient(infra.lotlServer.Client()),
		WithTrustStore(store),
	)

	err := fetcher.Refresh(context.Background())
	require.NoError(t, err, "refresh should succeed overall despite one failing TL")

	// Only FR should be loaded; DE failed gracefully.
	assert.Equal(t, 1, store.ServiceCount(), "only FR should be loaded")
	assert.Contains(t, store.CountryCodesLoaded(), "FR")
	assert.NotContains(t, store.CountryCodesLoaded(), "DE",
		"DE should not be loaded due to server error")
}

// TestFetcherIntegration_BackgroundStartStopLifecycle verifies the background
// refresh loop starts, performs at least one fetch, and stops cleanly.
func TestFetcherIntegration_BackgroundStartStopLifecycle(t *testing.T) {
	var fetchCount atomic.Int32

	infra := newTestTLInfra(t, []string{"DE"})
	defer infra.close()

	// Wrap the LOTL server to count fetches.
	lotlXML := infra.lotlXML.Load().(string)
	countingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, lotlXML)
	}))
	defer countingServer.Close()

	store := NewTrustStore()
	fetcher := NewTrustListFetcher(
		WithLOTLURL(countingServer.URL),
		WithHTTPClient(countingServer.Client()),
		WithTrustStore(store),
		WithRefreshInterval(MinRefreshInterval),
	)

	fetcher.Start(context.Background())

	// Wait for the initial fetch to complete.
	require.Eventually(t, func() bool {
		return fetchCount.Load() >= 1
	}, 5*time.Second, 50*time.Millisecond, "initial fetch should complete")

	// Verify the store was populated.
	assert.GreaterOrEqual(t, store.ServiceCount(), 1, "store should have at least one service")

	fetcher.Stop()

	// After stop, no more fetches should occur.
	countAfterStop := fetchCount.Load()
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, countAfterStop, fetchCount.Load(),
		"no fetches should occur after Stop()")
}

// TestFetcherIntegration_CountryFilterInFetcher verifies that the fetcher's
// allowed-countries filter restricts which national TLs are fetched.
func TestFetcherIntegration_CountryFilterInFetcher(t *testing.T) {
	var deRequested, frRequested, esRequested atomic.Bool

	countries := []string{"DE", "FR", "ES"}
	infra := newTestTLInfra(t, countries)
	defer infra.close()

	// Replace servers to track which were actually requested.
	for _, cc := range countries {
		ccLocal := cc
		xmlStore := infra.nationalXMLs[ccLocal]
		old := infra.nationalTLs[ccLocal]
		old.Close()

		newSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch ccLocal {
			case "DE":
				deRequested.Store(true)
			case "FR":
				frRequested.Store(true)
			case "ES":
				esRequested.Store(true)
			}
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, xmlStore.Load().(string))
		}))
		infra.nationalTLs[ccLocal] = newSrv
	}
	defer func() {
		for _, srv := range infra.nationalTLs {
			srv.Close()
		}
	}()

	// Rebuild LOTL with new server URLs.
	var pointers []string
	for _, cc := range countries {
		pointers = append(pointers, fmt.Sprintf(pointerTemplate, cc, infra.nationalTLs[cc].URL, cc))
	}
	infra.lotlXML.Store(fmt.Sprintf(lotlTemplate, strings.Join(pointers, "\n")))

	store := NewTrustStore()
	fetcher := NewTrustListFetcher(
		WithLOTLURL(infra.lotlServer.URL),
		WithHTTPClient(infra.lotlServer.Client()),
		WithTrustStore(store),
		WithAllowedCountries([]string{"DE", "ES"}), // FR excluded
	)

	err := fetcher.Refresh(context.Background())
	require.NoError(t, err)

	assert.True(t, deRequested.Load(), "DE should have been fetched")
	assert.False(t, frRequested.Load(), "FR should NOT have been fetched (filtered out)")
	assert.True(t, esRequested.Load(), "ES should have been fetched")

	assert.Equal(t, 2, store.ServiceCount(), "should have 2 services (DE and ES)")
	assert.Contains(t, store.CountryCodesLoaded(), "DE")
	assert.Contains(t, store.CountryCodesLoaded(), "ES")
	assert.NotContains(t, store.CountryCodesLoaded(), "FR")
}
