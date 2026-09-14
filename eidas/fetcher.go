package eidas

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fiware/VCVerifier/logging"
)

// Default configuration values for the TrustListFetcher.
const (
	// DefaultLOTLURL is the official EU List of Trusted Lists URL.
	DefaultLOTLURL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

	// DefaultRefreshInterval is the default interval between trust list refreshes (24 hours).
	DefaultRefreshInterval = 24 * time.Hour

	// MinRefreshInterval is the minimum allowed refresh interval (1 hour).
	MinRefreshInterval = 1 * time.Hour

	// MaxRefreshInterval is the maximum allowed refresh interval (7 days).
	MaxRefreshInterval = 7 * 24 * time.Hour

	// DefaultFetchTimeout is the default HTTP timeout for fetching a single trust list.
	DefaultFetchTimeout = 30 * time.Second

	// DefaultMaxWorkers is the default number of concurrent workers for fetching national TLs.
	DefaultMaxWorkers = 5

	// MaxResponseBodySize is the maximum allowed response body size (50 MB) to prevent
	// resource exhaustion from oversized responses.
	MaxResponseBodySize = 50 * 1024 * 1024

	// cacheControlMaxAge is the header directive prefix for extracting max-age values.
	cacheControlMaxAge = "max-age="
)

// FetcherOption is a functional option for configuring a TrustListFetcher.
type FetcherOption func(*TrustListFetcher)

// WithLOTLURL sets the URL of the List of Trusted Lists to fetch.
func WithLOTLURL(url string) FetcherOption {
	return func(f *TrustListFetcher) {
		f.lotlURL = url
	}
}

// WithRefreshInterval sets the interval between background trust list refreshes.
// Values outside [MinRefreshInterval, MaxRefreshInterval] are clamped.
func WithRefreshInterval(d time.Duration) FetcherOption {
	return func(f *TrustListFetcher) {
		f.refreshInterval = clampDuration(d, MinRefreshInterval, MaxRefreshInterval)
	}
}

// WithAllowedCountries restricts which national trust lists are fetched.
// An empty slice means all countries from the LOTL are fetched.
func WithAllowedCountries(countries []string) FetcherOption {
	return func(f *TrustListFetcher) {
		f.allowedCountries = make(map[string]struct{}, len(countries))
		for _, c := range countries {
			f.allowedCountries[strings.ToUpper(c)] = struct{}{}
		}
	}
}

// WithHTTPClient sets a custom HTTP client for fetching trust lists.
// Useful for testing with httptest.Server.
func WithHTTPClient(client *http.Client) FetcherOption {
	return func(f *TrustListFetcher) {
		f.httpClient = client
	}
}

// WithMaxWorkers sets the maximum number of concurrent workers for fetching
// national trust lists.
func WithMaxWorkers(n int) FetcherOption {
	return func(f *TrustListFetcher) {
		if n > 0 {
			f.maxWorkers = n
		}
	}
}

// WithTrustStore sets the TrustStore to populate with fetched trust services.
func WithTrustStore(store *TrustStore) FetcherOption {
	return func(f *TrustListFetcher) {
		f.store = store
	}
}

// TrustListFetcher downloads and parses ETSI TS 119 612 trust lists. It starts
// from the EU List of Trusted Lists (LOTL), follows distribution points to
// national trust lists, parses them concurrently, and populates a TrustStore
// with the extracted trust services.
//
// Background refresh runs on a configurable interval via Start(). Call Stop()
// for graceful shutdown.
//
// Known limitation: XMLDSig verification on trust lists is not performed.
// The fetcher relies on HTTPS for transport-level integrity.
type TrustListFetcher struct {
	lotlURL          string
	refreshInterval  time.Duration
	allowedCountries map[string]struct{} // empty = all countries
	httpClient       *http.Client
	maxWorkers       int
	store            *TrustStore

	// stopCh signals the background refresh goroutine to stop.
	stopCh chan struct{}
	// stopped is closed once the background goroutine has exited.
	stopped chan struct{}
	// running tracks whether the background goroutine is active.
	running bool
	mu      sync.Mutex
}

// NewTrustListFetcher creates a new TrustListFetcher with the given options.
// If no TrustStore is provided via WithTrustStore, a new one is created.
func NewTrustListFetcher(opts ...FetcherOption) *TrustListFetcher {
	f := &TrustListFetcher{
		lotlURL:         DefaultLOTLURL,
		refreshInterval: DefaultRefreshInterval,
		maxWorkers:      DefaultMaxWorkers,
		httpClient: &http.Client{
			Timeout: DefaultFetchTimeout,
		},
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(f)
	}
	if f.store == nil {
		f.store = NewTrustStore()
	}
	return f
}

// Store returns the TrustStore that this fetcher populates.
func (f *TrustListFetcher) Store() *TrustStore {
	return f.store
}

// Start begins the background refresh goroutine. It performs an initial fetch
// immediately and then refreshes at the configured interval.
//
// Calling Start on an already-running fetcher is a no-op. A stopped fetcher
// may be restarted by calling Start again.
func (f *TrustListFetcher) Start(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.running {
		return
	}
	// Recreate channels so a previously stopped fetcher can be restarted.
	f.stopCh = make(chan struct{})
	f.stopped = make(chan struct{})
	f.running = true
	go f.refreshLoop(ctx)
}

// Stop signals the background refresh goroutine to stop and waits for it to
// exit. It is safe to call Stop multiple times; subsequent calls are no-ops.
func (f *TrustListFetcher) Stop() {
	f.mu.Lock()
	if !f.running {
		f.mu.Unlock()
		return
	}
	f.running = false
	f.mu.Unlock()

	close(f.stopCh)
	<-f.stopped
}

// refreshLoop runs the periodic refresh cycle. It performs an initial fetch,
// then repeats at the configured interval until Stop() is called.
func (f *TrustListFetcher) refreshLoop(ctx context.Context) {
	defer close(f.stopped)

	// Initial fetch.
	logging.Log().Infof("TrustListFetcher: starting initial fetch from %s", f.lotlURL)
	if err := f.Refresh(ctx); err != nil {
		logging.Log().Errorf("TrustListFetcher: initial fetch failed: %v", err)
	}

	ticker := time.NewTicker(f.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-f.stopCh:
			logging.Log().Info("TrustListFetcher: stopping background refresh")
			return
		case <-ctx.Done():
			logging.Log().Info("TrustListFetcher: context cancelled, stopping background refresh")
			return
		case <-ticker.C:
			logging.Log().Infof("TrustListFetcher: starting periodic refresh from %s", f.lotlURL)
			if err := f.Refresh(ctx); err != nil {
				logging.Log().Errorf("TrustListFetcher: periodic refresh failed: %v", err)
			}
		}
	}
}

// Refresh fetches the LOTL, resolves national TLs, and updates the TrustStore.
// This can be called directly for a one-shot fetch, or it is called by the
// background refresh loop.
func (f *TrustListFetcher) Refresh(ctx context.Context) error {
	// Fetch and parse the LOTL.
	lotlData, cacheMaxAge, err := f.fetchURL(ctx, f.lotlURL)
	if err != nil {
		return fmt.Errorf("failed to fetch LOTL from %s: %w", f.lotlURL, err)
	}
	_ = cacheMaxAge // Reserved for future adaptive refresh interval.

	lotl, err := ParseTrustList(lotlData)
	if err != nil {
		return fmt.Errorf("failed to parse LOTL: %w", err)
	}

	if !lotl.IsLOTL() {
		return fmt.Errorf("fetched document is not a LOTL (TSLType: %s)", lotl.SchemeInformation.TSLType)
	}

	// Extract distribution points (national TL URLs).
	distPoints := lotl.GetDistributionPoints()
	if len(distPoints) == 0 {
		logging.Log().Warn("TrustListFetcher: LOTL contains no distribution points for national TLs")
		return nil
	}

	// Filter by allowed countries if configured.
	filteredPoints := f.filterDistributionPoints(distPoints)
	logging.Log().Infof("TrustListFetcher: found %d national TLs (%d after country filter)",
		len(distPoints), len(filteredPoints))

	// Fetch national TLs concurrently with bounded workers.
	f.fetchNationalTLs(ctx, filteredPoints)

	logging.Log().Infof("TrustListFetcher: refresh complete, %d countries loaded, %d total services",
		len(f.store.CountryCodesLoaded()), f.store.ServiceCount())

	return nil
}

// filterDistributionPoints returns only distribution points whose country code
// is in the allowed set. If no countries are configured (empty set), all
// distribution points are returned.
func (f *TrustListFetcher) filterDistributionPoints(points []DistributionPoint) []DistributionPoint {
	if len(f.allowedCountries) == 0 {
		return points
	}
	var filtered []DistributionPoint
	for _, p := range points {
		if _, ok := f.allowedCountries[strings.ToUpper(p.SchemeTerritory)]; ok {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// fetchNationalTLs fetches and parses the national trust lists concurrently
// using a bounded worker pool, then updates the TrustStore. Countries that
// were previously loaded but are no longer present in the current set of
// distribution points are pruned from the store.
func (f *TrustListFetcher) fetchNationalTLs(ctx context.Context, points []DistributionPoint) {
	type fetchResult struct {
		countryCode string
		services    []TrustedService
		err         error
	}

	results := make(chan fetchResult, len(points))
	semaphore := make(chan struct{}, f.maxWorkers)

	var wg sync.WaitGroup
	for _, point := range points {
		wg.Add(1)
		go func(dp DistributionPoint) {
			defer wg.Done()

			// Acquire semaphore slot.
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results <- fetchResult{
					countryCode: dp.SchemeTerritory,
					err:         ctx.Err(),
				}
				return
			}

			services, err := f.fetchAndParseNationalTL(ctx, dp)
			results <- fetchResult{
				countryCode: dp.SchemeTerritory,
				services:    services,
				err:         err,
			}
		}(point)
	}

	// Close results channel once all workers are done.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Track which countries were successfully refreshed so stale entries
	// can be pruned afterward.
	refreshedCountries := make(map[string]struct{}, len(points))

	// Collect results and update the store.
	for res := range results {
		if res.err != nil {
			logging.Log().Warnf("TrustListFetcher: failed to fetch national TL for %s: %v",
				res.countryCode, res.err)
			continue
		}
		f.store.Update(res.countryCode, res.services)
		refreshedCountries[res.countryCode] = struct{}{}
	}

	// Build the set of countries that should be in the store: all countries
	// from the current distribution points (even those that failed to fetch,
	// so we don't prune on transient errors).
	expectedCountries := make(map[string]struct{}, len(points))
	for _, p := range points {
		expectedCountries[p.SchemeTerritory] = struct{}{}
	}

	// Remove countries no longer present in the LOTL or allowed-countries set.
	f.store.RemoveCountriesNotIn(expectedCountries)
}

// fetchAndParseNationalTL fetches a single national trust list and extracts
// its trust services.
func (f *TrustListFetcher) fetchAndParseNationalTL(ctx context.Context, dp DistributionPoint) ([]TrustedService, error) {
	data, _, err := f.fetchURL(ctx, dp.TSLLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TL for %s from %s: %w",
			dp.SchemeTerritory, dp.TSLLocation, err)
	}

	tl, err := ParseTrustList(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TL for %s: %w", dp.SchemeTerritory, err)
	}

	services, err := tl.GetTrustServices()
	if err != nil {
		return nil, fmt.Errorf("failed to extract services for %s: %w", dp.SchemeTerritory, err)
	}

	logging.Log().Debugf("TrustListFetcher: fetched %d services for country %s",
		len(services), dp.SchemeTerritory)

	return services, nil
}

// fetchURL fetches a URL and returns the response body bytes along with the
// Cache-Control max-age value (0 if absent or unparseable).
func (f *TrustListFetcher) fetchURL(ctx context.Context, url string) ([]byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request for %s: %w", url, err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("unexpected status code %d for %s", resp.StatusCode, url)
	}

	// Limit response body to prevent resource exhaustion.
	limitedReader := io.LimitReader(resp.Body, MaxResponseBodySize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body from %s: %w", url, err)
	}
	if int64(len(body)) > MaxResponseBodySize {
		return nil, 0, fmt.Errorf("response body from %s exceeds maximum size of %d bytes", url, MaxResponseBodySize)
	}

	maxAge := parseCacheControlMaxAge(resp.Header.Get("Cache-Control"))

	return body, maxAge, nil
}

// parseCacheControlMaxAge extracts the max-age value from a Cache-Control
// header value. Returns 0 if the header is empty, does not contain max-age,
// or the value is unparseable.
func parseCacheControlMaxAge(header string) time.Duration {
	if header == "" {
		return 0
	}

	for _, directive := range strings.Split(header, ",") {
		lower := strings.TrimSpace(strings.ToLower(directive))
		if strings.HasPrefix(lower, cacheControlMaxAge) {
			valueStr := lower[len(cacheControlMaxAge):]
			seconds, err := strconv.ParseInt(valueStr, 10, 64)
			if err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}

	return 0
}

// clampDuration returns d clamped to [min, max].
func clampDuration(d, min, max time.Duration) time.Duration {
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}
