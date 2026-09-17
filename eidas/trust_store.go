package eidas

import (
	"bytes"
	"crypto/x509"
	"sync"
	"time"

	"github.com/fiware/VCVerifier/logging"
)

// TrustStore provides thread-safe, in-memory storage and querying of trusted
// services extracted from ETSI TS 119 612 trust lists. It is populated by the
// TrustListFetcher and consumed by the eIDAS validation service.
//
// All read methods acquire a read lock and all write methods acquire a write
// lock, making it safe for concurrent use from multiple goroutines.
type TrustStore struct {
	mu sync.RWMutex
	// services is keyed by ISO 3166-1 alpha-2 country code.
	services map[string][]TrustedService
}

// NewTrustStore creates a new, empty TrustStore ready for use.
func NewTrustStore() *TrustStore {
	return &TrustStore{
		services: make(map[string][]TrustedService),
	}
}

// Update replaces the trust services for a given country code. This is called
// by the TrustListFetcher after successfully fetching and parsing a national
// trust list.
func (ts *TrustStore) Update(countryCode string, services []TrustedService) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.services[countryCode] = services
	logging.Log().Debugf("TrustStore: updated %d services for country %s", len(services), countryCode)
}

// Clear removes all cached trust services.
func (ts *TrustStore) Clear() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.services = make(map[string][]TrustedService)
}

// RemoveCountriesNotIn removes trust services for any country code that is
// not present in the given set. This is used during refresh to prune stale
// entries for countries that were removed from the LOTL or the allowed-countries
// configuration.
func (ts *TrustStore) RemoveCountriesNotIn(keepCountries map[string]struct{}) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for code := range ts.services {
		if _, keep := keepCountries[code]; !keep {
			logging.Log().Debugf("TrustStore: pruning stale country %s", code)
			delete(ts.services, code)
		}
	}
}

// GetTrustedServices returns trust services matching the given filters.
//
// If countryCode is non-empty, only services from that country are returned.
// If countryCode is empty, services from all countries are searched.
//
// If serviceTypes is non-empty, only services whose ServiceType matches one
// of the given URIs are returned. If empty, all service types match.
//
// If onlyGranted is true, only services with status "granted" are returned.
func (ts *TrustStore) GetTrustedServices(countryCode string, serviceTypes []string, onlyGranted bool) []TrustedService {
	return ts.GetTrustedServicesAt(countryCode, serviceTypes, onlyGranted, time.Time{})
}

// GetTrustedServicesAt returns trust services matching the given filters,
// evaluating each service's status and type as of the given time.
//
// The filters behave as described on GetTrustedServices. The at parameter
// selects which entry of a service's status timeline the status and type
// filters are applied to: the entry that was in effect at that time, taken
// from the ServiceHistory (ETSI TS 119 612 §5.5.5). A service with no entry
// covering that time is excluded — it cannot be shown to have been trusted
// then. A zero at evaluates the current entry.
func (ts *TrustStore) GetTrustedServicesAt(countryCode string, serviceTypes []string, onlyGranted bool, at time.Time) []TrustedService {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	typeSet := make(map[string]struct{}, len(serviceTypes))
	for _, st := range serviceTypes {
		typeSet[st] = struct{}{}
	}

	var result []TrustedService

	if countryCode != "" {
		// Single country lookup.
		result = ts.filterServices(ts.services[countryCode], typeSet, onlyGranted, at)
	} else {
		// All-country scan.
		for _, svcList := range ts.services {
			result = append(result, ts.filterServices(svcList, typeSet, onlyGranted, at)...)
		}
	}

	return result
}

// filterServices returns the subset of services matching the given type set
// and granted-only constraint as of the given time. Must be called under at
// least a read lock.
func (ts *TrustStore) filterServices(services []TrustedService, typeSet map[string]struct{}, onlyGranted bool, at time.Time) []TrustedService {
	var out []TrustedService
	for _, svc := range services {
		if onlyGranted && !svc.IsGrantedAt(at) {
			continue
		}
		if !svc.HasServiceTypeAt(at, typeSet) {
			continue
		}
		out = append(out, svc)
	}
	return out
}

// IsTrustedService checks whether the given X.509 certificate is associated
// with any trusted service matching the filters.
//
// Matching is done by raw certificate byte comparison: the given certificate's
// Raw bytes are compared against the Raw bytes of each certificate in matching
// trust services. This identifies leaf certificates; for CA chain validation,
// use GetTrustedServices and build a verify chain with x509.Certificate.Verify.
//
// If countryCode is non-empty, only that country's services are checked.
// If serviceTypes is non-empty, only matching service types are checked.
// Only granted services are considered.
func (ts *TrustStore) IsTrustedService(certificate *x509.Certificate, countryCode string, serviceTypes []string) bool {
	if certificate == nil {
		return false
	}

	matchingServices := ts.GetTrustedServices(countryCode, serviceTypes, true)
	for _, svc := range matchingServices {
		for _, cert := range svc.Certificates {
			if bytes.Equal(cert.Raw, certificate.Raw) {
				logging.Log().Debugf("TrustStore: certificate match found for service %q (TSP: %s, country: %s)",
					svc.ServiceName, svc.TSPName, svc.CountryCode)
				return true
			}
		}
	}
	return false
}

// CountryCodesLoaded returns the list of country codes currently loaded in the store.
func (ts *TrustStore) CountryCodesLoaded() []string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	codes := make([]string, 0, len(ts.services))
	for code := range ts.services {
		codes = append(codes, code)
	}
	return codes
}

// ServiceCount returns the total number of trust services across all countries.
func (ts *TrustStore) ServiceCount() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	count := 0
	for _, svcList := range ts.services {
		count += len(svcList)
	}
	return count
}
