package eidas

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fiware/VCVerifier/logging"
)

// VerifyCertificateChain verifies that leafCert chains up to a trusted CA in
// the TrustStore. It queries the store for trusted services matching the given
// country and service type filters, then attempts PKIX chain validation
// against each service's certificates as root CAs.
//
// Parameters:
//   - leafCert: the end-entity certificate to verify.
//   - intermediates: optional intermediate certificates that complete the chain.
//   - store: the TrustStore containing trusted CA certificates from EU Trusted Lists.
//   - countryCode: ISO 3166-1 alpha-2 country code to restrict the search.
//     Empty string searches all countries.
//   - serviceTypes: ETSI service type URIs to filter trusted services.
//     Empty slice matches all service types.
//
// Returns nil if the certificate chains to at least one trusted service,
// or an error describing the validation failure.
func VerifyCertificateChain(
	leafCert *x509.Certificate,
	intermediates []*x509.Certificate,
	store *TrustStore,
	countryCode string,
	serviceTypes []string,
) error {
	return VerifyCertificateChainAt(leafCert, intermediates, store, countryCode, serviceTypes, time.Time{})
}

// VerifyCertificateChainAt verifies that leafCert chains up to a CA that was a
// trusted service at the given time.
//
// It behaves like VerifyCertificateChain, except that each candidate service's
// status and service type are evaluated as of at, using the service history
// from the trust list (ETSI TS 119 612 §5.5.5). This is what allows a signature
// to be validated against the trust status that applied when it was created,
// rather than only against the status that applies now. A zero at evaluates the
// current status.
//
// Note that at selects the trust list entry; it is not passed to PKIX chain
// building, which still validates the certificates against the current time.
func VerifyCertificateChainAt(
	leafCert *x509.Certificate,
	intermediates []*x509.Certificate,
	store *TrustStore,
	countryCode string,
	serviceTypes []string,
	at time.Time,
) error {
	if store == nil {
		return fmt.Errorf("trust store is nil")
	}

	trustedServices := store.GetTrustedServicesAt(countryCode, serviceTypes, true, at)
	if len(trustedServices) == 0 {
		logging.Log().Debugf("VerifyCertificateChain: no trusted services found for country %q, types %v", countryCode, serviceTypes)
		return fmt.Errorf("no trusted services found for country %q", countryCode)
	}

	// Build an intermediate certificate pool if we have any.
	var intermediatePool *x509.CertPool
	if len(intermediates) > 0 {
		intermediatePool = x509.NewCertPool()
		for _, ic := range intermediates {
			intermediatePool.AddCert(ic)
		}
	}

	for _, svc := range trustedServices {
		if len(svc.Certificates) == 0 {
			continue
		}

		roots := x509.NewCertPool()
		for _, cert := range svc.Certificates {
			roots.AddCert(cert)
		}

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediatePool,
			// We only care about chain validity, not specific key usages,
			// because eIDAS trust list certificates are CA certificates that
			// may not have ExtKeyUsage set. An empty KeyUsages slice means
			// x509.ExtKeyUsageServerAuth is checked by default in Go, so we
			// explicitly set it to x509.ExtKeyUsageAny to accept any usage.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		if _, err := leafCert.Verify(opts); err == nil {
			logging.Log().Debugf("VerifyCertificateChain: certificate chains to trusted service %q (TSP: %s, country: %s)",
				svc.ServiceName, svc.TSPName, svc.CountryCode)
			return nil
		}
	}

	return fmt.Errorf("certificate does not chain to any trusted service")
}
