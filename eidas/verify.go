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
	opts ...ChainVerificationOption,
) error {
	return VerifyCertificateChainAt(leafCert, intermediates, store, countryCode, serviceTypes, time.Time{}, opts...)
}

// ChainVerificationOption configures an individual chain verification.
type ChainVerificationOption func(*chainVerification)

// chainVerification holds the optional parts of a chain verification.
type chainVerification struct {
	revocationChecker *RevocationChecker
}

// WithRevocationCheck makes chain verification consult the given revocation
// checker for every certificate in the built chain below the trust anchor.
// Without it, no revocation checking is performed.
func WithRevocationCheck(checker *RevocationChecker) ChainVerificationOption {
	return func(cv *chainVerification) {
		cv.revocationChecker = checker
	}
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
	opts ...ChainVerificationOption,
) error {
	if store == nil {
		return fmt.Errorf("trust store is nil")
	}

	verification := &chainVerification{}
	for _, opt := range opts {
		opt(verification)
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

	// Retains the first revocation failure, so that a revoked certificate is
	// reported as revoked rather than as simply untrusted.
	var revocationErr error

	for _, svc := range trustedServices {
		if len(svc.Certificates) == 0 {
			continue
		}

		roots := x509.NewCertPool()
		for _, cert := range svc.Certificates {
			roots.AddCert(cert)
		}

		verifyOptions := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediatePool,
			// We only care about chain validity, not specific key usages,
			// because eIDAS trust list certificates are CA certificates that
			// may not have ExtKeyUsage set. An empty KeyUsages slice means
			// x509.ExtKeyUsageServerAuth is checked by default in Go, so we
			// explicitly set it to x509.ExtKeyUsageAny to accept any usage.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		chains, err := leafCert.Verify(verifyOptions)
		if err != nil {
			continue
		}

		// A chain that builds is only accepted if no certificate on it has
		// been revoked. Another candidate service may still yield a chain
		// that is both valid and unrevoked, so keep the first revocation
		// error and carry on rather than failing immediately.
		chainErr := verification.checkRevocation(chains)
		if chainErr != nil {
			if revocationErr == nil {
				revocationErr = chainErr
			}
			continue
		}

		logging.Log().Debugf("VerifyCertificateChain: certificate chains to trusted service %q (TSP: %s, country: %s)",
			svc.ServiceName, svc.TSPName, svc.CountryCode)
		return nil
	}

	if revocationErr != nil {
		return revocationErr
	}

	return fmt.Errorf("certificate does not chain to any trusted service")
}

// checkRevocation runs the configured revocation checker over the built chains.
// A chain passes when none of its certificates below the trust anchor is
// revoked; the first chain that passes is enough.
func (cv *chainVerification) checkRevocation(chains [][]*x509.Certificate) error {
	if !cv.revocationChecker.Enabled() {
		return nil
	}

	var firstErr error
	for _, chain := range chains {
		err := cv.revocationChecker.CheckChain(chain)
		if err == nil {
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}
