package eidas

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/ocsp"
)

// --- Revocation checking (OCSP / CRL) ---
//
// Chain validation against a trust list establishes that a certificate was
// issued under a listed CA. It says nothing about whether that certificate has
// since been revoked: a trust list is updated when the *service* status
// changes, not when an individual certificate is withdrawn. Revocation is
// published by the issuing CA through OCSP (RFC 6960) and CRLs (RFC 5280), and
// this file consults both.

// Revocation check modes, selected through the eidas.revocationCheck setting.
const (
	// RevocationCheckOff performs no revocation checking at all.
	RevocationCheckOff = "off"

	// RevocationCheckSoft rejects a certificate that is known to be revoked,
	// but accepts one whose status could not be determined — because the
	// certificate names no responder, or because the responder could not be
	// reached. This is the default.
	RevocationCheckSoft = "soft"

	// RevocationCheckHard additionally rejects a certificate whose revocation
	// status could not be determined.
	RevocationCheckHard = "hard"
)

// Defaults for the RevocationChecker.
const (
	// DefaultRevocationTimeout is the HTTP timeout for a single OCSP or CRL request.
	DefaultRevocationTimeout = 10 * time.Second

	// DefaultRevocationCacheExpiry is how long a determined revocation status is
	// cached when the responder declares no NextUpdate of its own.
	DefaultRevocationCacheExpiry = 1 * time.Hour

	// MaxRevocationResponseSize bounds an OCSP or CRL response body (10 MB).
	MaxRevocationResponseSize = 10 * 1024 * 1024

	// revocationCacheCleanupInterval is how often expired cache entries are purged.
	revocationCacheCleanupInterval = 10 * time.Minute

	// ocspRequestContentType is the media type of an OCSP request body.
	ocspRequestContentType = "application/ocsp-request"
)

// ErrorCertificateRevoked is returned when a certificate in the chain has been
// revoked by its issuer.
var ErrorCertificateRevoked = errors.New("certificate_revoked")

// ErrorRevocationStatusUnknown is returned in hard-fail mode when the
// revocation status of a certificate could not be determined.
var ErrorRevocationStatusUnknown = errors.New("revocation_status_unknown")

// RevocationStatus is the outcome of checking one certificate.
type RevocationStatus int

const (
	// RevocationStatusUnknown means no responder could be consulted, or none
	// gave a usable answer.
	RevocationStatusUnknown RevocationStatus = iota
	// RevocationStatusGood means a responder confirmed the certificate is not revoked.
	RevocationStatusGood
	// RevocationStatusRevoked means a responder reported the certificate as revoked.
	RevocationStatusRevoked
)

// RevocationCheckerOption configures a RevocationChecker.
type RevocationCheckerOption func(*RevocationChecker)

// WithRevocationMode sets the check mode. Unrecognised values fall back to
// RevocationCheckSoft; the configuration layer validates the value up front.
func WithRevocationMode(mode string) RevocationCheckerOption {
	return func(rc *RevocationChecker) {
		rc.mode = mode
	}
}

// WithRevocationHTTPClient sets the HTTP client used for OCSP and CRL requests.
func WithRevocationHTTPClient(client *http.Client) RevocationCheckerOption {
	return func(rc *RevocationChecker) {
		if client != nil {
			rc.httpClient = client
		}
	}
}

// WithRevocationCacheExpiry sets how long a determined status is cached when
// the responder declares no NextUpdate.
func WithRevocationCacheExpiry(expiry time.Duration) RevocationCheckerOption {
	return func(rc *RevocationChecker) {
		if expiry > 0 {
			rc.cacheExpiry = expiry
		}
	}
}

// RevocationChecker checks certificates for revocation via OCSP, falling back
// to CRLs. Results are cached per certificate, so a busy verifier does not
// re-query a responder for every presented credential.
//
// A RevocationChecker is safe for concurrent use.
type RevocationChecker struct {
	mode        string
	httpClient  *http.Client
	cacheExpiry time.Duration
	statusCache *cache.Cache
}

// NewRevocationChecker creates a RevocationChecker. Without options it runs in
// soft-fail mode with the default timeout and cache expiry.
func NewRevocationChecker(opts ...RevocationCheckerOption) *RevocationChecker {
	rc := &RevocationChecker{
		mode:        RevocationCheckSoft,
		cacheExpiry: DefaultRevocationCacheExpiry,
		httpClient: &http.Client{
			Timeout: DefaultRevocationTimeout,
		},
	}
	for _, opt := range opts {
		opt(rc)
	}
	rc.statusCache = cache.New(rc.cacheExpiry, revocationCacheCleanupInterval)
	return rc
}

// Enabled reports whether this checker performs any checking.
func (rc *RevocationChecker) Enabled() bool {
	return rc != nil && rc.mode != RevocationCheckOff
}

// CheckChain checks every certificate in a verified chain except the trust
// anchor, whose standing is expressed by the trust list itself rather than by
// a revocation responder.
//
// The chain is ordered leaf first, as returned by x509.Certificate.Verify.
func (rc *RevocationChecker) CheckChain(chain []*x509.Certificate) error {
	if !rc.Enabled() || len(chain) < 2 {
		return nil
	}

	// The last entry is the trust anchor; each other certificate is checked
	// against the one that issued it.
	for i := 0; i < len(chain)-1; i++ {
		if err := rc.checkCertificate(chain[i], chain[i+1]); err != nil {
			return err
		}
	}

	return nil
}

// checkCertificate determines and enforces the revocation status of a single
// certificate against its issuer.
func (rc *RevocationChecker) checkCertificate(certificate, issuer *x509.Certificate) error {
	status := rc.statusOf(certificate, issuer)

	switch status {
	case RevocationStatusRevoked:
		logging.Log().Warnf("RevocationChecker: certificate %q (serial %s) has been revoked",
			certificate.Subject.CommonName, certificate.SerialNumber)
		return fmt.Errorf("%w: %q (serial %s)", ErrorCertificateRevoked,
			certificate.Subject.CommonName, certificate.SerialNumber)
	case RevocationStatusGood:
		return nil
	default:
		if rc.mode == RevocationCheckHard {
			logging.Log().Warnf("RevocationChecker: revocation status of certificate %q (serial %s) is unknown and hard-fail is configured",
				certificate.Subject.CommonName, certificate.SerialNumber)
			return fmt.Errorf("%w: %q (serial %s)", ErrorRevocationStatusUnknown,
				certificate.Subject.CommonName, certificate.SerialNumber)
		}
		logging.Log().Debugf("RevocationChecker: revocation status of certificate %q (serial %s) is unknown, accepting (soft-fail)",
			certificate.Subject.CommonName, certificate.SerialNumber)
		return nil
	}
}

// statusOf returns the cached status for a certificate, determining it first if
// it is not cached. Only determined statuses are cached; an unknown status is
// retried on the next presentation, so a temporarily unreachable responder does
// not pin a certificate to "unknown" for the whole cache lifetime.
func (rc *RevocationChecker) statusOf(certificate, issuer *x509.Certificate) RevocationStatus {
	key := revocationCacheKey(certificate, issuer)
	if cached, found := rc.statusCache.Get(key); found {
		if status, ok := cached.(RevocationStatus); ok {
			return status
		}
	}

	status, validUntil := rc.determineStatus(certificate, issuer)
	if status == RevocationStatusUnknown {
		return status
	}

	expiry := rc.cacheExpiry
	if !validUntil.IsZero() {
		if remaining := time.Until(validUntil); remaining > 0 && remaining < expiry {
			expiry = remaining
		}
	}
	rc.statusCache.Set(key, status, expiry)

	return status
}

// determineStatus queries OCSP first and falls back to CRLs. The second return
// value is the time until which the answer is valid, or the zero time when the
// responder declared none.
func (rc *RevocationChecker) determineStatus(certificate, issuer *x509.Certificate) (RevocationStatus, time.Time) {
	if status, validUntil, ok := rc.checkOCSP(certificate, issuer); ok {
		return status, validUntil
	}
	if status, validUntil, ok := rc.checkCRL(certificate, issuer); ok {
		return status, validUntil
	}
	return RevocationStatusUnknown, time.Time{}
}

// checkOCSP queries the responders named in the certificate's Authority
// Information Access extension. The third return value reports whether any
// responder gave a usable answer.
func (rc *RevocationChecker) checkOCSP(certificate, issuer *x509.Certificate) (RevocationStatus, time.Time, bool) {
	if len(certificate.OCSPServer) == 0 {
		return RevocationStatusUnknown, time.Time{}, false
	}

	request, err := ocsp.CreateRequest(certificate, issuer, nil)
	if err != nil {
		logging.Log().Warnf("RevocationChecker: failed to build OCSP request for %q: %v",
			certificate.Subject.CommonName, err)
		return RevocationStatusUnknown, time.Time{}, false
	}

	for _, responderURL := range certificate.OCSPServer {
		if err := validateRevocationURL(responderURL); err != nil {
			logging.Log().Warnf("RevocationChecker: skipping OCSP responder %q: %v", responderURL, err)
			continue
		}

		body, err := rc.post(responderURL, ocspRequestContentType, request)
		if err != nil {
			logging.Log().Warnf("RevocationChecker: OCSP request to %s failed: %v", responderURL, err)
			continue
		}

		response, err := ocsp.ParseResponseForCert(body, certificate, issuer)
		if err != nil {
			logging.Log().Warnf("RevocationChecker: failed to parse OCSP response from %s: %v", responderURL, err)
			continue
		}

		switch response.Status {
		case ocsp.Good:
			return RevocationStatusGood, response.NextUpdate, true
		case ocsp.Revoked:
			return RevocationStatusRevoked, response.NextUpdate, true
		default:
			// ocsp.Unknown: this responder does not know the certificate.
			// Another responder, or a CRL, may still answer.
			logging.Log().Debugf("RevocationChecker: OCSP responder %s does not know certificate %q",
				responderURL, certificate.Subject.CommonName)
		}
	}

	return RevocationStatusUnknown, time.Time{}, false
}

// checkCRL downloads the certificate's CRL distribution points and looks the
// certificate up by serial number. Only CRLs that verify against the issuer are
// used. The third return value reports whether any CRL gave a usable answer.
func (rc *RevocationChecker) checkCRL(certificate, issuer *x509.Certificate) (RevocationStatus, time.Time, bool) {
	for _, distributionPoint := range certificate.CRLDistributionPoints {
		if err := validateRevocationURL(distributionPoint); err != nil {
			logging.Log().Warnf("RevocationChecker: skipping CRL distribution point %q: %v", distributionPoint, err)
			continue
		}

		body, err := rc.get(distributionPoint)
		if err != nil {
			logging.Log().Warnf("RevocationChecker: CRL request to %s failed: %v", distributionPoint, err)
			continue
		}

		revocationList, err := x509.ParseRevocationList(body)
		if err != nil {
			logging.Log().Warnf("RevocationChecker: failed to parse CRL from %s: %v", distributionPoint, err)
			continue
		}

		// An unauthenticated CRL could otherwise be used to mark any
		// certificate as revoked, or to hide a revocation.
		if err := revocationList.CheckSignatureFrom(issuer); err != nil {
			logging.Log().Warnf("RevocationChecker: CRL from %s is not signed by the certificate's issuer: %v",
				distributionPoint, err)
			continue
		}

		for _, entry := range revocationList.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
				return RevocationStatusRevoked, revocationList.NextUpdate, true
			}
		}

		return RevocationStatusGood, revocationList.NextUpdate, true
	}

	return RevocationStatusUnknown, time.Time{}, false
}

// get performs a bounded GET request.
func (rc *RevocationChecker) get(requestURL string) ([]byte, error) {
	response, err := rc.httpClient.Get(requestURL)
	if err != nil {
		return nil, err
	}
	return readRevocationResponse(response)
}

// post performs a bounded POST request.
func (rc *RevocationChecker) post(requestURL, contentType string, body []byte) ([]byte, error) {
	response, err := rc.httpClient.Post(requestURL, contentType, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return readRevocationResponse(response)
}

// readRevocationResponse reads a bounded response body and rejects non-200 responses.
func readRevocationResponse(response *http.Response) ([]byte, error) {
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, MaxRevocationResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if int64(len(body)) > MaxRevocationResponseSize {
		return nil, fmt.Errorf("response exceeds maximum size of %d bytes", MaxRevocationResponseSize)
	}

	return body, nil
}

// validateRevocationURL rejects distribution points that are not plain HTTP(S)
// URLs. The URLs come out of the presented certificate, so they are not fully
// trusted even though the certificate chains to a listed CA; ldap:// and
// file:// in particular must not be dereferenced.
func validateRevocationURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("unparseable URL: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return errors.New("URL has no host")
	}
	return nil
}

// revocationCacheKey identifies a certificate by its issuer and serial number,
// which is what a revocation responder is asked about.
func revocationCacheKey(certificate, issuer *x509.Certificate) string {
	return issuer.Subject.String() + "|" + certificate.SerialNumber.String()
}
