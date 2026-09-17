package eidas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func init() {
	initTestLogging()
}

// revocationTestChain is an issuer CA plus a leaf certificate it signed.
type revocationTestChain struct {
	issuerCert *x509.Certificate
	issuerKey  *ecdsa.PrivateKey
	leafCert   *x509.Certificate
}

// newRevocationTestChain builds an issuer CA and a leaf certificate pointing at
// the given OCSP responder and CRL distribution point URLs.
func newRevocationTestChain(t *testing.T, ocspServers, crlDistributionPoints []string) revocationTestChain {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Revocation Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)
	issuerCert, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Revocation Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		OCSPServer:            ocspServers,
		CRLDistributionPoints: crlDistributionPoints,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return revocationTestChain{issuerCert: issuerCert, issuerKey: issuerKey, leafCert: leafCert}
}

// chain returns the certificate chain in the order x509.Certificate.Verify
// produces: leaf first, trust anchor last.
func (c revocationTestChain) chain() []*x509.Certificate {
	return []*x509.Certificate{c.leafCert, c.issuerCert}
}

// startOCSPResponder serves an OCSP response with the given status for the
// chain's leaf certificate.
func startOCSPResponder(t *testing.T, c revocationTestChain, status int) *httptest.Server {
	t.Helper()

	template := ocsp.Response{
		Status:       status,
		SerialNumber: c.leafCert.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	if status == ocsp.Revoked {
		template.RevokedAt = time.Now().Add(-time.Hour)
		template.RevocationReason = ocsp.KeyCompromise
	}

	response, err := ocsp.CreateResponse(c.issuerCert, c.issuerCert, template, c.issuerKey)
	require.NoError(t, err)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(response)
	}))
}

// startCRLServer serves a CRL signed by the chain's issuer, listing the given
// serial numbers as revoked.
func startCRLServer(t *testing.T, c revocationTestChain, revokedSerials []*big.Int) *httptest.Server {
	t.Helper()

	var entries []x509.RevocationListEntry
	for _, serial := range revokedSerials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Hour),
		})
	}

	template := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Minute),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, c.issuerCert, c.issuerKey)
	require.NoError(t, err)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(crlDER)
	}))
}

// TestRevocationChecker_OCSP verifies that an OCSP responder's verdict decides
// the outcome, and that the mode governs what happens when it cannot be reached.
func TestRevocationChecker_OCSP(t *testing.T) {
	tests := []struct {
		name          string
		ocspStatus    int
		unreachable   bool
		mode          string
		expectedError error
	}{
		{
			name:       "good certificate passes",
			ocspStatus: ocsp.Good,
			mode:       RevocationCheckSoft,
		},
		{
			name:          "revoked certificate is rejected in soft mode",
			ocspStatus:    ocsp.Revoked,
			mode:          RevocationCheckSoft,
			expectedError: ErrorCertificateRevoked,
		},
		{
			name:          "revoked certificate is rejected in hard mode",
			ocspStatus:    ocsp.Revoked,
			mode:          RevocationCheckHard,
			expectedError: ErrorCertificateRevoked,
		},
		{
			name:        "unreachable responder is accepted in soft mode",
			unreachable: true,
			mode:        RevocationCheckSoft,
		},
		{
			name:          "unreachable responder is rejected in hard mode",
			unreachable:   true,
			mode:          RevocationCheckHard,
			expectedError: ErrorRevocationStatusUnknown,
		},
		{
			name:        "revoked certificate is ignored when checking is off",
			ocspStatus:  ocsp.Revoked,
			mode:        RevocationCheckOff,
			unreachable: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Build the chain against a placeholder URL first, then point it at
			// the responder that answers for this chain's leaf.
			placeholder := newRevocationTestChain(t, []string{"http://127.0.0.1:1/ocsp"}, nil)

			var responderURL string
			if tc.unreachable {
				responderURL = "http://127.0.0.1:1/ocsp"
			} else {
				responder := startOCSPResponder(t, placeholder, tc.ocspStatus)
				defer responder.Close()
				responderURL = responder.URL
			}

			testChain := newRevocationTestChainAt(t, placeholder, responderURL)

			checker := NewRevocationChecker(WithRevocationMode(tc.mode))
			err := checker.CheckChain(testChain.chain())

			if tc.expectedError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedError)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// newRevocationTestChainAt re-issues the leaf of an existing chain with the
// given OCSP responder URL, keeping the issuer (and therefore the responder's
// signature validity) intact.
func newRevocationTestChainAt(t *testing.T, base revocationTestChain, ocspServer string) revocationTestChain {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: base.leafCert.SerialNumber,
		Subject:      pkix.Name{CommonName: "Revocation Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		OCSPServer:   []string{ocspServer},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, base.issuerCert, &leafKey.PublicKey, base.issuerKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return revocationTestChain{issuerCert: base.issuerCert, issuerKey: base.issuerKey, leafCert: leafCert}
}

// TestRevocationChecker_CRL verifies the CRL fallback for certificates that
// name no OCSP responder.
func TestRevocationChecker_CRL(t *testing.T) {
	tests := []struct {
		name          string
		revoked       bool
		mode          string
		expectedError error
	}{
		{
			name: "certificate absent from the CRL passes",
			mode: RevocationCheckHard,
		},
		{
			name:          "certificate listed on the CRL is rejected",
			revoked:       true,
			mode:          RevocationCheckSoft,
			expectedError: ErrorCertificateRevoked,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := newRevocationTestChain(t, nil, nil)

			var revokedSerials []*big.Int
			if tc.revoked {
				revokedSerials = []*big.Int{base.leafCert.SerialNumber}
			}
			crlServer := startCRLServer(t, base, revokedSerials)
			defer crlServer.Close()

			// Re-issue the leaf pointing at the CRL server, keeping the serial
			// so the CRL entry still matches.
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			leafTemplate := &x509.Certificate{
				SerialNumber:          base.leafCert.SerialNumber,
				Subject:               pkix.Name{CommonName: "Revocation Test Leaf"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				CRLDistributionPoints: []string{crlServer.URL},
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, base.issuerCert, &leafKey.PublicKey, base.issuerKey)
			require.NoError(t, err)
			leafCert, err := x509.ParseCertificate(leafDER)
			require.NoError(t, err)

			testChain := revocationTestChain{issuerCert: base.issuerCert, issuerKey: base.issuerKey, leafCert: leafCert}

			checker := NewRevocationChecker(WithRevocationMode(tc.mode))
			err = checker.CheckChain(testChain.chain())

			if tc.expectedError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedError)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// TestRevocationChecker_NoDistributionPoints verifies the outcome for a
// certificate that names neither an OCSP responder nor a CRL.
func TestRevocationChecker_NoDistributionPoints(t *testing.T) {
	testChain := newRevocationTestChain(t, nil, nil)

	softChecker := NewRevocationChecker(WithRevocationMode(RevocationCheckSoft))
	assert.NoError(t, softChecker.CheckChain(testChain.chain()),
		"soft mode accepts a certificate with no revocation information")

	hardChecker := NewRevocationChecker(WithRevocationMode(RevocationCheckHard))
	err := hardChecker.CheckChain(testChain.chain())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrorRevocationStatusUnknown)
}

// TestRevocationChecker_CachesDeterminedStatus verifies that a determined
// status is served from the cache instead of re-querying the responder.
func TestRevocationChecker_CachesDeterminedStatus(t *testing.T) {
	base := newRevocationTestChain(t, []string{"http://127.0.0.1:1/ocsp"}, nil)

	requests := 0
	response, err := ocsp.CreateResponse(base.issuerCert, base.issuerCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: base.leafCert.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}, base.issuerKey)
	require.NoError(t, err)

	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write(response)
	}))
	defer responder.Close()

	testChain := newRevocationTestChainAt(t, base, responder.URL)

	checker := NewRevocationChecker(WithRevocationMode(RevocationCheckHard))
	require.NoError(t, checker.CheckChain(testChain.chain()))
	require.NoError(t, checker.CheckChain(testChain.chain()))

	assert.Equal(t, 1, requests, "the second check should be served from the cache")
}

// TestRevocationChecker_RejectsUnsignedCRL verifies that a CRL not signed by
// the certificate's issuer is ignored rather than trusted.
func TestRevocationChecker_RejectsUnsignedCRL(t *testing.T) {
	base := newRevocationTestChain(t, nil, nil)
	foreign := newRevocationTestChain(t, nil, nil)

	// A CRL signed by an unrelated CA that claims the leaf is revoked.
	crlServer := startCRLServer(t, foreign, []*big.Int{base.leafCert.SerialNumber})
	defer crlServer.Close()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber:          base.leafCert.SerialNumber,
		Subject:               pkix.Name{CommonName: "Revocation Test Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{crlServer.URL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, base.issuerCert, &leafKey.PublicKey, base.issuerKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	testChain := revocationTestChain{issuerCert: base.issuerCert, issuerKey: base.issuerKey, leafCert: leafCert}

	checker := NewRevocationChecker(WithRevocationMode(RevocationCheckSoft))
	assert.NoError(t, checker.CheckChain(testChain.chain()),
		"a CRL from an unrelated issuer must not revoke the certificate")
}

// TestValidateRevocationURL verifies that only plain HTTP(S) distribution
// points are dereferenced.
func TestValidateRevocationURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		expectError bool
	}{
		{name: "http", url: "http://crl.example.com/list.crl"},
		{name: "https", url: "https://crl.example.com/list.crl"},
		{name: "ldap is rejected", url: "ldap://directory.example.com/cn=CRL", expectError: true},
		{name: "file is rejected", url: "file:///etc/passwd", expectError: true},
		{name: "no host", url: "http:///list.crl", expectError: true},
		{name: "not a URL", url: "://nonsense", expectError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRevocationURL(tc.url)
			if tc.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
