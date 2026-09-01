package verifier

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
)

// TestAssertPublicAddress verifies the classification the address guard applies
// to every address the issuer resolution would connect to.
func TestAssertPublicAddress(t *testing.T) {
	tests := []struct {
		testName string
		address  string
		allowed  bool
	}{
		{"a public IPv4 address", "93.184.216.34", true},
		{"a public IPv6 address", "2606:2800:220:1:248:1893:25c8:1946", true},
		{"loopback", "127.0.0.1", false},
		{"the whole loopback range", "127.13.37.1", false},
		{"IPv6 loopback", "::1", false},
		{"the unspecified address", "0.0.0.0", false},
		{"the IPv6 unspecified address", "::", false},
		{"RFC 1918 10/8", "10.0.0.5", false},
		{"RFC 1918 172.16/12", "172.20.1.1", false},
		{"RFC 1918 192.168/16", "192.168.1.1", false},
		{"RFC 4193 unique local IPv6", "fd00::1", false},
		{"link-local", "169.254.1.1", false},
		{"the cloud metadata address", "169.254.169.254", false},
		{"link-local IPv6", "fe80::1", false},
		{"multicast", "224.0.0.1", false},
		{"carrier-grade NAT", "100.64.0.1", false},
		{"IETF protocol assignments", "192.0.0.170", false},
		{"the benchmarking range", "198.18.0.1", false},
		{"the reserved 240/4 range", "240.0.0.1", false},
		{"a 4-in-6 mapped private address", "::ffff:10.0.0.5", false},
		{"a NAT64-embedded private address", "64:ff9b::10.0.0.5", false},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			address, err := netip.ParseAddr(tc.address)
			assert.NoError(t, err, "the test address should parse")

			guardErr := assertPublicAddress(address.Unmap())
			if tc.allowed {
				assert.NoError(t, guardErr, "%s should be reachable", tc.address)
				return
			}
			assert.ErrorIs(t, guardErr, ErrorAddressNotAllowed, "%s must not be reachable", tc.address)
		})
	}
}

// TestAssertPublicAddress_InvalidAddress verifies that a zero address — what a
// failed parse yields — is rejected rather than treated as routable.
func TestAssertPublicAddress_InvalidAddress(t *testing.T) {
	assert.ErrorIs(t, assertPublicAddress(netip.Addr{}), ErrorAddressNotAllowed)
}

// TestDialPublicAddress_MalformedAddress verifies that an address the dialer
// cannot split into host and port is refused instead of dialed.
func TestDialPublicAddress_MalformedAddress(t *testing.T) {
	logging.Configure(testLoggingConfig)

	conn, err := dialPublicAddress(context.Background(), "tcp", "no-port-here")
	assert.ErrorIs(t, err, ErrorAddressNotAllowed)
	assert.Nil(t, conn)
}

// TestResolveIssuerKeys_PrivateIssuerAddressIsRefused verifies the guard on the
// *first* hop of a resolution: the issuer identifier itself comes from an
// unverified token, so an identifier naming an internal address must not make
// the verifier connect to it. The metadata server here is a real loopback
// listener, and the default resolver refuses to reach it.
func TestResolveIssuerKeys_PrivateIssuerAddressIsRefused(t *testing.T) {
	logging.Configure(testLoggingConfig)

	server, _ := startWellKnownJwksServer(t, "refused-key")
	resolver := NewCachingHttpsIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL)

	keys, err := resolver.ResolveIssuerKeys(context.Background(), server.URL, "refused-key")

	assert.Error(t, err, "an issuer on a loopback address must not resolve")
	assert.Nil(t, keys)
}

// TestResolveIssuerKeys_PrivateIssuerAddressAllowedByConfiguration verifies the
// opt-out: a deployment whose issuers live in its own network resolves them
// once WithAllowPrivateAddresses is set.
func TestResolveIssuerKeys_PrivateIssuerAddressAllowedByConfiguration(t *testing.T) {
	logging.Configure(testLoggingConfig)

	server, _ := startWellKnownJwksServer(t, "allowed-key")
	resolver := NewCachingHttpsIssuerResolver(cache.New(5*time.Minute, 10*time.Minute), DefaultJwksCacheTTL).
		WithAllowPrivateAddresses(true)

	keys, err := resolver.ResolveIssuerKeys(context.Background(), server.URL, "allowed-key")

	assert.NoError(t, err)
	assert.Len(t, keys, 1)
}
