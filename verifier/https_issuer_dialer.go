package verifier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/fiware/VCVerifier/logging"
)

const (
	// metadataDialTimeout is the maximum duration of establishing a single TCP
	// connection to an issuer's metadata or JWKS endpoint.
	metadataDialTimeout = 5 * time.Second

	// metadataDialKeepAlive is the keep-alive interval of metadata connections.
	metadataDialKeepAlive = 30 * time.Second

	// networkIP is the network passed to the resolver to accept both IPv4 and
	// IPv6 answers for a metadata host.
	networkIP = "ip"
)

// ErrorAddressNotAllowed indicates that an issuer identifier — or a host a
// metadata document named — resolves to an address the verifier refuses to
// connect to: loopback, a private or link-local range, or another address that
// only exists inside the deployment's own network.
//
// The very first request of a resolution is made to a host the *token* names,
// before any trust-registry check has run, so without this guard an
// unauthenticated presentation carrying `iss: "https://10.0.0.5:8443/x"` would
// make the verifier probe the internal network on the sender's behalf.
var ErrorAddressNotAllowed = errors.New("address_not_allowed")

// blockedAddressPrefixes are ranges that netip's own classification does not
// cover but that must not be reachable through an issuer identifier either.
var blockedAddressPrefixes = []netip.Prefix{
	// RFC 6598 carrier-grade NAT space, routable inside provider networks.
	netip.MustParsePrefix("100.64.0.0/10"),
	// RFC 6890 IETF protocol assignments, which include 192.0.0.170/32 etc.
	netip.MustParsePrefix("192.0.0.0/24"),
	// RFC 2544 benchmarking range.
	netip.MustParsePrefix("198.18.0.0/15"),
	// RFC 1112 reserved former class E space.
	netip.MustParsePrefix("240.0.0.0/4"),
	// RFC 6052 NAT64 well-known prefix — an IPv6 address here embeds an IPv4
	// address and would otherwise smuggle a private target past the checks.
	netip.MustParsePrefix("64:ff9b::/96"),
}

// metadataDialer establishes the connections of the HTTPS issuer resolver. It
// carries no per-resolver state and is safe for concurrent use.
var metadataDialer = &net.Dialer{
	Timeout:   metadataDialTimeout,
	KeepAlive: metadataDialKeepAlive,
}

// dialContext is the DialContext of the resolver's HTTP client.
//
// Unless the deployment opted into private targets, the host is resolved here
// and every answer is classified before a connection is attempted; the
// connection is then made to the address that was checked, not to the name.
// Re-resolving the name inside the dialer would reopen the DNS-rebinding hole
// this exists to close: a name that answers with a public address for the
// check and a private one for the connection.
func (r *CachingHttpsIssuerResolver) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if r.allowPrivateAddresses {
		return metadataDialer.DialContext(ctx, network, address)
	}
	return dialPublicAddress(ctx, network, address)
}

// dialPublicAddress resolves a `host:port` address and connects to the first
// answer that is a publicly routable address. An address that is not is never
// dialed, and a host whose every answer is blocked fails with
// ErrorAddressNotAllowed.
func dialPublicAddress(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a host:port address: %v", ErrorAddressNotAllowed, address, err)
	}

	addresses, err := net.DefaultResolver.LookupNetIP(ctx, networkIP, host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", host, err)
	}

	lastErr := fmt.Errorf("%w: %s resolved to no usable address", ErrorAddressNotAllowed, host)
	for _, resolved := range addresses {
		// A 4-in-6 address is classified by the IPv4 address it carries, not by
		// the mapping that wraps it.
		resolved = resolved.Unmap()
		if allowErr := assertPublicAddress(resolved); allowErr != nil {
			logging.Log().Warnf("Refusing to connect to %s: %v", host, allowErr)
			lastErr = allowErr
			continue
		}
		conn, dialErr := metadataDialer.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

// assertPublicAddress reports whether an address may be connected to while
// resolving an issuer identifier. Everything that is not globally routable is
// rejected: loopback, the RFC 1918 / RFC 4193 private ranges, link-local
// (including the cloud metadata address 169.254.169.254), multicast, the
// unspecified address and the ranges in blockedAddressPrefixes.
func assertPublicAddress(address netip.Addr) error {
	if !address.IsValid() {
		return fmt.Errorf("%w: not a valid IP address", ErrorAddressNotAllowed)
	}
	if address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
		address.IsInterfaceLocalMulticast() || address.IsMulticast() {
		return fmt.Errorf("%w: %s is not a globally routable address", ErrorAddressNotAllowed, address)
	}
	for _, prefix := range blockedAddressPrefixes {
		if prefix.Contains(address) {
			return fmt.Errorf("%w: %s is in the reserved range %s", ErrorAddressNotAllowed, address, prefix)
		}
	}
	return nil
}
