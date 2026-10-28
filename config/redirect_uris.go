package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// redirectUriWildcard ends an allowedRedirectUris entry that accepts every path below its own.
const redirectUriWildcard = "/*"

var ErrorInvalidAllowedRedirectUri = errors.New("invalid_allowed_redirect_uri")

// ValidateAllowedRedirectUri checks an allowedRedirectUris entry. An entry is an absolute http(s)
// URI without user info or fragment, compared as an exact string, or one whose path ends in "/*",
// which accepts every path below it on the same scheme, host and port. A "*" anywhere else is not
// a pattern: a regular expression or a glob in a redirect URI allow-list is a classic way to let
// an unintended host or path through (RFC 9700 §4.1.3 requires exact matching), so none is
// supported.
func ValidateAllowedRedirectUri(entry string) error {
	base := entry
	if strings.HasSuffix(entry, redirectUriWildcard) {
		base = strings.TrimSuffix(entry, "*")
	}
	if strings.Contains(base, "*") {
		return fmt.Errorf("%w: %q - \"*\" is only allowed as the last path segment (\"https://host/path/*\")", ErrorInvalidAllowedRedirectUri, entry)
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("%w: %q - %v", ErrorInvalidAllowedRedirectUri, entry, err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if (scheme != "http" && scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || strings.Contains(base, "#") {
		return fmt.Errorf("%w: %q - expected an absolute http(s) URI without user info or fragment", ErrorInvalidAllowedRedirectUri, entry)
	}
	if scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return fmt.Errorf("%w: %q - http is only allowed for loopback hosts", ErrorInvalidAllowedRedirectUri, entry)
	}
	if strings.HasSuffix(entry, redirectUriWildcard) && (parsed.RawQuery != "" || parsed.ForceQuery) {
		return fmt.Errorf("%w: %q - a wildcard entry cannot carry a query", ErrorInvalidAllowedRedirectUri, entry)
	}
	if strings.HasSuffix(entry, redirectUriWildcard) {
		if _, ok := normalizeWildcardPath(parsed.EscapedPath()); !ok {
			return fmt.Errorf("%w: %q - a wildcard path cannot contain dot segments or encoded separators", ErrorInvalidAllowedRedirectUri, entry)
		}
	}
	return nil
}

// RedirectUriWellFormed reports whether a redirect URI is an absolute http(s) URI with a host and
// without user info or fragment (RFC 6749 §3.1.2). It is checked for every login, with or without
// allowedRedirectUris: the cross-device v2 page navigates to the URI, so a "javascript:" or
// "data:" URI would run in the verifier's origin, and an empty one would send the code back to the
// login page. http stays allowed for every host - a same-device callback behind a TLS-terminating
// proxy is one.
func RedirectUriWellFormed(redirectUri string) bool {
	parsed, err := url.Parse(redirectUri)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return (scheme == "http" || scheme == "https") && parsed.Host != "" && parsed.Opaque == "" &&
		parsed.User == nil && parsed.Fragment == "" && !strings.Contains(redirectUri, "#")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ValidateServicesAllowedRedirectUris checks the allowedRedirectUris of every service, naming the
// service of the first invalid entry.
func ValidateServicesAllowedRedirectUris(services []ConfiguredService) error {
	for _, service := range services {
		for _, entry := range service.AllowedRedirectUris {
			if err := ValidateAllowedRedirectUri(entry); err != nil {
				return fmt.Errorf("service %q: %w", service.Id, err)
			}
		}
	}
	return nil
}

// RedirectUriAllowed reports whether the redirect URI matches one of the allowed entries (see
// ValidateAllowedRedirectUri). An invalid entry matches nothing.
func RedirectUriAllowed(allowed []string, redirectUri string) bool {
	for _, entry := range allowed {
		if ValidateAllowedRedirectUri(entry) != nil {
			continue
		}
		if !strings.HasSuffix(entry, redirectUriWildcard) {
			if redirectUri == entry {
				return true
			}
			continue
		}
		if matchesWildcardEntry(strings.TrimSuffix(entry, "*"), redirectUri) {
			return true
		}
	}
	return false
}

// matchesWildcardEntry reports whether the redirect URI is below the prefix of a wildcard entry
// (which ends in "/"). Both are parsed, so the comparison is on scheme, host and port - never a
// string prefix, which "https://rp.example.evil.com" would pass for "https://rp.example". Only the
// path may vary: a query, a fragment or user info are rejected, as are dot segments and encoded
// separators, which a browser, proxy or relying party may resolve to a path outside the prefix.
func matchesWildcardEntry(prefix string, redirectUri string) bool {
	entry, err := url.Parse(prefix)
	if err != nil {
		return false
	}
	candidate, err := url.Parse(redirectUri)
	if err != nil {
		return false
	}
	if candidate.User != nil || candidate.Opaque != "" || candidate.RawQuery != "" || candidate.ForceQuery ||
		candidate.Fragment != "" || strings.Contains(redirectUri, "#") || strings.Contains(redirectUri, "\\") {
		return false
	}
	if !strings.EqualFold(candidate.Scheme, entry.Scheme) || !strings.EqualFold(candidate.Host, entry.Host) {
		return false
	}
	path, pathOK := normalizeWildcardPath(candidate.EscapedPath())
	prefixPath, prefixOK := normalizeWildcardPath(entry.EscapedPath())
	if !pathOK || !prefixOK {
		return false
	}
	return strings.HasPrefix(path, prefixPath)
}

func normalizeWildcardPath(path string) (string, bool) {
	for {
		lowered := strings.ToLower(path)
		if strings.Contains(lowered, "%2e") || strings.Contains(lowered, "%2f") || strings.Contains(lowered, "%5c") {
			return "", false
		}
		for segment := range strings.SplitSeq(path, "/") {
			if segment == "." || segment == ".." {
				return "", false
			}
		}

		decoded, err := url.PathUnescape(path)
		if err != nil {
			return "", false
		}
		if decoded == path {
			return path, true
		}
		path = decoded
	}
}
