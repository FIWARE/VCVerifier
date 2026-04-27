package config

// Named constants for per-credential revocation-list configuration and for the
// shared status-list client transport defaults. Keeping these named here avoids
// magic values scattered across the codebase.

// Status purposes recognised by the W3C Bitstring Status List / StatusList2021
// specifications. Additional purposes may be added later without breaking the
// zero-value default of an empty `AcceptedPurposes` list.
const (
	// StatusPurposeRevocation indicates that the bit in the referenced status list
	// communicates whether the credential has been revoked.
	StatusPurposeRevocation = "revocation"
	// StatusPurposeSuspension indicates that the bit in the referenced status list
	// communicates whether the credential is currently suspended.
	StatusPurposeSuspension = "suspension"
)

// Defaults for the shared status-list client transport settings. They only
// parametrise the HTTP client and cache that fetch status-list credentials —
// they do NOT gate the feature. The feature itself is gated per credential
// type via `CredentialStatus.Enabled`.
const (
	// DefaultStatusCacheExpirySeconds is the default TTL, in seconds, for
	// entries in the status-list credential cache.
	DefaultStatusCacheExpirySeconds = 300
	// DefaultStatusHttpTimeoutSeconds is the default timeout, in seconds, for
	// HTTP requests that fetch a status-list credential.
	DefaultStatusHttpTimeoutSeconds = 10
)

// DefaultAcceptedStatusPurposes returns the fallback list of status purposes
// applied when a credential enables status checking but does not explicitly
// declare the purposes it enforces. The slice is intentionally allocated fresh
// on every call so callers may mutate the result without affecting others.
func DefaultAcceptedStatusPurposes() []string {
	return []string{StatusPurposeRevocation}
}
