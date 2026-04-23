# Implementation Plan: [VCVerifier] CredentialsRevocationList support

## Overview

Add support for checking the revocation status of incoming Verifiable Credentials
against a W3C `BitstringStatusList` / `StatusList2021` style revocation list. Each
credential that carries a `credentialStatus` entry referencing a
`BitstringStatusListEntry` (or `StatusList2021Entry`) will have its bit looked up in
the referenced status-list credential. If the bit is set (revoked), the credential
is rejected. A cached HTTP client fetches and caches status-list credentials to avoid
per-request network calls. The feature is wired in as an additional
`ValidationService` in the verifier's validation chain, is configurable
**per credential type** (not globally), is optional and defaults to disabled, and is
covered by table-driven unit tests following the existing repository patterns.

## Configuration shape (per review feedback)

Revocation-list checking is configured **per credential** in
`config/configClient.go`, next to `TrustedParticipantsLists`, `TrustedIssuersLists`,
`HolderVerification`, `RequireCompliance`, and `JwtInclusion`. It is NOT a global
switch on `config.Verifier`. The feature is OFF by default: a credential that does
not declare `credentialStatus` in its per-credential config is validated exactly
as it is today, with no network calls.

Shared, non-credential-specific knobs (cache TTL and HTTP timeout for the
status-list fetcher) live on `config.Verifier` only as defaults used by the
shared client — they do not gate the feature.

## Steps

### Step 1: Add per-credential configuration for the revocation list feature

Extend `config/configClient.go` to expose revocation-list config on each
`Credential`:

- Add a new struct `CredentialStatus` with these `mapstructure`/`json` fields
  (mirroring the style of `HolderVerification` / `JwtInclusion`):
  - `Enabled bool` — per-credential-type switch. When omitted or `false`, no
    revocation check is performed for this credential type. Omitted by default
    on every credential so existing configurations behave exactly as today.
  - `AcceptedPurposes []string` — status purposes (`revocation`, `suspension`,
    ...) this credential type enforces. When empty, defaults to
    `[StatusPurposeRevocation]` at read time (do not default via mapstructure
    so the YAML can distinguish "not set" from an explicit empty list).
  - `RequireStatus bool` — when `true`, credentials of this type that are
    missing a `credentialStatus` entry are rejected. Defaults to `false`.
- Add a field
  `CredentialStatus CredentialStatus \`json:"credentialStatus,omitempty" mapstructure:"credentialStatus,omitempty"\``
  on the existing `Credential` struct (not on `Verifier`, not on
  `ScopeEntry`). The `,omitempty` tag ensures the field is fully optional.
- Document every new field using GoDoc comments following the existing
  `Credential` / `JwtInclusion` pattern in the same file.
- No magic constants: introduce named constants in a new
  `config/credential_status.go` file for the defaults and purpose strings
  (`StatusPurposeRevocation = "revocation"`,
  `StatusPurposeSuspension = "suspension"`). Do NOT introduce cache-expiry or
  HTTP-timeout config per credential — those are shared; see Step 3.
- Add a small shared section on `config.Verifier`
  (`config/config.go`) for the status-list client's transport settings only:
  - `StatusListCacheExpiry int` (seconds, default `300`) — TTL for the
    status-list credential cache.
  - `StatusListHttpTimeout int` (seconds, default `10`) — timeout for fetching
    the status-list credential.
  Introduce named constants (`DefaultStatusCacheExpirySeconds = 300`,
  `DefaultStatusHttpTimeoutSeconds = 10`). These are NOT feature flags and
  never enable/disable the check — they only parametrise the shared client
  used when at least one credential opts in.

**Files touched:** `config/configClient.go`, `config/config.go`,
`config/credential_status.go` (new, constants only).

**Acceptance:** `go build ./...` succeeds; existing
`config/configClient_test.go` still passes; a new parameterised test asserts
that (a) a credential without a `credentialStatus` block deserialises to a
zero-value `CredentialStatus` with `Enabled == false`, and (b) a credential
with `credentialStatus: { enabled: true }` deserialises with `Enabled == true`
and `AcceptedPurposes` empty.

### Step 2: Expose the per-credential config through `CredentialsConfig`

Extend the `CredentialsConfig` interface in
`verifier/credentialsConfig.go` with:

```go
// GetCredentialStatusConfig returns the per-credential revocation-list
// configuration for the given service, scope and credential type.
// Returns a zero-value config (Enabled == false) when nothing is configured.
GetCredentialStatusConfig(serviceIdentifier string, scope string, credentialType string) (config.CredentialStatus, error)
```

- Implement it on `ServiceBackedCredentialsConfig` by looking up the scoped
  `Credential` entry (same pattern as `GetHolderVerification` and
  `GetJwtInclusion`) and returning its `CredentialStatus` field.
- Return `config.CredentialStatus{}` (all zero values → `Enabled == false`)
  when the credential type is unknown so the caller can treat "unknown" and
  "not configured" the same way. No error in that case.
- Update every existing mock of `CredentialsConfig` in the test files so the
  project still compiles — specifically `mockCredentialsConfig` in
  `verifier/verifier_test.go` (search the file for the other `Get*`
  implementations and add one that returns an empty struct).
- GoDoc on the new interface method.

**Files touched:** `verifier/credentialsConfig.go`,
`verifier/credentialsConfig_test.go` (extend existing tests),
`verifier/verifier_test.go` (update mock).

**Acceptance:** `go build ./...` succeeds; `go test ./verifier/... -v` still
passes. A new table-driven test in `credentialsConfig_test.go` covers: known
credential type with config returns the config; known credential type without
a `credentialStatus` block returns the zero value; unknown credential type
returns the zero value with no error.

### Step 3: Define the status-list credential data model

Create a self-contained data-model file for fetched status-list credentials and
entries, independent of the verifier package:

- New file `common/credential_status.go` containing:
  - Constants for the supported type names:
    `TypeBitstringStatusListEntry = "BitstringStatusListEntry"`,
    `TypeBitstringStatusListCredential = "BitstringStatusListCredential"`,
    `TypeStatusList2021Entry = "StatusList2021Entry"`,
    `TypeStatusList2021Credential = "StatusList2021Credential"`.
  - Named field-key constants (`StatusListKeyEncodedList`,
    `StatusListKeyStatusPurpose`, `StatusListEntryKeyStatusListIndex`,
    `StatusListEntryKeyStatusListCredential`, `StatusListEntryKeyStatusPurpose`,
    `StatusListEntryKeyStatusSize`, `StatusListEntryKeyType`).
  - `type StatusListEntry struct { ID, Type, StatusPurpose, StatusListCredential string; StatusListIndex uint64; StatusSize int }`.
  - `type StatusListCredential struct { EncodedList, StatusPurpose string }` (decoded
    form; the bitstring itself is kept as a `[]byte` after gzip + base64url
    decoding).
  - A helper `ParseStatusListEntries(raw interface{}) ([]StatusListEntry, error)`
    that accepts the nested `credentialStatus` value (a single object, an
    array, or nil) per the W3C VC 2.0 spec.
  - A helper `DecodeBitstring(encoded string) ([]byte, error)` that
    base64url-decodes then gzip-inflates, returning the raw bitstring.
  - A helper `IsStatusSet(bitstring []byte, index uint64, statusSize int) (bool, error)`
    that returns the bit value at the given index, bounds-checked.
- All helpers have GoDoc comments. No magic numbers: introduce
  `DefaultStatusSizeBits = 1`, `BitsPerByte = 8`.

**Files touched:** `common/credential_status.go` (new),
`common/credential_status_test.go` (new).

**Acceptance:** Table-driven unit tests cover:
  - Parsing single-object and array `credentialStatus` fields.
  - Missing `credentialStatus` returns an empty slice with no error.
  - Malformed entries return a typed error.
  - `DecodeBitstring` round-trips a known test vector.
  - `IsStatusSet` correctly returns true/false for the first, a middle, and the
    last index of a small bitstring, and errors on out-of-range indices.

### Step 4: Build a cached status-list credential fetcher

Introduce a client responsible for fetching and caching status-list credentials:

- New file `verifier/credential_status_client.go`:
  - `type StatusListCredentialClient interface { Fetch(url string) (*common.Credential, error) }`.
  - `type CachingStatusListClient struct { httpClient *http.Client; cache common.Cache }`
    implementing the interface, using `patrickmn/go-cache` as
    `caching_client.go` already does.
  - Constructor
    `NewCachingStatusListClient(timeout time.Duration, cacheExpiry time.Duration) *CachingStatusListClient`
    that builds the HTTP client and cache from `config.Verifier`'s
    `StatusListHttpTimeout` / `StatusListCacheExpiry` (Step 1).
  - `Fetch` performs a GET, parses the response body using the existing VC
    parser. The parsed `*common.Credential` is cached by URL.
  - All public symbols carry GoDoc comments. Named constants for the default
    `Accept` header (`ContentTypeCredentialJson = "application/vc+ld+json"`)
    and the cache cleanup multiplier (reusing `2×expiry` pattern from existing
    code).

**Files touched:** `verifier/credential_status_client.go` (new),
`verifier/credential_status_client_test.go` (new).

**Acceptance:** Tests use `httptest.NewServer` to serve a static status-list
credential. Parameterised cases cover: cache hit, cache miss triggers fetch,
HTTP error is propagated, unparsable JSON returns a typed error. Run
`go test ./verifier/... -run TestCachingStatusListClient -v`.

### Step 5: Implement the `CredentialStatusValidationService`

Add the validation service, matching the `ValidationService` interface used by
the rest of the verifier:

- New file `verifier/credential_status.go`:
  - `type CredentialStatusValidationContext struct { PerType map[string]config.CredentialStatus }`
    — the context carries the per-credential-type config resolved from
    `CredentialsConfig` in Step 2. (Map key is the credential type, same shape
    as `TrustRegistriesValidationContext.trustedIssuersLists`.)
  - `type CredentialStatusValidationService struct { client StatusListCredentialClient; clock common.Clock }`.
  - `func (s *CredentialStatusValidationService) ValidateVC(vc *common.Credential, ctx ValidationContext) (bool, error)`:
    1. Cast `ctx` to `CredentialStatusValidationContext`; on failure return
       `ErrorCannotConvertContext` (re-use the existing typed error).
    2. Look up the credential's type(s) in `PerType`. If none of the credential's
       declared types has a config with `Enabled == true`, return `true, nil`
       (no-op — feature off for this credential).
    3. Merge `AcceptedPurposes` from all matching configs; default to
       `[StatusPurposeRevocation]` when empty.
    4. Merge `RequireStatus`: `true` if ANY matching config requires it.
    5. Read the credential's raw JSON and extract `credentialStatus` via
       `common.ParseStatusListEntries`.
    6. If no entries: return `true, nil` when `RequireStatus` is false,
       `false, ErrorStatusMissing` otherwise.
    7. For each entry:
       - Skip entries whose `statusPurpose` is not in the merged
         `AcceptedPurposes`.
       - Only handle recognized types from Step 3; unknown types are logged
         and skipped (forward-compatible).
       - Fetch the status-list credential via the client.
       - Decode the bitstring via `common.DecodeBitstring`.
       - Call `common.IsStatusSet`. If set, return
         `false, ErrorCredentialRevoked`.
    8. Return `true, nil` if no matching entry indicates revocation.
  - Typed errors: `ErrorCredentialRevoked`, `ErrorStatusMissing`,
    `ErrorStatusListUnparseable`, `ErrorStatusListPurposeMismatch` (exported
    `var ... = errors.New(...)` following the `verifier.go` convention).
  - All public types and functions documented.
  - Compile-time assertion
    `var _ ValidationService = (*CredentialStatusValidationService)(nil)`.

**Files touched:** `verifier/credential_status.go` (new).

**Acceptance:** Compile succeeds; unit tests follow in Step 7.

### Step 6: Wire the service and per-credential context into the verifier

Thread the new service and per-credential context into the verifier:

- In `verifier/verifier.go` `InitVerifier`:
  - After the existing validation services are built, unconditionally
    construct a `CachingStatusListClient` using the shared
    `StatusListHttpTimeout` / `StatusListCacheExpiry` from
    `config.Verifier`, then a `CredentialStatusValidationService`
    wrapping it. The service is always appended; when no credential has
    `CredentialStatus.Enabled = true`, `ValidateVC` is a no-op so there is no
    performance impact.
  - Append the new service to the `validationServices` slice passed to
    `CredentialVerifier`.
- Add a helper
  `getCredentialStatusValidationContext(clientId, scope string, credentialTypes []string) (CredentialStatusValidationContext, error)`
  next to `getTrustRegistriesValidationContext`. For each requested
  credential type it calls the new `GetCredentialStatusConfig` from Step 2
  and populates `PerType`.
- In both validation loops in `verifier.go` (~L603 `GenerateToken` and
  ~L846 VP validation), build the new context alongside the existing one and
  dispatch it to the matching service. Use a runtime type switch on each
  `ValidationService` to decide which context to pass (keeps the
  `ValidationService` interface unchanged). If a cleaner dispatch already
  exists by the time this step runs, reuse it.

**Files touched:** `verifier/verifier.go`.

**Acceptance:** `go build ./...` succeeds. `go test ./verifier/... -v` still
passes — the feature defaults to disabled per credential, so no legacy test
should see a behavior change.

### Step 7: Unit tests for the validation service

Follow the `compliance_test.go` / `trustedissuer_test.go` pattern:

- New file `verifier/credential_status_test.go`:
  - `type mockStatusListClient struct { credentials map[string]*common.Credential; err error }` with a `Fetch` method.
  - `TestCredentialStatusValidationService_ValidateVC` — table-driven with the
    following cases:
    - Credential type not present in `PerType` → valid, no fetch.
    - Credential type present with `Enabled = false` → valid, no fetch.
    - Credential without `credentialStatus` and `RequireStatus=false` → valid.
    - Credential without `credentialStatus` and `RequireStatus=true` → error
      `ErrorStatusMissing`.
    - Revoked bit set at the credential's index → `false, ErrorCredentialRevoked`.
    - Revoked bit clear → `true, nil`.
    - Status purpose not in `AcceptedPurposes` → entry skipped, result `true`.
    - Fetch failure (`client.err != nil`) → error propagated.
    - Malformed bitstring → `ErrorStatusListUnparseable`.
    - Two status entries (suspension + revocation), revocation bit set →
      `false, ErrorCredentialRevoked`.
  - Use in-line helpers to build `*common.Credential` values carrying raw
    `credentialStatus` objects, mirroring how `compliance_test.go` uses
    `common.CreateCredential` + `SetRawJSON`.

**Files touched:** `verifier/credential_status_test.go` (new).

**Acceptance:** `go test ./verifier/... -run TestCredentialStatusValidationService -v`
passes. Coverage for the new files ≥80 %.

### Step 8: Integration wiring test for `InitVerifier`

Extend `verifier/verifier_test.go` with a parameterised test covering
`InitVerifier`:

- Case A: No credential configured with `CredentialStatus.Enabled = true` →
  `CredentialStatusValidationService` is still constructed (service is always
  appended), but validation is a no-op (cover via a dedicated test that runs
  `ValidateVC` with an empty `PerType`).
- Case B: At least one credential in static config has
  `CredentialStatus.Enabled = true` → `CredentialStatusValidationService`
  present and its `PerType` context contains the expected type.

Do not exercise the real HTTP client; verify only construction and context
assembly. No new network dependencies. Follow existing `TestInitVerifier`-style
setup if one exists, otherwise add it using the repo's `mockX` conventions.

**Files touched:** `verifier/verifier_test.go`.

**Acceptance:** `go test ./verifier/... -run TestInitVerifier -v` passes.

### Step 9: Documentation and sample config

- Update `README.md` with a short `### Credential revocation list` section:
  supported entry types, that configuration is **per credential type** under
  each service's scope/`credentials` entry, and the new shared knobs
  (`statusListCacheExpiry`, `statusListHttpTimeout`) on `verifier:`.
- Add a commented-out example `credentialStatus:` block inside a credential
  entry in the existing example service config (not under `verifier:`) so
  operators can discover the feature.
- Update `CLAUDE.md`: add `credential_status.go`, `credential_status_client.go`,
  and `common/credential_status.go` to the "Package Responsibilities" list so
  future agents know where the logic lives.

**Files touched:** `README.md`, example config (under `config/data/` or the
existing sample YAML), `CLAUDE.md`.

**Acceptance:** Documentation is accurate with respect to the shipped
configuration keys and the new files exist at the paths listed.

### Step 10: Final verification

Run the full test suite and a build to confirm nothing regressed:

```bash
go build -o VCVerifier .
go test ./... -v -coverprofile=profile.cov
```

Fix any regressions before closing the ticket. No functional code changes in
this step — it is a guardrail.

**Acceptance:** Clean build and all tests green.
