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
(enable/disable, cache expiry, accepted status purposes), and is covered by
table-driven unit tests following the existing repository patterns.

## Steps

### Step 1: Add configuration for the revocation list feature

Extend `config/config.go` to expose configuration for credential-status checking:

- Add a new struct `CredentialStatus` with these `mapstructure` fields:
  - `Enabled bool` (default `false`) — master switch; when `false` the verifier
    behaves exactly as today.
  - `CacheExpiry int` (seconds, default `300`) — TTL for the status-list credential
    cache.
  - `AcceptedPurposes []string` (default `["revocation"]`) — status purposes
    (`revocation`, `suspension`, ...) the verifier enforces; entries with an
    unrecognized purpose are ignored when this list does not contain the purpose.
  - `RequireStatus bool` (default `false`) — when `true`, credentials missing a
    `credentialStatus` entry are rejected.
  - `HttpTimeout int` (seconds, default `10`) — timeout for fetching the
    status-list credential.
- Add a field `CredentialStatus CredentialStatus \`mapstructure:"credentialStatus"\``
  on the existing `Verifier` struct.
- Document every new field using GoDoc comments (per repo convention — see
  `Verifier` fields in the same file).
- No magic constants: introduce named constants for the defaults
  (`DefaultStatusCacheExpirySeconds`, `DefaultStatusHttpTimeoutSeconds`,
  `StatusPurposeRevocation`, `StatusPurposeSuspension`).

**Files touched:** `config/config.go`.

**Acceptance:** `go build ./...` succeeds; existing `config/configClient_test.go`
still passes; a unit test asserts that an empty YAML produces the documented
defaults when the section is omitted.

### Step 2: Define the status-list credential data model

Create a small, self-contained data-model file that describes a fetched
status-list credential and its entries, independent of the verifier package:

- New file `common/credential_status.go` containing:
  - Constants for the supported type names:
    `TypeBitstringStatusListEntry = "BitstringStatusListEntry"`,
    `TypeBitstringStatusListCredential = "BitstringStatusListCredential"`,
    `TypeStatusList2021Entry = "StatusList2021Entry"`,
    `TypeStatusList2021Credential = "StatusList2021Credential"`.
  - Named field-key constants (`StatusListKeyEncodedList`,
    `StatusListKeyStatusPurpose`, `StatusListEntryKeyStatusListIndex`,
    `StatusListEntryKeyStatusListCredential`, `StatusListEntryKeyStatusPurpose`,
    `StatusListEntryKeyStatusSize` — default `1`).
  - `type StatusListEntry struct { ID, Type, StatusPurpose, StatusListCredential string; StatusListIndex uint64; StatusSize int }`.
  - `type StatusListCredential struct { EncodedList, StatusPurpose string }` (decoded
    form; the bitstring itself is kept as a `[]byte` after gzip + base64url
    decoding).
  - A helper `ParseStatusListEntry(raw map[string]interface{}) (*StatusListEntry, error)`
    that reads the nested `credentialStatus` object (supporting both a single
    object and an array form per the W3C VC 2.0 spec).
  - A helper `DecodeBitstring(encoded string) ([]byte, error)` that base64url-decodes
    then gzip-inflates, returning the raw bitstring.
  - A helper `IsStatusSet(bitstring []byte, index uint64, statusSize int) (bool, error)`
    that returns the bit value at the given index, bounds-checked.

- All helpers have GoDoc comments. No magic numbers: introduce
  `DefaultStatusSizeBits = 1`, `BitsPerByte = 8`.

**Files touched:** `common/credential_status.go` (new),
`common/credential_status_test.go` (new).

**Acceptance:** Table-driven unit tests cover:
  - Parsing single-object and array `credentialStatus` fields.
  - Missing / malformed entries return a typed error.
  - `DecodeBitstring` round-trips a known RFC 8949 test vector.
  - `IsStatusSet` correctly returns true/false for the first, a middle, and the
    last index of a small bitstring, and errors on out-of-range indices.

### Step 3: Build a cached status-list credential fetcher

Introduce a client responsible for fetching and caching status-list credentials:

- New file `verifier/credential_status_client.go`:
  - `type StatusListCredentialClient interface { Fetch(url string) (*common.Credential, error) }`.
  - `type CachingStatusListClient struct { httpClient *http.Client; cache common.Cache }`
    implementing the interface, using `patrickmn/go-cache` just like
    `caching_client.go`.
  - Constructor `NewCachingStatusListClient(timeout time.Duration, cacheExpiry time.Duration) *CachingStatusListClient`
    reusing `common.DiskFileAccessor` only where needed (network path only here).
  - `Fetch` performs a GET, parses the response body using the existing VC parser
    (`common.ParseCredential` if available, otherwise the path used by
    `presentation_parser.go`). The parsed `*common.Credential` is cached by URL.
  - All public symbols carry GoDoc comments. Named constants for the default
    `Accept` header (`ContentTypeCredentialJson = "application/vc+ld+json"`) and
    for the cache cleanup multiplier (reusing `2×expiry` pattern from existing
    code).

**Files touched:** `verifier/credential_status_client.go` (new),
`verifier/credential_status_client_test.go` (new).

**Acceptance:** Tests use `httptest.NewServer` to serve a static status-list
credential. Parameterized cases cover: cache hit, cache miss triggers fetch,
HTTP error is propagated, unparsable JSON returns a typed error. Run
`go test ./verifier/... -run TestCachingStatusListClient -v`.

### Step 4: Implement the `CredentialStatusValidationService`

Add the validation service that ties the data model and client together, matching
the `ValidationService` interface used by the rest of the verifier:

- New file `verifier/credential_status.go`:
  - `type CredentialStatusValidationContext struct { AcceptedPurposes []string; RequireStatus bool }`.
  - `type CredentialStatusValidationService struct { client StatusListCredentialClient; clock common.Clock }`.
  - `func (s *CredentialStatusValidationService) ValidateVC(vc *common.Credential, ctx ValidationContext) (bool, error)`:
    1. Cast `ctx` to `CredentialStatusValidationContext`; on failure return
       `ErrorCannotConverContext` (re-use the existing error type).
    2. Read the credential's raw JSON and extract `credentialStatus` (may be
       missing, a single object, or an array).
    3. If missing: return `RequireStatus`-dependent result (`true` when not
       required, `false` + `ErrorStatusMissing` when required).
    4. For each entry:
       - Skip entries whose `statusPurpose` is not in `AcceptedPurposes`.
       - Only handle recognized types from Step 2; unknown types are logged
         and skipped (to stay forward-compatible).
       - Fetch the status-list credential via the client.
       - Decode the bitstring via `common.DecodeBitstring`.
       - Call `common.IsStatusSet`. If set, return `false, ErrorCredentialRevoked`.
    5. Return `true, nil` if no matching entry indicates revocation.
  - Typed errors: `ErrorCredentialRevoked`, `ErrorStatusMissing`,
    `ErrorStatusListUnparseable`, `ErrorStatusListPurposeMismatch` (exported
    `var ... = errors.New(...)` following the `verifier.go` convention).
  - All public types and functions documented.

**Files touched:** `verifier/credential_status.go` (new).

**Acceptance:** Compile succeeds; no test yet (tests follow in Step 6). The
service must satisfy the `ValidationService` interface — enforce this with a
compile-time assertion `var _ ValidationService = (*CredentialStatusValidationService)(nil)`.

### Step 5: Wire the service into `InitVerifier`

Thread the new service into the verifier initialisation:

- In `verifier/verifier.go` `InitVerifier`:
  - After the existing validation services are built (~line 322), if
    `verifierConfig.CredentialStatus.Enabled` is true, construct a
    `CachingStatusListClient` using the configured timeout and cache expiry, then
    a `CredentialStatusValidationService` wrapping it.
  - Append the new service to the `validationServices` slice passed to
    `CredentialVerifier`.
- In `GenerateToken` (~line 603) where the existing `for _, verificationService := range v.validationServices` loop runs, supply the
  `CredentialStatusValidationContext` for this service. Because each service
  currently receives the same `verificationContext`, introduce a lightweight
  per-service dispatch: extend the loop to pick the correct context by type,
  or (preferred, less invasive) have the service accept the existing
  `TrustRegistriesValidationContext` and read its own configuration from a
  struct field populated at construction time. Choose the second approach to
  avoid changing the `ValidationService` interface.

**Files touched:** `verifier/verifier.go`.

**Acceptance:** `go build ./...` succeeds. An existing test run
(`go test ./verifier/... -v`) still passes — the feature defaults to disabled, so
no legacy test should see a behavior change.

### Step 6: Unit tests for the validation service

Follow the `compliance_test.go` / `trustedissuer_test.go` pattern:

- New file `verifier/credential_status_test.go`:
  - `type mockStatusListClient struct { credentials map[string]*common.Credential; err error }` with a `Fetch` method.
  - `TestCredentialStatusValidationService_ValidateVC` — table-driven with the
    following cases:
    - Credential without `credentialStatus` and `RequireStatus=false` → valid.
    - Credential without `credentialStatus` and `RequireStatus=true` → error
      `ErrorStatusMissing`.
    - Revoked bit set at the credential's index → `false, ErrorCredentialRevoked`.
    - Revoked bit clear → `true, nil`.
    - Status purpose not in `AcceptedPurposes` → entry skipped, result `true`.
    - Fetch failure (`client.err != nil`) → error propagated.
    - Malformed bitstring → `ErrorStatusListUnparseable`.
    - Two status entries, first for `suspension`, second for `revocation` with
      bit set → `false, ErrorCredentialRevoked`.
  - Use in-line helpers to build `*common.Credential` values carrying raw
    `credentialStatus` objects, mirroring how `compliance_test.go` uses
    `common.CreateCredential` + `SetRawJSON`.

**Files touched:** `verifier/credential_status_test.go` (new).

**Acceptance:** `go test ./verifier/... -run TestCredentialStatusValidationService -v`
passes. Overall package coverage for the new files is ≥80 %.

### Step 7: Integration wiring test for `InitVerifier`

Extend `verifier/verifier_test.go` with a parameterised test covering
`InitVerifier` with and without the feature enabled:

- Case A: `CredentialStatus.Enabled = false` → existing number of validation
  services unchanged.
- Case B: `CredentialStatus.Enabled = true` → validation services slice has
  one additional entry of type `*CredentialStatusValidationService`.

Do not exercise the real HTTP client; verify only construction. No new network
dependencies. Follow existing `TestInitVerifier`-style setup if one exists,
otherwise add it using the repo's `mockX` conventions.

**Files touched:** `verifier/verifier_test.go`.

**Acceptance:** `go test ./verifier/... -run TestInitVerifier -v` passes.

### Step 8: Documentation and sample config

- Update `README.md` with a short `### Credential revocation list` section:
  supported entry types, the new config block, and the defaults.
- Add a commented-out `credentialStatus:` block under `verifier:` in
  `server.yaml` so operators can discover the feature.
- Update `CLAUDE.md`: add `credential_status.go`, `credential_status_client.go`,
  and `common/credential_status.go` to the "Package Responsibilities" list so
  future agents know where the logic lives.

**Files touched:** `README.md`, `server.yaml`, `CLAUDE.md`.

**Acceptance:** Documentation is accurate with respect to the shipped
configuration keys and the new files exist at the paths listed.

### Step 9: Final verification

Run the full test suite and a build to confirm nothing regressed:

```bash
go build -o VCVerifier .
go test ./... -v -coverprofile=profile.cov
```

Fix any regressions before closing the ticket. No functional code changes in
this step — it is a guardrail.

**Acceptance:** Clean build and all tests green.
