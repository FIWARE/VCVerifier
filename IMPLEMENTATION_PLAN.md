# Implementation Plan: VCVerifier support for TIR v5

## Overview

Extend VCVerifier to support EBSI Trusted Issuers Registry (TIR) v5 API alongside existing v3/v4 support. The v5 API returns attribute references (URLs) instead of inline attributes, requiring multi-step fetching (get issuer, list attributes with pagination, fetch each attribute). Configuration is extended with a `type` parameter on `TrustedIssuersLists` (mirroring the existing `TrustedParticipantsList` pattern): type `"ebsi"` selects v3/v4 auto-detection (default, backward-compatible), type `"ebsi-v5"` selects the v5 flow.

## Steps

### Step 1: Extend TrustedIssuersLists config type from []string to structured type

**Goal:** Change `TrustedIssuersLists` from a plain `[]string` (URL-only) to a structured type with `Type` + `Url` fields, mirroring the existing `TrustedParticipantsList`/`TrustedParticipantsLists` pattern. All existing configs must continue to work unchanged (backward compatibility).

**Files to modify:**

- **`config/configClient.go`:**
  - Create `TrustedIssuersList` struct with `Type string` and `Url string` fields (JSON/mapstructure tags), analogous to `TrustedParticipantsList` (line 197).
  - Create `TrustedIssuersLists` type (slice of `TrustedIssuersList`) with a custom `UnmarshalJSON` method: try structured format first, fall back to plain string array (each string becomes `{Type: DEFAULT_LIST_TYPE, Url: url}`). This mirrors `TrustedParticipantsLists.UnmarshalJSON` (lines 204-232).
  - Update the `Credential` struct field `TrustedIssuersLists` from `[]string` to `TrustedIssuersLists` (line 113).

- **`verifier/credentialsConfig.go`:**
  - Update `CredentialsConfig` interface: change `GetTrustedIssuersLists` return type from `[]string` to `[]config.TrustedIssuersList` (line 51).
  - Update `cacheBasedCredentialsConfig.GetTrustedIssuersLists` implementation to return `[]config.TrustedIssuersList` (lines 287-299).

- **`verifier/verifier.go`:**
  - Update `TrustRegistriesValidationContext.trustedIssuersLists` field type from `map[string][]string` to `map[string][]configModel.TrustedIssuersList` (line 194).
  - Update `GetTrustedIssuersLists()` return type accordingly (line 198).
  - Update `getTrustRegistriesValidationContext` and `getTrustRegistriesValidationContextFromScope` to use the new type (lines 1125, 1139, 1142, 1189, 1217, 1220).

- **`verifier/trustedissuer.go`:**
  - Update `ValidateVC` to work with `[]TrustedIssuersList` instead of `[]string`. For backward compatibility in this step, extract URLs from entries where `Type == "ebsi"` (or empty/default) and pass them to the existing `tirClient.GetTrustedIssuer`. The `isWildcardTil` helper must be updated to check `Url` field instead of raw strings.
  - Update `isWildcardTil` signature from `[]string` to `[]config.TrustedIssuersList`.

- **`database/models.go`:**
  - Update `CredentialDB.VO()` to construct `config.TrustedIssuersList{Type: listType, Url: endpoint}` entries instead of plain strings for `TrustedIssuers` endpoints (lines 286-287). Pass through `ListType` from `EndpointEntry`.
  - Update `CredentialDB.FromVO()` to read `Type` and `Url` from `TrustedIssuersList` entries when building `EndpointEntry` values (lines 315-320).

**Tests to add/update:**

- **`config/configClient_test.go`:** Add tests for `TrustedIssuersLists` custom `UnmarshalJSON`: structured format, plain string array fallback, mixed validation.
- **`verifier/trustedissuer_test.go`:** Update `getVerificationContext()`, `getWildcardVerificationContext()`, `getInvalidMixedVerificationContext()`, and `getWildcardAndNormalVerificationContext()` helpers to construct `TrustedIssuersList` values instead of raw strings.
- **`verifier/trustedparticipant_test.go`:** Update any test helpers that construct `TrustRegistriesValidationContext` with `trustedIssuersLists`.
- **`database/models_test.go`:** Update round-trip tests for `CredentialDB.VO()`/`FromVO()` to verify `TrustedIssuersList` type and URL are preserved.

**Acceptance criteria:**
- All existing YAML/JSON configs with `trustedIssuersLists: ["https://..."]` continue to work (parsed as `[{type: "ebsi", url: "https://..."}]`).
- New structured format `trustedIssuersLists: [{type: "ebsi-v5", url: "https://..."}]` is accepted.
- All existing tests pass (with updated test helpers).
- `go build ./...` succeeds with no compilation errors.

---

### Step 2: Implement TIR v5 client methods in tir/tirClient.go

**Goal:** Add v5 API support to the TIR HTTP client. The v5 API differs from v3/v4: `GET /v5/issuers/{did}` returns `{did, attributes: "<url>", hasAttributes: true/false}` (attributes is a URL reference, not inline). Fetching attributes requires: `GET /v5/issuers/{did}/attributes` (paginated list of attribute IDs/hrefs) then `GET /v5/issuers/{did}/attributes/{id}` (individual attribute with the same `hash`/`body`/`issuerType`/`tao`/`rootTao` fields as v3/v4). The final result must be assembled into the existing `TrustedIssuer` struct for downstream compatibility.

**Files to modify:**

- **`tir/tirClient.go`:**
  - Add path constant `ISSUERS_V5_PATH = "v5/issuers"`.
  - Add v5-specific response structs:
    - `TrustedIssuerV5Response` — `{Did string, Attributes string, HasAttributes bool}` (the `Attributes` field is a URL).
    - `AttributesListV5Response` — paginated list: `{Items []AttributeListItem, Links PaginationLinks, Total int, PageSize int, Self string}`.
    - `AttributeListItem` — `{ID string, Href string}`.
    - `PaginationLinks` — `{First, Last, Next, Prev string}`.
    - `AttributeV5Response` — single attribute: `{Attribute IssuerAttribute, Did string}`.
  - Add `getIssuerV5Url(did string) string` helper returning `ISSUERS_V5_PATH + "/" + did`.
  - Add `getAttributesV5Url(did string) string` helper returning `ISSUERS_V5_PATH + "/" + did + "/attributes"`.
  - Extend the `TirClient` interface with two new methods:
    - `IsTrustedParticipantV5(tirEndpoint string, did string) bool` — calls `GET /v5/issuers/{did}`, returns true if 200.
    - `GetTrustedIssuerV5(tirEndpoints []string, did string) (bool, TrustedIssuer, error)` — for each endpoint: (1) `GET /v5/issuers/{did}`, (2) if `hasAttributes`, follow pagination on the attributes URL to collect all attribute IDs, (3) fetch each attribute individually, (4) assemble into `TrustedIssuer{Did, Attributes}`. Cache the assembled result in `tirCache`/`tilCache`.
  - Implement pagination loop for `AttributesListV5Response`: follow `Links.Next` until empty or equal to current page.
  - Reuse existing `HttpGetClient` interface for all HTTP calls.

**Tests to add:**

- **`tir/tirClient_test.go`:**
  - Add table-driven tests for `IsTrustedParticipantV5`: mock HTTP responses for 200 (found), 404 (not found), network error.
  - Add table-driven tests for `GetTrustedIssuerV5`: mock multi-step flow (issuer response → attributes list → individual attributes), verify assembled `TrustedIssuer` matches expected. Include cases for: single attribute, multiple attributes, pagination (multiple pages), issuer with `hasAttributes: false`, issuer not found (404), attribute fetch error (partial failure).
  - Test caching behavior: second call for same DID should hit cache.

**Acceptance criteria:**
- `TirClient` interface has `IsTrustedParticipantV5` and `GetTrustedIssuerV5` methods.
- V5 multi-step attribute fetching correctly assembles a `TrustedIssuer` with all attributes.
- Pagination is handled (follows `next` links).
- Results are cached using existing `tirCache`/`tilCache`.
- All new and existing tests pass.

---

### Step 3: Wire v5 dispatch in verifier layer (trustedissuer.go and trustedparticipant.go)

**Goal:** Route "ebsi-v5" typed entries to the new v5 TIR client methods. The existing "ebsi" type continues to use v3/v4 auto-detection. The dispatch pattern follows the existing `trustedparticipant.go` model (type-based `if` checks).

**Files to modify:**

- **`verifier/trustedparticipant.go`:**
  - Add constant `typeEbsiV5 = "ebsi-v5"` alongside existing `typeGaiaX` and `typeEbsi` (line 17).
  - In `ValidateVC`, add a new dispatch branch: `if participantList.Type == typeEbsiV5` calls `tpvs.tirClient.IsTrustedParticipantV5(participantList.Url, ...)` (after line 57).

- **`verifier/trustedissuer.go`:**
  - Add constant `typeEbsiV5 = "ebsi-v5"` and `typeEbsi = "ebsi"`.
  - Refactor `ValidateVC` to dispatch based on `TrustedIssuersList.Type`:
    - For entries with type `"ebsi"` (or empty/default): collect URLs into a `[]string` slice and call `tpvs.tirClient.GetTrustedIssuer(urls, did)` (preserving existing v3/v4 behavior).
    - For entries with type `"ebsi-v5"`: collect URLs into a `[]string` slice and call `tpvs.tirClient.GetTrustedIssuerV5(urls, did)`.
    - The wildcard check (`isWildcardTil`) should apply across all entries regardless of type.
  - Ensure that if a credential type has a mix of "ebsi" and "ebsi-v5" entries, both are tried (ebsi entries via v3/v4, ebsi-v5 entries via v5), and the first successful match wins.

**Tests to add/update:**

- **`verifier/trustedparticipant_test.go`:**
  - Add test cases for "ebsi-v5" type: participant found via v5, participant not found via v5, mixed ebsi + ebsi-v5 lists.
  - Update mock `TirClient` to implement `IsTrustedParticipantV5`.

- **`verifier/trustedissuer_test.go`:**
  - Add test cases for "ebsi-v5" type: issuer found via v5, issuer not found via v5.
  - Add test case for mixed types: one "ebsi" entry and one "ebsi-v5" entry for the same credential type.
  - Update mock `TirClient` to implement `GetTrustedIssuerV5`.
  - Update existing test helper functions to use `TrustedIssuersList` struct with explicit `Type: "ebsi"`.

**Acceptance criteria:**
- "ebsi-v5" type in `TrustedParticipantsList` routes to `IsTrustedParticipantV5`.
- "ebsi-v5" type in `TrustedIssuersLists` routes to `GetTrustedIssuerV5`.
- "ebsi" (and empty/default) type continues to use v3/v4 auto-detection.
- Mixed type lists work correctly.
- All tests pass.

---

### Step 4: End-to-end verification, test fixtures, and documentation

**Goal:** Add integration-level test scenarios covering the complete flow from config parsing through TIR v5 verification. Update test fixture files and config examples. Ensure all tests pass and the build is clean.

**Files to modify/add:**

- **`config/data/`:** Add or update YAML/JSON test fixtures:
  - A fixture with `trustedIssuersLists` in the new structured format (type "ebsi-v5").
  - A fixture with mixed old-format (string array) and new-format entries to verify backward compatibility.
  - A fixture with `trustedParticipantsLists` including "ebsi-v5" type entry.

- **`verifier/verifier_test.go`:**
  - Add or update integration-level tests that exercise the full `AuthenticationResponse` or `GenerateToken` flow with "ebsi-v5" configured trust registries (using mocked TIR client).
  - Verify that `getTrustRegistriesValidationContext` correctly propagates type information from config through to the validation context.

- **`database/models_test.go`:**
  - Add round-trip tests for `CredentialDB` with "ebsi-v5" typed trusted issuers lists: `FromVO()` → `VO()` preserves type and URL.

- **`config/configClient_test.go`:**
  - Add test for `ReadConfig()` / config parsing with the new structured `trustedIssuersLists` format in YAML.
  - Verify that YAML `trustedIssuersLists: ["https://url"]` still parses correctly (backward compat via mapstructure).

**Verification steps:**
- Run `go build ./...` — must succeed with no errors.
- Run `go vet ./...` — must succeed with no warnings.
- Run `go test ./... -v` — all tests must pass.
- Run `go test ./... -v -coverprofile=profile.cov` to verify coverage of new code paths.

**Acceptance criteria:**
- All new and existing tests pass.
- Config backward compatibility is verified by tests (old `[]string` format, new structured format, database round-trip).
- The full verification chain works end-to-end with "ebsi-v5" configuration.
- No compilation warnings or vet issues.
