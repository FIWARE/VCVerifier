# Implementation Plan: The VCVerifier should support W3C Verifiable Credentials 2.0

## Overview

The VCVerifier currently supports only the W3C VC Data Model 1.1 (`https://www.w3.org/2018/credentials/v1`). This plan adds support for VC Data Model 2.0 (`https://www.w3.org/ns/credentials/v2`) so the verifier can accept **incoming** credentials in either format. A new configuration option (`vcDataModelVersions`) will allow operators to restrict which version(s) are accepted. The work is scoped to version detection, context vendoring, configuration, validation of incoming credentials, and status list type handling — Data Integrity Proof suites beyond `JsonWebSignature2020` remain out of scope (documented known gap). M2M token provider changes are explicitly out of scope: VC 2.0 support is only for incoming credential verification, not for credentials/presentations the verifier itself produces.

## Steps

### Step 1: Vendor the W3C VC Data Model 2.0 JSON-LD context and register it in the embedded loader

**What:** Download the official W3C Credentials V2 JSON-LD context and vendor it alongside the existing V1 context.

**Files affected:**
- `common/contexts/credentials-v2.jsonld` — **new file**: the vendored W3C VC Data Model 2.0 context document (fetched from `https://www.w3.org/ns/credentials/v2`).
- `common/embedded_context_loader.go` — Add a `contextFileW3CVCV2` constant and register the mapping `ContextCredentialsV2 → contextFileW3CVCV2` in `embeddedContextFiles`.
- `common/embedded_context_loader_test.go` — Add tests verifying the V2 context is served by `EmbeddedContextLoader` and that unknown URLs still delegate to the fallback.

**Acceptance criteria:**
- `NewEmbeddedContextLoader` serves documents for both `ContextCredentialsV1` and `ContextCredentialsV2`.
- The vendored V2 context file parses as valid JSON.
- Existing V1 context behavior is unchanged.
- Tests pass: `go test ./common/... -v -run TestEmbedded`.

### Step 2: Add VC Data Model version detection and the `vcDataModelVersions` configuration option

**What:** Introduce a utility to detect which VC Data Model version a credential or presentation uses (based on its `@context` array), a new config field to control which versions the verifier accepts, and startup validation for that field.

**Files affected:**
- `common/credential.go` — Add a `DetectVCDataModelVersion(contexts []string) []string` function that returns a slice of detected versions (`"1.1"`, `"2.0"`, or both) based on which context URLs (`ContextCredentialsV1`, `ContextCredentialsV2`) appear in the context array. Returns an empty slice when no recognized context is found. Add constants `VCDataModelVersion11 = "1.1"` and `VCDataModelVersion20 = "2.0"`. Add a `VCDataModelVersionAll` slice containing both.
- `common/credential_test.go` — Add table-driven tests for `DetectVCDataModelVersion` covering: V1-only context (returns `["1.1"]`), V2-only context (returns `["2.0"]`), both contexts present (returns `["1.1", "2.0"]`), no recognized context (returns `[]`), empty context slice (returns `[]`).
- `config/config.go` — Add `VCDataModelVersions []string` field to the `Verifier` struct with `mapstructure:"vcDataModelVersions"` tag and a default of `["1.1", "2.0"]` (accept both).
- `verifier/verifier.go` (`verifyConfig`) — Validate that `VCDataModelVersions` contains only recognized values (`"1.1"`, `"2.0"`). Return a new `ErrorUnsupportedVCDataModelVersion` error if not. If the slice is empty after config loading, default to both versions.
- `verifier/verifier_test.go` — Extend `TestVerifyConfig` table to cover valid and invalid `vcDataModelVersions` values.
- `config/data/config_test.yaml` (and/or a new `config/data/config_test_vc_versions.yaml`) — Add test fixture YAML with the new field.

**Acceptance criteria:**
- `DetectVCDataModelVersion` correctly identifies V1, V2, both, and unknown (returns appropriate slice for each case).
- Config parsing reads `vcDataModelVersions` from YAML.
- `verifyConfig` rejects invalid version strings.
- Default (empty/unset) means both versions are accepted.
- Tests pass: `go test ./common/... ./config/... ./verifier/... -v`.

### Step 3: Enforce VC Data Model version filtering in credential validation

**What:** Wire the version-detection logic into the credential validation pipeline so credentials whose VC Data Model version is not in the configured `vcDataModelVersions` list are rejected. This applies across all grant types and credential formats (JWT-VC, JSON-LD VP, SD-JWT).

**Files affected:**
- `verifier/jwt_verifier.go` — Add a `vcDataModelVersions []string` field to `CredentialValidator`. In `ValidateVC`, place the version check **first** (before date validation and mode-specific validation) as a cheap, config-driven gate that fails fast. Call `DetectVCDataModelVersion` on the credential's `Context` field and reject with a new `ErrorVCDataModelVersionNotAccepted` error if none of the detected versions are in the configured list. If no recognized context URL is found (empty detected versions), always reject — the `vcDataModelVersions` check is orthogonal to `validationMode` and applies regardless of the validation mode setting.
- `verifier/verifier.go` — Pass `config.Verifier.VCDataModelVersions` to the `CredentialValidator` constructor (line ~352).
- `verifier/jwt_verifier_test.go` — Add tests for:
  - V1 credential accepted when config allows `["1.1"]`.
  - V2 credential accepted when config allows `["2.0"]`.
  - V1 credential rejected when config allows only `["2.0"]`.
  - V2 credential rejected when config allows only `["1.1"]`.
  - Both accepted when config allows `["1.1", "2.0"]`.
  - Unknown context (no recognized context URL) always rejected regardless of validation mode.

**Acceptance criteria:**
- Credentials with V1 context pass when `"1.1"` is in `vcDataModelVersions`.
- Credentials with V2 context pass when `"2.0"` is in `vcDataModelVersions`.
- Credentials whose version is not in the list are rejected with `ErrorVCDataModelVersionNotAccepted`.
- Existing tests continue to pass (they use V1 credentials with the default config allowing both).
- Tests pass: `go test ./verifier/... -v`.

### Step 4: Handle VC 2.0 status list types (`BitstringStatusListEntry`)

**What:** The W3C VC Data Model 2.0 introduces `BitstringStatusListEntry` as the successor to V1's `StatusList2021Entry` for credential revocation/suspension status. Update the status list handling to recognize and process `BitstringStatusListEntry` in addition to the existing `StatusList2021Entry` type, so incoming V2 credentials with status information can be verified.

**Files affected:**
- `verifier/credential_status_client.go` — Add support for `BitstringStatusListEntry` type alongside the existing `StatusList2021Entry`. Both types share the same fundamental structure (statusListIndex, statusListCredential, statusPurpose) but with updated field names per the V2 spec. Add a constant for the new type name.
- `verifier/credential_status_client_test.go` — Add tests verifying that `BitstringStatusListEntry` is recognized and processed correctly, including: valid V2 status entry, mixed V1/V2 status entries in a credential, and rejection of unknown status entry types.
- `common/credential.go` — Add a `CredentialStatusTypeBitstringStatusList` constant if not already present.

**Acceptance criteria:**
- `BitstringStatusListEntry` credentials are processed correctly for revocation/suspension checks.
- Existing `StatusList2021Entry` behavior is unchanged.
- Unknown status entry types are still rejected.
- Tests pass: `go test ./verifier/... -v`.

**Note:** M2M token provider changes are explicitly out of scope. VC 2.0 support applies only to incoming credential verification. The M2M flow (`tir/tokenProvider.go`) continues to produce V1 presentations — the presentation's `Context` defaults to V1 and the credential's context does not propagate automatically to the wrapping presentation. If V2 M2M presentations are needed in the future, a `WithContext` option could be added to `NewPresentation`, but that is not part of this plan.

### Step 5: End-to-end integration tests, documentation, and config example updates

**What:** Add integration-level tests that exercise the full credential verification flow with VC 2.0 credentials, update documentation, example config, and OpenAPI spec to reflect the new option.

**Files affected:**
- `verifier/verifier_test.go` — Add integration-style tests that:
  - Submit a VC 2.0 JSON-LD credential through the verification pipeline and confirm it passes with `vcDataModelVersions: ["2.0"]`.
  - Submit a VC 1.1 credential and confirm it is rejected with `vcDataModelVersions: ["2.0"]`.
  - Submit a VC 2.0 credential and confirm it is rejected with `vcDataModelVersions: ["1.1"]`.
  - Submit both V1 and V2 credentials with `vcDataModelVersions: ["1.1", "2.0"]` and confirm both pass.
- `server.yaml` — Add a commented-out example of the `vcDataModelVersions` field under `verifier:` with documentation explaining the accepted values and default behavior.
- `api/api.yaml` — Update the OpenAPI spec examples that currently hardcode V1 context URLs (lines ~489, ~518) to document V2 as an alternative format. Add example payloads showing V2 context where appropriate.
- `CLAUDE.md` — Update the "Configuration" and "Known Gaps" sections to document the new `vcDataModelVersions` config option and the VC 2.0 support.

**Acceptance criteria:**
- All new integration tests pass with both V1 and V2 credentials.
- `server.yaml` example is accurate and well-documented.
- OpenAPI spec examples reflect both V1 and V2 credential formats.
- `CLAUDE.md` accurately reflects the new capability.
- Full test suite passes: `go test ./... -v`.
