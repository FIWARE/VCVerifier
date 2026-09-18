# Implementation Plan: The VCVerifier should support W3C Verifiable Credentials 2.0

## Overview

The VCVerifier currently supports only the W3C VC Data Model 1.1 (`https://www.w3.org/2018/credentials/v1`). This plan adds support for VC Data Model 2.0 (`https://www.w3.org/ns/credentials/v2`) so the verifier can accept credentials in either format. A new configuration option (`vcDataModelVersions`) will allow operators to restrict which version(s) are accepted. The work is scoped to version detection, context vendoring, configuration, and validation — Data Integrity Proof suites beyond `JsonWebSignature2020` remain out of scope (documented known gap).

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
- `common/credential.go` — Add a `DetectVCDataModelVersion(contexts []string) string` function that returns `"1.1"`, `"2.0"`, or `"unknown"` based on whether `ContextCredentialsV1` or `ContextCredentialsV2` appears in the context array. Add constants `VCDataModelVersion11 = "1.1"` and `VCDataModelVersion20 = "2.0"`. Add a `VCDataModelVersionAll` slice containing both.
- `common/credential_test.go` — Add table-driven tests for `DetectVCDataModelVersion` covering: V1-only context, V2-only context, both contexts present (should return V2 as it is the more specific), no recognized context, empty context slice.
- `config/config.go` — Add `VCDataModelVersions []string` field to the `Verifier` struct with `mapstructure:"vcDataModelVersions"` tag and a default of `["1.1", "2.0"]` (accept both).
- `verifier/verifier.go` (`verifyConfig`) — Validate that `VCDataModelVersions` contains only recognized values (`"1.1"`, `"2.0"`). Return a new `ErrorUnsupportedVCDataModelVersion` error if not. If the slice is empty after config loading, default to both versions.
- `verifier/verifier_test.go` — Extend `TestVerifyConfig` table to cover valid and invalid `vcDataModelVersions` values.
- `config/data/config_test.yaml` (and/or a new `config/data/config_test_vc_versions.yaml`) — Add test fixture YAML with the new field.

**Acceptance criteria:**
- `DetectVCDataModelVersion` correctly identifies V1, V2, both, and unknown.
- Config parsing reads `vcDataModelVersions` from YAML.
- `verifyConfig` rejects invalid version strings.
- Default (empty/unset) means both versions are accepted.
- Tests pass: `go test ./common/... ./config/... ./verifier/... -v`.

### Step 3: Enforce VC Data Model version filtering in credential validation

**What:** Wire the version-detection logic into the credential validation pipeline so credentials whose VC Data Model version is not in the configured `vcDataModelVersions` list are rejected. This applies across all grant types and credential formats (JWT-VC, JSON-LD VP, SD-JWT).

**Files affected:**
- `verifier/jwt_verifier.go` — Add a `vcDataModelVersions []string` field to `CredentialValidator`. In `ValidateVC`, after date validation and before mode-specific validation, call `DetectVCDataModelVersion` on the credential's `Context` field and reject with a new `ErrorVCDataModelVersionNotAccepted` error if the detected version is not in the configured list. If the version is `"unknown"` (no recognized context URL), reject unless the validation mode is `"none"`.
- `verifier/verifier.go` — Pass `config.Verifier.VCDataModelVersions` to the `CredentialValidator` constructor (line ~352).
- `verifier/jwt_verifier_test.go` — Add tests for:
  - V1 credential accepted when config allows `["1.1"]`.
  - V2 credential accepted when config allows `["2.0"]`.
  - V1 credential rejected when config allows only `["2.0"]`.
  - V2 credential rejected when config allows only `["1.1"]`.
  - Both accepted when config allows `["1.1", "2.0"]`.
  - Unknown context handling per validation mode.

**Acceptance criteria:**
- Credentials with V1 context pass when `"1.1"` is in `vcDataModelVersions`.
- Credentials with V2 context pass when `"2.0"` is in `vcDataModelVersions`.
- Credentials whose version is not in the list are rejected with `ErrorVCDataModelVersionNotAccepted`.
- Existing tests continue to pass (they use V1 credentials with the default config allowing both).
- Tests pass: `go test ./verifier/... -v`.

### Step 4: Update Presentation marshaling and M2M token provider for VC 2.0 context support

**What:** Update `Presentation.MarshalJSON` so it no longer hardcodes the V1 context as its fallback — instead, it should use whatever context is set on the presentation. Update the M2M token provider's VP construction to set the context explicitly so it works correctly regardless of the verifier's own credential version.

**Files affected:**
- `common/credential.go` (`MarshalJSON`) — Keep the fallback to `ContextCredentialsV1` when `Context` is empty (backward compatibility), but add a `WithContext(ctx ...string) PresentationOpt` option so callers can explicitly set a V2 context when constructing a presentation.
- `common/credential_test.go` — Test `MarshalJSON` with: empty context (defaults to V1), explicit V1 context, explicit V2 context, mixed contexts.
- `tir/tokenProvider.go` (`signVerifiablePresentation`) — No change needed if the credential being wrapped already carries a V2 context, because `MarshalJSON` will use the presentation's `Context` if set. Document this behavior with a code comment. If the M2M flow needs to produce V2 presentations in the future, `WithContext` is available.
- `common/credential_test.go` — Test `NewPresentation` with `WithContext(ContextCredentialsV2)` produces a presentation that marshals with the V2 context URL.

**Acceptance criteria:**
- `WithContext` option works and is used in `MarshalJSON`.
- Default behavior (empty context) still produces V1 context for backward compatibility.
- M2M token provider still produces valid signed presentations.
- Tests pass: `go test ./common/... ./tir/... -v`.

### Step 5: End-to-end integration tests, documentation, and config example updates

**What:** Add integration-level tests that exercise the full credential verification flow with VC 2.0 credentials, update documentation and example config to reflect the new option.

**Files affected:**
- `verifier/verifier_test.go` — Add integration-style tests that:
  - Submit a VC 2.0 JSON-LD credential through the verification pipeline and confirm it passes with `vcDataModelVersions: ["2.0"]`.
  - Submit a VC 1.1 credential and confirm it is rejected with `vcDataModelVersions: ["2.0"]`.
  - Submit a VC 2.0 credential and confirm it is rejected with `vcDataModelVersions: ["1.1"]`.
  - Submit both V1 and V2 credentials with `vcDataModelVersions: ["1.1", "2.0"]` and confirm both pass.
- `server.yaml` — Add a commented-out example of the `vcDataModelVersions` field under `verifier:` with documentation explaining the accepted values and default behavior.
- `CLAUDE.md` — Update the "Configuration" and "Known Gaps" sections to document the new `vcDataModelVersions` config option and the VC 2.0 support.

**Acceptance criteria:**
- All new integration tests pass with both V1 and V2 credentials.
- `server.yaml` example is accurate and well-documented.
- `CLAUDE.md` accurately reflects the new capability.
- Full test suite passes: `go test ./... -v`.
