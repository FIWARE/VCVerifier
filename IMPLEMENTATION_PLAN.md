# Implementation Plan: Support HTTPS-based client identifiers in the vc-verifier

## Overview

Extend VCVerifier to support HTTPS-based credential issuer identifiers alongside the existing DID-based ones (did:key, did:web, did:jwk, did:elsi). When a credential's `iss` claim is an HTTPS URL (e.g. `https://issuer.example.com`) instead of a DID, the verifier will discover the issuer's public keys via `.well-known/jwt-vc-issuer` (per the SD-JWT VC spec / OpenID4VCI) or `.well-known/openid-credential-issuer` metadata endpoints, fetch the JWKS from the discovered `jwks_uri`, and use those keys for JWT signature verification. This follows the OAuth2.0/OIDC trust model as referenced in OpenID4VP 1.0.

## Steps

### Step 1: Implement HTTPS issuer metadata resolver

**Goal:** Create a new component that, given an HTTPS URL issuer identifier, fetches the issuer's metadata from well-known endpoints and resolves the signing key(s) via JWKS.

**Background:** Per the SD-JWT VC specification (Section 5, Issuer Metadata) and OpenID4VCI, an HTTPS-based issuer publishes its metadata at `<issuer-url>/.well-known/jwt-vc-issuer` (primary) or `<issuer-url>/.well-known/openid-credential-issuer` (fallback). The metadata document contains a `jwks_uri` field (or inline `jwks`). The JWKS endpoint returns a standard JSON Web Key Set. RFC 8414 (OAuth 2.0 Authorization Server Metadata) uses `<issuer-url>/.well-known/oauth-authorization-server` but the SD-JWT VC / OID4VCI well-known paths are the primary target for credential issuers.

**Files to create/modify:**

- **`verifier/https_issuer_resolver.go`** (new file):
  - Define an `HttpsIssuerResolver` interface with method:
    - `ResolveIssuerKey(issuerURL string, kid string) (jwk.Key, error)` — fetches metadata, resolves JWKS, finds the key matching `kid`.
  - Define an `IssuerMetadata` struct to represent the metadata response (fields: `Issuer string`, `JwksUri string`, `Jwks *jwk.Set` for inline keys).
  - Implement `CachingHttpsIssuerResolver` struct with:
    - An HTTP client (`*http.Client`) for fetching metadata and JWKS.
    - A `common.Cache` for caching resolved JWKS keyset per issuer URL (to avoid repeated HTTP calls).
    - A configurable cache TTL.
  - Implement the resolution flow:
    1. Check if JWKS for this issuer URL is already cached; if so, look up the key by `kid`.
    2. Otherwise, try fetching `<issuerURL>/.well-known/jwt-vc-issuer`. If that returns 404, try `<issuerURL>/.well-known/openid-credential-issuer`. If both fail, return an error.
    3. Parse the metadata JSON, extract `jwks_uri` (or inline `jwks`).
    4. If `jwks_uri` is present, fetch the JWKS from that URL.
    5. Parse the JWKS, cache the keyset, and find the key matching `kid`.
    6. If no `kid` is provided, return the first key in the set (single-key issuers).
  - Define named constants for well-known paths:
    - `WellKnownJwtVcIssuer = "/.well-known/jwt-vc-issuer"`
    - `WellKnownOIDCCredentialIssuer = "/.well-known/openid-credential-issuer"`
  - Define error sentinels:
    - `ErrorIssuerMetadataNotFound` — neither well-known endpoint returned valid metadata.
    - `ErrorIssuerJwksNotFound` — metadata has no `jwks_uri` and no inline `jwks`.
    - `ErrorIssuerKeyNotFound` — JWKS did not contain a key matching the requested `kid`.
    - `ErrorIssuerMismatch` — the `issuer` field in the metadata does not match the expected issuer URL.
  - Validate that the `issuer` field in the metadata matches the expected issuer URL (security check per RFC 8414 Section 3.3).

- **`verifier/https_issuer_resolver_test.go`** (new file):
  - Table-driven tests using `httptest.Server` to mock the metadata and JWKS endpoints:
    - Successful resolution via `.well-known/jwt-vc-issuer` with `jwks_uri`.
    - Fallback to `.well-known/openid-credential-issuer` when first endpoint returns 404.
    - Inline `jwks` in metadata (no `jwks_uri`).
    - Key lookup by `kid` in a multi-key JWKS.
    - Default to first key when no `kid` is provided.
    - Caching: second call should not make HTTP requests.
    - Error cases: metadata not found (both endpoints 404), JWKS fetch failure, no matching key, issuer mismatch.

**Acceptance criteria:**
- `HttpsIssuerResolver` correctly fetches metadata from well-known endpoints and resolves signing keys from JWKS.
- Caching prevents redundant HTTP requests.
- All error cases are handled with descriptive errors.
- All tests pass.

---

### Step 2: Integrate HTTPS issuer key resolution into JWTProofChecker

**Goal:** Modify the JWT signature verification pipeline (`JWTProofChecker`) to detect HTTPS-based issuer identifiers and route them through the new `HttpsIssuerResolver` instead of the DID registry.

**Background:** Currently, `JWTProofChecker.VerifyJWTAndReturnKey()` (in `verifier/jwt_proof_checker.go`, line 54) extracts the issuer identifier from `kid` or `iss` JWT claims, then calls `resolveKey()` which delegates to `did.Registry.Resolve()`. The `extractDIDFromKid()` helper (line 129) already returns `""` for non-DID `kid` values, falling through to the `iss` claim. For HTTPS-based issuers, we need an alternate code path: detect that the `iss` is an HTTPS URL (starts with `https://`), and resolve the key via the `HttpsIssuerResolver`.

**Files to modify:**

- **`verifier/jwt_proof_checker.go`:**
  - Add a new field `httpsResolver HttpsIssuerResolver` to the `JWTProofChecker` struct (line 33). When nil, HTTPS issuers are not supported (maintaining backward compatibility).
  - Update `NewJWTProofChecker` to accept an optional `HttpsIssuerResolver` parameter. To avoid breaking the existing call sites, use a setter method pattern: add `func (jpc *JWTProofChecker) WithHttpsResolver(resolver HttpsIssuerResolver) *JWTProofChecker` that sets the resolver and returns the checker.
  - Add a helper function `isHttpsIssuer(issuer string) bool` that returns `true` if the string starts with `"https://"`.
  - Modify `VerifyJWTAndReturnKey()` (around line 81, after `issuerDID` is determined):
    - After the existing did:elsi check (line 86), add: if `isHttpsIssuer(issuerDID)` and `jpc.httpsResolver != nil`, call `jpc.httpsResolver.ResolveIssuerKey(issuerDID, kid)` to get the signing key. Then use that key for `jws.Verify()` as in the existing DID path (line 98).
    - If the issuer is HTTPS but no resolver is configured, return a new error `ErrorHttpsIssuerNotSupported`.
    - The existing DID-based path remains unchanged for `did:*` issuers.

- **`verifier/presentation_parser.go`:**
  - Update `InitPresentationParser()` (line 84) to create a `CachingHttpsIssuerResolver` and attach it to the `JWTProofChecker` via the `WithHttpsResolver` setter.
  - Use `cache.New()` for the resolver's cache (same pattern as `sessionCache`/`tokenCache` in `verifier.go`).

- **`verifier/jwt_proof_checker_test.go`:**
  - Add test cases for HTTPS issuer resolution:
    - JWT with `iss: "https://issuer.example.com"` → verified using HTTPS resolver mock.
    - JWT with `iss: "https://..."` when no resolver is configured → `ErrorHttpsIssuerNotSupported`.
    - JWT with `iss: "did:web:..."` → existing DID path still works correctly.
    - JWT with `kid` containing an HTTPS URL → handled correctly.
  - Use a mock `HttpsIssuerResolver` implementation in tests.

**Acceptance criteria:**
- JWTs with `iss: "https://issuer.example.com"` are verified using HTTPS metadata discovery.
- JWTs with DID-based issuers (`did:web`, `did:key`, `did:jwk`, `did:elsi`) continue to work unchanged.
- Backward compatibility: existing code that calls `NewJWTProofChecker` without an HTTPS resolver still compiles and works.
- All existing and new tests pass.

---

### Step 3: Add HTTPS-based trust list type for trusted issuers and participants

**Goal:** Extend the trust registry validation layer to support an `"https"` trust list type. When configured, this type indicates that the credential issuer is identified by an HTTPS URL, and validation checks that the issuer URL is in the configured list of trusted HTTPS issuers.

**Background:** The existing trust list types (`"ebsi"`, `"ebsi-v5"`, `"gaia-x"` in `verifier/trustedparticipant.go`, lines 16-19) all work by looking up the credential's `Issuer.ID` (a DID) in an external registry. For HTTPS-based issuers, the trust model is different: the issuer's identity is its HTTPS URL, and cryptographic trust is established during JWT verification (Step 2) via metadata discovery. The trust list check validates that the issuer URL is in a configured allowlist. This is simpler than EBSI attribute-based validation — no external registry lookups are needed.

**Files to modify:**

- **`verifier/trustedparticipant.go`:**
  - Add constant `typeHttps = "https"` alongside existing `typeGaiaX`, `typeEbsi`, `typeEbsiV5` (line 16-19).
  - In `ValidateVC` (line 29), add a new dispatch branch: if `participantList.Type == typeHttps`:
    - Check if `verifiableCredential.Contents().Issuer.ID` starts with `https://`.
    - If the issuer is an HTTPS URL, consider it a trusted participant. The cryptographic trust was already established during JWT verification (the issuer proved control of its HTTPS URL by serving valid metadata and JWKS). The `participantList.Url` can optionally be used as a trusted domain allowlist (e.g. `https://trusted-domain.example.com`), where the issuer URL must match or be a sub-path of the configured URL.
    - If `participantList.Url` is `"*"`, any HTTPS issuer is trusted.
    - If the issuer is not an HTTPS URL (i.e. it's a DID), skip this entry (it's not applicable).

- **`verifier/trustedissuer.go`:**
  - Add constant `typeHttps = "https"` (around line 95-97 where `typeEbsi` and `typeEbsiV5` are used).
  - In `ValidateVC` (line 44), add handling for `typeHttps` entries in the dispatch logic (around line 96):
    - Collect HTTPS-typed URLs via `extractTilURLsByType(tilEntries, typeHttps)`.
    - For HTTPS type entries, validate that the credential's `Issuer.ID` matches one of the configured URLs. This is a simple string prefix match (the issuer URL must start with one of the configured trusted HTTPS issuer URLs).
    - Skip the EBSI attribute-based validation (`parseAttributes`) for HTTPS type entries — instead, if the issuer URL is in the list, consider the credential as having passed the trusted issuer check.
    - If the issuer is in the HTTPS trusted list, set `exist = true` and skip the `verifyWithCredentialsConfig` call for this credential type (or provide a pass-through that allows all claims).

- **`config/configClient.go`:**
  - No structural changes needed — `TrustedIssuersList` and `TrustedParticipantsList` already support arbitrary `Type` strings. Add comments documenting `"https"` as a valid type alongside `"ebsi"`, `"ebsi-v5"`, `"gaia-x"`.

- **`verifier/trustedparticipant_test.go`:**
  - Add test cases for `typeHttps`:
    - HTTPS issuer URL with matching configured HTTPS trusted participant → trusted.
    - HTTPS issuer URL not in list → not trusted.
    - DID-based issuer with HTTPS trust list type → not trusted (type mismatch).
    - Wildcard `"*"` URL with HTTPS issuer → trusted.
    - Mixed `"ebsi"` and `"https"` entries.

- **`verifier/trustedissuer_test.go`:**
  - Add test cases for `typeHttps`:
    - HTTPS issuer URL matching a configured trusted HTTPS issuer → trusted.
    - HTTPS issuer URL not matching → not trusted.
    - Mixed `"ebsi"` and `"https"` entries for the same credential type.

**Acceptance criteria:**
- New `"https"` trust list type is recognized and dispatched correctly.
- HTTPS-based issuers are validated against the configured HTTPS trusted issuers/participants list.
- Existing `"ebsi"`, `"ebsi-v5"`, and `"gaia-x"` types continue to work unchanged.
- All tests pass.

---

### Step 4: End-to-end tests, configuration fixtures, and CLAUDE.md update

**Goal:** Add integration-level test scenarios covering the complete flow from an HTTPS-issued credential through JWT verification to trust registry validation. Add configuration test fixtures. Update `CLAUDE.md` to document the new HTTPS issuer support. Ensure backward compatibility and clean builds.

**Files to modify/add:**

- **`config/data/`:** Add or update YAML/JSON test fixtures:
  - A fixture with `trustedIssuersLists` containing `"https"` type entries alongside `"ebsi"` entries.
  - A fixture with `trustedParticipantsLists` containing `"https"` type entries.
  - Verify that existing fixtures with string-format `trustedIssuersLists` still parse correctly (backward compat).

- **`verifier/verifier_test.go`:**
  - Add or extend integration-level tests that exercise the full `AuthenticationResponse` or `GenerateToken` flow with an HTTPS-based credential issuer:
    - Create a mock HTTPS issuer (`httptest.Server`) that serves `.well-known/jwt-vc-issuer` metadata and a JWKS endpoint.
    - Sign a test VC JWT using a key from the mock issuer's JWKS.
    - Configure a service with `"https"` type trusted issuers/participants lists pointing to the mock issuer.
    - Submit the VC via the verification pipeline and verify the flow succeeds end-to-end.
  - Verify that `getTrustRegistriesValidationContext` correctly propagates the `"https"` type from config through to the validation context.

- **`integration_test/helpers/`:** Add an HTTPS issuer mock helper (similar to `did_web_mock.go` at line 30) that serves `.well-known/jwt-vc-issuer` metadata and a JWKS endpoint. This can be reused across integration tests.

- **`CLAUDE.md`:** Update to reflect the new HTTPS issuer support:
  - Add `verifier/https_issuer_resolver.go` to the package responsibilities.
  - Document the `"https"` trust list type.
  - Add the `.well-known/jwt-vc-issuer` and `.well-known/openid-credential-issuer` metadata endpoints to the request flow description.

**Verification steps:**
- Run `go build ./...` — must succeed with no errors.
- Run `go vet ./...` — must succeed with no warnings.
- Run `go test ./... -v` — all tests must pass.
- Run `go test ./... -v -coverprofile=profile.cov` to verify coverage of new code paths.

**Acceptance criteria:**
- All new and existing tests pass.
- Configuration backward compatibility is verified (old `[]string` format, existing type entries all still work).
- The full verification chain works end-to-end with an HTTPS-based credential issuer.
- No compilation warnings or vet issues.
- Test fixtures demonstrate the new `"https"` trust list type configuration.
- `CLAUDE.md` is updated with new component documentation.
