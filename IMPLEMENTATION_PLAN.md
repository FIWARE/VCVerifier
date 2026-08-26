# Implementation Plan: Support HTTPS-based client identifiers in the vc-verifier

## Overview

Extend VCVerifier to support HTTPS-based credential issuer identifiers alongside the existing DID-based ones (did:key, did:web, did:jwk, did:elsi). The issuer identifier (`Issuer.ID`) is treated as a generic URI — both DIDs and HTTPS URLs are valid. When a credential's `iss` claim is an HTTPS URL (e.g. `https://issuer.example.com`) instead of a DID, the verifier discovers the issuer's public keys via two resolution paths:

1. **SD-JWT VC Issuer Metadata** (primary): `<issuer-url>/.well-known/jwt-vc-issuer` — the metadata contains `jwks_uri` or inline `jwks` (per draft-ietf-oauth-sd-jwt-vc, Section 5.2).
2. **OpenID4VCI Credential Issuer Metadata** (fallback): `<issuer-url>/.well-known/openid-credential-issuer` — the metadata contains `authorization_servers`, whose OAuth metadata (fetched via `/.well-known/oauth-authorization-server` per RFC 8414) provides `jwks_uri`.

For trust validation, rather than introducing a new trust list type, the existing trust list mechanism is extended to treat `Issuer.ID` as a URI. HTTPS-URL-based issuers are validated by URL matching against trust list entries, while DID-based issuers continue through the existing type-based dispatch (EBSI, Gaia-X).

## Steps

### Step 1: Implement HTTPS issuer metadata resolver

**Goal:** Create a new component that, given an HTTPS URL issuer identifier, fetches the issuer's metadata from well-known endpoints and resolves the signing key(s) via JWKS.

**Background:** Two distinct metadata endpoints exist for discovering an HTTPS-based issuer's signing keys:

1. **SD-JWT VC Issuer Metadata** (draft-ietf-oauth-sd-jwt-vc, Section 5.2): The well-known endpoint `<issuer-url>/.well-known/jwt-vc-issuer` returns a metadata document with the following fields:
   - `issuer` (REQUIRED): The Issuer identifier, which MUST match the `iss` value in the JWT.
   - `jwks_uri` (OPTIONAL): URL referencing the Issuer's JSON Web Key Set document.
   - `jwks` (OPTIONAL): Inline JSON Web Key Set document value.
   - The spec requires: "JWT VC Issuer Metadata MUST include either `jwks_uri` or `jwks`, but not both."

2. **OpenID4VCI Credential Issuer Metadata** (openid-4-verifiable-credential-issuance-1_0, Section 12.2.4): The well-known endpoint `<issuer-url>/.well-known/openid-credential-issuer` returns credential issuer metadata. This metadata does NOT include `jwks_uri` directly. Instead, it includes:
   - `authorization_servers` (OPTIONAL): An array of OAuth 2.0 Authorization Server identifiers. Each authorization server's own metadata (fetched via `<server-url>/.well-known/oauth-authorization-server` per RFC 8414) contains the `jwks_uri`.

The resolver must support **both** paths:
- **Primary path** (SD-JWT VC): Fetch `/.well-known/jwt-vc-issuer`, extract `jwks_uri` or inline `jwks` directly.
- **Fallback path** (OpenID4VCI): Fetch `/.well-known/openid-credential-issuer`, extract `authorization_servers`, then fetch each authorization server's metadata from `/.well-known/oauth-authorization-server` to obtain the `jwks_uri`.

**Files to create/modify:**

- **`verifier/https_issuer_resolver.go`** (new file):
  - Define an `HttpsIssuerResolver` interface with method:
    - `ResolveIssuerKey(issuerURL string, kid string) (jwk.Key, error)` — fetches metadata, resolves JWKS, finds the key matching `kid`.
  - Define metadata structs:
    - `JwtVcIssuerMetadata` — represents the SD-JWT VC issuer metadata response (fields: `Issuer string`, `JwksUri string`, `Jwks *jwk.Set`). Used for `/.well-known/jwt-vc-issuer`.
    - `OidcCredentialIssuerMetadata` — represents the OpenID4VCI credential issuer metadata (fields: `Issuer string`, `AuthorizationServers []string`). Used for `/.well-known/openid-credential-issuer`.
    - `OAuthServerMetadata` — represents an OAuth 2.0 Authorization Server metadata response (fields: `Issuer string`, `JwksUri string`). Used for `/.well-known/oauth-authorization-server`.
  - Implement `CachingHttpsIssuerResolver` struct with:
    - An HTTP client (`*http.Client`) for fetching metadata and JWKS.
    - A `common.Cache` for caching resolved JWKS keyset per issuer URL (to avoid repeated HTTP calls).
    - A configurable cache TTL.
  - Implement the resolution flow:
    1. Check if JWKS for this issuer URL is already cached; if so, look up the key by `kid`.
    2. **Primary path** (SD-JWT VC): Try fetching `<issuerURL>/.well-known/jwt-vc-issuer`. If successful, parse `JwtVcIssuerMetadata` and extract `jwks_uri` or inline `jwks`.
    3. **Fallback path** (OpenID4VCI): If the primary path fails (404 or missing JWKS fields), try `<issuerURL>/.well-known/openid-credential-issuer`. Parse `OidcCredentialIssuerMetadata`, extract `authorization_servers`, then for each authorization server, fetch `<server-url>/.well-known/oauth-authorization-server` to obtain the `jwks_uri` from the OAuth server's metadata.
    4. If both paths fail, return `ErrorIssuerMetadataNotFound`.
    5. Fetch the JWKS from the discovered `jwks_uri` (or use inline `jwks` from the primary path).
    6. Parse the JWKS, cache the keyset, and find the key matching `kid`.
    7. If no `kid` is provided, return the first key in the set (single-key issuers).
  - Define named constants for well-known paths:
    - `WellKnownJwtVcIssuer = "/.well-known/jwt-vc-issuer"`
    - `WellKnownOIDCCredentialIssuer = "/.well-known/openid-credential-issuer"`
    - `WellKnownOAuthAuthzServer = "/.well-known/oauth-authorization-server"`
  - Define error sentinels:
    - `ErrorIssuerMetadataNotFound` — neither well-known endpoint returned valid metadata.
    - `ErrorIssuerJwksNotFound` — metadata has no `jwks_uri` and no inline `jwks`, and no `authorization_servers` could provide a JWKS.
    - `ErrorIssuerKeyNotFound` — JWKS did not contain a key matching the requested `kid`.
    - `ErrorIssuerMismatch` — the `issuer` field in the metadata does not match the expected issuer URL.
  - Validate that the `issuer` field in the metadata matches the expected issuer URL (security check per RFC 8414 Section 3.3).

- **`verifier/https_issuer_resolver_test.go`** (new file):
  - Table-driven tests using `httptest.Server` to mock the metadata and JWKS endpoints:
    - Successful resolution via `.well-known/jwt-vc-issuer` with `jwks_uri` (SD-JWT VC primary path).
    - Successful resolution via `.well-known/jwt-vc-issuer` with inline `jwks` (no `jwks_uri`).
    - Fallback to `.well-known/openid-credential-issuer` when the primary endpoint returns 404: mock the OpenID4VCI metadata with `authorization_servers`, then mock the authorization server's `/.well-known/oauth-authorization-server` metadata to return `jwks_uri`, and verify key resolution succeeds through this chain.
    - Key lookup by `kid` in a multi-key JWKS.
    - Default to first key when no `kid` is provided.
    - Caching: second call should not make HTTP requests.
    - Error cases: metadata not found (both endpoints 404), JWKS fetch failure, no matching key, issuer mismatch, authorization server metadata fetch failure.

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

### Step 3: Treat issuer identifiers as URIs in trust validation

**Goal:** Make the trust registry validation layer treat `Issuer.ID` as a generic URI rather than requiring it to be a DID. When the issuer identifier is an HTTPS URL, the existing trust list types should handle it without introducing a separate type — the code auto-detects the URI scheme and dispatches accordingly.

**Background:** The existing trust list types (`"ebsi"`, `"ebsi-v5"`, `"gaia-x"` in `verifier/trustedparticipant.go`, lines 16-19) currently assume `Issuer.ID` is a DID and look it up in external registries. With HTTPS-based issuers, `Issuer.ID` is an HTTPS URL (e.g. `https://issuer.example.com`). Rather than adding a new `"https"` trust list type, the issuer identifier should be treated as a URI throughout the codebase. The existing trust list types already have `Url` fields — the validation logic should detect whether the credential's `Issuer.ID` is a DID or an HTTPS URL and handle each case accordingly:
- **DID-based issuer**: existing behavior — look up the DID in the configured registry (EBSI, Gaia-X).
- **HTTPS-URL-based issuer**: the issuer's cryptographic identity was already verified during JWT signature verification (Step 2, via metadata discovery and JWKS). Trust validation checks whether the issuer URL matches one of the configured trusted issuer/participant URLs.

**Files to modify:**

- **`verifier/trustedparticipant.go`:**
  - Add a helper function `isHttpsURI(id string) bool` that returns `true` if the string starts with `"https://"`.
  - In `ValidateVC` (line 29), before the existing type-based dispatch, add an early check: if the credential's `Issuer.ID` is an HTTPS URL (detected via `isHttpsURI`), perform a direct URL match against the `participantList.Url`:
    - If `participantList.Url` is `"*"`, the HTTPS issuer is trusted.
    - Otherwise, check if the HTTPS issuer URL matches (exact match or prefix match) the configured `participantList.Url`.
    - This applies regardless of the trust list `Type` — an HTTPS issuer is validated by URL matching, not by registry lookup.
  - If the `Issuer.ID` is a DID, continue with the existing type-based dispatch (`typeEbsi`, `typeEbsiV5`, `typeGaiaX`).

- **`verifier/trustedissuer.go`:**
  - Add a similar `isHttpsURI(id string) bool` helper (or share one via a common utility).
  - In `ValidateVC` (line 44), add handling for HTTPS-URL-based issuers:
    - If the credential's `Issuer.ID` is an HTTPS URL, iterate over the trust list entries and check whether the issuer URL matches one of the configured URLs. No EBSI attribute-based validation or external registry lookup is needed.
    - If the issuer URL matches a configured trusted issuer URL, set `exist = true`. The credential's claims are accepted since cryptographic trust was established during JWT verification.
    - If the `Issuer.ID` is a DID, continue with existing type-based dispatch logic.
  - Update `isWildcardTil` to work with URI-based entries.

- **`config/configClient.go`:**
  - No structural changes needed — `TrustedIssuersList` and `TrustedParticipantsList` already support arbitrary `Type` strings and `Url` fields. Add documentation comments noting that `Url` entries can be HTTPS issuer URLs (not only registry endpoint URLs).

- **`verifier/trustedparticipant_test.go`:**
  - Add test cases for HTTPS URI issuers:
    - HTTPS issuer URL matching configured trusted participant URL → trusted.
    - HTTPS issuer URL not in list → not trusted.
    - DID-based issuer → continues through existing type-based dispatch (unchanged behavior).
    - Wildcard `"*"` URL with HTTPS issuer → trusted.
    - Mixed DID and HTTPS issuer scenarios.

- **`verifier/trustedissuer_test.go`:**
  - Add test cases for HTTPS URI issuers:
    - HTTPS issuer URL matching a configured trusted issuer URL → trusted.
    - HTTPS issuer URL not matching → not trusted.
    - DID-based issuer → existing EBSI validation flow (unchanged behavior).
    - Mixed DID and HTTPS issuer trust list entries.

**Acceptance criteria:**
- `Issuer.ID` is treated as a URI — both DIDs and HTTPS URLs are handled.
- HTTPS-URL-based issuers are validated by URL matching against trust list entries, without requiring a new trust list type.
- DID-based issuers continue to work through existing type-based dispatch (`"ebsi"`, `"ebsi-v5"`, `"gaia-x"`).
- All existing tests pass, new tests cover HTTPS URI issuer scenarios.

---

### Step 4: End-to-end tests, configuration fixtures, and CLAUDE.md update

**Goal:** Add integration-level test scenarios covering the complete flow from an HTTPS-issued credential through JWT verification to trust registry validation. Add configuration test fixtures. Update `CLAUDE.md` to document the new HTTPS issuer support. Ensure backward compatibility and clean builds.

**Files to modify/add:**

- **`config/data/`:** Add or update YAML/JSON test fixtures:
  - A fixture with `trustedIssuersLists` and `trustedParticipantsLists` containing HTTPS issuer URLs alongside DID-based entries.
  - Verify that existing fixtures with string-format `trustedIssuersLists` still parse correctly (backward compat).

- **`verifier/verifier_test.go`:**
  - Add or extend integration-level tests that exercise the full `AuthenticationResponse` or `GenerateToken` flow with an HTTPS-based credential issuer:
    - Create a mock HTTPS issuer (`httptest.Server`) that serves `.well-known/jwt-vc-issuer` metadata and a JWKS endpoint.
    - Sign a test VC JWT using a key from the mock issuer's JWKS.
    - Configure a service with trusted issuers/participants lists containing the mock issuer's URL.
    - Submit the VC via the verification pipeline and verify the flow succeeds end-to-end.
  - Verify that `getTrustRegistriesValidationContext` correctly propagates URI-based issuer entries from config through to the validation context.

- **`integration_test/helpers/`:** Add an HTTPS issuer mock helper (similar to `did_web_mock.go` at line 30) that serves `.well-known/jwt-vc-issuer` metadata (with `jwks_uri`) and a JWKS endpoint. Also add a variant that serves `.well-known/openid-credential-issuer` metadata (with `authorization_servers`) for testing the OpenID4VCI fallback path. These can be reused across integration tests.

- **`CLAUDE.md`:** Update to reflect the new HTTPS issuer support:
  - Add `verifier/https_issuer_resolver.go` to the package responsibilities.
  - Document URI-based issuer identifier support in trust validation.
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
- Test fixtures demonstrate HTTPS issuer URL configuration alongside DID-based entries.
- `CLAUDE.md` is updated with new component documentation.
