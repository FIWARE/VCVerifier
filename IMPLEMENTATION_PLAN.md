# Implementation Plan: Add back did:elsi support

## Overview

Re-add `did:elsi` DID method support that was removed during ticket-55's Step 5, routing verification through the newly built internal eIDAS trust list infrastructure instead of the old external JAdES service. The `did:elsi` method (Alastria's eIDAS-based DID method) uses X.509 certificates carried in the JWT `x5c` header; the leaf certificate's `organizationIdentifier` (OID 2.5.4.97) must match the DID suffix, the JWT signature is verified using the certificate's public key, and the certificate must chain up to a trusted CA in the EU Trusted Lists via the `eidas.TrustStore`.

## Steps

### Step 1: Re-add did:elsi JWT proof verification with eIDAS trust list validation

**Goal:** Restore `did:elsi` as a recognized DID method in the JWT and LD proof paths, using the eIDAS trust store for certificate chain validation instead of the removed external JAdES service.

**What to do:**

**`verifier/jwt_proof_checker.go`** — Core verification logic:
- Add `trustStore *eidas.TrustStore` field to `JWTProofChecker` struct.
- Add `WithTrustStore(store *eidas.TrustStore) *JWTProofChecker` method (method-chaining pattern matching `WithHttpsResolver`).
- Re-add constants: `DidElsiPrefix = "did:elsi:"`, `DidPartsSeparator = ":"`.
- Re-add error variables: `ErrorEidasRequiredForElsi` (returned when trust store is nil), `ErrorIssuerValidationFailed` (issuer DID doesn't match certificate), `ErrorElsiUntrustedCertificate` (certificate doesn't chain to any trusted CA in trust list).
- Re-add `isDidElsiMethod(did string) bool` — returns true when the DID has the `did:elsi:` prefix and a non-empty method-specific identifier. Note: the did:elsi spec (Alastria) defines the method-specific identifier as an ETSI EN 319 412-1 `organizationIdentifier`, which uses a dash-separated format (e.g. `VATES-B12345678`), not colons. The check should validate `strings.HasPrefix(did, "did:elsi:") && len(did) > len("did:elsi:")` rather than counting colon-separated parts, since future identifiers may have different internal structure. This matches the original implementation's intent of detecting the did:elsi method prefix.
- Re-add `validateElsiIssuer(certificate *x509.Certificate, issuerDid string) error` — extracts `organizationIdentifier` (OID 2.5.4.97) from the certificate's Subject and verifies the DID suffix matches it.
- Add `verifyElsiJWT(token []byte, issuerDID string, headers jws.Headers) ([]byte, jwk.Key, error)`:
  1. Check `jpc.trustStore != nil` — fail with `ErrorEidasRequiredForElsi` if missing.
  2. Call `extractX5CFromToken(token)` to get the base64-encoded certificate chain from the `x5c` header (function already exists in the file).
  3. Parse the leaf certificate via `parseCertificate(certChain[0])` (function already exists).
  4. Call `validateElsiIssuer(leafCert, issuerDID)` to bind the DID to the certificate.
  5. Convert the leaf certificate's public key to a JWK via `jwk.Import(leafCert.PublicKey)`.
  6. Verify the JWT signature using `verifyJWSWithCandidateKeys(token, headers, []jwk.Key{pubKey})` (shared JWS verification function already exists in `jws_verification.go`).
  7. Parse any intermediate certificates from the chain.
  8. Verify the certificate chains to a trusted CA using PKIX chain building against the trust store. **Refactoring opportunity:** The PKIX chain verification logic (~30 lines: query trusted services, build `x509.VerifyOptions` with roots, call `leafCert.Verify(opts)`) already exists in `EidasValidationService.verifyCertificateAgainstTrustStore`. Extract this into a shared helper function (e.g. `VerifyCertificateChain(cert *x509.Certificate, intermediates []*x509.Certificate, store *TrustStore, countries []string, serviceTypes []string) error`) on `eidas.TrustStore` or in a new `eidas/verify.go`, so both `EidasValidationService.ValidateVC` and `verifyElsiJWT` call it. This avoids duplication that could drift over time. Reuse the existing `allCertificateServiceTypes` slice from `eidas_validation.go` (which already defines the qualified + non-qualified service type URIs) rather than defining a second copy. Search all countries (empty country code) since did:elsi itself does not carry per-credential country/qualified filters.
  9. Return `(payload, verifiedKey, nil)` on success.
- Wire did:elsi detection into `VerifyJWTAndReturnKey()`: after extracting `issuerDID`, check `isDidElsiMethod(issuerDID)` **before** the HTTPS issuer and DID resolution branches. For did:elsi, the `iss` claim from the payload is authoritative (not `kid`), matching the old behavior.
- Update the doc comment on `JWTProofChecker` struct to mention did:elsi support via eIDAS trust lists.

**`verifier/key_resolver.go`** — Re-add did:elsi detection for LD proof path:
- Re-add `didElsiMethodPrefix = "did:elsi:"` constant.
- Re-add `ErrorDidElsiNotSupportedForLDProof` error variable.
- Re-add `IsDidElsi(didStr string) bool` function.

**`verifier/ld_proof_checker.go`** — Re-add did:elsi rejection in LD proof path:
- In `resolveProofKeys()`, add a check for `IsDidElsi(signerDID)` **before** the DID resolution call. Return `ErrorDidElsiNotSupportedForLDProof`. This is correct because did:elsi uses JWS/JAdES signatures, not Linked Data Proofs.
- Update doc comments on `VerifyPresentation` and `VerifyCredential` to mention that did:elsi is explicitly rejected.

**`verifier/jwt_proof_checker_test.go`** — Unit tests:
- Test `isDidElsiMethod()` with valid and invalid inputs (table-driven).
- Test `validateElsiIssuer()` with matching and non-matching organization identifiers.
- Test `verifyElsiJWT()` with:
  - A valid did:elsi JWT (self-signed test certificate, matching org identifier, mock trust store returning matching trusted services) → success.
  - Missing x5c header → `ErrorNoCertInHeader`.
  - Organization identifier mismatch → `ErrorIssuerValidationFailed`.
  - Trust store is nil (eIDAS disabled) → `ErrorEidasRequiredForElsi`.
  - Certificate does not chain to any trusted service → `ErrorElsiUntrustedCertificate`.
- Test `VerifyJWTAndReturnKey()` dispatches to `verifyElsiJWT` when issuer is `did:elsi:*`.

**`verifier/ld_proof_checker_test.go`** — Test did:elsi rejection:
- Test that LD proof verification rejects a did:elsi signer with `ErrorDidElsiNotSupportedForLDProof`.

**Files:**
- `verifier/jwt_proof_checker.go` (modified)
- `verifier/jwt_proof_checker_test.go` (modified)
- `verifier/key_resolver.go` (modified)
- `verifier/ld_proof_checker.go` (modified)
- `verifier/ld_proof_checker_test.go` (modified)

**Acceptance criteria:**
- `go build ./...` succeeds.
- `go test ./verifier/... -v` passes with all new tests green.
- `isDidElsiMethod("did:elsi:VATES-12345678")` returns true (prefix + non-empty suffix).
- `isDidElsiMethod("did:key:z6Mk...")` returns false (wrong method prefix).
- `isDidElsiMethod("did:elsi:")` returns false (empty method-specific identifier).
- `validateElsiIssuer` correctly binds the DID suffix to the certificate's OID 2.5.4.97.
- JWT signature verification uses the certificate's public key via standard JWS, not an external service.
- Certificate trust verification uses `eidas.TrustStore` with PKIX chain building.
- LD proof path rejects did:elsi with `ErrorDidElsiNotSupportedForLDProof`.

---

### Step 2: Wire eIDAS trust store into JWTProofChecker and add integration tests

**Goal:** Connect the eIDAS trust store to the JWT proof checker during verifier initialization so did:elsi credentials are verified against the real trust list infrastructure, and add integration-level tests exercising the full flow.

**What to do:**

**`verifier/verifier.go`** — Wire trust store into proof checker:
- In `InitVerifier()`, after the eIDAS fetcher is created and started (line ~432), inject the trust store into the global proof checker via `GetProofChecker().WithTrustStore(fetcher.Store())`. Note on mutation semantics: `WithTrustStore` follows the same pattern as `WithHttpsResolver` — it mutates the receiver's field in place and returns the same `*JWTProofChecker` pointer. This means `GetProofChecker().WithTrustStore(...)` works correctly without needing to reassign the global, because the returned pointer is the same object.
- This must happen **after** `InitPresentationParser` has been called (which creates the global proof checker) and **after** the fetcher is started. The current init order in `main.go` is: `InitPresentationParser` → `InitVerifier`, so this naturally works.
- When eIDAS is disabled (`config.Eidas.Enabled == false`), the proof checker's trust store remains nil, and any did:elsi JWT will fail with `ErrorEidasRequiredForElsi`.
- Add a log message: `"did:elsi support enabled via eIDAS trust store"` when the trust store is injected.

**`verifier/presentation_parser.go`** — No changes needed:
- `NewJWTProofChecker(registry)` signature is unchanged.
- `WithTrustStore()` is called later in `InitVerifier`, not here.

**`verifier/elsi_integration_test.go`** — Integration tests:
- Test the full did:elsi verification flow end-to-end using a mock trust store populated with test CA certificates:
  - **Happy path:** Generate a test CA certificate and leaf certificate. Create an `eidas.TrustStore`, populate it with the CA certificate as a trusted service. Create a JWTProofChecker with the trust store. Build a JWT signed by the leaf certificate's private key, with `iss: "did:elsi:VATES-ORG123"` and the leaf cert (+ CA cert as intermediate) in the `x5c` header. The leaf cert's Subject contains OID 2.5.4.97 = `"VATES-ORG123"`. Verify the JWT succeeds.
  - **Untrusted issuer:** Same setup but with a different CA in the trust store (certificate doesn't chain to any trusted service) → `ErrorElsiUntrustedCertificate`.
  - **Issuer DID mismatch:** The cert's org identifier doesn't match the DID → `ErrorIssuerValidationFailed`.
  - **eIDAS disabled:** No trust store on the proof checker → `ErrorEidasRequiredForElsi`.
  - **LD proof rejection:** Attempt to verify an LD proof with a did:elsi signer → `ErrorDidElsiNotSupportedForLDProof`.
  - **Non-did:elsi JWT unchanged:** Verify that standard DID method JWTs (did:key, did:web) still work without trust store involvement.
- Use table-driven tests with `t.Run()` loops.
- Create test helper functions for:
  - Generating self-signed CA and leaf certificates with organization identifier (OID 2.5.4.97).
  - Building signed JWTs with x5c headers.

**`verifier/verifier_test.go`** (if applicable) — Verify wiring:
- If there are existing tests for `InitVerifier`, add a case verifying the proof checker receives the trust store when eIDAS is enabled.

**Files:**
- `verifier/verifier.go` (modified — inject trust store into proof checker)
- `verifier/elsi_integration_test.go` (new — integration tests)
- `verifier/verifier_test.go` (modified if applicable)

**Acceptance criteria:**
- `go test ./... -v` passes with all tests green, including new integration tests.
- `GetProofChecker().trustStore` is non-nil after `InitVerifier()` when eIDAS is enabled.
- Full did:elsi JWT verification flow works end-to-end: JWT signed by certificate → x5c extraction → issuer DID binding → JWS signature verification → trust list chain validation → success.
- did:elsi JWTs are rejected with a clear error when eIDAS is disabled.
- No regressions in existing test suites (HTTPS issuers, standard DID methods, eIDAS SD-JWT validation, LD proofs).

---

### Step 3: User-facing documentation for did:elsi support

**Goal:** Add clear, user-focused documentation to the README explaining what did:elsi support is, how to configure it, and how to use it. This ensures operators can enable and configure did:elsi credential verification without diving into the source code.

**What to do:**

**`README.md`** — Add a new section under "Trust Anchor Integration" (after the existing EBSI TIR and Gaia-X Registry sections):

Add a section titled **"did:elsi — eIDAS Trust List Verification"** covering:

1. **What is did:elsi?**
   - Brief explanation: `did:elsi` is a DID method based on the European eIDAS framework. It identifies organizations using their eIDAS `organizationIdentifier` (ETSI EN 319 412-1), carried in the X.509 certificate's Subject (OID 2.5.4.97). Example DID: `did:elsi:VATES-B12345678`.
   - How it works with VCVerifier: Verifiable Credentials issued by `did:elsi` identifiers carry the issuer's X.509 certificate chain in the JWT `x5c` header. VCVerifier verifies the JWT signature using the certificate's public key, binds the DID to the certificate's organization identifier, and validates the certificate chain against the EU Trusted Lists (ETSI TS 119 612).

2. **Prerequisites**
   - The eIDAS feature must be globally enabled. did:elsi verification depends on the eIDAS trust list infrastructure — the `eidas` section in `server.yaml` must have `enabled: true`.
   - Without eIDAS enabled, any `did:elsi` credential will be rejected with a clear error message.

3. **Configuration**
   - Show the relevant `server.yaml` configuration block:
     ```yaml
     eidas:
       enabled: true
       lotlUrl: "https://ec.europa.eu/tools/lotl/eu-lotl.xml"  # EU List of Trusted Lists
       refreshInterval: 86400  # seconds between trust list refreshes (default: 24h)
       countries: []  # empty = all EU countries; or e.g. ["DE", "FR", "ES"]
     ```
   - Explain each field in plain language:
     - `enabled` — Activates the eIDAS trust list fetcher and enables did:elsi credential verification.
     - `lotlUrl` — URL of the EU List of Trusted Lists (LOTL). The default points to the official EU LOTL. Override only for testing or if the EU changes the URL.
     - `refreshInterval` — How often (in seconds) to re-fetch and refresh the trust lists. Default is 86400 (24 hours).
     - `countries` — Optional list of ISO 3166-1 alpha-2 country codes to restrict which national trusted lists are consulted. Empty means all countries in the LOTL are used.

4. **How verification works**
   - Step-by-step description in user-friendly terms:
     1. VCVerifier receives a Verifiable Credential (JWT format) with `iss: "did:elsi:VATES-..."`.
     2. The `x5c` header is extracted to obtain the issuer's X.509 certificate chain.
     3. The DID's method-specific identifier (e.g. `VATES-B12345678`) is matched against the certificate's `organizationIdentifier` (OID 2.5.4.97).
     4. The JWT signature is verified using the certificate's public key.
     5. The certificate chain is validated against the cached EU Trusted Lists — the issuer's certificate must chain up to a trust service provider listed in the LOTL.
   - Note: did:elsi only supports JWT-format credentials. JSON-LD (Linked Data Proof) presentations with did:elsi signers are explicitly rejected — did:elsi uses JWS signatures, not LD proofs.

5. **Interaction with other trust anchors**
   - Clarify that did:elsi trust validation via the EU Trusted Lists is independent of the EBSI TIR and Gaia-X Registry trust anchors.
   - If a credential type also has `trustedParticipantsLists` or `trustedIssuersLists` configured, those checks run in addition to the eIDAS certificate chain validation — all configured checks must pass.

6. **Troubleshooting**
   - Common error messages and what they mean:
     - `ErrorEidasRequiredForElsi` — The global eIDAS feature is disabled. Enable `eidas.enabled: true` in `server.yaml`.
     - `ErrorIssuerValidationFailed` — The DID's organization identifier doesn't match the certificate. Check the issuer's DID and certificate Subject.
     - `ErrorElsiUntrustedCertificate` — The issuer's certificate doesn't chain to any trusted service in the EU Trusted Lists. Verify the issuer is registered with a trust service provider in the configured countries.

**Files:**
- `README.md` (modified — add did:elsi documentation section)

**Acceptance criteria:**
- README contains a user-focused section on did:elsi support under "Trust Anchor Integration".
- The section explains what did:elsi is, how to enable it, the full `server.yaml` configuration with explanations, how verification works step-by-step, interaction with other trust anchors, and common troubleshooting scenarios.
- Documentation is written for operators (not developers) — focuses on configuration and usage rather than implementation internals.
- No broken links or references to non-existent configuration options.
