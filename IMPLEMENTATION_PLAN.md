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
- Re-add `isDidElsiMethod(did string) bool` — returns true when the DID has the `did:elsi:` prefix and exactly three colon-separated parts.
- Re-add `validateElsiIssuer(certificate *x509.Certificate, issuerDid string) error` — extracts `organizationIdentifier` (OID 2.5.4.97) from the certificate's Subject and verifies the DID suffix matches it.
- Add `verifyElsiJWT(token []byte, issuerDID string, headers jws.Headers) ([]byte, jwk.Key, error)`:
  1. Check `jpc.trustStore != nil` — fail with `ErrorEidasRequiredForElsi` if missing.
  2. Call `extractX5CFromToken(token)` to get the base64-encoded certificate chain from the `x5c` header (function already exists in the file).
  3. Parse the leaf certificate via `parseCertificate(certChain[0])` (function already exists).
  4. Call `validateElsiIssuer(leafCert, issuerDID)` to bind the DID to the certificate.
  5. Convert the leaf certificate's public key to a JWK via `jwk.Import(leafCert.PublicKey)`.
  6. Verify the JWT signature using `verifyJWSWithCandidateKeys(token, headers, []jwk.Key{pubKey})` (shared JWS verification function already exists in `jws_verification.go`).
  7. Parse any intermediate certificates from the chain.
  8. Verify the certificate chains to a trusted CA using PKIX chain building against the trust store — reuse the same pattern as `EidasValidationService.verifyCertificateAgainstTrustStore` (query trusted services from the store, build `x509.VerifyOptions` with roots from trusted services, call `leafCert.Verify(opts)`). Search all countries (empty country code) and use all certificate service types (qualified + non-qualified), since did:elsi itself does not carry per-credential country/qualified filters.
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
- `isDidElsiMethod("did:elsi:VATES-12345678")` returns true.
- `isDidElsiMethod("did:key:z6Mk...")` returns false.
- `validateElsiIssuer` correctly binds the DID suffix to the certificate's OID 2.5.4.97.
- JWT signature verification uses the certificate's public key via standard JWS, not an external service.
- Certificate trust verification uses `eidas.TrustStore` with PKIX chain building.
- LD proof path rejects did:elsi with `ErrorDidElsiNotSupportedForLDProof`.

---

### Step 2: Wire eIDAS trust store into JWTProofChecker and add integration tests

**Goal:** Connect the eIDAS trust store to the JWT proof checker during verifier initialization so did:elsi credentials are verified against the real trust list infrastructure, and add integration-level tests exercising the full flow.

**What to do:**

**`verifier/verifier.go`** — Wire trust store into proof checker:
- In `InitVerifier()`, after the eIDAS fetcher is created and started (line ~432), inject the trust store into the global proof checker via `GetProofChecker().WithTrustStore(fetcher.Store())`.
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
