# Implementation Plan: Fix ld-credential issue in vcverifier

## Overview

JSON-LD / `ldp_vc` credentials and presentations are parsed structurally but no Linked Data Proof is ever cryptographically verified, creating a silent security gap. An attacker can submit unsigned or forged JSON-LD VPs to `/token` and their content flows into the issued JWT. This plan addresses the gap in two phases: first, clean-up and fail-closed hardening (C1–C5 from the ticket), then full LD-proof verification implementation (W1–W3, W5). The work is split into 8 self-contained steps, ordered so the highest-priority security fix (fail-closed) lands first.

## Steps

### Step 1: Fail closed on unverifiable JSON-LD input (C5 — security fix)

**Goal:** Make the JSON-LD parsing paths reject input they cannot verify, closing the most critical security gap immediately. This step requires no new cryptographic code — it only adds rejection logic to existing paths.

**Files to modify:**

- **`verifier/presentation_parser.go`:**
  - `parseJSONLDPresentation` (line 348): Return `ErrorInvalidProof` when the VP contains a `proof` member (unverifiable until W2/W3 land). When no `proof` is present, also reject — an unsigned VP must not be accepted.
  - `parseUnsignedJWTCredential` (line 400): Replace the base64 payload extraction with a call to the existing `JWTProofChecker` via the `ConfigurablePresentationParser` receiver. This function is currently a standalone function — refactor it to be a method on `ConfigurablePresentationParser` so it can access `ProofChecker`. The JSON-LD VP path at line 372 should call the new method. If `ProofChecker` is nil (no checker configured), reject the token.
  - Update `parseJSONLDPresentation` to be a method on `ConfigurablePresentationParser` (currently standalone) so it can dispatch to the proof-checking `parseUnsignedJWTCredential`.

- **`verifier/credential_status_client.go`:**
  - `parseStatusListCredentialBody` (line 213): When the body is JSON-LD (starts with `{`), log a warning that JSON-LD status list credential proof verification is not yet supported and return an error, mirroring the behavior when `jwtVerifier` is nil for JWT status lists. This prevents MITM attacks on status-list resolution.

**Tests to add/update:**

- **`verifier/presentation_parser_test.go`:**
  - Add table-driven tests for `parseJSONLDPresentation` rejection: unsigned JSON-LD VP (no proof member), JSON-LD VP with a proof member (unverifiable), JWT VC embedded in JSON-LD VP with valid signature (verify it is now checked), JWT VC embedded in JSON-LD VP with invalid signature (verify rejection).
  - Test that `ParsePresentation` correctly routes JSON-LD input (leading `{`) to the rejection path.

- **`verifier/credential_status_client_test.go`:**
  - Add test case for JSON-LD status list credential body — verify it returns an error.

**Acceptance criteria:**
- An unsigned JSON-LD VP submitted to `ParsePresentation` returns an error.
- A JSON-LD VP with a `proof` member returns `ErrorInvalidProof` (until LD-proof verification is implemented in later steps).
- A JWT VC embedded in a JSON-LD VP is verified via the existing `JWTProofChecker`.
- A JSON-LD status list credential is rejected with a clear error message.
- All existing tests pass — no regressions in JWT VP or SD-JWT paths.

---

### Step 2: Clean up stale validation modes and documentation (C1, C2)

**Goal:** Make the `validationMode` configuration honest. The `combined` and `jsonLd` modes claim to do JSON-LD validation but actually only check field presence. Deprecate them with a startup warning. Also fix stale documentation in `CLAUDE.md` and `README.md`.

**Files to modify:**

- **`verifier/jwt_verifier.go`:**
  - Add a `DeprecatedValidationModes` map or set containing `"combined"` and `"jsonLd"`.
  - Add a function `WarnDeprecatedMode(mode string)` that logs a prominent warning at `Warn` level if the configured mode is deprecated: `"validationMode '%s' is configured but does not perform real JSON-LD validation — it only checks field presence. Consider using 'none' or 'baseContext' instead."`.
  - Document the actual behavior of each mode in code comments.

- **`verifier/verifier.go`** (or wherever config is applied at startup):
  - Call `WarnDeprecatedMode` during verifier initialization when the configured `validationMode` is `combined` or `jsonLd`.

- **`README.md`:**
  - Update lines 133–138 to document the actual behavior of `combined` and `jsonLd` modes, noting they are deprecated aliases for basic field-presence validation. Add a note that full JSON-LD validation will be restored in a future release.

- **`CLAUDE.md`:**
  - Remove `trustbloc/vc-go, did-go, kms-go` from "Key Dependencies" section.
  - Remove reference to `verifier/elsi_proof_checker.go` (does not exist; did:elsi handling is in `verifier/jwt_proof_checker.go`).
  - Update the `jwt_verifier.go` description to reflect that validation modes only check content, not cryptographic proofs.
  - Add a note about the JSON-LD proof gap and ongoing remediation.

**Tests to add/update:**

- **`verifier/jwt_verifier_test.go`:**
  - Add test for `WarnDeprecatedMode` — verify it logs for `combined` and `jsonLd` but not for `none` or `baseContext`.

**Acceptance criteria:**
- Starting the verifier with `validationMode: combined` or `validationMode: jsonLd` logs a deprecation warning.
- `README.md` accurately describes the behavior of each validation mode.
- `CLAUDE.md` references only dependencies and files that exist in the codebase.
- No behavior change for existing configurations — modes still function as before, just with honest documentation and warnings.

---

### Step 3: Wire caching document loader and remove dead infrastructure (C3)

**Goal:** Either wire the existing `NewCachingDocumentLoader` (`verifier/caching_client.go`) into the TIR M2M authentication path or prepare it for use in the upcoming LD-proof verification. Fix the uncached `@context` fetch in the TIR M2M authentication hot path.

**Files to modify:**

- **`common/caching_document_loader.go`** (new file, moved from `verifier/caching_client.go`):
  - Move `CachingDocumentLoader` struct and `NewCachingDocumentLoader` function from `verifier/caching_client.go` to a new file in the `common` package. The struct uses only `common.Cache` and `piprate/json-gold/ld` — no circular dependency.
  - Add configurable cache TTL parameters (currently hardcoded to 300s/600s) via constructor parameters with sensible defaults.
  - Document the exported function and struct.

- **`verifier/caching_client.go`:**
  - Remove the now-moved code. If the file has no other contents, delete it entirely.

- **`tir/tokenProvider.go`:**
  - Replace `ld.NewDefaultDocumentLoader(http.DefaultClient)` at line 159 with a caching document loader. Add a `documentLoader ld.DocumentLoader` field to the `M2MTokenProvider` struct, injected at construction time.
  - Use the stored loader in `signVerifiablePresentation` instead of creating a new default loader on every call.

**Tests to add/update:**

- **`common/caching_document_loader_test.go`** (new file):
  - Test that `CachingDocumentLoader` returns cached documents on second call.
  - Test cache miss behavior (delegates to underlying loader).
  - Test error propagation from underlying loader.

- **`tir/tokenProvider_test.go`:**
  - Update tests to inject a mock or test document loader into `M2MTokenProvider`.

**Acceptance criteria:**
- `CachingDocumentLoader` lives in the `common` package, accessible to both `verifier/` and `tir/`.
- `tir/tokenProvider.go` uses a caching document loader instead of creating a new `DefaultDocumentLoader` on every signing call.
- `verifier/caching_client.go` is removed (code moved, not duplicated).
- All tests pass.

---

### Step 4: Extend data model with proof fields (W1)

**Goal:** Add proof-carrying fields to `common.Credential` so JSON-LD credentials and presentations can carry their proof(s) through the parsing pipeline. Extend `LDProof` to represent the full set of Data Integrity proof fields. Populate the proof in the JSON-LD parsing functions.

**Files to modify:**

- **`common/ldproof.go`:**
  - Extend `LDProof` struct (line 43) with additional fields from the Data Integrity specification: `ProofPurpose string`, `Challenge string`, `Domain string`, `ProofValue string`, `Cryptosuite string`. Keep existing fields (`Type`, `Created`, `VerificationMethod`, `JWS`).
  - Add a `ParseLDProof(proofMap map[string]interface{}) (*LDProof, error)` function that extracts proof fields from a JSON map. Handle both `jws` (JsonWebSignature2020) and `proofValue` (newer Data Integrity suites) as the signature carrier.
  - Add a `ParseLDProofs(proofRaw interface{}) ([]*LDProof, error)` function that handles both single-proof (map) and multi-proof (array of maps) cases, returning a slice.

- **`common/credential.go`:**
  - Add a `proofs []*LDProof` field to the `Credential` struct (line 138).
  - Add `Proofs() []*LDProof` getter method.
  - Add `SetProofs(proofs []*LDProof)` setter method.
  - Update `Presentation` to support multiple proofs: change `Proof *LDProof` (line 253) to `Proofs []*LDProof`. Update `MarshalJSON` (line 328) to serialize the new field. Update `AddLinkedDataProof` in `common/ldproof.go` to append to the slice instead of overwriting.

- **`verifier/presentation_parser.go`:**
  - `parseJSONLDCredential` (line 417): After building the credential, extract the `proof` member from `vcMap` using `common.ParseLDProofs`, and call `cred.SetProofs(...)`.
  - `parseJSONLDPresentation` (line 348): Extract the `proof` member from `vpMap` using `common.ParseLDProofs`, and set `pres.Proofs = ...`.
  - Preserve the raw JSON on both credentials and presentations (already done via `SetRawJSON` for credentials; verify presentations also retain raw JSON for canonicalization in W2).

**Tests to add/update:**

- **`common/ldproof_test.go`** (new file):
  - Table-driven tests for `ParseLDProof`: valid JsonWebSignature2020 proof, valid DataIntegrityProof with `proofValue`, proof with `challenge`/`domain`/`proofPurpose`, missing required fields, unknown type.
  - Table-driven tests for `ParseLDProofs`: single proof (map), multiple proofs (array), nil/empty input.

- **`common/credential_test.go`:**
  - Test that `Credential.Proofs()` and `SetProofs()` work correctly.
  - Test `Presentation` serialization with multiple proofs.

- **`verifier/presentation_parser_test.go`:**
  - Add tests verifying that `parseJSONLDCredential` populates the proof field.
  - Add tests verifying that `parseJSONLDPresentation` populates the VP-level proofs.

**Acceptance criteria:**
- `LDProof` represents all standard Data Integrity proof fields.
- Both `Credential` and `Presentation` can carry multiple proofs.
- JSON-LD parsing functions populate proof fields from the input document.
- Raw JSON is preserved for canonicalization.
- `AddLinkedDataProof` still works for VP signing (TIR M2M path).
- All existing tests pass with the structural changes.

---

### Step 5: Implement VerifyLinkedDataProof (W2)

**Goal:** Implement the verification counterpart to `AddLinkedDataProof`. This function verifies a JsonWebSignature2020 linked data proof by canonicalizing the document and proof options, computing the `tbs` hash, and verifying the detached JWS signature against a provided public key.

**Files to modify:**

- **`common/ldproof.go`:**
  - Add error variables: `ErrorLDProofVerifyMarshal`, `ErrorLDProofVerifyCanonDoc`, `ErrorLDProofVerifyCanonProof`, `ErrorLDProofVerifySignature`, `ErrorLDProofMissingCreated`, `ErrorLDProofUnsupportedType`, `ErrorLDProofAlgMismatch`, `ErrorLDProofMissingJWS`.
  - Add `VerifyLinkedDataProof(documentJSON []byte, proof *LDProof, publicKey jwk.Key, documentLoader ld.DocumentLoader) error`:
    1. Validate that `proof.Type` is a supported type (`JsonWebSignature2020`). Reject unknown types explicitly.
    2. Validate that `proof.Created` is present and non-empty. Optionally enforce a timestamp skew window.
    3. Validate that `proof.JWS` is present.
    4. Unmarshal `documentJSON` into a map, remove the `proof` member.
    5. Build proof options map: `@context` from the document, `type`, `created`, `verificationMethod` (and `proofPurpose`, `challenge`, `domain` if present).
    6. Normalize both document and proof options with URDNA2015 / N-Quads through the provided document loader (reuse exact constants from `AddLinkedDataProof`).
    7. Compute `tbs = sha256(canonicalProofOptions) || sha256(canonicalDocument)` — must match the signing order.
    8. Parse the detached JWS: split `header..signature`, decode the header, verify `b64=false` and `crit=["b64"]`.
    9. Cross-check the `alg` from the JWS header against the key type of the provided `publicKey` (e.g., RS256 requires RSA, ES256 requires EC P-256).
    10. Reconstruct `ASCII(header) || "." || tbs` and verify with `jws.Verify` (or manual signature verification using the reconstructed signing input).

**Tests to add/update:**

- **`common/ldproof_test.go`:**
  - Round-trip test: sign a presentation with `AddLinkedDataProof`, then verify with `VerifyLinkedDataProof`. This pins the canonicalization order and `tbs` computation.
  - Negative table-driven tests:
    - Tampered document content (modified `credentialSubject`).
    - Tampered `proof.created` timestamp.
    - Wrong verification method / key.
    - Algorithm mismatch (e.g., ES256 key with RS256 header).
    - Missing `proof.jws`.
    - Missing `proof.created`.
    - Unknown proof `type`.
    - Malformed JWS (wrong number of parts, missing `b64` header).
  - Test with both RSA and EC keys to verify algorithm cross-checking.

**Acceptance criteria:**
- `VerifyLinkedDataProof` correctly verifies proofs created by `AddLinkedDataProof`.
- All negative cases return specific, documented errors.
- Algorithm cross-checking prevents key-confusion attacks.
- The `tbs` computation order is consistent between signing and verification.
- Tests demonstrate both RSA and EC key support.

---

### Step 6: Implement LDProofChecker and wire into parser (W3)

**Goal:** Create an `LDProofChecker` that uses DID resolution to verify JSON-LD proofs on both VPs and VCs. Wire it into the presentation parser so JSON-LD VPs and VCs are cryptographically verified. Update the fail-closed logic from Step 1 to use the new checker instead of rejecting outright.

**Files to modify:**

- **`verifier/ld_proof_checker.go`** (new file):
  - Define `LDProofChecker` struct holding a `*did.Registry` and a `ld.DocumentLoader` (the caching loader from Step 3).
  - Add `NewLDProofChecker(registry *did.Registry, docLoader ld.DocumentLoader) *LDProofChecker`.
  - Add `VerifyPresentation(vpJSON []byte, proof *common.LDProof) (jwk.Key, error)`:
    1. Extract the DID from `proof.VerificationMethod` (split on `#` to get the DID, use the fragment to select the key).
    2. Resolve the DID via the `did.Registry` — reuse `resolveKey` logic factored out from `JWTProofChecker.resolveKey` (or call a shared helper).
    3. Call `common.VerifyLinkedDataProof(vpJSON, proof, key, docLoader)`.
    4. Return the resolved key (analogous to `JWTProofChecker.VerifyJWTAndReturnKey` returning the signer key for holder binding).
  - Add `VerifyCredential(vcJSON []byte, proof *common.LDProof) error`:
    1. Same DID resolution + key resolution flow.
    2. Call `common.VerifyLinkedDataProof(vcJSON, proof, key, docLoader)`.
  - Explicitly reject `did:elsi` in the LD-proof path — JAdES is JWS-based and does not apply to LD proofs. Return a clear error.

- **`verifier/key_resolver.go`** (new file or refactor from `jwt_proof_checker.go`):
  - Factor out the DID-to-key resolution logic from `JWTProofChecker.resolveKey` (line 106) into a shared function: `ResolveKeyFromDID(registry *did.Registry, didStr string, keyID string) (jwk.Key, error)`.
  - Update `JWTProofChecker.resolveKey` to delegate to the shared function.
  - This avoids code duplication between `JWTProofChecker` and `LDProofChecker`.

- **`verifier/presentation_parser.go`:**
  - Add `LDProofChecker *LDProofChecker` field to `ConfigurablePresentationParser` (alongside existing `ProofChecker *JWTProofChecker`).
  - Update `parseJSONLDPresentation` (currently fails closed from Step 1):
    - If `LDProofChecker` is available and VP has proofs, verify each proof via `LDProofChecker.VerifyPresentation`. Store the signer key via `pres.SetHolderKey(key)` for downstream holder binding.
    - If `LDProofChecker` is nil and VP has proofs, continue to return `ErrorInvalidProof` (fail-closed behavior from Step 1).
    - If VP has no proofs, continue to reject.
  - Update JSON-LD VC handling within `parseJSONLDPresentation`: for each VC with LD proofs, verify via `LDProofChecker.VerifyCredential`.
  - JWT VCs embedded in JSON-LD VPs continue to be verified via `JWTProofChecker` (from Step 1).

- **`verifier/presentation_parser.go` (`InitPresentationParser`):**
  - Construct an `LDProofChecker` using the same `did.Registry` as `JWTProofChecker` and the caching document loader from `common`.
  - Store it in `ConfigurablePresentationParser.LDProofChecker`.
  - Expose it via a `GetLDProofChecker()` accessor (analogous to `GetProofChecker()`).

**Tests to add:**

- **`verifier/ld_proof_checker_test.go`** (new file):
  - Table-driven tests for `VerifyPresentation`: valid VP with did:key, valid VP with did:web (mock HTTP server for DID document), invalid signature, unresolvable DID, did:elsi rejection.
  - Table-driven tests for `VerifyCredential`: valid VC with did:key proof, tampered VC, wrong key.
  - Test shared key resolution: verify that `ResolveKeyFromDID` returns the correct key for a given verification method fragment.

- **`verifier/presentation_parser_test.go`:**
  - Update the fail-closed tests from Step 1: when `LDProofChecker` is configured, a valid JSON-LD VP with correct proof should now be accepted.
  - Test end-to-end: create a VP with `AddLinkedDataProof`, parse it with `ParsePresentation`, verify it returns valid credentials with holder key set.
  - Test that a JSON-LD VP with an invalid proof is rejected even when `LDProofChecker` is configured.

**Acceptance criteria:**
- JSON-LD VPs with valid LD proofs are accepted and their credentials are returned.
- JSON-LD VPs with invalid or missing proofs are rejected.
- JSON-LD VCs within a VP have their proofs verified individually.
- The VP signer key is available for downstream holder binding.
- `did:elsi` + LD-proof is explicitly rejected.
- Key resolution logic is shared between `JWTProofChecker` and `LDProofChecker`.
- All existing JWT VP and SD-JWT tests continue to pass.

---

### Step 7: VP-level proof semantics and holder binding for JSON-LD (W5)

**Goal:** Complete the VP-level security properties for JSON-LD presentations: challenge/domain binding (replay prevention) and holder key binding. Without these, a verified VP is still replayable and holder identity is not established.

**Files to modify:**

- **`verifier/presentation_parser.go`:**
  - In `parseJSONLDPresentation`, after verifying the VP proof via `LDProofChecker`:
    - Check `proof.Challenge` against the expected session nonce. The nonce comes from the session management layer — thread the expected nonce through the parser (add a `nonce` parameter to `parseJSONLDPresentation` or store it in the parser context).
    - Check `proof.Domain` against the verifier's client ID / audience, if present.
    - If `challenge` or `domain` are present in the proof but do not match expected values, return a new error `ErrorProofChallengeMismatch` / `ErrorProofDomainMismatch`.
  - Store the LD-proof signer key via `pres.SetHolderKey(key)` (already handled in Step 6) so `verifyCnfBinding` works for JSON-LD VPs.

- **`verifier/verifier.go`:**
  - `verifyVPSignatureIfRequired` (line 1092): Currently returns immediately when `rawToken == nil` (which is the case for JSON-LD VPs). Update this to also check JSON-LD VPs: if the presentation has a holder key set (from LD-proof verification), holder verification is already done by the parser — no additional work needed. But if holder binding is required and no holder key is available, return an error.
  - Ensure the nonce/challenge expected by the JSON-LD VP proof path is derived from the same session nonce used for JWT VPs.

- **`common/credential.go`:**
  - Consider adding a `rawJSON` field to `Presentation` (similar to `Credential.rawJSON`) to store the original VP JSON for canonicalization. If not already stored, add it in the JSON-LD parsing path.

**Tests to add/update:**

- **`verifier/presentation_parser_test.go`:**
  - Test challenge binding: VP with correct `proof.challenge` matching session nonce — accepted. VP with wrong challenge — rejected.
  - Test domain binding: VP with `proof.domain` matching verifier's audience — accepted. Wrong domain — rejected.
  - Test holder key propagation: after parsing a JSON-LD VP, `pres.HolderKey()` returns the LD-proof signer key.

- **`verifier/verifier_test.go`:**
  - Test that `verifyVPSignatureIfRequired` correctly handles JSON-LD VPs with holder key from LD-proof.
  - Test that JSON-LD VPs without holder key are rejected when holder binding is required.

**Acceptance criteria:**
- JSON-LD VP `proof.challenge` is bound to the session nonce.
- JSON-LD VP `proof.domain` is validated when present.
- Holder binding works for JSON-LD VPs via the LD-proof signer key.
- `verifyVPSignatureIfRequired` handles JSON-LD VPs correctly.
- Replay attacks using captured JSON-LD VPs are prevented by challenge binding.

---

### Step 8: Log ldp_vc configuration warning, status-list LD-proof awareness, and integration tests (C4 + final verification)

**Goal:** Add a startup warning when `ldp_vc` format is configured (honest about current verification state), add awareness of JSON-LD status list credential proofs, and run comprehensive integration-level tests to verify the entire LD-proof verification chain end-to-end.

**Files to modify:**

- **`verifier/credentialsConfig.go`** or **`verifier/verifier.go`** (wherever credentials config is loaded):
  - During initialization, iterate configured credentials. If any credential uses `ldp_vc` format, log a prominent `Info` message noting that LD-proof verification is now enforced for this format and submissions without valid proofs will be rejected.

- **`verifier/credential_status_client.go`:**
  - Update `parseStatusListCredentialBody` for JSON-LD path: instead of unconditionally rejecting JSON-LD status list credentials (from Step 1), accept them if a `proof` member is present and can be verified via the `LDProofChecker`. Add an optional `LDProofChecker` parameter (or make it available through the struct). If no checker is available or no proof is present, continue to reject.

- **`verifier/ldproof_integration_test.go`** (new file):
  - End-to-end test: construct a JSON-LD VP with a did:key issuer, sign with `AddLinkedDataProof`, submit to the full parsing + verification pipeline, verify the presentation contains the expected credentials.
  - End-to-end test with did:web: mock HTTP server serving a DID document, construct and sign VP, verify parsing succeeds.
  - Negative end-to-end test: submit an unsigned JSON-LD VP, verify it is rejected at the parser level.
  - Negative test: submit a JSON-LD VP with tampered credential content, verify rejection.
  - Status list test: JSON-LD `BitstringStatusListCredential` with invalid proof — verify rejection.
  - Status list test: JSON-LD status list credential with valid proof — verify acceptance.
  - Regression test: verify JWT VPs, SD-JWT VPs, and did:elsi credentials continue to work unchanged.

**Verification steps:**
- Run `go build ./...` — must succeed with no errors.
- Run `go vet ./...` — must succeed with no warnings.
- Run `go test ./... -v` — all tests must pass.
- Run `go test ./... -v -coverprofile=profile.cov` — verify coverage of new LD-proof code paths.

**Acceptance criteria:**
- Startup info message logged when `ldp_vc` format is configured.
- JSON-LD status list credentials with valid proofs are accepted.
- JSON-LD status list credentials without valid proofs are rejected.
- Full end-to-end test coverage for the LD-proof verification chain.
- All existing tests pass — no regressions.
- Build and vet are clean.
