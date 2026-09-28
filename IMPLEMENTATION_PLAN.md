# Implementation Plan: DataIntegrity Proof in VCVerifier

## Overview

Add verification support for W3C Data Integrity `DataIntegrityProof` proofs using the `ecdsa-rdfc-2019` (P-256, P-384) and `eddsa-rdfc-2022` (Ed25519) cryptosuites. This requires: (1) factoring the multibase/multicodec key-decoding logic out of `did/did_key.go` into a shared helper, (2) decoding `publicKeyMultibase` in the DID document parser so `Multikey` verification methods produce usable JWKs, and (3) implementing the Data Integrity signature verification path alongside the existing `JsonWebSignature2020` path in `common/ldproof.go`. The JCS-based suites (`ecdsa-jcs-2019`, `eddsa-jcs-2022`) are included as a final optional step.

## Steps

### Step 1: Extract multibase/multicodec key decoding into a shared helper

Factor the multicodec-to-JWK conversion logic out of `did/did_key.go` into a new shared file `did/multikey.go`. This helper will be reusable by both `did:key` resolution and `publicKeyMultibase` decoding in DID documents.

**Files to create:**
- `did/multikey.go` — New file containing:
  - `TypeMultikey = "Multikey"` constant for the W3C Multikey verification method type.
  - `DecodeMultibaseKey(multibaseEncoded string) (jwk.Key, error)` — Takes a multibase-encoded string (e.g. `z6Mk...`), decodes the multibase encoding, reads the multicodec varint prefix, and delegates to the existing codec-specific conversion logic. Returns a `jwk.Key`.
  - `MulticodecToJWK(codec uint64, rawKey []byte) (jwk.Key, error)` — Exported version of the existing `multicodecToJWK` function, supporting `0xed` (Ed25519), `0x1200` (P-256), `0x1201` (P-384). The second return value (vmType string) from the current function is no longer needed by callers of the public API — the type is always `Multikey` in this context — but may be kept internally.
  - Move `decodeCompressedEC` to this file as well (it is only used by the multicodec converter).
  - Move multicodec prefix constants (`multicodecEd25519Pub`, `multicodecP256Pub`, `multicodecP384Pub`, `multicodecSecp256k1Pub`) to this file and export them.
- `did/multikey_test.go` — Tests for `DecodeMultibaseKey` with:
  - Valid Ed25519 multibase key → correct JWK key type (OKP, Ed25519)
  - Valid P-256 multibase key (compressed) → correct JWK key type (EC, P-256)
  - Valid P-384 multibase key (compressed) → correct JWK key type (EC, P-384)
  - Invalid multibase encoding → error
  - Unknown multicodec prefix → error
  - Truncated key data → error

**Files to modify:**
- `did/did_key.go` — Remove the moved functions and constants; import and call `MulticodecToJWK` (or the internal `multicodecToJWK` if kept unexported and just relocated) from the `Read` method. The `multicodecToJWK` call at line 89 becomes a call to the helper in `multikey.go`.

**Acceptance criteria:**
- All existing `did/did_key_test.go` tests pass unchanged.
- `DecodeMultibaseKey` is independently tested with parameterized test cases for each supported curve.
- No duplicate code between `did_key.go` and `multikey.go`.

---

### Step 2: Decode `publicKeyMultibase` in the DID document parser

Make `parseVerificationMethod` in `did/did_web.go` decode `publicKeyMultibase` values into JWKs using the shared helper from Step 1, so that `Multikey` verification methods produce a non-nil `JSONWebKey()`. This is the prerequisite the ticket identifies: without it, a DI credential fails at key resolution before reaching any signature check.

**Files to modify:**
- `did/did_web.go` — In `parseVerificationMethod` (line 216–218), when `publicKeyMultibase` is non-empty and `publicKeyJwk` is absent:
  1. Call `DecodeMultibaseKey(raw.PublicKeyMultibase)`.
  2. On success, set `vm.jsonWebKey = key` and `vm.Value = []byte(raw.PublicKeyMultibase)`.
  3. On failure, log a debug message and leave `vm.jsonWebKey` as nil (deferred failure at parse time — key resolution rejects the VM later via `ErrorNoVerificationKey`).
  
  This means `Multikey`, `Ed25519VerificationKey2020`, and any other type that uses `publicKeyMultibase` will now produce a usable JWK. The existing `publicKeyJwk` path remains the priority.

**Files to create:**
- `did/did_web_multikey_test.go` — Tests for DID document resolution with `publicKeyMultibase` verification methods:
  - A `did:web` document with a `Multikey` VM using Ed25519 `publicKeyMultibase` → `JSONWebKey()` returns non-nil OKP key.
  - A `did:web` document with a `Multikey` VM using P-256 `publicKeyMultibase` → `JSONWebKey()` returns non-nil EC key.
  - A `did:web` document with both `publicKeyJwk` and `publicKeyMultibase` → JWK takes priority.
  - A `did:web` document with invalid `publicKeyMultibase` → `JSONWebKey()` returns nil, no panic.
  - Integration test: resolve key via `key_resolver.go` for a DID with a `Multikey` VM → key resolves successfully.

**Acceptance criteria:**
- `vm.JSONWebKey()` returns a valid key for Multikey verification methods with Ed25519, P-256, and P-384 `publicKeyMultibase` values.
- Existing `publicKeyJwk`-based verification methods continue to work unchanged.
- `verifier/key_resolver.go` resolves keys from Multikey VMs without any changes to its own code.

---

### Step 3: Implement Data Integrity proof verification core

Add the cryptographic verification logic for `DataIntegrityProof` proofs with the `ecdsa-rdfc-2019` and `eddsa-rdfc-2022` cryptosuites. These use `proofValue` (multibase-encoded raw signature) instead of `jws`, and the same URDNA2015/RDFC-1.0 canonicalization the existing code already performs.

**Signature verification algorithm (per W3C Data Integrity specs):**
1. Validate proof type is `DataIntegrityProof` and `cryptosuite` is recognized.
2. Validate `created` is non-empty (same as JWS path).
3. Decode `proofValue` from multibase encoding. The raw bytes are in IEEE P1363 format for ECDSA (`r || s`, each zero-padded to the curve's field size — 32 bytes for P-256, 48 bytes for P-384), not ASN.1 DER. In Go, use `ecdsa.Verify(pubKey, hash, r, s)` with `r` and `s` extracted from the P1363 byte layout, **not** `ecdsa.VerifyASN1`.
4. Unmarshal document, strip `proof`, build proof options (with `cryptosuite` field included).
5. Canonicalize both document and proof options using URDNA2015 (same `json-gold` `Normalize` already in use — RDFC-1.0 is URDNA2015 standardized).
6. Assert proof options are covered (same `assertProofOptionsCovered` logic, extended for `cryptosuite` — see below).
7. Compute hash data (curve-conditional per W3C VC-DI-ECDSA §3.3.3/§3.3.4):
   - P-256 and Ed25519: `hashData = sha256(canonProofOptions) || sha256(canonDoc)`.
   - P-384: `hashData = sha384(canonProofOptions) || sha384(canonDoc)`.
8. Verify raw signature over `hashData`:
   - `ecdsa-rdfc-2019`: ECDSA verification — `ecdsa.Verify(pubKey, hashData, r, s)`. The `hashData` already contains the final hash (SHA-256 for P-256, SHA-384 for P-384); **no additional hashing** is applied by the verification step.
   - `eddsa-rdfc-2022`: Ed25519 signature over the hash data directly (`ed25519.Verify(pubKey, hashData, sig)`).

**Files to modify:**
- `common/ldproof.go`:
  - Add constants: `ProofTypeDataIntegrityProof = "DataIntegrityProof"`, `CryptosuiteEcdsaRdfc2019 = "ecdsa-rdfc-2019"`, `CryptosuiteEddsaRdfc2022 = "eddsa-rdfc-2022"`.
  - Add new error sentinel: `ErrorLDProofMissingProofValue`, `ErrorLDProofMalformedProofValue`, `ErrorLDProofUnsupportedCryptosuite`, `ErrorLDProofCryptosuiteKeyMismatch`.
  - Add `VerifyDataIntegrityProof(documentJSON []byte, proof *LDProof, publicKey jwk.Key, documentLoader ld.DocumentLoader) error` — the DI counterpart to `VerifyLinkedDataProof`. This function:
    - Validates `proof.Type == ProofTypeDataIntegrityProof`.
    - Validates `proof.Cryptosuite` is one of the two recognized suites.
    - Validates `proof.Created` is non-empty.
    - Validates `proof.ProofValue` is non-empty.
    - Decodes `proofValue` with `multibase.Decode`.
    - Strips proof from document, builds proof options (including `cryptosuite` in the options map).
    - Canonicalizes both with URDNA2015.
    - Asserts proof options are covered.
    - Computes hash data (curve-conditional): P-256 and Ed25519 use `sha256(canonProofOptions) || sha256(canonDoc)`; P-384 uses `sha384(canonProofOptions) || sha384(canonDoc)` (per W3C VC-DI-ECDSA §3.3.4).
    - For `ecdsa-rdfc-2019`: validates key is EC (P-256 or P-384), decodes `proofValue` from IEEE P1363 format (`r || s`), verifies ECDSA signature over `hashData` directly using `ecdsa.Verify` (no additional hashing — `hashData` is already the final digest).
    - For `eddsa-rdfc-2022`: validates key is OKP/Ed25519, verifies Ed25519 signature over `hashData` directly.
  - Modify `buildProofOptions` to include `cryptosuite` when present on the proof — add `if proof.Cryptosuite != "" { proofOptions[LDProofKeyCryptosuite] = proof.Cryptosuite }`.
  - Extend `assertProofOptionsCovered` to check both the `cryptosuite` IRI (`https://w3id.org/security#cryptosuite`) **and** its canonicalized object value (the literal string, e.g. `"ecdsa-rdfc-2019"`) against the expected value from the proof. Since `cryptosuite` is typed `cryptosuiteString` (a plain literal), the canonicalized value is directly comparable — match it against `expectedObject` the same way `created` and `challenge` are checked.
  - For the proof options context: Data Integrity proof terms (`cryptosuite`, `proofValue`) are defined by the VCDM 2.0 context (`https://www.w3.org/ns/credentials/v2`), which is already vendored as `credentials-v2.jsonld`. Use this as the proof suite context for Data Integrity proofs (the DI counterpart of `https://w3id.org/security/suites/jws-2020/v1` for JWS-2020). Do **not** add `https://w3id.org/security/data-integrity/v2` — the VCDM 2.0 context already defines all the needed terms, and adding a second context would change the canonicalization. Add an `EnsureDataIntegrityContext` function that ensures the VCDM 2.0 context is present in the proof options document (or a more general `EnsureProofContext` that selects between JWS-2020 and VCDM 2.0 based on proof type).

**Files to create:**
- `common/data_integrity_test.go` — Tests for `VerifyDataIntegrityProof`:
  - Test with valid `ecdsa-rdfc-2019` P-256 proof → success.
  - Test with valid `ecdsa-rdfc-2019` P-384 proof → success.
  - Test with valid `eddsa-rdfc-2022` Ed25519 proof → success.
  - Test with tampered document → signature verification fails.
  - Test with tampered `proofValue` → fails.
  - Test with wrong key type for cryptosuite → `ErrorLDProofCryptosuiteKeyMismatch`.
  - Test with unsupported cryptosuite → `ErrorLDProofUnsupportedCryptosuite`.
  - Test with missing `proofValue` → `ErrorLDProofMissingProofValue`.
  - Test with missing `created` → `ErrorLDProofMissingCreated`.
  - Test with invalid multibase in `proofValue` → `ErrorLDProofMalformedProofValue`.
  - All tests use table-driven pattern with `t.Run`.

**Note on test vectors:** Generate test credentials and signatures in the test setup using Go's `crypto/ecdsa`, `crypto/ed25519`, and the existing canonicalization + hashing code. This avoids depending on external test vector files while still being cryptographically rigorous.

**Acceptance criteria:**
- `VerifyDataIntegrityProof` correctly verifies all three key types (P-256, P-384, Ed25519).
- Tampered documents and signatures are rejected.
- Key-type/cryptosuite mismatches are caught with descriptive errors.
- `assertProofOptionsCovered` covers the `cryptosuite` field.
- Proof options canonicalization works correctly with the Data Integrity context.

---

### Step 4: Integrate Data Integrity verification into the proof dispatch chain

Wire `VerifyDataIntegrityProof` into the existing proof verification pipeline so that `DataIntegrityProof` proofs are verified end-to-end through the same `LDProofChecker` → `common.Verify*` flow as `JsonWebSignature2020` proofs.

**Files to modify:**
- `verifier/ld_proof_checker.go`:
  - Modify `verifyLDProofWithCandidateKeys` (line 227) to dispatch based on proof type:
    - If `proof.Type == common.ProofTypeJsonWebSignature2020` → call `common.VerifyLinkedDataProof` (existing behavior).
    - If `proof.Type == common.ProofTypeDataIntegrityProof` → call `common.VerifyDataIntegrityProof`.
    - Otherwise → return `common.ErrorLDProofUnsupportedType`.
  - No changes needed to `VerifyPresentation` or `VerifyCredential` — they already delegate to `verifyLDProofWithCandidateKeys` which will now handle both proof types.

- `verifier/presentation_parser.go` — Verify that the VP token parsing path for `ldp_vc` presentations correctly passes through Data Integrity proofs. The existing `ParseLDProof` already parses `proofValue` and `cryptosuite`, so this should work without changes. Verify and document.

**Files to modify (verification flow):**
- `verifier/ld_proof_checker.go` — The `VerifyLDVPProofFreshness` function: confirm it works for Data Integrity proofs, since it reads `proof.Created` which is present on DI proofs. No changes expected.
- `verifier/ld_proof_checker.go` — The `VerifyLDVPProofBinding` function: confirm it works for Data Integrity proofs (challenge + domain binding). No changes expected since it reads `proof.Challenge` and `proof.Domain`.

**Files to create/modify for tests:**
- `verifier/ld_proof_checker_test.go` — Add integration test cases:
  - Verify a credential with a valid `DataIntegrityProof` (`ecdsa-rdfc-2019`, P-256) → success.
  - Verify a credential with a valid `DataIntegrityProof` (`eddsa-rdfc-2022`, Ed25519) → success.
  - Verify a presentation with a valid `DataIntegrityProof` → success, correct holder binding.
  - Verify a credential where the proof signer does not match the issuer → `ErrorProofIssuerMismatch`.
  - Verify with wrong proof purpose → `ErrorProofPurposeMismatch`.
  - The tests should use DID documents with `Multikey` verification methods (testing the Step 1+2 integration).

**Acceptance criteria:**
- A `DataIntegrityProof` credential or presentation is verified end-to-end through the same `LDProofChecker` API as `JsonWebSignature2020`.
- All existing `JsonWebSignature2020` tests still pass.
- Issuer/holder binding, proof purpose, and proof freshness checks work identically for both proof types.
- A `DataIntegrityProof` with an unrecognized `cryptosuite` is rejected with `ErrorLDProofUnsupportedCryptosuite`.

---

### Step 5: End-to-end tests and documentation

Add comprehensive end-to-end tests that exercise the full verification pipeline from VP token parsing through credential verification, and update documentation.

**Files to create:**
- `verifier/data_integrity_e2e_test.go` — End-to-end tests:
  - Construct a JSON-LD Verifiable Presentation containing a Verifiable Credential, both signed with `DataIntegrityProof` (`ecdsa-rdfc-2019`), with `Multikey` verification methods in the DID documents. Parse the VP token, verify the presentation proof, extract and verify the credential proof — the full `ldp_vc` pipeline.
  - Same with `eddsa-rdfc-2022`.
  - Mixed: presentation signed with `JsonWebSignature2020`, credential signed with `DataIntegrityProof` (and vice versa) — both proof types coexist.
  - Credential with `Multikey` VM using `publicKeyMultibase` in a `did:web` document → key resolves, proof verifies.
  - VP with `DataIntegrityProof` on the `vp_token` grant type → freshness check applies to `proof.created`.

**Files to modify:**
- `CLAUDE.md` — Update the "Known Gaps" section to remove the item about Data Integrity suites being parsed but not verified. Add a note about supported cryptosuites (`ecdsa-rdfc-2019`, `eddsa-rdfc-2022`). Update the architecture section to mention Data Integrity proof support in `common/ldproof.go`. Note that JCS-based suites are optionally supported if Step 6 is included.
- `docs/json-ld-proof-verification.md` — Add a section on Data Integrity proof verification, describing the `VerifyDataIntegrityProof` function, the supported cryptosuites, the signature verification algorithm, and the `Multikey` verification method support.

**Acceptance criteria:**
- End-to-end tests demonstrate the full pipeline for Data Integrity proofs.
- Mixed proof type scenarios (JWS + DI) work correctly.
- Documentation accurately reflects the new capabilities.
- `go test ./... -v` passes with all new and existing tests.

---

### Step 6: (Optional) JCS-based cryptosuites (`ecdsa-jcs-2019`, `eddsa-jcs-2022`)

Add support for the JCS (JSON Canonicalization Scheme, RFC 8785) variants of the Data Integrity cryptosuites. These use JCS instead of RDFC-1.0 for canonicalization.

**Dependencies:**
- Add a JCS library dependency. The Go ecosystem has `github.com/nicholasgasior/gojcs` or `github.com/nicholasgasior/go-jcs`, or implement RFC 8785 canonicalization (deterministic JSON serialization) using `encoding/json` with sorted keys — RFC 8785 is relatively simple. The `golangs.org/x/exp/json` package or `github.com/nicholasgasior/gojcs` may be suitable. Evaluate and select.

**Files to modify:**
- `common/ldproof.go`:
  - Add constants: `CryptosuiteEcdsaJcs2019 = "ecdsa-jcs-2019"`, `CryptosuiteEddsaJcs2022 = "eddsa-jcs-2022"`.
  - Modify `VerifyDataIntegrityProof` to handle JCS suites. The JCS suites differ from RDFC suites in:
    1. Canonicalization: use JCS (RFC 8785) instead of URDNA2015.
    2. The proof options document: JCS suites canonicalize a JSON object (not JSON-LD), so no `@context` is needed.
    3. The hash data construction is similar: curve-conditional as in the RDFC path (SHA-256 for P-256/Ed25519, SHA-384 for P-384).
  - Factor the common signature verification logic (multibase decode, key type check, ECDSA/EdDSA verify) into a shared helper called by both RDFC and JCS paths.

**Files to create:**
- `common/jcs.go` — JCS canonicalization implementation or thin wrapper around a library.
- `common/jcs_test.go` — Tests for JCS canonicalization with RFC 8785 test vectors.
- `common/data_integrity_jcs_test.go` — Tests for `VerifyDataIntegrityProof` with JCS suites:
  - Valid `ecdsa-jcs-2019` P-256 proof → success.
  - Valid `eddsa-jcs-2022` Ed25519 proof → success.
  - Tampered document → fails.

**Acceptance criteria:**
- JCS canonicalization correctly implements RFC 8785.
- `ecdsa-jcs-2019` and `eddsa-jcs-2022` proofs verify correctly.
- All RDFC suite tests still pass.
- `go test ./... -v` passes.
