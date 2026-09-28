# Release Notes — W3C Data Integrity Proof Support

This release adds verification of [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
proofs (`DataIntegrityProof`) on JSON-LD credentials and presentations, for the two
RDF-canonicalization cryptosuites in common use:

| Cryptosuite | Specification | Keys |
| --- | --- | --- |
| `ecdsa-rdfc-2019` | [VC-DI-ECDSA](https://www.w3.org/TR/vc-di-ecdsa/) | EC P-256, P-384 |
| `eddsa-rdfc-2022` | [VC-DI-EDDSA](https://www.w3.org/TR/vc-di-eddsa/) | Ed25519 |

Until now `JsonWebSignature2020` was the only suite VCVerifier verified. `DataIntegrityProof` is
the securing mechanism VCDM 2.0 defines for JSON-LD, so an issuer following the current W3C
recommendations is more likely to emit one of the suites above than `JsonWebSignature2020` — the
VC 2.0 support shipped previously did not reach the credentials VC 2.0 issuers actually produce.

See [docs/json-ld-proof-verification.md](docs/json-ld-proof-verification.md) for the full design,
including the limitations below.

## Not a security fix

The previous behaviour was already fail-closed. `ParseLDProof` accepted a `proofValue`-based
proof, but `common.VerifyLinkedDataProof` rejected every proof type other than
`JsonWebSignature2020`, so a `DataIntegrityProof` credential was **rejected, not accepted
unverified**. This release closes an interoperability gap, not a hole.

## New Features

### Data Integrity proof verification

`common.VerifyDataIntegrityProof` canonicalizes the document and the proof options with
URDNA2015, computes `hash(canonical proof options) || hash(canonical document)` and verifies the
multibase-encoded raw signature carried in `proofValue`.

The hash is curve-conditional, as the specifications require: SHA-384 for P-384 with
`ecdsa-rdfc-2019`, SHA-256 for P-256 and Ed25519. ECDSA signatures are IEEE P1363 (`r || s`),
Ed25519 signatures are the raw 64 bytes.

The implementation is verified against the **published W3C test vectors** for all three
curve/suite combinations (`common/data_integrity_vectors_test.go`), not only against fixtures
this codebase signs itself.

### `Multikey` verification methods

A Data Integrity verification method normally carries `publicKeyMultibase` rather than
`publicKeyJwk`. The DID document parser previously stored that string without decoding it, so
`JSONWebKey()` returned nil and key resolution failed with `ErrorNoVerificationKey` before any
signature was checked.

`did/multikey.go` now decodes multibase + multicodec public keys (`0xed` Ed25519, `0x1200` P-256,
`0x1201` P-384) for both `did:key` resolution and DID document verification methods. A
verification method whose `publicKeyMultibase` cannot be decoded is skipped rather than aborting
the parse of the whole document.

`secp256k1` (`0xe7`) is recognized and rejected with an explicit error — the curve is not
available in Go's standard library.

### Proof type dispatch

`selectProofVerifier` routes by `proof.type`: `JsonWebSignature2020` to
`common.VerifyLinkedDataProof`, `DataIntegrityProof` to `common.VerifyDataIntegrityProof`, and
**anything else to a rejection** (`ErrorLDProofUnsupportedType`). The dispatch is exhaustive; an
unrecognized proof type is never reinterpreted as a supported one.

Every other check applies to Data Integrity proofs unchanged, because the dispatch sits below
them: issuer/holder binding of the verification method, the required proof purpose
(`assertionMethod` for credentials, `authentication` for presentations), verification
relationship enforcement, `challenge`/`domain` binding, proof freshness and holder binding. The
`cryptosuite` is part of the signed proof options and is asserted to be covered by the signature,
so one suite's signature cannot be replayed as another's.

Both proof families can appear in the same presentation: a `JsonWebSignature2020` presentation may
carry `DataIntegrityProof` credentials and vice versa.

## Configuration

None. No new configuration keys; Data Integrity proofs are verified wherever
`JsonWebSignature2020` proofs already were.

## Scope and Limitations

Out of scope for this release:

- **The JCS cryptosuites** (`ecdsa-jcs-2019`, `eddsa-jcs-2022`), which canonicalize with
  RFC 8785 instead of RDFC-1.0.
- **The selective-disclosure suites** (`bbs-2023`, `ecdsa-sd-2023`), which involve derived proofs.
- **Proof sets and proof chains** (`previousProof`).
- **Data Integrity on VCDM 1.1 documents**, which would additionally require vendoring the
  `https://w3id.org/security/data-integrity/v2` context.

Known limitations of what is implemented, all of which reject a conformant proof rather than
accept a bad one:

- **The proof options are rebuilt from a fixed set of fields** (`type`, `created`,
  `verificationMethod`, `proofPurpose`, `challenge`, `domain`, `cryptosuite`) instead of being
  copied from the proof, as VC-DI-ECDSA §3.2.5 specifies. A proof carrying any other member —
  `expires`, `nonce`, `id`, `previousProof` — canonicalizes differently for the verifier than it
  did for the issuer, and its signature does not verify.
- **`created` is required**, although VC-DATA-INTEGRITY §2.1 makes it optional. It is needed for
  the freshness check on presentations; on credential proofs it is an added restriction.
- **The proof options `@context` is extended rather than copied.** The VCDM 2.0 context is
  appended when absent, where the specification uses the document's context verbatim. For a
  VCDM 2.0 document — which is what a Data Integrity credential carries — the two are the same.
