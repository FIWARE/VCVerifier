# Release Notes: Remove trustbloc dependencies

## Summary

All three `trustbloc` libraries (`did-go`, `vc-go`, `kms-go`) and their transitive dependencies (`bbs-signature-go`, `sidetree-go`) have been replaced with custom, in-project implementations. This eliminates a set of unmaintained third-party dependencies while preserving full functional equivalence.

**Net change**: +5,213 lines / -1,146 lines across 59 files.

## What changed

### New packages

- **`did/`** — Custom DID resolution for `did:key`, `did:web`, and `did:jwk` methods, with a pluggable multi-method registry.
- **`common/credential.go`** — Project-local Verifiable Credential and Verifiable Presentation types (`Credential`, `Presentation`, `CredentialContents`, etc.), replacing `trustbloc/vc-go/verifiable`.
- **`common/vc_parser.go`** — Custom VP/VC parsing for both JSON-LD and JWT formats, with signature verification via `lestrrat-go/jwx` and the custom DID resolver.
- **`common/sdjwt.go`** — Custom SD-JWT parsing and verification (disclosure decoding, `_sd` digest matching, issuer signature verification, key binding JWT support).
- **`common/ldproof.go`** — Linked Data Proof creation for M2M token signing, replacing `vc-go/proof/creator` and related proof libraries.
- **`verifier/jwt_proof_checker.go`** — JWT proof checker replacing `trustbloc/vc-go/proof/checker` and the old `elsi_proof_checker.go`.

### Modified packages

- **`verifier/`** — All core verifier code (`verifier.go`, `presentation_parser.go`, `jwt_verifier.go`, `key_resolver.go`, `holder.go`, `trustedissuer.go`, `trustedparticipant.go`, `compliance.go`, `gaiax.go`, `request_object_client.go`) migrated from trustbloc types to local types.
- **`openapi/`** — HTTP handlers updated to use local credential/presentation types.
- **`tir/tokenProvider.go`** — M2M token provider rewritten to use local LD-proof creation and credential parsing instead of trustbloc's proof creator and verifiable credential library.
- **`gaiax/gaiaXClient.go`** — DID resolution switched from trustbloc VDR to custom `did/` package.

### Removed

- `verifier/elsi_proof_checker.go` — Replaced by `verifier/jwt_proof_checker.go`.
- All `trustbloc` imports across the entire codebase.
- 5 direct/indirect trustbloc dependencies from `go.mod` (`did-go`, `vc-go`, `kms-go`, `bbs-signature-go`, `sidetree-go`), along with ~120 lines of transitive dependencies from `go.sum`.

### Test coverage

Comprehensive tests were added before and during the migration for all replaced code paths, including `key_resolver_test.go`, `jwt_verifier_test.go`, `presentation_parser_test.go`, `trustedissuer_test.go`, `jwt_proof_checker_test.go`, `sdjwt_test.go`, `credential_test.go`, and all DID resolver tests.

## Migration steps (for reference)

The work was done incrementally across 13 PRs (#1-#12):

0. Added missing tests for trustbloc-dependent code
1. Introduced local credential/presentation types
2. Created custom DID resolution package
3-5. Replaced DID resolution across `jwt_verifier`, `key_resolver`, `request_object_client`, `api_api`, and `gaiax`
6. Migrated all production and test code to local types
7. Custom VP/VC parsing (replaced `verifiable.ParsePresentation`)
8. Custom SD-JWT verification
9. Custom credential content validation
11. Replaced trustbloc in `tir/tokenProvider.go`
12. Removed all trustbloc dependencies and ran `go mod tidy`
