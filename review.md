# Code Review — PR #116 "Ticket 54/work"

**Repo:** FIWARE/VCVerifier · **Base:** `main` (`0b9960b`) · **Head:** `ticket-54/work` (`ba3f8f4`)
**Size:** 42 files, +7859 / −417
**Build/tests:** `go build` OK, `go vet` clean, `go test ./...` all packages pass.

**Round 2 — re-review after remediation (commits `f57c1fd`, `ba3f8f4`).**
Round 1 raised 4 critical, 4 major and 8 minor findings. All 16 are resolved. Each of the four attacks
from round 1 was re-run against the current branch and is now blocked. See
[Verification](#verification-of-the-fixes) for the evidence and [Remaining notes](#remaining-notes) for
the one housekeeping item and three deployment-behaviour changes worth knowing about before merge.

---

## Verdict

**Approve, after removing `review.md` from the branch.**

The remediation did not paper over the findings — it fixed the underlying cause of each. The two that
mattered most were structural, and both were addressed at the root rather than at the symptom:

- The proof-options canonicalization now carries the JsonWebSignature2020 suite context, so the proof
  metadata is genuinely inside the signature — *and* a guard (`assertProofOptionsCovered`) turns any
  future regression of that property into a hard failure instead of a silent downgrade. That guard is the
  part I'd call out as the right instinct: it defends the invariant, not just the instance.
- Signature verification is now bound to identity in both directions — issuer for credentials, holder for
  presentations, plus proof purpose and DID-Core verification relationships. "A valid signature by an
  unrelated key is rejected" is now true, and the doc comment on `LDProofChecker` says so explicitly.

The security-relevant contexts are vendored into the binary and I verified both are byte-for-byte
JSON-equal to what `w3.org` and `w3id.org` serve today. That removes a network dependency from the
verification path and closes the "hostile context host changes what a document canonicalizes to" angle
that round 1 did not raise.

---

## Verification of the fixes

Each round-1 attack was reconstructed against the current code. Results:

| # | Round-1 attack | Round-2 result |
|---|---|---|
| 1 | Rewrite `challenge` on a captured VP to a fresh session nonce | `ld_proof_verify_signature_failed` |
| 1 | Rewrite `domain` / `created` | `ld_proof_verify_signature_failed` |
| 1 | Omit `challenge`+`domain` to opt out of binding | signature fails **and** `vp_proof_challenge_mismatch` |
| 1 | Downgrade `proofPurpose` to `assertionMethod` | `ld_proof_purpose_mismatch` |
| 2 | VC signed by attacker key, claiming a trusted issuer | `ld_proof_signer_is_not_the_credential_issuer` |
| 2 | VP signed by attacker key, claiming a victim holder | `ld_proof_signer_is_not_the_presentation_holder` |
| 3 | Unsigned JSON-LD VC inside a validly signed VP | `unsigned_credential_not_accepted` |
| 4 | JSON-LD VC smuggled through a JWT VP | routed through `parseAndVerifyJSONLDCredential` — same rejections |

Note the defence in depth on the omitted-`challenge` case: because absent proof fields change the
canonical proof options, removing them now breaks the signature *and* is caught by the binding check.

Interop and shape edge cases, all verified passing: document `@context` without the suite context;
`@context` as a bare string rather than an array; `issuer` in object (`{"id": ...}`) form. Forcing the
suite context into the proof options only — never into the verified document — is what makes the first
case work, and it is the right call.

---

## Finding-by-finding

### Critical

**1. Proof options not covered by the signature** — *resolved.*
`buildProofOptions` (`common/ldproof.go:330`) runs the context through `EnsureSuiteContext`, so
`created`, `verificationMethod`, `proofPurpose`, `challenge` and `domain` all expand and land in the
canonical form. `assertProofOptionsCovered` (`:354`) then asserts each populated field produced its
expected IRI, on both the signing and the verifying side, failing with
`ErrorLDProofOptionsNotCovered` otherwise. The vendored context (`common/contexts/jws-2020-v1.jsonld`)
matches `https://w3id.org/security/suites/jws-2020/v1` exactly.

**2. Proof key not bound to issuer / holder** — *resolved.*
`LDProofChecker.VerifyCredential` and `VerifyPresentation` (`verifier/ld_proof_checker.go:73,113`) now
take the expected identity, refuse an empty one (`ErrorMissingProofSubject`), require the matching proof
purpose (`assertProofPurpose`), require `verificationMethod`'s DID to equal that identity
(`assertProofSigner`), and resolve the key through `ResolveKeyForRelationship` so it must be authorized
for `authentication` / `assertionMethod`. `did:key` and `did:jwk` were updated to declare both
relationships and `did:web` now parses them, including embedded methods and relative `#fragment`
references. The status-list path got the same treatment from both ends: the proof must be by the status
list's own issuer, and `assertStatusListIssuer` requires that issuer to be the issuer of the referencing
credential — applied to cache hits too, so a list fetched for one issuer can't answer for another.

**3. Unsigned JSON-LD credentials accepted** — *resolved.*
`parseAndVerifyJSONLDCredential` (`verifier/presentation_parser.go:536`) rejects zero proofs with
`ErrorUnsignedCredential` and a nil checker with `ErrorInvalidProof`, mirroring the VP-level posture.

**4. JSON-LD credentials in a JWT VP not verified** — *resolved.*
Both VP paths (`:277` and `:517`) now call the same helper, with a comment explaining why the VP
signature says nothing about the credentials it carries. `parseJSONLDCredential` has no remaining callers
that skip verification — the only other one is the status-list path, which verifies first and parses
after. The SD-JWT path accepts credential strings only, so there is no third ingress.

### Major

**5. Tests validated against a synthetic context** — *resolved.* `newTestDocumentLoader` is now
`common.NewEmbeddedContextLoader(nil)`, i.e. the real vendored contexts with no fallback, so a test can
no longer accidentally rely on a term the production context does not define.

**6. `TestParseJSONLDPresentation_ValidVPWithCredentials` tested nothing** — *resolved.* Rewritten to
sign a credential with a separate issuer key, embed it in a holder-signed VP, and assert both the
credential's presence with the correct issuer and the holder key. A companion
`..._CredentialProofsAreEnforced` covers unsigned, wrong-signer and tampered credentials. The dead
`makeMinimalVC` helper is now used by the negative tests.

**7. Binding enforced on only one entry point** — *resolved.* `GenerateToken`
(`verifier/verifier.go:664-670`) now enforces domain binding for the `vp_token` and token-exchange
grants. Requiring a challenge there is correctly identified as impossible — those grants have no
server-issued nonce — and the comment says so rather than leaving it unexplained. The domain asymmetry
is fixed too: `VerifyLDVPProofBinding` treats an absent domain as a mismatch, so omitting the field is
no longer an opt-out.

**8. `CLAUDE.md` stale on arrival** — *resolved.* "Known Gaps" now lists what is actually still true, and
the dangling `caching_client.go` references are gone. `docs/json-ld-proof-verification.md` replaces the
working plan.

### Minor

All eight resolved: gofmt clean on every file this PR touches (`openapi/api_api_test.go` is the only
listed file left and it was already unformatted on `main`); `common.VPKeyProof` is now the single proof-key
constant and `jsonldVPProofKey` is gone; the duplicated `CachingStatusListClient` doc comment is merged
into one; `assertCurveMatchesAlgorithm` checks ES256/384/512 against P-256/384/521;
`signVerifiablePresentation` falls back when `documentLoader` is nil, and `InitM2MTokenProvider` warns
when the configured verification method is not an absolute URI (a relative one would be dropped during
expansion — a nice catch that follows from fixing Finding 1); `main.go` initializes the presentation
parser before the verifier so the status-list client gets a real checker instead of a lazy global; and
`IMPLEMENTATION_PLAN.md` is removed. Proof purpose validation, raised as minor Finding 15, ended up
being part of the Finding 2 fix.

---

## Remaining notes

**Housekeeping — do before merge:** `review.md` (this file) is tracked on the branch as of `ba3f8f4`.
Review notes shouldn't land on `main`; `git rm review.md` before merging.

Three behaviour changes that are correct but worth knowing about at deploy time — none of them blocks
the merge:

- **Outbound M2M tokens changed shape.** `AddLinkedDataProof` now appends the suite context to the VP's
  `@context` and sets `proofPurpose: authentication`. Any external TIR/EBSI endpoint consuming these
  tokens sees a different document. The change is required — without it the old proofs covered nothing —
  but it is worth a line in the release notes.
- **`did:web` issuers that declare `authentication` but not `assertionMethod` will now be rejected** for
  credential proofs. That is what DID Core says should happen, and documents declaring no relationships
  at all still fall through with a warning (documented under Known Gaps), but the partially-declared case
  is the sharper compatibility edge and isn't called out there.
- **`verifier.clientIdentification.id` unset means no domain binding.** Now warned at startup when
  `ldp_vc` is configured, which is the right balance against breaking existing deployments — just be
  aware the warning is the only thing standing between that config and an unenforced audience check.
