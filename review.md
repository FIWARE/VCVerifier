# Code Review — PR #116 "Ticket 54/work"

**Repo:** FIWARE/VCVerifier · **Base:** `main` (`0b9960b`) · **Head:** `ticket-54/work` (`e816616`)
**Size:** 28 files, +5642 / −292 · **Reviewer:** senior engineering review
**Build/tests:** `go build` OK, `go vet` clean, `go test ./...` all packages pass.

---

## Verdict

**Request changes.** Do not merge in the current state.

The PR sets out to close a real and serious gap (JSON-LD / `ldp_vc` proofs were never verified) and the
overall structure — `LDProofChecker`, shared `ResolveKeyFromDID`, fail-closed status-list handling,
deprecation warnings — is sound and heading in the right direction. The problem is what happens when the
new code meets a real-world credential:

1. **The signature does not cover the proof metadata** when the standard W3C context is used, so
   `challenge` (nonce) and `domain` are attacker-controlled — the new replay protection added in Step 7 is
   cosmetic (Finding 1).
2. **The proof key is never bound to the credential issuer or the VP holder**, so a valid signature by
   *anybody* is accepted as a valid signature by the *claimed* issuer (Finding 2).
3. **JSON-LD credentials with no proof at all are silently accepted** inside an otherwise-valid VP
   (Finding 3), and JSON-LD credentials embedded in a JWT VP are never LD-verified at all (Finding 4).

The net effect is that the feature does not deliver the security property it advertises, while the test
suite reports green because the tests are written against a hand-made JSON-LD context that does not
behave like the real one. Each of the findings below was reproduced against this branch; the
reproduction is described so it can be re-run.

---

## Critical findings

### 1. Proof options (`challenge`, `domain`, `created`, `proofPurpose`) are not covered by the signature — replay protection is bypassable

**Files:** `common/ldproof.go:413-433` (verify), `common/ldproof.go:248-253` (sign),
`verifier/presentation_parser.go:531-570` (`VerifyLDVPProofBinding`), `verifier/verifier.go:939-946`

The proof options that get canonicalized and hashed are built with `@context` copied from the *document*:

```go
proofOptions := JSONObject{
    JSONLDKeyContext:             docMap[JSONLDKeyContext],   // e.g. credentials/v1
    JSONLDKeyType:                proof.Type,
    LDProofKeyCreated:            proof.Created,
    LDProofKeyVerificationMethod: proof.VerificationMethod,
}
// + proofPurpose / challenge / domain when non-empty
```

The real `https://www.w3.org/2018/credentials/v1` context does **not** define `created`,
`verificationMethod`, `proofPurpose`, `challenge`, `domain`, `jws`, or the term
`JsonWebSignature2020` at the top level — they only exist inside the scoped context of the `proof` term.
JSON-LD expansion therefore **drops every one of these properties**, and URDNA2015 normalizes the whole
proof-options document down to a single triple.

Reproduced by normalizing those proof options against the real fetched context:

```
canonical proof options = "_:c14n0 <...#type> <JsonWebSignature2020> .\n"   (83 bytes)
after changing challenge, domain AND created:
canonical proof options = "_:c14n0 <...#type> <JsonWebSignature2020> .\n"   (83 bytes)   ← identical
```

End-to-end against `LDProofChecker.VerifyPresentation` with a document loader serving the real W3C
context: a VP is signed with `challenge: "session-nonce-AAA"`; the challenge is then rewritten to
`"session-nonce-ZZZ-attacker-replay"`, the domain to a different verifier and `created` to `1999-01-01`.
Both the original and the tampered proof verify with `err = nil`.

**Impact.** `VerifyLDVPProofBinding` compares `proof.Challenge` against the session nonce, but that field
is unauthenticated. A captured JSON-LD VP can be replayed against any later session by simply editing the
`challenge` string — the exact attack Step 7 claims to prevent. `domain` (audience binding) and `created`
(freshness) are equally forgeable. The `<JsonWebSignature2020>` relative IRI in the output is itself a red
flag that the normalization is not producing a meaningful proof-options document.

**Also an interop bug in the other direction:** real JsonWebSignature2020 implementations sign proof
options under `https://w3id.org/security/suites/jws-2020/v1` (or `security/v2`), producing a completely
different canonical form. This implementation can therefore only verify proofs produced by its own
`AddLinkedDataProof`. It is simultaneously fail-open on binding and fail-closed on genuine credentials.

**Fix.** Set the proof-options `@context` explicitly to the JsonWebSignature2020 / security context
(not the document's), per the suite spec, in **both** `AddLinkedDataProof` and `VerifyLinkedDataProof`.
Then add a guard: after normalizing the proof options, assert that the canonical form actually contains
triples for `created`, `verificationMethod` and (when present) `challenge`/`domain`, and fail closed if
it does not — so a context regression can never silently degrade to "nothing is signed" again.

---

### 2. The proof key is not bound to the credential issuer or the VP holder

**Files:** `verifier/ld_proof_checker.go:63-76` (`VerifyCredential`), `:42-55` (`VerifyPresentation`),
`verifier/presentation_parser.go:505-522`, `verifier/verifier.go:1139-1147`

`VerifyCredential` resolves the public key from `proof.verificationMethod` and verifies the signature
against it. It never checks that the DID in `verificationMethod` is the credential's `issuer`. Since
`did:key` is self-minted and `did:web` only requires control of a domain, the signature attests to
nothing more than "somebody signed this".

Reproduced: a VC with `issuer: did:web:very-trusted-issuer.example.com` is signed with an attacker's key
(`did:web:attacker.example.com#key-1`), wrapped in a VP signed by the same attacker key, and submitted to
`ParsePresentation`:

```
ACCEPTED VC signed by attacker key did:web:attacker.example.com#key-1
         but claiming issuer did:web:very-trusted-issuer.example.com
```

Downstream trust-registry checks (`trustedissuer.go`, `verifyChain`) key off the *claimed* `issuer`
field, so this is a complete issuer-forgery path once JSON-LD input is enabled.

The same hole exists on the VP side. `verifyVPSignatureIfRequired` treats holder binding as satisfied when
`presentation.HolderKey() != nil` — but that key is whatever key signed the proof, which the attacker
chose. There is no equivalent of the JWT path's `verifyCnfBinding`: nothing ties the VP signer to
`vp.holder` or to the credential subject. Holder binding for JSON-LD is therefore a null check, not a
binding check.

**The same gap applies to status lists** (`verifier/credential_status_client.go:276-338`). The comment
claims the change "prevents MITM attacks on status-list resolution", but an active network attacker can
serve a status list credential self-signed with their own `did:key` and it verifies — every revocation
bit cleared. The claim in the doc comment should not ship as written.

**Fix.**
- In `VerifyCredential`, require `ExtractDIDAndFragment(proof.VerificationMethod)` to equal the
  credential's `issuer` (accept the `issuer.id` object form too), and reject otherwise.
- In `VerifyPresentation` / `verifyVPSignatureIfRequired`, require the VP proof DID to equal `vp.holder`,
  and check the credential's `credentialSubject.id` / `cnf` against the VP signer as the JWT path does.
- For status lists, bind the credential's `issuer` to the issuer of the VC that referenced it.
- Ideally also require the verification method to appear in the DID document's `assertionMethod`
  (credentials) / `authentication` (presentations) relationship, not just in `verificationMethod`
  (`verifier/key_resolver.go:90-97` searches only the flat list).

---

### 3. JSON-LD credentials with **no** proof are silently accepted

**File:** `verifier/presentation_parser.go:505-522`

```go
case map[string]interface{}:
    cred, credErr := parseJSONLDCredential(v)
    ...
    if len(cred.Proofs()) > 0 {      // ← unsigned credentials skip verification entirely
        ... verify each proof ...
    }
    pres.AddCredentials(cred)
```

`parseJSONLDCredential` (`:665-673`) only populates `proofs` when a `proof` member exists. A credential
with no `proof` yields an empty slice, the `if` is skipped, and the credential is added to the
presentation unverified.

Reproduced: a VP signed correctly by the holder, containing one unsigned VC claiming
`issuer: did:web:very-trusted-issuer.example.com`:

```
ACCEPTED unsigned VC. credentials=1 issuer=did:web:very-trusted-issuer.example.com
```

This directly contradicts the fail-closed posture the PR establishes for VPs one function above
(`ErrorUnsignedPresentation`) and re-opens the exact hole the ticket exists to close. Note that Step 1 of
this same PR rejected *all* JSON-LD input; Steps 6-8 re-opened it without carrying the fail-closed rule
down to embedded credentials.

**Fix.** Reject a JSON-LD VC with zero LD proofs (and with zero *verifiable* proofs) with a dedicated
error, mirroring `ErrorUnsignedPresentation`. Add the negative test — there is currently none.

---

### 4. JSON-LD credentials embedded in a **JWT** VP are never LD-verified

**File:** `verifier/presentation_parser.go:262-267`

```go
case map[string]interface{}:
    cred, err := parseJSONLDCredential(v)   // no proof verification, ever
    if err != nil { return nil, err }
    pres.AddCredentials(cred)
```

`parseJWTPresentation` handles embedded JSON-LD credentials by parsing them structurally and adding them,
with no call into `LDProofChecker` — even though the parser holds one. So the entire feature is bypassable
by wrapping forged JSON-LD credentials in a JWT VP, which any holder can mint with their own key.

This branch predates the PR, but the PR is precisely the fix for "JSON-LD credentials are never
cryptographically checked", and it leaves half of the entry points untouched. Fixing 2 and 3 without
fixing this leaves the attack fully available.

**Fix.** Factor the credential-proof verification out of `parseJSONLDPresentation` into a helper and call
it from both VP paths.

---

## Major findings

### 5. The test suite validates against a synthetic JSON-LD context, so it cannot catch Finding 1

**File:** `verifier/ld_proof_checker_test.go:73-155`

`newTestDocumentLoader` returns a hand-written "credentials v1" context that defines `created`,
`verificationMethod`, `proofPurpose`, `challenge`, `domain` and `JsonWebSignature2020` **at the top
level** — terms the real W3C context does not define there. Every LD-proof test (unit and "integration")
runs against it.

Consequence: `TestVerifyLinkedDataProof` cases such as "tampered timestamp" pass only because of the
fabricated context, and the entire class of bug in Finding 1 is invisible to CI. Tests named
"integration" that never touch a real context are not integration tests.

**Fix.** Vendor the real `https://www.w3.org/2018/credentials/v1` and the jws-2020 security context as
test fixtures and serve them from the test loader. Keep the synthetic context only where a test
deliberately needs a custom vocabulary.

### 6. `TestParseJSONLDPresentation_ValidVPWithCredentials` is abandoned scaffolding that tests nothing

**File:** `verifier/presentation_parser_test.go:1185-1290`

The test builds `vpMap`, then `_ = vpMap`. It builds `pres2`, then `_ = pres2`. It builds
`vpBytesNoProof`, then `_ = vpBytesNoProof`. It contains the comments *"hacky but tests the path"* and
*"We need to re-sign because the document changed. So let's just test a VP with no credentials
instead."* — and then asserts on `vpJSON`, the VP **without** credentials. It also discards
`json.Unmarshal` errors at lines 1267 and 1288, and asserts only `parseErr == nil && result != nil`.

The single test whose name promises coverage of the credential-verification path provides none. Combined
with `makeMinimalVC` in `ldproof_integration_test.go:92` being **declared and never called**, and every
happy-path integration VP being credential-free (`signTestVP:81-90`), the VC-proof branch at
`presentation_parser.go:509-521` has effectively zero positive coverage.

**Fix.** Delete or rewrite this test so it actually signs a VP *containing* a signed credential and
asserts the credential is verified; drop the dead helper or use it in the Finding-3 negative test.

### 7. Challenge/domain binding is enforced on only one of the three VP entry points

**Files:** `verifier/verifier.go:939-946` vs. `verifier/verifier.go:650-660`

`VerifyLDVPProofBinding` is called from `AuthenticationResponse` only. `GenerateToken` — which serves both
the `vp_token` grant and the RFC 8693 token-exchange grant — calls `verifyVPSignatureIfRequired` and never
checks challenge or domain. Even after Finding 1 is fixed, a JSON-LD VP submitted through those grants has
no replay or audience binding at all.

Additionally, `expectedDomain` is `v.clientIdentification.Id` (`config/config.go:214`), which has no
default. When it is unset the domain check is skipped silently. And in `VerifyLDVPProofBinding`
(`presentation_parser.go:557-563`) the domain check is skipped whenever `proof.Domain == ""`, so an
attacker omits the field to opt out. Challenge handling is correct here (absence is treated as a
mismatch); domain should behave the same way, or the asymmetry should be documented as deliberate.

### 8. `CLAUDE.md` "Known Gaps" is stale on arrival and references a deleted file

**File:** `CLAUDE.md:107-112`

The section added in the PR's first commit states *"JSON-LD / `ldp_vc` proof verification is not
implemented"* and *"`parseJSONLDPresentation` explicitly documents 'no proof verification'"* — both
untrue by the end of the same PR. It also cites `verifier/caching_client.go`, which this PR deletes
(moved to `common/caching_document_loader.go`); the file is still listed under the package layout at
`CLAUDE.md:52` as well. A reader who trusts this document will conclude the feature does not exist.

Similarly, `verifier/presentation_parser.go:190-193` still documents `ParsePresentation` as *"JSON-LD VPs
are currently rejected because LD-proof verification is not yet implemented (see IMPLEMENTATION_PLAN.md
Steps 5-7)"*, which is no longer what the function does.

---

## Minor findings

### 9. Three new/modified files are not `gofmt`-clean

`common/ldproof.go` (misaligned map literal at `:413-417`), `common/ldproof_test.go`,
`verifier/ld_proof_checker_test.go`. Four other listed files were already unformatted on `main` and are
not this PR's responsibility. Run `gofmt -w` on the three above; CI does not currently gate on format,
which is worth adding separately.

### 10. Magic string `"proof"` used instead of the existing constant

`verifier/credential_status_client.go:295` and `:315`/`:331` use the literal `"proof"` while
`common.VPKeyProof` and `verifier.jsonldVPProofKey` both exist. Project convention (CLAUDE.md, "No magic
constants") calls for the constant. There are also two competing constants for the same value
(`common.VPKeyProof` at `common/credential.go:66` and `jsonldVPProofKey` at
`presentation_parser.go:400`) — collapse to one.

### 11. Duplicated doc comment on `CachingStatusListClient`

`verifier/credential_status_client.go:132-141`: the new doc paragraph was added below the old one instead
of replacing it, so the type now carries two stacked comment blocks, the first of which describes the
pre-change behaviour.

### 12. Algorithm/key cross-check does not verify the EC curve

`common/ldproof.go:104-115`: `algKeyTypeMap` maps `ES256 → jwa.EC()` but nothing asserts P-256 (nor
P-384 for ES384, etc.), despite the commit message claiming "ES256→EC P-256". `jwx` will most likely
reject the mismatch downstream, but the check should be explicit since it is presented as a security
control.

### 13. `M2MTokenProvider.documentLoader` can be nil for struct-literal construction

`tir/tokenProvider.go:76-79` adds the field, and `InitM2MTokenProvider` populates it, but any code
constructing `M2MTokenProvider{...}` directly (tests do) leaves it nil. `AddLinkedDataProof` then sets
`ldOpts.DocumentLoader = nil` (`common/ldproof.go:257`), overwriting json-gold's default and risking a nil
dereference the first time a remote context is needed. Guard with a fallback in `signVerifiablePresentation`.

### 14. Hidden global dependency for the status-list LD checker

`verifier/verifier.go:371` passes `nil` for `ldProofChecker` and `Fetch` falls back to the package global
`GetLDProofChecker()` (`credential_status_client.go:211-218`) because `InitVerifier` (main.go:61) runs
before `InitPresentationParser` (main.go:64). It works and it fails closed, but the ordering dependency is
implicit. Prefer reordering the two inits, or passing a lazy accessor function explicitly, so the coupling
is visible.

### 15. `proofPurpose` is never validated

Nothing checks that a VP proof carries `proofPurpose: authentication` or a VC proof
`proofPurpose: assertionMethod`. Combined with Finding 2's missing verification-relationship check, a key
authorized only for assertions can be used to authenticate, and vice versa.

### 16. `IMPLEMENTATION_PLAN.md` is shipped to `main`

376 lines of working plan document in the repo root. If it is meant as durable design documentation it
belongs in `docs/` with the "Steps 1-8 / to be implemented" framing removed, since code comments now
reference "Steps 5-7" as future work that has already landed. Otherwise it should not be in the merge.

---

## What is good

- `LDProofChecker` / `ResolveKeyFromDID` / `ExtractDIDAndFragment` is the right decomposition, and
  deduplicating DID→key resolution between the JWT and LD paths is a genuine improvement.
- The detached-JWS validation in `VerifyLinkedDataProof` (`common/ldproof.go:339-395`) is careful and
  correct: empty-payload enforcement, explicit `b64:false`, `crit` containing `b64`, and an
  algorithm/key-type cross-check are all things that are commonly skipped.
- Fail-closed defaults are the right instinct throughout — nil checker rejects, unsigned VP rejects, empty
  proof array rejects. The gaps in Findings 2-4 are places the same instinct was not carried far enough,
  not a different philosophy.
- Moving `CachingDocumentLoader` into `common/` and wiring it into the TIR M2M signing hot path is a real
  fix for a real per-call `DefaultDocumentLoader` allocation.
- Deprecating `combined`/`jsonLd` with a startup warning and rewriting the README to describe what the
  modes actually do is honest and overdue.
- Doc comments on new exported symbols are thorough and follow GoDoc conventions.

---

## Suggested path forward

Findings 1-4 are one coherent problem — *the signature is verified, but nothing about what it means is
checked* — and should be fixed together before this merges:

1. Fix the proof-options context (Finding 1) and add the "did the proof options actually normalize to
   something" guard.
2. Add issuer↔`verificationMethod` and holder↔`verificationMethod` binding (Finding 2).
3. Reject unsigned JSON-LD credentials (Finding 3) and route JWT-VP-embedded JSON-LD credentials through
   the same verification (Finding 4).
4. Re-point the tests at the real W3C contexts (Finding 5) and rewrite the credential-path test
   (Finding 6) — without this, none of the above is actually verified by CI.
5. Extend challenge/domain binding to `GenerateToken` (Finding 7).

The minor findings can be swept in the same pass or split into a follow-up. Once the security items are
resolved this is a solid and welcome change.
