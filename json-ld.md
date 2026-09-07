# JSON-LD / `ldp_vc` support — current state, clean-up and re-implementation plan

> Status: **`ldp_vc` is not verifiable.** JSON-LD credentials and presentations are parsed
> structurally but no Linked Data Proof (Data Integrity / `JsonWebSignature2020`) is ever
> checked. The configuration surface still advertises `ldp_vc`, which makes this a silent
> security gap rather than an unimplemented feature.

---

## 1. Current state

### 1.1 What is cryptographically verified today

All signature verification goes through a single component, `verifier.JWTProofChecker`
(`verifier/jwt_proof_checker.go:33`). It only understands **JWS/JWT**:

| Input | Verified? | Path |
|---|---|---|
| JWT VP containing JWT VCs (`jwt_vc_json`) | yes — VP signature + every embedded VC signature | `parseJWTPresentation` (`verifier/presentation_parser.go:152`) |
| SD-JWT VCs (`vc+sd-jwt`, `dc+sd-jwt`) | yes | `ConfigurableSdJwtParser.ParseWithSdJwt` |
| `did:elsi` credentials | yes — JAdES / X.509 chain via `jades` | `JWTProofChecker.verifyElsiJWT` (`verifier/jwt_proof_checker.go:154`) |
| Holder binding (`cnf`, RFC 7800) | yes, when a VP JWT key was resolved | `verifyCnfBinding` (`verifier/presentation_parser.go:547`) |
| **JSON-LD VP with LD proof** | **no** | `parseJSONLDPresentation` (`verifier/presentation_parser.go:334`) |
| **JSON-LD VC with LD proof (`ldp_vc`)** | **no** | `parseJSONLDCredential` (`verifier/presentation_parser.go:403`) |
| **JWT VC embedded in a JSON-LD VP** | **no** — signature deliberately skipped | `parseUnsignedJWTCredential` (`verifier/presentation_parser.go:386`) |
| JSON-LD W3C status-list credential | **no** | `parseStatusListCredentialBody` (`verifier/credential_status_client.go:213`) |

`ParsePresentation` (`verifier/presentation_parser.go:142`) dispatches purely on the first
byte of the token: a leading `{` routes to the JSON-LD branch, everything else to the JWT
branch. So a caller can reach the unverified path simply by submitting a JSON VP.

### 1.2 What the JSON-LD branch actually does

`parseJSONLDCredential` extracts `id`, `type`, `@context`, `issuer`, `credentialSubject`
and `credentialStatus`, stores the original map via `SetRawJSON`, and returns. The `proof`
member is never read — `common.Credential` (`common/credential.go:138`) has no field to
hold it. Only `common.Presentation` carries `Proof *LDProof` (`common/credential.go:253`),
and that field exists for *signing*, not verifying.

`parseJSONLDPresentation` carries the explicit comment *"no proof verification"* and
`parseUnsignedJWTCredential` is reached with a `logging.Log().Warn(...)` — so the gap is
known and logged, but not enforced.

### 1.3 The only LD-proof code in the tree is outbound

`common/ldproof.go` implements `(*Presentation).AddLinkedDataProof` (`common/ldproof.go:66`):
URDNA2015 canonicalization via `piprate/json-gold`, SHA-256 of proof options and document,
detached `b64=false` JWS. It is used in exactly one place —
`tir.M2MTokenProvider.signVerifiablePresentation` (`tir/tokenProvider.go:153`) — to sign the
presentation the verifier itself sends to the Trusted Issuers Registry. **There is no
verification counterpart.**

### 1.4 Where the gap can bite

* An unsigned or forged JSON-LD VP submitted to `/token` is accepted structurally. The
  credential content then flows into trust-registry lookups and ends up in the issued JWT.
* The only thing that can still force a signature check on a VP is holder verification
  (`verifier/verifier.go:1112`), and that runs `GetProofChecker().VerifyJWTAndReturnKey` on
  the raw token — i.e. it only helps for JWT VPs, and only when
  `GetHolderVerification` is enabled for the client/scope/credential-type combination.
* JSON-LD status-list credentials are fetched over HTTP and trusted as-is, so a
  man-in-the-middle can flip revocation state. The JWT variant of the same document *is*
  verified (`verifier/credential_status_client.go:237`), which makes the asymmetry easy to miss.

### 1.5 How we got here

LD-proof verification used to come for free from `trustbloc/vc-go`. It was removed during
the trustbloc replacement without a replacement implementation:

| Commit | What was dropped |
|---|---|
| `9d7296b` Step 7: Custom VP/VC parsing | `verifiable.ParsePresentation` with `WithPresProofChecker` / `WithPresJSONLDDocumentLoader`, `defaults.NewDefaultProofChecker`, `ElsiProofChecker`, `jwt.CheckProof` |
| `6f51b4a` Step 9: Custom credential content validation | `tbCred.ValidateCredential(verifiable.WithJSONLDValidation())` and schema validation, replaced by presence checks |
| `3e95be8` Step 12: Remove all trustbloc dependencies | `trustbloc/vc-go`, `did-go`, `kms-go` from `go.mod` |

Note that Step 9 also silently degraded the `validationMode` semantics — see §2.

---

## 2. Clean-up list

These items are about removing or correcting misleading surface. None of them make
`ldp_vc` work; they make the current behaviour honest. They are worth doing **even if we
decide not to re-implement LD-proof verification**.

### C1 — `validationMode: jsonLd` and `combined` are lies

`verifier/jwt_verifier.go:80` maps both `combined` and `jsonLd` to
`validateCredentialContent` (`:96`), which only asserts that `issuer` and `type` are
non-empty. No JSON-LD expansion, no schema validation happens anywhere.

Actions:
* Either implement real JSON-LD expansion validation (see W4), or
* collapse the modes and mark `combined`/`jsonLd` as deprecated aliases in
  `SupportedModes`, logging a startup warning when they are configured.
* Fix `README.md:132-138`, which still documents `combined` as *"ld and schema validation"*
  and `jsonLd` as *"uses JSON-LD parser for validation"*.

### C2 — `CLAUDE.md` is stale

It lists `trustbloc/vc-go, did-go, kms-go` under "Key Dependencies" (gone since `3e95be8`)
and references `verifier/elsi_proof_checker.go`, which no longer exists — did:elsi handling
lives in `verifier/jwt_proof_checker.go:154` now. It also describes
`jwt_verifier.go` validation modes as if they still did JSON-LD work.

### C3 — Dead or near-dead JSON-LD infrastructure

* `verifier/caching_client.go` (`NewCachingDocumentLoader`) has **no production caller**
  since Step 7. It used to back `WithPresJSONLDDocumentLoader`. Either wire it into the
  new verification path (W3 needs exactly this) or delete it.
* `tir/tokenProvider.go:159` constructs `ld.NewDefaultDocumentLoader(http.DefaultClient)`
  inline on every signing call, bypassing the cache that already exists. This should use
  the caching loader regardless of the `ldp_vc` decision — it is an uncached network fetch
  of `@context` documents in the hot path of TIR authentication.

### C4 — `ldp_vc` advertised as a supported format

The format is selectable in configuration and in the API contract, with no verification
behind it:
* `database/models.go:15,22` — `ldp_vc` ⇄ `LDP_VC` mapping
* `api/credentials-config.yaml:405` — enum value
* `config/configClient.go:577` — `MetaDataQuery.TypeValues`, documented as *"Required for ldp_vc"*
* `api/api.yaml:439,507` — `ldp_vc` examples and the `VerifiableCredential` / `Proof` schemas

Until W1–W3 land, either reject `ldp_vc` at configuration-load time with a clear error, or
log a prominent startup warning per configured credential. Silently accepting the config is
the worst of the three options.

### C5 — Fail closed on unverifiable input

Independent of any LD-proof work, the parser should not return a presentation it could not
verify:
* `parseJSONLDPresentation` (`verifier/presentation_parser.go:334`) should return
  `ErrorInvalidProof` when a `proof` member is present but unverifiable, and reject outright
  when no proof is present at all.
* `parseUnsignedJWTCredential` used from the JSON-LD VP path
  (`verifier/presentation_parser.go:359`) should verify the embedded JWT VC with the
  existing `JWTProofChecker` — that case needs no LD-proof support at all and is a
  straightforward fix.
* `parseStatusListCredentialBody` (`verifier/credential_status_client.go:213`) should treat
  a JSON-LD status list with an unverified proof the same way it now treats a JWT status
  list without a verifier configured.

---

## 3. What needs to be done to verify `ldp_vc` properly

The work is scoped as independent steps; W1–W3 are the minimum for a correct
implementation, W4–W5 restore the content-validation behaviour that was lost alongside it.

### W1 — Represent the proof in the data model

* Add a proof-carrying field to `common.Credential` (`common/credential.go:138`), analogous
  to `Presentation.Proof` (`common/credential.go:253`). A VC may carry **multiple** proofs,
  so model it as a slice, and make `common.LDProof` (`common/ldproof.go:43`) tolerant of
  the fields it currently ignores (`proofPurpose`, `challenge`, `domain`, `expires`,
  `cryptosuite`, `proofValue`).
* Populate it in `parseJSONLDCredential` (`verifier/presentation_parser.go:403`) and in
  `parseJSONLDPresentation` (`:334`), which today drops the VP's own `proof` member as well.
* Keep the raw JSON around — `SetRawJSON` already does this, and canonicalization must run
  over the *original* document, not over a re-serialized `CredentialContents` (any
  round-trip through the struct loses unknown members and therefore breaks the signature).

### W2 — Implement `VerifyLinkedDataProof`

Mirror `AddLinkedDataProof` (`common/ldproof.go:66`) with a verification function in
`common/ldproof.go`, reusing its existing constants (`LDNormAlgorithmURDNA`,
`LDNormFormatNQuads`, `JWSHeader*`):

1. Copy the document, remove the `proof` member.
2. Rebuild proof options from the proof itself (`@context` from the document, `type`,
   `created`, `verificationMethod`, and — once supported — `proofPurpose`, `challenge`,
   `domain`).
3. Normalize both with URDNA2015 / N-Quads through a **caching** document loader (C3).
4. `tbs = sha256(canonicalProofOptions) || sha256(canonicalDocument)` — must match the
   signing order in `common/ldproof.go:113`.
5. Verify the detached JWS: split `header..signature`, reconstruct
   `ASCII(header) || "." || tbs`, and verify with `jws.Verify` using the resolved key.
   Reject any `alg`/`crit`/`b64` header combination other than the detached-`b64=false`
   form the signer produces.

Constraints worth writing down in the implementation:
* Do **not** trust the `alg` in the proof's JWS header alone — cross-check it against the
  key type resolved from the DID document.
* Require a `created` timestamp and reject proofs outside an acceptable skew window;
  `AddLinkedDataProof` always writes one, so a missing `created` is a red flag.
* Reject unknown proof `type` values explicitly rather than falling through.

### W3 — Wire verification into an LD proof checker

* Add an `LDProofChecker` alongside `JWTProofChecker`, sharing the same `did.Registry`
  (`did/resolver.go:26`) for `did:key` / `did:web` / `did:jwk` resolution. Key resolution
  logic can be lifted from `JWTProofChecker.resolveKey` (`verifier/jwt_proof_checker.go:106`)
  — factor it out rather than duplicating it.
* The `verificationMethod` in an LD proof is a DID URL with a fragment; resolve the DID and
  select the verification method by fragment. `compareVerificationMethod` and
  `getKeyFromMethod` (`verifier/jwt_verifier.go:47,58`) already contain related logic and
  should be reused or replaced consistently.
* Bind it into `InitPresentationParser` (`verifier/presentation_parser.go:83`) next to the
  existing `NewJWTProofChecker` call, and expose it the same way `GetProofChecker`
  (`:68`) does.
* Enforce it in the JSON-LD paths listed under C5, so those paths fail closed once a
  checker is available.
* Decide explicitly what happens for `did:elsi` in the JSON-LD case — the JAdES validator
  is JWS-based and does not apply to LD proofs. Most likely: reject `did:elsi` + `ldp_vc`
  as an unsupported combination.

### W4 — Restore JSON-LD content validation (optional, ties into C1)

If `validationMode: jsonLd` is to mean anything again, `validateCredentialContent`
(`verifier/jwt_verifier.go:96`) needs a real implementation: JSON-LD expansion of the raw
credential through the caching document loader, rejecting documents that drop terms (i.e.
undefined properties) during expansion. This is the check that `trustbloc`'s
`verifiable.WithJSONLDValidation()` provided.

### W5 — Presentation-level proof semantics

For JSON-LD VPs, verifying the proof is not sufficient on its own:
* `challenge` must be bound to the session nonce and `domain` to the verifier's client id,
  otherwise a verified VP is still replayable. The JWT path gets this from the session
  nonce handling; the LD path has no equivalent today.
* Holder binding must be re-established: `SetHolderKey`
  (`common/credential.go:269`) is only ever called from the JWT path
  (`verifier/presentation_parser.go:177`), so `verifyCnfBinding` (`:547`) is a no-op for
  JSON-LD VPs. The LD-proof signer key should be stored the same way.

---

## 4. Test plan

* Round-trip test in `common`: sign a presentation with `AddLinkedDataProof` and verify it
  with the new function — this pins the canonicalization and `tbs` ordering.
* Negative table-driven cases (per the repo's parameterized-test convention): tampered
  `credentialSubject`, tampered `proof.created`, wrong `verificationMethod`, `alg`
  mismatched against the resolved key, missing `proof`, unknown proof `type`, unresolvable
  DID, `challenge`/`domain` mismatch.
* Fixtures for a real `ldp_vc` with a `did:web` and a `did:key` issuer, verified against a
  served DID document.
* Regression test asserting that an unsigned JSON-LD VP submitted to `/token` is rejected
  (this is the C5 behaviour and should be added before the LD work, as it is the security
  fix).
* Status-list test for a JSON-LD `BitstringStatusListCredential` with an invalid proof.

---

## 5. Recommendation

The security-relevant part is small and independent of the LD-proof work: **C5 first**
(fail closed on JSON-LD input, and verify JWT VCs embedded in JSON-LD VPs — which needs no
new crypto), then **C4** (stop advertising `ldp_vc`), then **C1/C2/C3** (documentation and
dead code).

W1–W3 are only worth the effort if `ldp_vc` is actually in use by a deployment or required
by a trust framework we support. The ecosystem has moved to `jwt_vc_json` and SD-JWT, and
the verifier's own signing path (`tir/tokenProvider.go`) is the only remaining LD-proof
producer. If no consumer needs it, dropping `ldp_vc` from the configuration surface (C4)
is the cheaper and safer outcome than maintaining a hand-rolled Data Integrity
implementation.
