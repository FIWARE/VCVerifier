# JSON-LD Proof Verification

How VCVerifier verifies Linked Data Proofs on JSON-LD (`ldp_vc`) Verifiable
Credentials and Verifiable Presentations.

Two proof families are verified:

- **`JsonWebSignature2020`** — detached JWS (`jws` member) over URDNA2015
  canonicalized data. Verification is in `common.VerifyLinkedDataProof`.
- **`DataIntegrityProof`** — multibase-encoded raw signature (`proofValue`
  member) over URDNA2015 canonicalized data. Verification is in
  `common.VerifyDataIntegrityProof`. Supported cryptosuites:
  `ecdsa-rdfc-2019` (P-256, P-384) and `eddsa-rdfc-2022` (Ed25519).

## Why a valid signature is not enough

Checking that a proof's signature verifies against the key named in its
`verificationMethod` establishes exactly one thing: *somebody who controls
that key signed this document*. Since `did:key` is self-minted and `did:web`
only requires control of a domain, that on its own says nothing about who
issued a credential or who is presenting it. Verification therefore has four
layers, and all of them have to hold.

### 1. The signature covers the proof metadata

For both proof types the input to the signature is
`hash(canonical proof options) || hash(canonical document)`, both
canonicalized with URDNA2015. The hash is SHA-256 for P-256, Ed25519 and
`JsonWebSignature2020`, or SHA-384 for P-384 with `ecdsa-rdfc-2019` (see
[§ Data Integrity proof verification](#data-integrity-proof-verification) for
details). For `JsonWebSignature2020` this hash data is signed via a detached
JWS (`jws` member). For `DataIntegrityProof` the same hash data is signed
directly and the raw signature bytes are multibase-encoded as the `proofValue`
member.

The proof options document is the proof itself, minus its `jws`/`proofValue`
member — every other member it carries is covered, including ones VCVerifier
has no field for. Its `@context` depends on the suite: for `JsonWebSignature2020` the document's context extended with
`https://w3id.org/security/suites/jws-2020/v1`, which is what defines
`created`, `verificationMethod`, `proofPurpose`, `challenge` and `domain` for
that suite; for `DataIntegrityProof` the document's context verbatim, as
VC-DI-ECDSA §3.2.5 requires — a VCDM 2.0 document already defines every proof
term.

This matters more than it looks. The plain W3C
`https://www.w3.org/2018/credentials/v1` context does not define those terms
at the top level; they only exist inside the scoped context of the `proof`
term. Canonicalizing proof options under it alone drops every one of them and
leaves a single type triple — a signature that covers nothing about the proof.
`challenge` and `domain` would then be freely rewritable in a captured
presentation.

Two things guard against that:

- `common.EnsureSuiteContext` adds the suite context on both the signing and
  the verification side, and `Presentation.AddLinkedDataProof` also adds it to
  the signed document itself so the emitted proof is expandable by others.
- `assertProofOptionsCovered` parses the canonical N-Quads and fails with
  `ErrorLDProofOptionsNotCovered` when a populated proof field produced no
  triple. A context regression cannot silently degrade to "nothing is signed".

The coverage check compares *parsed predicates*, not raw text (see
`common/nquads.go`). A substring search over the N-Quads blob cannot tell a
predicate IRI apart from the same characters appearing inside a literal, so a
proof could satisfy the challenge requirement by writing
`"domain": "<https://w3id.org/security#challenge>"` while carrying no
challenge triple at all. Where the expected object is known verbatim
(`created`, `verificationMethod`, `challenge`, `domain`) it is compared too, so
a term cannot be covered by a value other than the one the proof claims.
`proofPurpose` is checked on its predicate only, since it expands to a
context-defined IRI.

Note the practical consequence: a `verificationMethod` that is not an absolute
URI is dropped during expansion, so signing and verification both reject it.

### 2. The key is bound to the claimed identity

`LDProofChecker` requires the DID of `proof.verificationMethod` to be:

| Document                | Bound to                            | Error on mismatch          |
| ----------------------- | ----------------------------------- | -------------------------- |
| Verifiable Credential   | the credential's `issuer` (or `issuer.id`) | `ErrorProofIssuerMismatch` |
| Verifiable Presentation | the presentation's `holder`         | `ErrorProofHolderMismatch` |

A missing issuer or holder is itself a rejection
(`ErrorMissingProofSubject`) — there would be nothing to bind to. This is what
stops a credential signed with an attacker key from claiming a trusted issuer,
which downstream trust-registry checks would then honour.

### 3. The proof purpose matches the document

A presentation proof must declare `proofPurpose: authentication`, a credential
proof `proofPurpose: assertionMethod`. An absent purpose is a rejection, not a
skipped check (`ErrorProofPurposeMismatch`).

### 4. The key is authorized for that relationship

`ResolveKeyForRelationship` additionally requires the verification method to be
listed under the DID document's `authentication` (presentations) or
`assertionMethod` (credentials) relationship
(`ErrorVerificationRelationshipNotAllowed`).

`did:key` and `did:jwk` documents declare their single key for both
relationships, per their method specifications. For `did:web`, both
reference-style (`"did:web:example.com#key-1"`) and embedded verification
methods are parsed.

**Known limitation:** a DID document that declares no verification
relationship at all cannot be checked against one. Such documents fall back to
the flat `verificationMethod` list and a warning is logged.

## Replay and audience binding

`VerifyLDVPProofBinding` checks the semantics of the (now signed) `challenge`
and `domain` fields:

- `challenge` must equal the session nonce — replay prevention.
- `domain` must equal `verifier.clientIdentification.id` — audience binding.

Both treat an **absent** field as a mismatch when the corresponding
expectation is set, so omitting a field is not a way to opt out.

Every expected binding has to be carried by **one and the same** proof.
Tracking the bindings independently across the proof list would let a
presentation with two proofs — one with the right challenge, the other with the
right domain — pass without any single signature binding this session to this
verifier. A proof that names a challenge or domain other than the expected one
is rejected wherever in the list it appears.

Where each applies:

| Grant                                     | Challenge                | Domain | Proof age |
| ----------------------------------------- | ------------------------ | ------ | --------- |
| `authorization_code` (`AuthenticationResponse`) | session nonce      | yes    | bounded by the session |
| `vp_token` (`GenerateToken`)              | not available — no server-issued nonce | yes | `verifier.ldProofMaxAge` |
| `urn:ietf:params:oauth:grant-type:token-exchange` | not available    | yes    | `verifier.ldProofMaxAge` |

The domain check only runs when `verifier.clientIdentification.id` is
configured. Deployments accepting `ldp_vc` should set it; without it there is
no audience binding on any grant.

### Proof freshness

The grants without a server-issued nonce have no challenge to bind against, so
the proof's own `created` timestamp is what keeps a captured presentation from
being replayed until its credentials expire. `VerifyLDVPProofFreshness`
rejects a proof older than `verifier.ldProofMaxAge` (default 300s,
`ErrorProofNotFresh`), and is fail-closed on the timestamp itself: a missing
(`ErrorProofCreatedMissing`), unparseable (`ErrorProofCreatedUnparseable`) or
future-dated (`ErrorProofCreatedInFuture`) `created` is rejected rather than
treated as "nothing to check". A 30s skew allowance covers independent holder
and verifier clocks; setting `ldProofMaxAge: 0` disables the check.

`created` is covered by the signature (see rule 1), so it cannot be rewritten
in a captured presentation.

### Holder binding of JSON-LD credentials

A JWT VC is bound to the presenter through its `cnf` claim
(`verifyCnfBinding`). The JSON-LD equivalent is `verifyJSONLDHolderBinding`:
when the presentation declares a `holder`, an identified `credentialSubject`
must be that holder, otherwise the credential is rejected with
`ErrorHolderSubjectMismatch`. Without it a credential issued to somebody else
could be replayed inside an attacker-signed VP — and `HolderValidationService`
runs only from `GenerateToken`, never from `AuthenticationResponse`.

The check runs after the credential's proofs have been verified — the subject
of an inauthentic credential is not worth reasoning about — and is skipped when
no subject carries an `id`. Such a credential makes claims about nobody in
particular, so replaying it transfers no identity, and rejecting it would break
the many credentials that legitimately omit the id.

## Fail-closed rules

| Input                                                    | Result                                 |
| -------------------------------------------------------- | -------------------------------------- |
| JSON-LD VP with no `proof` member, or an empty proof array | `ErrorUnsignedPresentation`            |
| JSON-LD VP with a proof but no configured `LDProofChecker` | `ErrorInvalidProof`                    |
| JSON-LD VC with no proof — in a JSON-LD **or** a JWT VP    | `ErrorUnsignedCredential`              |
| JSON-LD status list credential with no proof               | `ErrorStatusListJSONLDProofMissing`    |
| JSON-LD status list credential, no configured checker      | `ErrorStatusListJSONLDProofUnsupported`|
| `did:elsi` in an LD-proof context                          | `ErrorDidElsiNotSupportedForLDProof`   |

JSON-LD credentials embedded in a **JWT** presentation go through exactly the
same credential verification as those in a JSON-LD presentation. A JWT VP is
minted by the holder, so it cannot be allowed to vouch for the credentials it
carries.

## Status lists

Verifying the proof on a status-list credential shows who signed the list, not
that the list is the right one — an attacker who can answer the status-list URL
picks both the issuer it names and the key it is signed with.

Both status-list surfaces therefore bind the list to the issuer of the
credential that referenced it:

| Client                                   | Bound value                    | Error on mismatch |
| ---------------------------------------- | ------------------------------ | ----------------- |
| `StatusListCredentialClient.Fetch` (W3C) | the list credential's `issuer` | `ErrorStatusListIssuerMismatch` |
| `IETFStatusListClient.FetchIETF`         | the status-list JWT's `iss`    | `ErrorStatusListIssuerMismatch` |

The check is applied to cached entries too, so a legitimate lookup cannot warm
the cache for a foreign issuer. A referencing credential with **no** issuer is
rejected with `ErrorStatusListIssuerUnknown` rather than exempted: skipping the
only check that anchors the list to a known party would fail open on exactly
the credentials that name nobody.

## Contexts

`https://www.w3.org/2018/credentials/v1` and
`https://w3id.org/security/suites/jws-2020/v1` are vendored under
`common/contexts/` and embedded in the binary.
`common.NewVerificationDocumentLoader` serves them directly and delegates any
other URL to a caching remote loader.

Canonicalization is signature-relevant input: if the context that defines the
proof terms could be changed, delayed or blocked by whoever hosts it, so could
the verification result. Serving those two from the binary removes that
dependency. It also means the tests run against the real contexts rather than
a hand-written stand-in — a stand-in that defines the proof terms at the top
level would make proof options look covered when, against the genuine context,
they are not.

## Algorithm and key cross-checks

`VerifyLinkedDataProof` enforces, before any signature check:

- a detached JWS of the form `header..signature` with an empty payload part,
- `b64: false` and `crit` containing `b64` in the header,
- the JWS algorithm against the key type (`ES*` → EC, `RS*`/`PS*` → RSA,
  `EdDSA` → OKP),
- for ECDSA, the exact curve: ES256 → P-256, ES384 → P-384, ES512 → P-521
  (`ErrorLDProofCurveMismatch`).

## Data Integrity proof verification

`common.VerifyDataIntegrityProof` verifies `DataIntegrityProof` proofs as
specified by the W3C Data Integrity specification. It supports two
cryptosuites:

### Supported cryptosuites

| Cryptosuite          | Algorithm       | Key types             | Signature encoding |
| -------------------- | --------------- | --------------------- | ------------------ |
| `ecdsa-rdfc-2019`    | ECDSA over P-256 / P-384 | EC (P-256, P-384) | IEEE P1363 (r ‖ s) |
| `eddsa-rdfc-2022`    | EdDSA (Ed25519) | OKP (Ed25519)         | raw 64-byte signature |

### Algorithm

1. **Canonicalize** both the document and the proof options with URDNA2015,
   the same way `JsonWebSignature2020` does. The proof options are the proof
   minus its `proofValue`, under the document's own `@context`.
2. **Hash**: `hashData = hash(canonical proof options) || hash(canonical
   document)`, where the hash is SHA-256 (P-256 / Ed25519) or SHA-384
   (P-384).
3. **Decode** the `proofValue` from multibase (base58btc, prefix `z`).
4. **Verify** the signature against `hashData`:
   - `ecdsa-rdfc-2019`: hash `hashData` with SHA-256 (P-256) or SHA-384
     (P-384), then verify the IEEE P1363-encoded ECDSA signature.
   - `eddsa-rdfc-2022`: verify the Ed25519 signature over `hashData` directly.

### Key resolution and Multikey verification methods

Data Integrity proofs commonly use DID documents with `Multikey`-typed
verification methods, where the public key is encoded as a `publicKeyMultibase`
string (multibase + multicodec prefix). The key resolution path
(`did/multikey.go`) decodes these into JWKs:

| Multicodec code | Key type    | Curve / algorithm | Constant in code       |
| --------------- | ----------- | ----------------- | ---------------------- |
| `0x1200`        | EC          | P-256             | `MulticodecP256Pub`    |
| `0x1201`        | EC          | P-384             | `MulticodecP384Pub`    |
| `0xed`          | OKP         | Ed25519           | `MulticodecEd25519Pub` |

`secp256k1` (`MulticodecSecp256k1Pub`, `0xe7`) is recognized and **rejected**:
the curve is not available in Go's standard library, so a verification method
carrying one produces an explicit error rather than a silently unusable key.

`JsonWebKey2020` verification methods (with `publicKeyJwk`) are also supported,
so both VM types work with Data Integrity proofs.

### Cross-checks

`VerifyDataIntegrityProof` enforces:

- The `cryptosuite` field must be one of the supported values; an unknown
  suite is rejected with `ErrorLDProofUnsupportedCryptosuite`.
- The resolved key must match the cryptosuite: `ecdsa-rdfc-2019` requires an
  EC key (P-256 or P-384), `eddsa-rdfc-2022` requires an OKP/Ed25519 key.
  A mismatch is rejected with `ErrorLDProofCryptosuiteKeyMismatch`.
- The `proofValue` must decode from multibase and have the length the curve
  requires (`2 x` the coordinate size for ECDSA, 64 bytes for Ed25519);
  anything else is rejected with `ErrorLDProofMalformedProofValue`.
- A failing signature is rejected with `ErrorLDProofVerifyDataIntegrity`.

### Integration with the proof pipeline

The proof type dispatch is `selectProofVerifier` in
`verifier/ld_proof_checker.go`, called from `verifyLDProofWithCandidateKeys`:

| `proof.type`            | Verified by                    |
| ----------------------- | ------------------------------ |
| `JsonWebSignature2020`  | `common.VerifyLinkedDataProof` |
| `DataIntegrityProof`    | `common.VerifyDataIntegrityProof` |
| anything else           | rejected, `ErrorLDProofUnsupportedType` |

The dispatch is exhaustive: an unrecognized proof type is **rejected**, never
reinterpreted as one of the two supported ones. All other layers — identity
binding (§2), proof purpose (§3), verification relationship enforcement (§4),
replay / freshness / holder binding — apply identically to both proof types.

Mixed-proof scenarios are supported: a VP signed with `JsonWebSignature2020`
can contain credentials signed with `DataIntegrityProof`, and vice versa.

### Limitations

- **`created` is required**, while VC-DATA-INTEGRITY §2.1 makes it optional.
  A conformant Data Integrity proof without it is rejected with
  `ErrorLDProofMissingCreated`.
- **`expires` is canonicalized but not enforced.** It is covered by the
  signature, so it cannot be altered, but an expired proof is not rejected on
  that ground.
- **The JCS cryptosuites** (`ecdsa-jcs-2019`, `eddsa-jcs-2022`), the
  selective-disclosure suites (`bbs-2023`, `ecdsa-sd-2023`), proof sets and
  proof chains (`previousProof`), and Data Integrity on VCDM 1.1 documents are
  not supported.

## Signing

`Presentation.AddLinkedDataProof` and `common.CreateLinkedDataProof` produce
proofs through the same code path that verification consumes.
`CreateLinkedDataProof` works on any proof-less JSON-LD document map, which is
what the tests use to sign credentials.

The M2M token provider (`tir/tokenProvider.go`) signs its participant
presentation with `proofPurpose: authentication`. Two things have to line up
for the emitted presentation to verify against its own proof:

- `m2m.verificationMethod` must be an absolute DID URL. A relative reference
  is dropped during expansion, so `assertProofOptionsCovered` would reject
  every signing attempt. `InitM2MTokenProvider` fails with
  `ErrorTokenProviderNoVerificationMethod` at startup rather than letting that
  surface as a runtime error on the first token request, and there is no
  built-in default for the field.
- The signer and the algorithm advertised in the JWS header have to describe
  the same operation. `signerForKeyType` returns both from one place:
  `RSARS256` → `RS256Signer` (RSASSA-PKCS1-v1_5) and `RSAPS256` → `PS256Signer`
  (RSASSA-PSS), so a PS256 header over a PKCS#1 v1.5 signature cannot be
  reintroduced.

`Presentation.AddLinkedDataProof` derives the presentation's emitted
`@context` from the marshalled document it actually signed. `MarshalJSON`
defaults an empty `@context` to `credentials/v1`; deriving it from the original
value instead would emit a presentation whose context no longer matches the one
the proof was computed over.
