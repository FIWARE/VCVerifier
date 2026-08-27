# JSON-LD Proof Verification

How VCVerifier verifies Linked Data Proofs on JSON-LD (`ldp_vc`) Verifiable
Credentials and Verifiable Presentations.

Only the `JsonWebSignature2020` suite is verified. Other Data Integrity
cryptosuites (`proofValue`-based) are parsed into `common.LDProof` but are not
accepted for verification.

## Why a valid signature is not enough

Checking that a proof's signature verifies against the key named in its
`verificationMethod` establishes exactly one thing: *somebody who controls
that key signed this document*. Since `did:key` is self-minted and `did:web`
only requires control of a domain, that on its own says nothing about who
issued a credential or who is presenting it. Verification therefore has four
layers, and all of them have to hold.

### 1. The signature covers the proof metadata

The signature is computed over
`sha256(canonical proof options) || sha256(canonical document)`, both
canonicalized with URDNA2015.

The proof options document is the proof without its `jws` member. Its
`@context` is the *document's* context extended with
`https://w3id.org/security/suites/jws-2020/v1` — the suite context is what
defines `created`, `verificationMethod`, `proofPurpose`, `challenge` and
`domain`.

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
- `assertProofOptionsCovered` inspects the canonical N-Quads and fails with
  `ErrorLDProofOptionsNotCovered` when a populated proof field produced no
  triple. A context regression cannot silently degrade to "nothing is signed".

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

Where each applies:

| Grant                                     | Challenge                | Domain |
| ----------------------------------------- | ------------------------ | ------ |
| `authorization_code` (`AuthenticationResponse`) | session nonce      | yes    |
| `vp_token` (`GenerateToken`)              | not available — no server-issued nonce | yes |
| `urn:ietf:params:oauth:grant-type:token-exchange` | not available    | yes    |

The domain check only runs when `verifier.clientIdentification.id` is
configured. Deployments accepting `ldp_vc` should set it; without it there is
no audience binding on any grant.

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
that the list is the right one. `StatusListCredentialClient.Fetch` therefore
also takes the issuer of the credential that referenced the list and rejects a
mismatch with `ErrorStatusListIssuerMismatch`. The check is applied to cached
entries too, so a legitimate lookup cannot warm the cache for a foreign
issuer.

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

## Signing

`Presentation.AddLinkedDataProof` and `common.CreateLinkedDataProof` produce
proofs through the same code path that verification consumes.
`CreateLinkedDataProof` works on any proof-less JSON-LD document map, which is
what the tests use to sign credentials.

The M2M token provider (`tir/tokenProvider.go`) signs its participant
presentation with `proofPurpose: authentication`. Its configured
`m2m.verificationMethod` must be an absolute DID URL — the built-in default
(`JsonWebKey2020`) is not one, and a warning is logged at startup when the
configured value has no scheme.
