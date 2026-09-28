# VC-JOSE-COSE Support

VCVerifier supports the [W3C VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/) securing
mechanism for Verifiable Credentials and Verifiable Presentations. This document describes
how the three new formats — `vc+jwt` credentials, `vp+jwt` presentations and
`EnvelopedVerifiableCredential` — are parsed and verified.

## `vc+jwt` Credentials

A `vc+jwt` credential is a JWT whose JOSE `typ` header is `vc+jwt`. Unlike a classic `jwt_vc`,
the JWT payload **is** the credential — there is no wrapping `vc` claim. The JSON-LD fields
(`@context`, `type`, `issuer`, `credentialSubject`, `validFrom`, `validUntil`, etc.) appear at
the top level of the JWT payload.

### Registered claims (VC-JOSE-COSE §3.1.3)

The payload *is* the credential, so a registered JWT claim is a **redundant copy** of a
property the document already states — never an input that overrules it.

| JWT claim | Document property | Rule |
|-----------|-------------------|------|
| `iss` | `issuer` | must agree when both are present; either one alone is the issuer |
| `sub` | `credentialSubject[0].id` | must agree when both are present; permitted only for a single subject |
| `jti` | `id` | must agree when both are present |
| `nbf` | — | may only move `validFrom` later |
| `exp` | — | may only move `validUntil` earlier |
| `iat` | — | not mapped: it is the signature's issuance time |
| `cnf` | — | preserved for holder binding (RFC 7800) |

A claim that disagrees with its property makes the credential malformed. The errors are
`ErrorIssClaimIssuerMismatch`, `ErrorSubClaimSubjectMismatch` and `ErrorJtiClaimIDMismatch`;
a `sub` alongside several subjects is `ErrorSubClaimMultipleSubjects`.

§3.1.3 is explicit that `iat` and `exp` "represent the issuance and expiration time of the
signature, respectively — different from credential's `validFrom` and `validUntil`", and that
`nbf` is NOT RECOMMENDED. The payload's `validFrom` / `validUntil` therefore state the
credential's validity, and a registered claim present anyway may only narrow that window.

### Issuer binding

A `vc+jwt` has **no `iss` claim to resolve a key from**: the issuer is the credential's own
`issuer` property, which is part of the signed document. Verification therefore runs in two
passes (`parseVCJoseCredential`):

1. Decode the payload *without* verifying it and read nothing from it but the issuer, which
   only decides whose key to resolve. Lying here does not help a forger — naming an issuer
   they do not control means the verifier resolves that issuer's key, which will not verify
   their signature.
2. Verify against a key belonging to that issuer via
   `JWTProofChecker.VerifyJWTForIssuer`, then re-read the credential from the payload the
   verification returned.

The first pass is never reused for anything else. A `kid` still selects *which* of the
issuer's keys to use, but a `kid` naming a different DID is rejected
(`ErrorIssuerKeyMismatch`), and a credential naming no issuer at all is rejected
(`ErrorVCJWTNoIssuer`). All three issuer kinds are supported: DID, `did:elsi` and HTTPS.

A `vc+jwt` routinely carries no `kid`, since its issuer is named by the document rather than
the envelope. Key resolution then treats every verification method the DID document declares
as a candidate, mirroring what the HTTPS issuer resolver already does for a JWKS.

### Parsing

The `typ` header is read by `jwtMediaType()` in `verifier/presentation_parser.go` and
normalized by `normalizeJOSEType()`. When `typ` is `vc+jwt`, the token is dispatched to
`parseVCJoseCredential` → `vcJwtClaimsToCredential`, which reads credential fields directly
from the JWT payload instead of looking inside a `vc` claim.

The credential format is set to `common.FormatVCJWT` (`"vc+jwt"`).

### Well-formedness

- **`vc` / `vp` claims are rejected.** §1.1.2.1: "The JWT Claim Names `vc` and `vp` MUST NOT
  be present in any JWT Claims Set that comprises a verifiable credential or presentation."
  A token carrying both shapes describes two documents at once, so it is rejected
  (`ErrorVCJoseReservedClaim`) rather than resolved by precedence.
- **A `vc+jwt` must be a VCDM 2.0 document.** §3.1.1 secures a 2.0 credential, so a payload
  whose first `@context` entry is not the 2.0 base context is rejected
  (`ErrorVCJWTNotDataModel2`) regardless of `verifier.vcDataModelVersions`. That setting
  selects which data models are *acceptable*; it does not decide what a `vc+jwt` is.

### Version gate

`vc+jwt` credentials carry `@context` and participate in the VC Data Model version gate on
top of the check above, the same way `jwt_vc` and `ldp_vc` credentials do. SD-JWT VCs remain
the only exempt format (no `@context`).

## `vp+jwt` Presentations

A `vp+jwt` presentation is a JWT whose JOSE `typ` header is `vp+jwt`. The JWT payload **is**
the presentation — there is no wrapping `vp` claim. The `verifiableCredential` array, `holder`,
`@context`, and `type` are read directly from the top-level JWT claims.

### The presenter

VC-JOSE-COSE defines **no `iss` → `holder` mapping**: §4.1.2 registers `iss` for key discovery
only. The presenter is the presentation's own `holder` property.

| JWT claim | Presentation property | Rule |
|-----------|-----------------------|------|
| `iss` | `holder` | must agree when both are present; accepted alone when `holder` is absent, which VCDM 2.0 permits |
| `jti` | `id` | must agree when both are present |

A presentation naming nobody at all is rejected (`ErrorVPJWTNoHolder`): `Presentation.Holder`
becomes the subject of the issued access token and drives holder policy validation, so there
would be nothing for the signature to bind to.

### Well-formedness

- **`vc` / `vp` claims are rejected**, on the same §1.1.2.1 terms as a `vc+jwt`.
- **A `vp+jwt` must be a VCDM 2.0 document.** §3.1.2 secures a 2.0 presentation just as §3.1.1
  secures a 2.0 credential, so an envelope whose first `@context` entry is not the 2.0 base
  context is rejected (`ErrorVPJWTNotDataModel2`), independently of
  `verifier.vcDataModelVersions`. The check runs before the `verifiableCredential` array is
  parsed: a presentation that is not a well-formed `vp+jwt` is refused on its own account,
  not on whatever its contents happen to say.

  This is the one place a presentation envelope's `@context` is checked. The configurable
  version gate deliberately does not look at it (see `docs/vc-data-model-versions.md`) — that
  gate decides which data models a deployment *accepts* for the credentials being asserted,
  while this decides what a `vp+jwt` *is*. Classic JWT VPs and JSON-LD VPs remain ungated.

### Holder binding

`vp+jwt` uses RFC 7800 `cnf`, the same mechanism as every other JWT path
(`verifyCnfBinding`). VC-JOSE-COSE §4.1.3 registers `cnf` for exactly this purpose. VCDM 2.0's
`confirmationMethod` is a *reserved* property with no defined semantics, so it is deliberately
**not** implemented — see the Known Gaps section of `CLAUDE.md`.

### Signature verification

Like a `vc+jwt`, a `vp+jwt` names its signer in the payload rather than the envelope, so
`parseVPJosePresentation` uses the same two-pass shape: read the holder from the unverified
payload to decide whose key to resolve, verify with `ProofChecker.VerifyJWTForIssuer`, then
parse only the payload the verification returned. The resolved holder key is stored on the
presentation for downstream use.

### Parsing

When `parseJWTPresentation` detects `typ: vp+jwt`, it delegates to `parseVPJosePresentation`,
which reads the presentation structure from the top-level claims. Each entry in the
`verifiableCredential` array is dispatched based on its shape:

- A **string** is parsed as a JWT credential (either `vc+jwt` or classic `jwt_vc`, detected by
  `typ` header). VCDM 2.0 §4.13 expects credentials in a 2.0 presentation to be carried as
  `EnvelopedVerifiableCredential` objects; bare JWT strings are accepted as a deliberate
  leniency, which is also what lets a v1.1 `jwt_vc` ride inside a 2.0 presentation.
- A **JSON object** with `"type": "EnvelopedVerifiableCredential"` is parsed as an enveloped
  credential (see below).
- Any other **JSON object** is parsed as a JSON-LD credential with Linked Data Proofs.

Every credential is verified against **its own** issuer; the VP signature says nothing about
who issued the credentials it carries.

## `EnvelopedVerifiableCredential`

An `EnvelopedVerifiableCredential` (VCDM 2.0 §4.13) embeds a secured credential inside a VP
using a `data:` URI. It appears as a JSON-LD object in the VP's `verifiableCredential` array:

```json
{
  "@context": "https://www.w3.org/ns/credentials/v2",
  "type": "EnvelopedVerifiableCredential",
  "id": "data:application/vc+jwt,eyJhbGciOi..."
}
```

### Parsing

`parseEnvelopedCredential` in `verifier/presentation_parser.go` recognizes the envelope:

1. Checks that `type` is `"EnvelopedVerifiableCredential"`.
2. Checks that `id` starts with `"data:application/vc+jwt,"`, compared case-insensitively —
   RFC 2397 makes the `data` scheme and the media type case-insensitive.
3. Extracts the JWT string after the prefix.
4. Checks that the token inside really is a `vc+jwt`. `parseJWTCredential` re-dispatches on
   the inner `typ`, so without this the envelope's declared media type would say nothing
   about what it carries and a legacy `jwt_vc` would be accepted under a `vc+jwt` label.
5. Delegates to `parseJWTCredential`, which verifies it against its own issuer.

The `@context` on the envelope object is for JSON-LD typing only — the actual credential
content is inside the JWT.

### VP compatibility

Enveloped credentials are recognized inside any VP format:

| VP format | Enveloped credential support |
|-----------|------------------------------|
| Classic JWT VP (`vp` claim) | ✅ |
| JSON-LD VP (Linked Data Proof) | ✅ |
| `vp+jwt` (VC-JOSE-COSE) | ✅ |

### Constraints

- The `data:` URI must not have parameters (e.g., `data:application/vc+jwt;base64,...` is
  rejected). The JWT is placed directly after the media type, not base64-encoded again.
- Only `application/vc+jwt` is recognized as a media type. Other `data:` URI media types are
  not supported.
- The token inside must declare `typ: vc+jwt`, matching the media type the envelope declares.

## Format dispatch

Dispatch on the `typ` header is **exhaustive**: a type that does not belong in the position it
was found in is rejected with `ErrorUnexpectedJWTType`, never reinterpreted as another format.
A `vp+jwt` handed in where a credential is expected is an error, and so is a `vc+jwt` handed
in where a presentation is expected.

`normalizeJOSEType` canonicalizes the header first. RFC 7515 §4.1.9 lets a producer omit the
`application/` prefix and makes media types case-insensitive, so `vc+jwt`,
`application/vc+jwt`, `VC+JWT` and `Application/VC+JWT` all name the same type.

The optional `cty` header is checked while dispatching: §3.1.3 says it SHOULD be `vc` for a
credential and `vp` for a presentation, and a `cty` contradicting the `typ` describes a token
whose own headers disagree about what it contains.

| Token shape | `typ` header | Format | Parser |
|---|---|---|---|
| Compact JWT (no `~`) | absent / `JWT` | `jwt_vc` / JWT VP | `parseJWTCredential` / `parseJWTPresentation` |
| Compact JWT | `vc+jwt` | `vc+jwt` | `parseJWTCredential` → `parseVCJoseCredential` |
| Compact JWT | `vp+jwt` | `vp+jwt` | `parseJWTPresentation` → `parseVPJosePresentation` |
| Compact JWT | anything else | — | rejected (`ErrorUnexpectedJWTType`) |
| Compact JWT with `~` disclosures | — | `sd-jwt` | `ParseWithSdJwt` |
| JSON object (`{...}`) | — | `ldp_vc` / `ldp_vp` | `parseJSONLDPresentation` / `parseAndVerifyJSONLDCredential` |
| JSON object with `type: EnvelopedVerifiableCredential` | — | embedded `vc+jwt` | `parseEnvelopedCredential` |

## Status lists

A `vc+jwt` status-list credential is verified the same way as any other `vc+jwt`: the issuer
is read from the payload and the signature checked against a key belonging to it
(`VerifyStatusListJWTForIssuer`). The path has **no fallback** — an unverifiable status list
is rejected (`ErrorStatusListVCJoseUnverifiable`) rather than trusted, because a status list
that cannot be attributed to anyone is worth less than none at all.

The `x5c` fallback that `VerifyStatusListJWT` offers is not reachable from here. It lifts a
key out of whatever certificate the token carries without validating a chain, which combined
with an issuer read from the same unverified payload would let anyone able to answer the
status-list URL serve a self-signed list attributed to the real issuer.

## Configuration

No additional configuration is needed. VC-JOSE-COSE support is always enabled. The existing
`verifier.vcDataModelVersions` option controls which VC Data Model versions are accepted for
`vc+jwt` credentials, just as it does for `jwt_vc` and `ldp_vc`.

## Related documentation

- [VC Data Model versions](vc-data-model-versions.md) — version detection, configuration, and
  compatibility table.
- [JSON-LD proof verification](json-ld-proof-verification.md) — how `JsonWebSignature2020`
  proofs are verified for `ldp_vc` credentials.
- [HTTPS-based issuer identifiers](https-issuer-identifiers.md) — key discovery for issuers
  identified by HTTPS URLs.
