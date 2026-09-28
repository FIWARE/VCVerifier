# Release Notes — W3C VC Data Model 2.0 Support

This release adds support for the [W3C VC Data Model
2.0](https://www.w3.org/TR/vc-data-model-2.0/) data model alongside v1.1: the v2 JSON-LD context
is vendored and served offline, the data model version of an incoming credential is detected and
can be restricted by configuration, and the VC 2.0 status list types are handled.

See [docs/vc-data-model-versions.md](docs/vc-data-model-versions.md) for the full picture,
including what VC 2.0 support does **not** cover.

## ⚠️ Breaking Change — every JSON-LD credential must declare a base context

The VC Data Model version of a credential is now enforced, and the enforcement is strict:

- The version is taken from the **first** entry of the credential's `@context`, as both data
  models require (VCDM 2.0 §4.3, VCDM 1.1 §4.1). A base context appearing later in the array no
  longer declares a version.
- A credential carrying **both** base contexts declares no version. It is valid under neither
  data model and no longer satisfies an allowlist for either.
- A credential whose `@context` is absent or whose first entry is not a recognized base context
  is **rejected** with `vc_data_model_version_not_accepted`. Previously such a credential was
  treated as "not a data model credential" and skipped the check entirely.

`verifier.vcDataModelVersions` defaults to both versions, and an empty list means *all recognized
versions*, not *check disabled* — **there is no configuration in which these credentials are
accepted.**

**Who is affected:** deployments accepting `ldp_vc` or `jwt_vc` credentials that carry no
`@context`, a non-W3C `@context`, a base context in a position other than the first, or both base
contexts. SD-JWT VCs are unaffected — they are exempt from the check.

The rejection is logged with the credential id and the `@context` that was seen, so an affected
credential can be identified from the logs.

## 🔒 Security Fix — signing key is now bound to the claimed issuer

A JWT credential's signing key is resolved from the `kid` header, while the issuer it
asserts is read from the `iss` claim. Nothing required the two to agree, so a credential
signed with a self-generated key (`kid: did:jwk:<own key>#0`) while claiming an unrelated
issuer (`iss: did:web:trusted.issuer.example.com`) verified successfully and was parsed
with the **claimed** issuer. Since the trusted-issuer and trusted-participant lookups key
off the credential's issuer, such a credential could be attributed to any issuer a
deployment trusts.

`JWTProofChecker.VerifyJWTAndReturnKey` now rejects a token whose `kid` names a DID
different from its `iss` claim, with `issuer_key_mismatch`. This affects every JWT path:
`jwt_vc` credentials, JWT presentations and SD-JWT VCs. A `kid` that is not a DID (a bare
key id or a relative fragment) asserts no identity and is not compared, so those tokens
are unaffected. The JSON-LD path already bound the proof key to the credential issuer.

Legitimate credentials whose `kid` and `iss` name the same DID, or whose `kid` is a bare
key id, continue to verify unchanged. A deployment that was (knowingly or not) accepting
credentials signed by a key belonging to a DID other than the issuer will see them
rejected.

## 🔒 Security Fix — VC-JOSE-COSE documents are bound to the identity they name

The fix above binds the signing key to the *envelope's* `iss` claim. VC-JOSE-COSE tokens have
no `iss` claim: a `vc+jwt`'s issuer is the credential's own `issuer` property and a `vp+jwt`'s
presenter is the presentation's `holder`, both inside the payload. Those properties were read
after verification but never checked against the key that produced the signature, so with the
`kid` deciding key resolution on its own:

- a `vc+jwt` signed with a self-generated `did:jwk` key could name **any** trusted issuer in
  `issuer` and be accepted — and `issuer` is what the trusted-issuer registry lookups key off,
  so this was full issuer impersonation;
- a `vp+jwt` could claim **any** `holder`, which becomes the subject of the issued access token
  and drives holder policy validation;
- a `vc+jwt` **status list** took the `x5c` fallback, which lifts a key out of whatever
  certificate the token carries without validating a chain. Anyone able to answer the
  status-list URL could serve a self-signed list attributed to the credential's real issuer,
  with every revocation bit clear.

`JWTProofChecker.VerifyJWTForIssuer` now verifies these tokens against a key belonging to the
identity the document itself names, and the parsers read that identity before resolving a key.
A document naming nobody is rejected (`vc_jwt_credential_has_no_issuer`,
`vp_jwt_presentation_has_no_holder`), and the `vc+jwt` status-list path has no fallback at all
(`vc_jose_status_list_verification_not_supported`).

Tokens signed by a key their claimed issuer or holder actually controls verify unchanged.

## New Features

### VC Data Model 2.0 context

- The `https://www.w3.org/ns/credentials/v2` context is vendored in `common/contexts/` and served
  by the embedded document loader, so v2 credentials are canonicalized and verified without any
  network access, exactly like the v1 context.

### Version detection and filtering

- `common.DetectVCDataModelVersion` derives the data model version from the first `@context`
  entry.
- The new `verifier.vcDataModelVersions` option restricts which versions are accepted. Allowed
  values are `"1.1"` and `"2.0"`; the default is both.
- Credentials failing the check are rejected with `vc_data_model_version_not_accepted`.

### VC 2.0 status lists

- `BitstringStatusListEntry` / `BitstringStatusListCredential` (VCDM 2.0) are handled alongside
  the existing `StatusList2021Entry` / `StatusList2021Credential`, with the same issuer binding.

## Configuration

```yaml
verifier:
    vcDataModelVersions:
        - "1.1"
        - "2.0"
```

**Quote the values.** An unquoted YAML list (`[1.1, 2.0]`) is read as floats and `2.0` arrives as
`2`. These spellings are normalized rather than rejected, so an unquoted list still boots, but
quoting avoids the question. An unrecognized value fails startup with
`unsupported_vc_data_model_version`, naming the offending value.

The option applies to **incoming credentials only**. The presentation envelope's own `@context`
is not checked: the envelope is built by the wallet, and its data model version is not a property
of the credentials being asserted.

## Scope and Limitations

VC 2.0 support means the **data model**. The credential still has to be secured by a mechanism
VCVerifier verifies, which today means `ldp_vc` with a `JsonWebSignature2020` Linked Data Proof,
or `jwt_vc` carrying a v1.1-style `vc` claim with a v2 context.

### VC-JOSE-COSE (`vc+jwt` / `vp+jwt`)

- [VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/) is now fully supported. In a `vc+jwt`
  credential, the JWT payload **is** the credential (no `vc` claim wrapper). In a `vp+jwt`
  presentation, the JWT payload **is** the presentation (no `vp` claim wrapper). The `typ` JOSE
  header selects the parsing path.
- `vc+jwt` credentials participate in the VC Data Model version gate — `verifier.vcDataModelVersions`
  applies to them the same way it does to `jwt_vc` and `ldp_vc`. On top of that a `vc+jwt` must
  carry the VCDM 2.0 base context: VC-JOSE-COSE §3.1.1 secures a 2.0 document, so a v1.1 payload
  is not a well-formed `vc+jwt` even where 1.1 credentials are accepted.

**Identity binding.** Neither format names its signer in the JWT envelope — a `vc+jwt` has no
`iss` claim, and its issuer is the credential's own `issuer` property; a `vp+jwt`'s presenter is
the presentation's `holder`. Both are verified against a key belonging to the identity the
*document* names, not the one the `kid` or `iss` header suggests. A credential or presentation
attributed to a party whose key did not sign it is rejected, which matters because the credential
issuer is what the trusted-issuer registry lookups key off and the presentation holder becomes the
subject of the issued access token.

**Registered claims are redundant copies.** `iss`/`issuer`, `sub`/`credentialSubject.id` and
`jti`/`id` must agree where both are present; a disagreement makes the document malformed.
Per VC-JOSE-COSE §3.1.3, `iat` and `exp` time the *signature* rather than the credential, so the
payload's `validFrom`/`validUntil` state its validity and `nbf`/`exp` may only narrow that window.
`iat` is not mapped to `validFrom` at all.

**Both formats must be VCDM 2.0 documents.** VC-JOSE-COSE §3.1.1 defines `vc+jwt` over a 2.0
credential and §3.1.2 defines `vp+jwt` over a 2.0 presentation, so a payload whose first
`@context` entry is not the 2.0 base context is rejected at parse time — regardless of
`verifier.vcDataModelVersions`, which selects which data models a deployment accepts rather than
what these formats are. On a presentation the check runs before its credentials are parsed. This
is the only case where a presentation envelope's `@context` is examined; classic JWT VPs and
JSON-LD VPs are unaffected.

**Dispatch on `typ` is exhaustive.** A type that does not belong where it was found — a `vp+jwt`
in a credential position, a `vc+jwt` in a presentation position, or any unimplemented type — is
rejected with `unexpected_jwt_typ_header` rather than reinterpreted as the legacy `vc`/`vp`-claim
format. Per RFC 7515 §4.1.9, `application/vc+jwt` and `vc+jwt` are the same type, in any case.

**Holder binding** on `vp+jwt` uses RFC 7800 `cnf`, which VC-JOSE-COSE §4.1.3 registers for that
purpose. VCDM 2.0's `confirmationMethod` is a reserved property with no defined semantics and is
not implemented.

### Enveloped credentials

- `EnvelopedVerifiableCredential` (VCDM 2.0 §4.13) is now recognized inside any VP format:
  a JSON-LD object with `"type": "EnvelopedVerifiableCredential"` whose `id` is a
  `data:application/vc+jwt,<compact-JWS>` URI is extracted and parsed as a `vc+jwt` credential.
- The declared media type binds what is inside the envelope: the token must itself be a `vc+jwt`.
  The prefix is matched case-insensitively, as RFC 2397 requires; parameters and the `;base64`
  variant are rejected.

Not supported:

- **COSE** (`vc+cose`) — only the JOSE half of VC-JOSE-COSE is implemented.
- **`DataIntegrityProof` cryptosuites** (`ecdsa-rdfc-2019`, `eddsa-rdfc-2022`, …) — parsed but
  not verified. A VC 2.0 issuer following the current W3C recommendations is more likely to use
  these than `JsonWebSignature2020`, so this is worth checking against the issuers a deployment
  has to accept.
