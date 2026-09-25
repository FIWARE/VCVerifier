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

### Claim mapping (VC-JOSE-COSE §3.3.1)

| JWT claim | Credential field |
|-----------|------------------|
| `iss` | `issuer` |
| `sub` | `credentialSubject[0].id` |
| `jti` | `id` |
| `nbf` / `iat` | `validFrom` |
| `exp` | `validUntil` |

Both the JWT-level claims and the payload-level JSON-LD fields are accepted. When both are
present, the JWT-level claim takes precedence; the payload-level field is used as a fallback
when the JWT claim is absent. For `issuer`, a mismatch between `iss` and the payload `issuer`
is an error. For `sub`, `jti`, and dates, the JWT claim silently overrides the payload value
with no mismatch check.

### Parsing

The `typ` header is detected by `jwtMediaType()` in `verifier/presentation_parser.go`. When
`typ` is `vc+jwt`, the token is dispatched to `vcJwtClaimsToCredential`, which reads
credential fields directly from the JWT payload instead of looking inside a `vc` claim.

The credential format is set to `common.FormatVCJWT` (`"vc+jwt"`).

### Version gate

`vc+jwt` credentials carry `@context` and participate in the VC Data Model version gate. The
`verifier.vcDataModelVersions` configuration applies to them the same way it applies to
`jwt_vc` and `ldp_vc` credentials. SD-JWT VCs remain the only exempt format (no `@context`).

## `vp+jwt` Presentations

A `vp+jwt` presentation is a JWT whose JOSE `typ` header is `vp+jwt`. The JWT payload **is**
the presentation — there is no wrapping `vp` claim. The `verifiableCredential` array, `holder`,
`@context`, and `type` are read directly from the top-level JWT claims.

### Claim mapping (VC-JOSE-COSE §3.3.2)

| JWT claim | Presentation field |
|-----------|--------------------|
| `iss` | `holder` |
| `jti` | `id` |

### Parsing

When `parseJWTPresentation` detects `typ: vp+jwt`, it delegates to `parseVPJWTPresentation`,
which reads the presentation structure from the top-level claims. Each entry in the
`verifiableCredential` array is dispatched based on its shape:

- A **string** is parsed as a JWT credential (either `vc+jwt` or classic `jwt_vc`, detected by
  `typ` header).
- A **JSON object** with `"type": "EnvelopedVerifiableCredential"` is parsed as an enveloped
  credential (see below).
- Any other **JSON object** is parsed as a JSON-LD credential with Linked Data Proofs.

### Signature verification

The VP JWT signature is verified during parsing by `ProofChecker.VerifyJWTAndReturnKey`, the
same path used for classic JWT VPs. The resolved holder key is stored on the presentation for
downstream use.

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
2. Checks that `id` starts with `"data:application/vc+jwt,"`.
3. Extracts the JWT string after the prefix.
4. Delegates to `parseJWTCredential`, which detects `typ: vc+jwt` and parses accordingly.

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

## Format dispatch summary

| Token shape | `typ` header | Format | Parser |
|---|---|---|---|
| Compact JWT (no `~`) | absent / `JWT` | `jwt_vc` / JWT VP | `parseJWTCredential` / `parseJWTPresentation` |
| Compact JWT | `vc+jwt` | `vc+jwt` | `parseJWTCredential` → `vcJwtClaimsToCredential` |
| Compact JWT | `vp+jwt` | `vp+jwt` | `parseJWTPresentation` → `parseVPJWTPresentation` |
| Compact JWT with `~` disclosures | — | `sd-jwt` | `ParseWithSdJwt` |
| JSON object (`{...}`) | — | `ldp_vc` / `ldp_vp` | `parseJSONLDPresentation` / `parseAndVerifyJSONLDCredential` |
| JSON object with `type: EnvelopedVerifiableCredential` | — | embedded `vc+jwt` | `parseEnvelopedCredential` |

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
