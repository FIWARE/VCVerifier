# W3C VC Data Model versions

VCVerifier accepts credentials built on the [W3C VC Data Model
v1.1](https://www.w3.org/TR/vc-data-model/) and on the [W3C VC Data Model
v2.0](https://www.w3.org/TR/vc-data-model-2.0/). Which of the two a deployment is willing to
consume is controlled by `verifier.vcDataModelVersions`.

This document describes how the version of a credential is determined, what the option does, and
— importantly — which parts of VC Data Model 2.0 are *not* implemented.

## Detecting the version

The version is derived from the **first entry** of the credential's `@context`:

| First `@context` entry | Version |
|------------------------|---------|
| `https://www.w3.org/2018/credentials/v1` | `1.1` |
| `https://www.w3.org/ns/credentials/v2` | `2.0` |

Both data models require their base context to lead: VC Data Model 2.0 §4.3 mandates
`https://www.w3.org/ns/credentials/v2` as the first item, and VC Data Model 1.1 §4.1 mandates
`https://www.w3.org/2018/credentials/v1`. A base context appearing anywhere else does **not**
determine the version — otherwise any document could claim a version by appending the base
context after its own.

A credential declares no version, and is therefore rejected, when:

- its `@context` is absent or empty, or
- its first `@context` entry is not one of the two base contexts, or
- it carries **both** base contexts — such a document is valid under neither data model, and
  must not satisfy an allowlist for either.

Contexts following the base context (proof suites, credential-specific vocabularies) do not
affect the detected version.

## Configuration

```yaml
verifier:
    vcDataModelVersions:
        - "1.1"
        - "2.0"
```

- **Default**: both versions. An empty or absent list means "all recognized versions", *not*
  "accept anything" — there is no way to switch the check off.
- **Quote the values.** An unquoted list (`vcDataModelVersions: [1.1, 2.0]`) is read by YAML as
  floats, so `2.0` reaches the verifier as `2`. The bare `1` and `2` are normalized to `1.1` and
  `2.0` rather than rejected, but quoting avoids the question. An unrecognized value fails
  startup with `unsupported_vc_data_model_version`, naming the offending value.
- **Credentials only.** The allowlist is applied to each incoming credential. The enclosing
  presentation's own `@context` is not checked: the presentation is an envelope built by the
  wallet, and its data model version is not a property of the credentials being asserted.
- **SD-JWT VCs are exempt.** An SD-JWT VC (`dc+sd-jwt`, `vc+sd-jwt`) is an IETF credential typed
  via its `vct` claim. It carries no `@context` and no data model version, so no allowlist can
  apply to it. This is the only exemption, and it is keyed on the credential format — a
  `ldp_vc`/`jwt_vc` whose `@context` is missing or unrecognized is rejected, not exempted.

A credential failing the check is rejected with `vc_data_model_version_not_accepted`; the log
entry names the credential and the `@context` that was seen.

## Status lists

Both status list generations are supported, and the entry type selects the format:

| `credentialStatus.type` | Status credential |
|-------------------------|-------------------|
| `StatusList2021Entry` | `StatusList2021Credential` |
| `BitstringStatusListEntry` (VC 2.0) | `BitstringStatusListCredential` |

The IETF token status list is supported alongside them. In every case the status list is bound to
the issuer of the referencing credential.

## Supported scope of VC Data Model 2.0

VC 2.0 support means the **data model**: the `https://www.w3.org/ns/credentials/v2` context,
`validFrom`/`validUntil`, and the VC 2.0 status list types. The credential still has to be
secured by a mechanism VCVerifier verifies, which today means:

| Format | Securing mechanism | Supported |
|--------|--------------------|-----------|
| `ldp_vc` | `JsonWebSignature2020` (Linked Data Proof) | ✅ |
| `jwt_vc` | JWS over a v1.1-style `vc` claim, with a v2 context | ✅ |
| `ldp_vc` | `DataIntegrityProof` (`ecdsa-rdfc-2019`, `eddsa-rdfc-2022`, …) | ❌ parsed, not verified |
| `vc+jwt` / `vp+jwt` | VC-JOSE-COSE | ❌ |
| — | `EnvelopedVerifiableCredential` (VCDM 2.0 §4.13) | ❌ |

### Not supported

- **VC-JOSE-COSE** ([W3C](https://www.w3.org/TR/vc-jose-cose/)) is the securing mechanism VCDM
  2.0 defines for JOSE. The JWT payload *is* the credential or presentation, with no `vc`/`vp`
  claim. VCVerifier reads the credential out of the `vc` claim and the presentation out of the
  `vp` claim, so a `vc+jwt` credential parses with no issuer, types or subject, and a `vp+jwt`
  presentation is rejected with `presentation_no_credentials`.
- **Enveloped credentials** (`EnvelopedVerifiableCredential`, a `data:application/vc+jwt,…` URL
  inside a presentation) are not recognized.
- **Data Integrity cryptosuites** other than `JsonWebSignature2020` are parsed but not verified.
  A VC 2.0 issuer following the current W3C recommendations is more likely to use
  `DataIntegrityProof` than `JsonWebSignature2020`, so this is worth checking against the issuers
  a deployment has to accept.

See [docs/json-ld-proof-verification.md](json-ld-proof-verification.md) for how the supported
Linked Data Proofs are verified.
