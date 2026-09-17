# eIDAS 2.0 Trust List Verification

## Introduction

VCVerifier supports verifying Verifiable Credentials against the European Union's [Trusted Lists](https://esignature.ec.europa.eu/efda/tl-browser/) as defined by [ETSI TS 119 612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.02.01_60/ts_119612v020201p.pdf). This enables operators to ensure that credential issuers hold certificates issued by trust service providers (TSPs) recognized under the [eIDAS 2.0 regulation](https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation), the EU's framework for electronic identification and trust services.

Two verification paths are available:

- **SD-JWT credential validation** — Per-credential `eidasConfig` validates that an SD-JWT credential's issuer holds a certificate trusted by the EU Trusted Lists. This is configured individually for each credential type.
- **`did:elsi` credential verification** — Credentials issued by [`did:elsi`](https://www.w3.org/TR/did-core/) identifiers are automatically verified against the EU Trusted Lists when the global eIDAS feature is enabled. No per-credential configuration is needed.

Both paths require the global `eidas.enabled` toggle to be set to `true`.

## How It Works

### Background Trust List Fetching

When the global eIDAS feature is enabled, VCVerifier fetches the EU [List of Trusted Lists (LOTL)](https://ec.europa.eu/tools/lotl/eu-lotl.xml) on startup. The LOTL is an XML document maintained by the European Commission that references each EU member state's national trusted list. VCVerifier discovers and fetches these national trusted lists, extracting all trust service providers (TSPs) and their CA certificates into an in-memory trust store.

### Periodic Refresh

After the initial fetch, VCVerifier re-fetches all trust lists on a configurable interval (default: 24 hours). This ensures that newly added or revoked trust services are picked up without restarting the verifier.

### Certificate Chain Validation

When a credential is presented for verification, VCVerifier extracts the issuer's X.509 certificate (from the SD-JWT `x5c` header or the `did:elsi` JWT `x5c` header) and validates its certificate chain against the cached trust store using standard PKIX chain building — the same mechanism browsers use for TLS certificate validation.

### Qualified vs. Non-Qualified Trust Services

The EU Trusted Lists distinguish between **qualified** and **non-qualified** trust services:

- **Qualified Trust Service Providers (QTSPs)** are subject to stricter EU regulatory oversight and auditing. Their service types include `CA/QC` (Certificate Authority for Qualified Certificates) and `NationalRootCA-QC`.
- **Non-qualified** trust services (service type `CA/PKC`) operate under less stringent requirements.

The `requireQualified` field (default: `true`) controls which service types are accepted during certificate chain validation. When set to `true`, only certificates chaining to qualified trust services are accepted. When set to `false`, non-qualified CAs are also accepted.

Under eIDAS, "qualified" is a property of the issued certificate, not only of the issuing
CA's trust-list entry: a CA listed under `CA/QC` may also issue non-qualified certificates.
`requireQualified: true` therefore applies two checks:

1. the issuing CA must be listed under `CA/QC` or `NationalRootCA-QC` in the trust list, and
2. the issuer's own certificate must declare a **QcCompliance** statement in its
   `qcStatements` extension (ETSI EN 319 412-5 §4.2.1, OID `0.4.0.1862.1.1`).

A certificate that carries no `qcStatements` extension, or one that cannot be parsed, fails
the second check with `eidas_certificate_not_qualified`. The `QcType` (esign / eseal / web)
and `QcSSCD` statements are parsed and logged, but are not enforced — restricting a
credential type to, say, qualified seals only is not currently configurable.

## Global Configuration Reference

The global eIDAS configuration lives in the `eidas:` block of `server.yaml`. All fields are optional — the feature is disabled by default.

```yaml
eidas:
    # Master toggle for the entire eIDAS feature. When false (default), no trust
    # lists are fetched, did:elsi credentials are rejected, and per-credential
    # eidasConfig is rejected with HTTP 400.
    enabled: true

    # URL of the EU List of Trusted Lists (LOTL). Override only for testing or
    # if the EU changes the URL.
    lotlUrl: "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

    # How often (in seconds) to re-fetch and refresh the trust lists.
    # Clamped to [3600, 604800] (1 hour to 7 days). Default: 86400 (24 hours).
    refreshInterval: 86400

    # ISO 3166-1 alpha-2 country codes to restrict which national trusted lists
    # are consulted. Empty (default) means all countries in the LOTL are used.
    countries: ["DE", "FR", "ES"]

    # Maximum number of concurrent national trust list fetches during a refresh
    # cycle. Increase for faster refresh, decrease to reduce network load.
    maxWorkers: 5

    # HTTP timeout (in seconds) for each individual trust list fetch request.
    fetchTimeout: 30

    # Whether to keep using a trust list that has passed its NextUpdate time.
    # Default false: an overdue list is rejected, because the scheme operator
    # committed to publishing a newer one by then.
    allowStaleTrustLists: false

    # When a trust service's status is evaluated: "current" (default) or
    # "issuance". See "Status Evaluation Time" below.
    statusEvaluation: current

    # Certificate revocation checking: "off", "soft" (default) or "hard".
    revocationCheck: soft

    # HTTP timeout in seconds for a single OCSP or CRL request.
    revocationTimeout: 10

    # How long (seconds) a determined revocation status is cached when the
    # responder declares no NextUpdate of its own.
    revocationCacheExpiry: 3600
```

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Master toggle for the entire eIDAS feature. |
| `lotlUrl` | string | `https://ec.europa.eu/tools/lotl/eu-lotl.xml` | URL of the EU List of Trusted Lists. |
| `refreshInterval` | int | `86400` | Seconds between background trust list refreshes. Clamped to [3600, 604800]. |
| `countries` | string list | `[]` (all) | ISO 3166-1 alpha-2 country code filter. Empty means all countries. |
| `maxWorkers` | int | `5` | Maximum concurrent national trust list fetches during refresh. |
| `fetchTimeout` | int | `30` | HTTP timeout in seconds per trust list fetch request. |
| `allowStaleTrustLists` | bool | `false` | Accept trust lists that have passed their `NextUpdate` time. |
| `statusEvaluation` | string | `current` | When trust service status is evaluated: `current` or `issuance`. |
| `revocationCheck` | string | `soft` | Certificate revocation checking: `off`, `soft` or `hard`. |
| `revocationTimeout` | int | `10` | HTTP timeout in seconds per OCSP or CRL request. |
| `revocationCacheExpiry` | int | `3600` | Seconds a determined revocation status is cached absent a responder `NextUpdate`. |

### Trust List Freshness

Every fetched trust list is checked against its own metadata before it is used:

- **`NextUpdate`** — a list whose `NextUpdate` time has passed is rejected (`trust_list_stale`).
  The scheme operator committed to publishing a newer list by that time, so an overdue list
  can no longer be assumed to reflect the current service statuses. Set
  `allowStaleTrustLists: true` to keep using it anyway.
- **`ListIssueDateTime`** — a list claiming to have been issued in the future is rejected
  (`trust_list_not_yet_issued`).
- **`TSLSequenceNumber`** — a national list carrying a lower sequence number than the one
  already loaded for that country is rejected (`trust_list_rollback`). Sequence numbers
  increase with every publication, so a lower one means an older list is being served in
  place of the loaded one, which would silently reinstate withdrawn services.

Both timestamp comparisons allow five minutes of clock skew. A list that declares no
`NextUpdate` at all cannot be judged for staleness; it is accepted and logged as such.

A rejected **LOTL** aborts the whole refresh cycle, leaving the previously loaded trust
store untouched. A rejected **national list** only skips that country: its previously
loaded services are kept (they are not pruned on a failed fetch) and the rest of the
refresh proceeds.

### Certificate Revocation

Chaining to a trust-list CA establishes that a certificate was issued under a listed
service. It does not establish that the certificate is still valid: an individual
certificate is withdrawn through OCSP (RFC 6960) or a CRL (RFC 5280) published by its
issuing CA, not through the trust list, which only records changes to the *service*.

Every certificate on a successfully built chain — all of them except the trust anchor,
whose standing the trust list itself expresses — is therefore checked against the
responders it names. OCSP is tried first, using the responders in the certificate's
Authority Information Access extension; if none answers, the CRL distribution points are
downloaded and the certificate is looked up by serial number. A CRL is only used when it
verifies against the certificate's issuer.

| `revocationCheck` | Revoked certificate | Status could not be determined |
|-------------------|---------------------|-------------------------------|
| `off` | accepted | accepted |
| `soft` (default) | **rejected** (`certificate_revoked`) | accepted, logged |
| `hard` | **rejected** (`certificate_revoked`) | **rejected** (`revocation_status_unknown`) |

"Could not be determined" covers a certificate that names no responder at all, a responder
that cannot be reached, and a responder that does not know the certificate. `hard` gives
the strongest guarantee but makes verification depend on the availability of every issuing
CA's responder, so it needs those endpoints to be reachable from the verifier.

Determined statuses are cached — until the responder's `NextUpdate`, or for
`revocationCacheExpiry` when it declares none — so a busy verifier does not re-query a
responder for every presented credential. An undetermined status is never cached, so a
temporarily unreachable responder does not pin a certificate to "unknown".

Only `http://` and `https://` distribution points are dereferenced; `ldap://` and other
schemes named in a certificate are skipped. Response bodies are size-bounded.

### Status Evaluation Time

A trust service's status is not a constant: a CA can be granted, put under supervision and
later withdrawn. ETSI TS 119 612 §5.5.5 records these transitions in the service's
`ServiceHistory`, and expects the status to be evaluated as of the relevant point in time.
`statusEvaluation` selects that point:

| Value | Evaluated against | Effect |
|-------|-------------------|--------|
| `current` (default) | the status the service holds now | A credential is rejected once its issuing CA is withdrawn, regardless of when the credential was issued. |
| `issuance` | the status in effect at the credential's `validFrom` / `issuanceDate` | A credential stays verifiable after its issuing CA is withdrawn, as long as the CA was granted when the credential was issued. This is the ETSI semantics for validating a signature as of signing time. |

In `issuance` mode both the service status **and** the service type are read from the
history entry that was in effect then, so a CA that was `CA/QC` at issuance and is only
`CA` today still satisfies `requireQualified` for credentials from that period.

Two cases fall back to the current status in `issuance` mode, each logged:

- a credential that carries no issuance date, and
- a service whose history does not reach back to the issuance time — it cannot be shown to
  have been trusted then, so it is not treated as trusted.

An unrecognised `statusEvaluation` value is rejected at startup rather than silently
defaulting, because it decides whether a credential from a withdrawn CA is accepted.

`did:elsi` verification always uses the current status: it has no per-credential
configuration and the JWT carries no issuance date at the point the chain is checked.

### Behavior When Disabled

When `eidas.enabled` is `false` (the default):

- No background trust list fetching occurs and no memory is allocated for the trust store.
- Any `did:elsi` credential is rejected with `eidas_trust_store_required_for_did_elsi`.
- Attempting to enable `eidasConfig` on any credential type results in an HTTP 400 error at configuration load time.

## SD-JWT Credential Validation

### Use Case

SD-JWT credential validation verifies that an SD-JWT credential's issuer holds an X.509 certificate trusted by the EU Trusted Lists. This is the primary eIDAS 2.0 verification path for credentials that carry issuer certificates in the SD-JWT `x5c` header.

### Per-Credential Configuration

The `eidasConfig` block is configured per credential type, alongside other trust checks like `trustedParticipantsLists`, `trustedIssuersLists`, `holderVerification`, and `credentialStatus`:

```yaml
credentials:
    -   type: EuropeanHealthCertificate
        trustedIssuersLists:
            VerifiableCredential:
                - type: ebsi
                  url: https://tir.example.com
        eidasConfig:
            # Toggle eIDAS validation for this credential type.
            enabled: true
            # Per-credential country filter. When non-empty, overrides the
            # global eidas.countries for this credential type. When empty,
            # falls back to the global setting.
            allowedCountries: ["DE", "FR"]
            # When true (default), only qualified trust services (QTSPs) are
            # accepted. When false, non-qualified CAs are also accepted.
            requireQualified: true
```

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Toggle eIDAS validation for this credential type. |
| `allowedCountries` | string list | `[]` (falls back to global) | Per-credential country filter. Overrides `eidas.countries` when non-empty. |
| `requireQualified` | bool pointer | `true` | When `true`, only qualified trust services are accepted. When `false`, non-qualified CAs are also accepted. |

### Full Configuration Example

The following example shows a service with two credential types — one with eIDAS validation enabled and one without:

```yaml
eidas:
    enabled: true
    countries: ["DE", "FR", "ES", "IT"]
    refreshInterval: 86400

configRepo:
    services:
        -   id: healthService
            defaultOidcScope: "default"
            oidcScopes:
                default:
                    credentials:
                        # This credential type requires eIDAS validation
                        -   type: EuropeanHealthCertificate
                            trustedIssuersLists:
                                VerifiableCredential:
                                    - type: ebsi
                                      url: https://tir.example.com
                            eidasConfig:
                                enabled: true
                                allowedCountries: ["DE", "FR"]
                                requireQualified: true
                            holderVerification:
                                enabled: true
                                claim: subject

                        # This credential type does NOT use eIDAS validation
                        -   type: CustomerCredential
                            trustedParticipantsLists:
                                VerifiableCredential:
                                    - https://tir-pdc.ebsi.fiware.dev
                            holderVerification:
                                enabled: true
                                claim: subject
                    presentationDefinition:
                        id: health-presentation
                        input_descriptors:
                            id: health-descriptor
                            constraints:
                                fields:
                                    - id: type-field
                                      path:
                                        - $.vct
                                      filter:
                                        const: "EuropeanHealthCertificate"
                            format:
                                'sd+jwt-vc':
                                    alg: ES256
```

### Important Notes

- **Additional check, not a replacement.** eIDAS validation runs alongside (not instead of) trusted participants/issuers list checks, holder verification, and revocation checks. All configured checks must pass for the credential to be accepted.
- **SD-JWT format required.** eIDAS validation requires the credential to be in SD-JWT format. JWT-VC and JSON-LD credentials are rejected with `eidas_validation_requires_sd_jwt_format` if `eidasConfig` is enabled for their type.
- **Global toggle must be enabled.** The global `eidas.enabled` must be `true` for per-credential `eidasConfig` to work. If the global toggle is off, attempting to enable `eidasConfig` on a credential type results in an HTTP 400 error.

## did:elsi Verification

### What is did:elsi?

`did:elsi` is a [DID method](https://www.w3.org/TR/did-core/) based on the European eIDAS framework. It identifies organizations using their eIDAS `organizationIdentifier` as defined in [ETSI EN 319 412-1](https://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.04.02_20/en_31941201v010402a.pdf), carried in the X.509 certificate's Subject field (OID 2.5.4.97).

Example DID: `did:elsi:VATES-B12345678`

For a quick reference on `did:elsi` configuration, see the [did:elsi section in the README](../README.md#didelsi--eidas-trust-list-verification).

### Automatic Activation

Unlike per-credential SD-JWT validation, `did:elsi` verification is **automatically enabled** when the global `eidas.enabled` is set to `true`. No per-credential configuration is needed — any credential issued by a `did:elsi` identifier triggers eIDAS trust list verification.

### How Verification Works

When VCVerifier receives a credential issued by a `did:elsi` identifier:

1. **Extract the certificate chain** — The `x5c` header of the JWT is parsed to obtain the issuer's X.509 certificate chain.
2. **Bind the DID to the certificate** — The DID's method-specific identifier (e.g. `VATES-B12345678`) is matched against the certificate's `organizationIdentifier` (OID 2.5.4.97). If they do not match, verification fails with `did_elsi_issuer_validation_failed`.
3. **Verify the JWT signature** — The JWT signature is verified using the leaf certificate's public key.
4. **Validate the certificate chain** — The certificate chain is validated against the cached EU Trusted Lists. The issuer's certificate must chain up to a trust service provider listed in the LOTL.

### Limitations

- **JWT format only.** `did:elsi` only supports JWT-format credentials. JSON-LD (Linked Data Proof) presentations with `did:elsi` signers are explicitly rejected with `did_elsi_not_supported_for_ld_proofs`.
- **No per-credential filtering.** Unlike per-credential eIDAS validation, `did:elsi` searches all countries and all certificate service types (both qualified and non-qualified). There is no per-credential country or qualified filter for `did:elsi`.

## Interaction with Other Trust Anchors

The eIDAS certificate chain validation is **independent** of the [EBSI Trusted Issuers Registry](https://hub.ebsi.eu/apis/conformance/trusted-issuers-registry) and [Gaia-X Registry](https://gitlab.com/gaia-x/lab/compliance/gx-registry) trust anchors.

- A credential can be validated by both eIDAS and EBSI/Gaia-X if both are configured — all checks must pass.
- `did:elsi` issuers can also be registered in trusted participants or trusted issuers lists if desired.
- The eIDAS trust store is a separate subsystem: it fetches and caches EU Trusted Lists independently of EBSI TIR queries or Gaia-X compliance checks.

## Dynamic Configuration via Credentials Config Service

The per-credential `eidasConfig` block is supported by the [Credentials Config Service](https://github.com/FIWARE/credentials-config-service) (version >= 2.0.0), allowing dynamic per-credential eIDAS configuration without restarting the verifier. This means operators can enable or disable eIDAS validation for individual credential types, adjust country filters, and toggle the qualified requirement at runtime.

The **global** `eidas:` settings (LOTL URL, refresh interval, countries, maxWorkers, fetchTimeout) remain in `server.yaml` and require a restart to change.

## Troubleshooting

### Error Messages

| Error | Meaning | Resolution |
|-------|---------|------------|
| `eidas_validation_requires_sd_jwt_format` | `eidasConfig` is enabled for a credential type, but the presented credential is not in SD-JWT format. | eIDAS validation only works with SD-JWT credentials. Either disable `eidasConfig` for this credential type, or ensure the credential is presented in SD-JWT format. |
| `eidas_no_x5c_certificates_available` | The SD-JWT credential does not carry X.509 certificates in the `x5c` header. | The issuer must include the certificate chain in the SD-JWT `x5c` header for eIDAS validation. Check the issuer's credential issuance configuration. |
| `eidas_issuer_not_trusted_by_trust_list` | The issuer's certificate does not chain to any trusted service in the EU Trusted Lists. | Verify that the issuer is registered with a trust service provider in the configured countries. If using `allowedCountries`, ensure the issuer's country is included. |
| `certificate_revoked` | A certificate on the issuer's chain has been revoked by its issuing CA. | The issuer must obtain a new certificate. |
| `revocation_status_unknown` | `revocationCheck: hard` is set and the revocation status of a certificate on the chain could not be determined. | Make the issuer's OCSP/CRL endpoints reachable from the verifier, or fall back to `revocationCheck: soft`. |
| `eidas_certificate_not_qualified` | `requireQualified` is set, but the issuer's certificate declares no QcCompliance statement in its `qcStatements` extension, or that extension cannot be parsed. | Have the issuer use a qualified certificate, or set `requireQualified: false` for this credential type if non-qualified issuers are acceptable. |
| `trust_list_stale` | A fetched trust list has passed its `NextUpdate` time. | Normally transient — the scheme operator is late publishing. Set `eidas.allowStaleTrustLists: true` to keep using the overdue list. |
| `trust_list_not_yet_issued` | A fetched trust list claims a `ListIssueDateTime` in the future. | Check the verifier's system clock; if it is correct, the list itself is faulty. |
| `trust_list_rollback` | A national trust list was served with a lower `TSLSequenceNumber` than the one already loaded. | An older list is being served in place of the loaded one. The previously loaded services are kept; investigate the distribution point. |
| `invalid_status_starting_time` | A trust service entry carries an unparseable `StatusStartingTime`. | The trust list is malformed; that country's list is skipped. Report it to the scheme operator. |
| `eidas_trust_store_required_for_did_elsi` | The global eIDAS feature is disabled, but a `did:elsi` credential was received. | Set `eidas.enabled: true` in `server.yaml` and restart the verifier. |
| `did_elsi_issuer_validation_failed` | The DID's organization identifier does not match the certificate's Subject (OID 2.5.4.97). | Check that the issuer's DID suffix matches the `organizationIdentifier` in the X.509 certificate. |
| `did_elsi_certificate_not_trusted` | The `did:elsi` issuer's certificate does not chain to any trusted service in the EU Trusted Lists. | Verify that the issuer is registered with a trust service provider. If using `eidas.countries`, ensure the issuer's country is included. |
| `did_elsi_not_supported_for_ld_proofs` | A JSON-LD (Linked Data Proof) presentation was submitted with a `did:elsi` signer. | `did:elsi` only supports JWT-format credentials. Use JWT-encoded credentials instead. |

### Operational Tips

- **Startup time.** The initial trust list fetch may take 30-60 seconds on startup depending on network conditions. Watch the logs for messages like `TrustListFetcher: refresh complete, N countries loaded, M total services` to confirm successful loading.
- **Empty trust store.** If no trust services are loaded after startup, verify that:
  - The LOTL URL is reachable from the verifier's network.
  - The `countries` filter is not too restrictive (an empty list means all countries).
  - DNS resolution and outbound HTTPS (port 443) are not blocked by firewalls.
- **Slow or unreliable networks.** The `maxWorkers` and `fetchTimeout` fields can be tuned for environments with slow or unreliable network access to the EU trust list servers:
  - Decrease `maxWorkers` (e.g. to `2` or `3`) to reduce concurrent connections.
  - Increase `fetchTimeout` (e.g. to `60`) to allow more time per request.
- **Refresh interval.** The `refreshInterval` is clamped to [3600, 604800] seconds (1 hour to 7 days). Setting a value outside this range is automatically adjusted to the nearest bound. The default of 86400 seconds (24 hours) is appropriate for most production deployments.
