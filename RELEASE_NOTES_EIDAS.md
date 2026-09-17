# Release Notes — eIDAS 2.0 Conformant Credentials Verification

This release adds support for the eIDAS 2.0 trust framework: EU Trusted Lists
(ETSI TS 119 612) are fetched and cached, and credentials can be validated
against the trust services they contain.

## ⚠️ Breaking Change — `did:elsi` requires the eIDAS feature

`did:elsi` verification no longer runs through the JAdES validator; the `jades`
package has been removed. Verification now goes through
`JWTProofChecker.verifyElsiJWT`, which validates the JWS signature and chains the
`x5c` certificate to a CA in the EU Trusted Lists.

**Every deployment that uses `did:elsi` must set `eidas.enabled: true`.** Until
the trust store has been populated, all `did:elsi` verifications fail with
`eidas_trust_store_required_for_did_elsi`. The eIDAS feature is disabled by
default, so an upgrade without a configuration change breaks these deployments.

The guarantees differ from the JAdES ones. Still verified: the payload is covered
by the signature; the signature is made with the key of the `x5c` certificate;
that certificate is bound to the DID through its `organizationIdentifier`
(OID 2.5.4.97); and it is valid and chains to a granted service in the trust
lists. No longer verified: the AdES signed properties (claimed signing time,
signing certificate reference, signature policy) and the JAdES envelope
structure. See
[docs/eidas-verification.md](docs/eidas-verification.md#breaking-change-replacement-of-the-jades-validator);
the four retained properties are pinned by `TestVerifyElsiJWT_Guarantees`.

## New Features

### EU Trusted List support

- ETSI TS 119 612 trust lists are parsed into Go structs: trust service
  providers, their services, X.509 certificates, service types and status URIs
  (`eidas/trustlist.go`).
- A background fetcher resolves the EU List of Trusted Lists (LOTL), follows it
  to the national lists, fetches them through a bounded worker pool and populates
  an in-memory trust store (`eidas/fetcher.go`, `eidas/trust_store.go`). Country
  filtering, refresh interval and graceful start/stop are configurable.

### SD-JWT credential validation

Per-credential-type `eidasConfig` enables an independent validation step
alongside the trusted participants / trusted issuers checks. It enforces SD-JWT
format, takes the issuer certificate from the `x5c` header, and verifies the
chain against the trust lists with PKIX chain building.

### Verified against the live EU Trusted Lists

The implementation is exercised against the production LOTL
(`https://ec.europa.eu/tools/lotl/eu-lotl.xml`, sequence number 394) and all 31 national
XML distribution points it references.

ETSI identifier URIs are compared without their scheme. The published lists use
`http://uri.etsi.org/...`, so a comparison against the `https://` spelling — which is how
the specification text is often transcribed — matched nothing: the LOTL was not recognised
as a LOTL, no distribution points were found, and no service type or status ever matched.

Alongside that, three properties of the real lists are handled:

- Every territory publishes its list twice under the same TSL type, as XML and as a PDF.
  Distribution points are filtered by media type so only the XML is followed.
- Six national lists carry at least one certificate that Go's `crypto/x509` rejects. Such a
  certificate is now dropped from its entry instead of failing the whole list; previously
  AT, DE, FR, IT, LT and RO were lost entirely to a single legacy certificate each.
- One national endpoint rejects Go's default user agent with `403`, so a descriptive
  `User-Agent` is sent.

Together these take a full refresh from **0 countries loaded** to **31 countries, 4733
trust services, 963 of them granted qualified CA services**.

### Trust list freshness and rollback protection

- A list that has passed its `NextUpdate` is rejected (`trust_list_stale`), as is
  one claiming to be issued in the future (`trust_list_not_yet_issued`). Five
  minutes of clock skew are tolerated. `eidas.allowStaleTrustLists` downgrades
  this to a warning.
- A national list served with a lower `TSLSequenceNumber` than the one already
  loaded is rejected (`trust_list_rollback`), so an older list cannot reinstate
  withdrawn services.
- A list that does not declare an EU status determination approach is logged as
  such: its statuses are set by a third-country scheme operator, or by no
  declared rule.

### Point-in-time trust status

`ServiceHistory` is evaluated, so a service's status and type can be read as of a
point in the past. `eidas.statusEvaluation` selects which point:

- `current` (default) — the status the service holds now.
- `issuance` — the status in effect at the credential's `validFrom`, so a
  credential stays verifiable after its issuing CA is withdrawn.

### Qualified certificate enforcement

`requireQualified` now checks the issuer certificate's own `qcStatements`
extension for a `QcCompliance` statement (ETSI EN 319 412-5) in addition to the
CA's trust-list service type. A CA listed under `CA/QC` can issue non-qualified
certificates, so the service type alone was not sufficient. Certificates without
the statement are rejected with `eidas_certificate_not_qualified`.

### Certificate revocation

Chain validation consults OCSP (RFC 6960) and, as a fallback, CRLs (RFC 5280) for
every certificate below the trust anchor. `eidas.revocationCheck` selects the
policy: `soft` (default) rejects known-revoked certificates, `hard` also rejects
an undetermined status, `off` disables the check.

## Configuration

New `eidas:` settings in `server.yaml`:

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master toggle for the eIDAS feature. |
| `lotlUrl` | official EU LOTL | URL of the List of Trusted Lists. |
| `refreshInterval` | `86400` | Seconds between background refreshes. |
| `countries` | all | ISO 3166-1 alpha-2 country filter. |
| `maxWorkers` | `5` | Concurrent national list fetches. |
| `fetchTimeout` | `30` | HTTP timeout per trust list fetch, in seconds. |
| `allowStaleTrustLists` | `false` | Accept lists past their `NextUpdate`. |
| `statusEvaluation` | `current` | `current` or `issuance`. |
| `revocationCheck` | `soft` | `off`, `soft` or `hard`. |
| `revocationTimeout` | `10` | HTTP timeout per OCSP/CRL request, in seconds. |
| `revocationCacheExpiry` | `3600` | Cache lifetime of a determined status, in seconds. |

An unrecognised `statusEvaluation` or `revocationCheck` fails at startup rather
than falling back silently, because both decide whether a credential is accepted.

Per-credential-type `eidasConfig` (via the Credentials Config Service):
`enabled`, `allowedCountries`, `requireQualified`.

## Known Limitations

- **Estonia, and any endpoint behind aggressive bot filtering,** may still refuse the
  fetcher; the country is then skipped with a warning and its previously loaded services
  are kept.
- **XMLDSig signatures on trust lists are not verified.** Integrity relies on
  HTTPS transport. A compromised distribution point can serve a modified list.
- **`did:elsi` uses current trust status only** and searches all countries and
  both qualified and non-qualified CA service types.
- **`QcType` and `QcSSCD` are parsed but not enforced** — restricting a credential
  type to, say, qualified seals only is not configurable.
- **`hard` revocation mode** makes verification depend on the availability of
  every issuing CA's OCSP responder or CRL endpoint.

## Documentation

- [docs/eidas-verification.md](docs/eidas-verification.md) — full feature
  documentation: configuration, validation flow, freshness, status evaluation,
  revocation, `did:elsi`, troubleshooting.
