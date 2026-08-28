# HTTPS-based Issuer Identifiers

VCVerifier accepts credential issuer identifiers that are HTTPS URLs
(`https://issuer.example.com`) alongside the DID methods it already supports
(`did:key`, `did:web`, `did:jwk`, `did:elsi`). An issuer identifier is treated
as a generic URI: whether it is a DID or an HTTPS URL only decides *how* the
signing key is discovered, not what the rest of the verification chain does
with it.

## Why

Not every credential issuer publishes a DID document. The SD-JWT VC and
OpenID4VCI specifications identify an issuer by its HTTPS URL and publish the
signing keys under well-known endpoints. Requiring a DID would exclude every
issuer that follows those specs.

## Key discovery

`verifier/https_issuer_resolver.go` implements `HttpsIssuerResolver`. Given an
issuer URL it resolves a JWKS through two paths, in order:

1. **SD-JWT VC Issuer Metadata** (primary, draft-ietf-oauth-sd-jwt-vc §5.2):
   the well-known segment is *inserted between host and path*, so issuer
   `https://example.com/tenant1` is looked up at
   `https://example.com/.well-known/jwt-vc-issuer/tenant1`. The metadata
   provides either an inline `jwks` or a `jwks_uri`.
2. **OpenID4VCI Credential Issuer Metadata** (fallback): OpenID4VCI §12.2.4
   *appends* its segment instead, so the same issuer is looked up at
   `https://example.com/tenant1/.well-known/openid-credential-issuer`. Its
   `authorization_servers` are resolved via
   `/.well-known/oauth-authorization-server` (RFC 8414 §3.1, inserted like the
   primary path), whose metadata provides the `jwks_uri`.

The two placement conventions genuinely differ; `wellKnownURLInserted` and
`wellKnownURLAppended` implement them separately.

The `issuer` field in the fetched metadata must equal the issuer URL the
lookup started from (RFC 8414 §3.3) — on **every** hop: the SD-JWT VC
metadata, the OpenID4VCI metadata (`issuer` or `credential_issuer`) and the
authorization server metadata. Both sides are canonicalized the same way (a
trailing slash is ignored), so an issuer whose identifier ends in `/` is
neither rejected against its own metadata nor able to pass as another one. A
mismatch fails with `ErrorIssuerMismatch` and is **not** retried through the
other path: an endpoint that answers while claiming a different identity is a
security signal, not a reason to follow one more hop.

Resolved key sets are cached per issuer URL for `DefaultJwksCacheTTL`
(15 minutes), or for the shorter lifetime the origin declares via
`Cache-Control: max-age` — an origin may shorten its keys' cache lifetime but
not extend it beyond the configured TTL. Resolution *failures* are cached too
(`DefaultJwksFailureCacheTTL`, 30s), so a flood of tokens naming an
unresolvable issuer cannot be turned into a flood of outbound requests.
`CachingHttpsIssuerResolver` is created once in `InitPresentationParser` and
shared — via `GetHttpsIssuerResolver()` — by every component that resolves
issuer keys, so one cache serves the JWT path, the JSON-LD proof path and
status-list verification.

### Key rotation

A cached key set that does not contain the requested `kid` triggers **one**
refetch per `MinJwksRefetchInterval` (1 minute). A rotated key is therefore
picked up without waiting out the cache TTL, while unknown key ids cannot
drive the outbound request rate.

### Outbound request restrictions

Everything the resolver fetches is chosen by whoever presented the token: the
issuer URL comes from the token, and the next hops (`jwks_uri`,
`authorization_servers`) come from a document that URL serves. Proof
verification runs before any trust-registry check, so this is reachable from
unauthenticated input and is confined accordingly:

- A URL taken from a metadata document must use the **same scheme** as the
  issuer (no https→http downgrade) and live on the **issuer's own host**,
  unless the operator listed the host in `verifier.httpsIssuerAllowedHosts`.
  Anything else fails with `ErrorMetadataURLNotAllowed`.
- Redirects may not leave the origin of the original request, and at most
  `maxMetadataRedirects` (5) are followed.
- Response bodies are read through an `io.LimitReader` bounded to
  `maxMetadataResponseBytes` (1 MiB).
- Every request carries a context with the resolver's timeout
  (`httpClientTimeout`, 10s).

```yaml
verifier:
  # only needed when an issuer's JWKS or authorization server lives on a
  # different host than the issuer identifier itself
  httpsIssuerAllowedHosts:
    - "keys.example.com"
```

## Where HTTPS issuers are resolved

| Path | Component | Identifier it resolves |
| --- | --- | --- |
| JWT VC / VP signatures | `verifier/jwt_proof_checker.go` | the `iss` claim |
| JSON-LD Linked Data Proofs | `verifier/ld_proof_checker.go` | the proof's `verificationMethod` |
| Status list JWTs | `verifier/credential_status_client.go` | the status list's `iss` claim |

Each of these dispatches on `isHttpsIssuer()` and falls back to DID
resolution for everything else. When an HTTPS identifier is encountered but no
resolver is configured, verification fails closed with
`ErrorHttpsIssuerNotSupported` — it is never silently downgraded.

### `kid` selection

The JWT paths pass the JWS `kid` header straight through to the resolver.

The JSON-LD path cannot: a `verificationMethod` is a URI, and it is the
**fragment** that names the key inside the issuer's JWKS.
`httpsJwksKeyId()` extracts it, so `https://issuer.example.com#key-1` selects
the JWKS entry with `kid` `key-1`.

When no `kid` is available — a fragment-less `verificationMethod`, or a JWS
without a `kid` header — the resolver returns **every** signature-capable key
of the set and the caller accepts the first one that verifies the signature.
Picking `keySet.Key(0)` would make verification depend on JWKS ordering.
Keys marked `use: enc`, or whose `key_ops` exclude `verify`, are never
candidates.

The algorithm is taken from the JWS header but pinned before use: it must be
in the allowlist (`verifier/jws_verification.go` — the RSA, PSS, ECDSA and
EdDSA families; never `none` or the symmetric `HS*` family), and it must match
the `alg` the JWKS entry declares, when it declares one.

## Trust validation

Trust lists are **not** extended for HTTPS issuers, and their entries are never
read as issuer identities. A `trustedIssuersLists` / `trustedParticipantsLists`
entry is always the address of a trusted-issuers-list API to query — EBSI
(v3/v4, v5) or Gaia-X — and the issuer identifier of the credential is looked
up there, whether it is a DID or an HTTPS URL:

```yaml
trustedIssuersLists:
  -   type: ebsi
      url: https://til-pdc.ebsi.fiware.dev
```

So an HTTPS issuer becomes trusted by being registered in one of the
configured registries, exactly like a DID-based one. Nothing in
`verifier/trustedissuer.go` or `verifier/trustedparticipant.go` branches on the
shape of the identifier.

Two consequences worth stating explicitly:

- **A registry address is not an issuer identity.** A credential whose `issuer`
  happens to equal a configured registry URL gets no special treatment; it is
  looked up like any other and rejected unless the registry knows it.
- **The wildcard keeps its meaning.** `url: "*"` in a trusted-issuers list
  waives the registry lookup for that credential type — for every issuer, DID-
  or HTTPS-based alike.

`tir.issuerPathSegment` places the identifier into the registry lookup URL. It
percent-encodes only the characters that would otherwise end the path segment
(`/`, `?`, `#`), so `https://issuer.example.com/tenant1` is addressed as one
issuer, while a DID reaches the registry byte for byte as configured —
including the `%3A` a `did:web` with a port already carries, which a
general-purpose escaper would turn into `%253A`.

Gaia-X entries resolve the issuer as a DID, so an HTTPS issuer simply fails to
resolve there and is not trusted through that path.

## Security notes

- **Transport is the trust anchor.** Key discovery relies on TLS for the
  well-known endpoints, so an HTTPS issuer is exactly as trustworthy as its
  certificate and DNS. This is the model the SD-JWT VC and OpenID4VCI specs
  assume; it is weaker than a DID document anchored in a registry, which is
  why an HTTPS issuer still has to be registered in a trusted-issuers registry
  (or covered by a wildcard) before it is accepted.
- **No verification relationships.** A JWKS has no `authentication` /
  `assertionMethod` distinction, so the relationship enforcement
  `ResolveKeyForRelationship` applies to DID documents cannot apply here. The
  LD-proof path logs that it cannot enforce the relationship and accepts the
  key. The guards that *do* still apply are the `proofPurpose` assertion and
  the binding of the proof signer to the document's `issuer` / `holder`, so a
  key is never accepted for an unrelated identity. This mirrors how a DID
  document that declares no relationships is treated.
- **Status lists stay bound to their issuer.** `assertStatusListIssuer`
  compares issuer strings, so an HTTPS-issued status list must be issued by
  the same HTTPS issuer as the credential that referenced it.
- **Key discovery is not an SSRF primitive.** See *Outbound request
  restrictions* above: same-scheme, same-host (or explicitly allowed),
  origin-bound redirects, bounded bodies, cached failures.

## Known gaps

- The JSON-LD path requires the `verificationMethod` to be the issuer URL plus
  a fragment. A `verificationMethod` that is a *different* URL under the same
  origin (e.g. `https://issuer.example.com/keys/1` for issuer
  `https://issuer.example.com`) is rejected by the signer-binding check.
- An issuer whose JWKS or authorization server lives on another host is only
  resolvable after that host is added to `verifier.httpsIssuerAllowedHosts`.
  The default confines discovery to the issuer's own origin.
