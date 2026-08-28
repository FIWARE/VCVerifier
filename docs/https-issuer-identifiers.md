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
   `<issuer-url>/.well-known/jwt-vc-issuer`. The metadata provides either an
   inline `jwks` or a `jwks_uri`.
2. **OpenID4VCI Credential Issuer Metadata** (fallback):
   `<issuer-url>/.well-known/openid-credential-issuer`. Its
   `authorization_servers` are resolved via
   `/.well-known/oauth-authorization-server` (RFC 8414), whose metadata
   provides the `jwks_uri`.

The `issuer` field in the fetched metadata must equal the issuer URL the
lookup started from (RFC 8414 §3.3). A mismatch is rejected with
`ErrorIssuerMismatch`, so an issuer cannot delegate its identity to a
different party by serving somebody else's metadata.

Resolved key sets are cached per issuer URL (`DefaultJwksCacheTTL`, 15
minutes). `CachingHttpsIssuerResolver` is created once in
`InitPresentationParser` and shared — via `GetHttpsIssuerResolver()` — by
every component that resolves issuer keys, so one cache serves the JWT path,
the JSON-LD proof path and status-list verification.

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
the JWKS entry with `kid` `key-1`. A `verificationMethod` with no fragment
yields an empty `kid`, which makes the resolver fall back to the only (first)
key in the set.

## Trust validation

Trust lists are not extended with a new type. `Issuer.ID` is treated as a URI
and HTTPS issuers are matched by URL against the configured trust list
entries:

- `verifier/trustedissuer.go` — `validateHttpsIssuer` matches the issuer URL
  against the `TrustedIssuersLists` entries of every credential type.
- `verifier/trustedparticipant.go` — the issuer URL is matched against the
  `TrustedParticipantsLists` entries, regardless of the list `Type`.

The wildcard entry `*` matches any HTTPS issuer; otherwise the match is exact
string equality. An HTTPS issuer is never looked up in an external registry:
EBSI and Gaia-X registries are keyed by DID, and the cryptographic trust for
an HTTPS issuer was already established during signature verification via
metadata discovery and JWKS. Configuring an HTTPS URL in a trust list is
therefore the explicit statement that this issuer is accepted.

## Security notes

- **Transport is the trust anchor.** Key discovery relies on TLS for the
  well-known endpoints, so an HTTPS issuer is exactly as trustworthy as its
  certificate and DNS. This is the model the SD-JWT VC and OpenID4VCI specs
  assume; it is weaker than a DID document anchored in a registry, which is
  why an HTTPS issuer still has to appear in a trust list.
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

## Known gaps

- The JSON-LD path requires the `verificationMethod` to be the issuer URL plus
  a fragment. A `verificationMethod` that is a *different* URL under the same
  origin (e.g. `https://issuer.example.com/keys/1` for issuer
  `https://issuer.example.com`) is rejected by the signer-binding check.
- `integration_test/helpers/https_issuer_mock.go` provides mock issuer servers
  (well-known endpoints, inline and referenced JWKS, OIDC fallback) but no
  end-to-end integration test consumes them yet; coverage for the HTTPS paths
  is at unit level.
