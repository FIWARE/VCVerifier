# Code Review — PR #119 "Ticket 53/work" (HTTPS-based issuer identifiers)

**Target:** https://github.com/FIWARE/VCVerifier/pull/119
**Head:** `3ed45fc` (`ticket-53/work` → `main`)
**Scope:** 21 files, +3128 / −27
**Build/vet/test status:** `go build ./...`, `go vet ./...` and `go test ./...` all pass locally.

## Summary

The feature is well-structured and the code reads cleanly: a single `HttpsIssuerResolver`
abstraction, one shared instance with one JWKS cache, three dispatch points
(`jwt_proof_checker.go`, `ld_proof_checker.go`, `credential_status_client.go`), all failing
closed when the resolver is absent. Doc comments are thorough and the design doc
(`docs/https-issuer-identifiers.md`) is genuinely useful. Test coverage of the resolver
itself is good (732 lines).

However, **the trust-validation half of the change is not safe to merge as-is.** Reusing the
existing `trustedIssuersLists` / `trustedParticipantsLists` `url` field to mean *"an issuer
identity"* on top of its established meaning *"a registry endpoint"* creates an authorization
bypass, and the HTTPS path silently drops the per-credential-type scoping that the DID path
enforces. Those are blocking. The resolver also has some spec-conformance and robustness
issues that should be addressed before this is used against real issuers.

---

## Blocking

### 1. Registry URLs and issuer identities share one config field → trust bypass
`verifier/trustedissuer.go:75-76,150-163`, `verifier/trustedparticipant.go:60-71,97-104`

`TrustedIssuersList.Url` has always meant *"the address of a trust registry to query"*. The
new code reinterprets the same field as *"an issuer identifier to string-compare against"*
whenever the credential's issuer happens to start with `https://`, with no way to tell the two
apart. Registry URLs are `https://` too.

The PR's own fixture demonstrates the collision — `config/data/config_test_https_issuer.yaml`
puts both meanings in one list under the same `type: ebsi`:

```yaml
trustedIssuersLists:
  - type: ebsi
    url: https://til-pdc.ebsi.fiware.dev     # a registry endpoint
  - type: ebsi
    url: https://issuer.example.com          # an issuer identity
```

With this config, a credential whose `issuer` is literally `https://til-pdc.ebsi.fiware.dev`
is trusted unconditionally — no registry lookup, no attribute check. Registry URLs are public
knowledge, so this is attacker-reachable: anyone who can serve
`/.well-known/jwt-vc-issuer` on a host matching a configured registry URL is trusted. Every
existing deployment that points at an `https://` TIR/TIL is silently exposed the moment this
ships.

**Fix:** give HTTPS issuers their own list type rather than overloading `url`. Either a new
`type` value (`type: https-issuer`, matched only when `isHttpsIssuer(issuerID)`) or a separate
`trustedIssuerUrls` field. Then `matchesHttpsIssuerURL` should only consider entries carrying
that marker, and the fixture should stop mixing the two.

### 2. HTTPS issuers escape per-credential-type trust scoping
`verifier/trustedissuer.go:154-163`

The DID path iterates the credential's **own** types and looks up `til[credentialType]`, so an
issuer trusted for `EmployeeCredential` cannot vouch for `AdminCredential`. `validateHttpsIssuer`
ignores the credential's types entirely and iterates the whole `til` map, returning `true` on the
first match anywhere:

```go
for credType, tilEntries := range til {      // every type in the scope, not the credential's
    for _, entry := range tilEntries {
        if matchesHttpsIssuerURL(issuerID, entry.Url) {
            return true, nil
        }
    }
}
```

So an HTTPS issuer configured only for a low-privilege credential type is accepted for every
other type in the same scope. It also skips the `ErrorNoTilForType` check, so a credential type
with no TIL configured at all passes.

The same applies to the wildcard: `matchesHttpsIssuerURL` treats `*` as matching regardless of
type, whereas `isWildcardTil` is evaluated per type in the DID path. A `*` configured for one
type now trusts any HTTPS issuer for all types.

**Fix:** scope the loop to `verifiableCredential.Contents().Types` (skipping `baseCredentialTypes`
as the DID path does) and keep the per-type wildcard semantics.

### 3. Unauthenticated SSRF via attacker-chosen issuer URL
`verifier/https_issuer_resolver.go:125-289`

Proof verification runs during `ParsePresentation` (`verifier/presentation_parser.go:263,520`),
which is **before** any trust-registry validation (`verifier/verifier.go:720-726`). An
unauthenticated caller posting a VP token therefore fully controls the URL the verifier fetches:

- `issuerURL` comes straight from the JWT `iss` / LD `verificationMethod` with no allowlist.
- `metadata.jwks_uri` and `metadata.authorization_servers[]` are then followed **without any
  scheme or host restriction** — the response body picks the next hop, so an attacker-controlled
  `/.well-known/jwt-vc-issuer` can redirect the fetch to `http://169.254.169.254/…` or any
  internal address.
- `fetchJSON` uses the default `http.Client` redirect policy, so an `https://` metadata URL can
  302 into `http://` or an internal host.
- Failures are not cached (`ResolveIssuerKey` only caches on success), so each rejected token
  costs up to four fresh outbound requests — a cheap amplifier.
- `io.ReadAll(resp.Body)` at line 283 is unbounded; a hostile endpoint can stream until the
  process OOMs.

**Fix:** require `https` scheme on `jwks_uri` and every `authorization_servers` entry and pin
them to the issuer's host (or a configured allowlist); set `CheckRedirect` to reject cross-scheme
and off-host redirects; wrap the body in `io.LimitReader`; and negatively cache resolution
failures with a short TTL. Consider gating the resolver behind the configured trusted-issuer
URLs so unknown hosts are never contacted at all.

---

## Should fix before merge

### 4. Well-known paths are appended, not inserted — wrong for issuers with a path
`verifier/https_issuer_resolver.go:159,230`

```go
metadataURL := issuerURL + WellKnownJwtVcIssuer
```

Both SD-JWT VC §5.2 and RFC 8414 §3.1 require the well-known segment to be inserted **between
the host and the path**, not appended. For issuer `https://example.com/tenant1` the correct URL
is `https://example.com/.well-known/jwt-vc-issuer/tenant1`; this code requests
`https://example.com/tenant1/.well-known/jwt-vc-issuer`. Any multi-tenant issuer will fail to
resolve. (OpenID4VCI's `/.well-known/openid-credential-issuer` *is* appended, so
`resolveViaFallbackPath` at line 197 is correct as written — the two conventions genuinely
differ and that's worth a comment.)

### 5. Key rotation is not handled — stale cache never refreshes
`verifier/https_issuer_resolver.go:129-134`

```go
if cached, found := r.cache.Get(issuerURL); found {
    if keySet, ok := cached.(jwk.Set); ok {
        return findKeyInSet(keySet, kid)     // no refetch when kid is absent
    }
}
```

When an issuer rotates and signs with a new `kid`, the cached set doesn't contain it and every
verification fails for up to `DefaultJwksCacheTTL` (15 min) with `ErrorIssuerKeyNotFound`. The
standard behaviour is to treat a cache miss on `kid` as a trigger to refetch once (with a
rate limit to avoid turning it into a DoS vector).

### 6. Empty `kid` picks an arbitrary key instead of trying all
`verifier/https_issuer_resolver.go:298-305`, `verifier/ld_proof_checker.go:242-247`

`findKeyInSet` returns `keySet.Key(0)` when no `kid` is given. `httpsJwksKeyId` returns `""` for
any `verificationMethod` without a fragment, and JWTs are not required to carry `kid`. For a
multi-key JWKS this makes verification depend on JWKS ordering — a signature valid under key #2
is rejected. Iterating the set and accepting the first key that verifies is both correct and
what every JWKS consumer does.

### 7. `alg` taken from the attacker-controlled header, key `alg`/`use` ignored
`verifier/jwt_proof_checker.go:148-149`

```go
alg, _ := headers.Algorithm()
payload, err := jws.Verify(token, jws.WithKey(alg, key))
```

The error is discarded and there is no allowlist. jwx will reject an outright type mismatch, but
nothing here pins the algorithm to what the JWKS entry declares. A JWKS key with `"alg": "PS256"`
or `"use": "enc"` will still be used for RS256 verification. Prefer the key's own `alg` when
present, otherwise validate the header value against a fixed allowlist, and don't swallow the
`ok` return.

### 8. `ErrorIssuerMismatch` is masked by the fallback path
`verifier/https_issuer_resolver.go:137-147`

A failed issuer check on the primary path is a security signal, not a "try the next endpoint"
signal — but it's swallowed and the code falls through to `resolveViaFallbackPath`, ultimately
surfacing as `ErrorIssuerMetadataNotFound`. Operators lose the ability to distinguish "no
metadata" from "the endpoint claimed a different identity". Return `ErrorIssuerMismatch`
immediately.

### 9. Fallback path skips the RFC 8414 issuer check the primary path performs
`verifier/https_issuer_resolver.go:237-246`

`OAuthServerMetadata.Issuer` is declared and parsed but never compared to `authServerURL`, and
`OidcCredentialIssuerMetadata.Issuer` is never compared to `issuerURL`. RFC 8414 §3.3 requires
that check on both. Right now the primary path is strict and the fallback path is not, which is
exactly backwards from a defence perspective — the fallback follows an extra attacker-supplied
hop.

### 10. Trailing-slash normalization breaks exact issuer matching
`verifier/https_issuer_resolver.go:126,172`

`issuerURL` is trimmed of its trailing `/` before both URL construction and the
`metadata.Issuer != issuerURL` comparison. An issuer whose canonical identifier genuinely is
`https://example.com/` publishes `"issuer": "https://example.com/"` and is rejected as a
mismatch. Either normalize both sides or don't normalize at all — as written, the comparison
is neither exact nor consistent.

---

## Minor / cleanup

- **`integration_test/helpers/https_issuer_mock.go` is dead code.** 294 lines of exported
  helpers with zero consumers; `CLAUDE.md` acknowledges this as a known gap. Given the trust
  logic above, an end-to-end test that exercises a real HTTPS issuer through the full flow would
  have caught findings 1 and 2. Either land the tests in this PR or drop the file until they exist.
- **No `context.Context` plumbing** in the resolver — a 10s client timeout is the only bound,
  and requests can't be cancelled when the caller goes away.
- **`ErrorNoTilDefined` is the wrong error** for `validateHttpsIssuer`'s no-match case
  (`trustedissuer.go:162`). A TIL *is* defined; the issuer just isn't in it. It also aliases
  `ErrorNoTilForType` (same message string) — pre-existing, but the new call site makes it more
  confusing.
- **Cache TTL ignores HTTP caching headers.** `Cache-Control` / `max-age` on the JWKS response
  is discarded in favour of a fixed 15 min.
- **README not updated.** The new config semantics for `trustedIssuersLists` /
  `trustedParticipantsLists` are only described in `docs/https-issuer-identifiers.md` and in
  struct comments — nothing in the user-facing README.
- **Git history pollution.** Commit `f9cb9c9` adds a full `gh_2.50.0_linux_amd64/` CLI
  distribution (binary + man pages), removed again later in the branch. It's absent from the net
  diff but permanently in the history — worth squashing before merge.

---

## What's good

- The three dispatch points all fail closed with `ErrorHttpsIssuerNotSupported` when no resolver
  is configured, and the nil-interface check is correct (`GetHttpsIssuerResolver()` returns a
  genuinely nil interface when `InitPresentationParser` hasn't run).
- Sharing one resolver instance across the JWT, LD-proof and status-list paths so a single JWKS
  cache serves all three is the right call, and the init ordering is documented at the call site
  (`verifier/verifier.go:373-376`).
- `resolveHttpsProofKey` keeps `proofPurpose` and issuer/holder binding enforced even though
  verification relationships can't be, and the doc comment explains precisely why — a genuinely
  good piece of documentation of a limitation rather than a silent gap.
- Ordering `isHttpsIssuer` before the `did:elsi` rejection in `resolveProofKey` is correct, and
  refactoring repeated `verifiableCredential.Contents().Issuer.ID` into a local is a nice
  drive-by cleanup.
- The `httpsJwksKeyId` fragment-vs-full-URI distinction between the LD path and the DID path is
  subtle and correctly handled.

---

## Recommendation

**Request changes.** Findings 1–3 are security-relevant and reachable from unauthenticated
input; 1 and 2 change the trust decision for existing deployments. Findings 4–10 are correctness
and conformance issues that will surface as soon as this meets a real issuer. The resolver
architecture and the JWT/LD/status-list integration are sound and worth keeping — the work is
concentrated in the trust-list modelling and in hardening the outbound fetch.
