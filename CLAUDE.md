# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VCVerifier is a FIWARE component implementing SIOP-2/OIDC4VP authentication flows. It exchanges Verifiable Credentials (VCs) for JWTs, enabling VC-based authentication and authorization. Supports multiple trust frameworks (EBSI, Gaia-X) and credential formats (JSON-LD VCs, SD-JWTs).

## Build & Test Commands

```bash
# Build
go build -o VCVerifier .

# Run all tests
go test ./... -v

# Run all tests with coverage
go test ./... -v -coverprofile=profile.cov

# Run tests for a single package
go test ./verifier/... -v

# Run a specific test
go test ./verifier/... -v -run TestVerifyConfig

# Docker build (multi-platform)
docker build -t vcverifier .
```

There is no Makefile or linter configuration. CI runs `go test ./... -v` with Go 1.24.

## Configuration

Runtime config is loaded from `server.yaml` (override with `CONFIG_FILE` env var). The config is parsed by `config.ReadConfig()` using gookit/config with YAML driver and mapstructure tags.

Key config sections: `server` (port, timeouts, template/static dirs), `logging`, `verifier` (DID, TIR address, policies, validation mode, key algorithm), `ssiKit` (auditor URL), `configRepo` (dynamic service configurations with scopes and trust endpoints).

## Architecture

**Entry point**: `main.go` — reads config, initializes logging and verifier, sets up Gin router with routes from `openapi/`, serves on configured port with graceful shutdown.

### Package Responsibilities

- **`verifier/`** — Core package (~1500 lines in `verifier.go`). Session management, JWT creation (RS256/ES256), QR code generation, nonce/state management. Request object modes: `urlEncoded`, `byValue`, `byReference`. Also contains:
  - `presentation_parser.go` — Parses VP tokens (JSON-LD and SD-JWT formats), JSON-LD document loading with caching
  - `jwt_verifier.go` — VC content validation with modes: `none`, `combined`, `jsonLd`, `baseContext` (note: `combined` and `jsonLd` currently only check field presence, not real JSON-LD validation). DID verification method resolution for did:key, did:web, did:jwk
  - `trustedissuer.go` / `trustedparticipant.go` — EBSI registry verification
  - `compliance.go` — Policy compliance checking (signatures, dates, etc.)
  - `holder.go` — Holder verification
  - `gaiax.go` — Gaia-X compliance checks
  - `jwt_proof_checker.go` — JWT signature verification via DID-resolved keys; also handles did:elsi via the X.509 `x5c` chain plus the eIDAS trust list (`eidas.VerifyCertificateChain`) and HTTPS-based issuers via `HttpsIssuerResolver`
  - `ld_proof_checker.go` — JSON-LD Linked Data Proof verification (`JsonWebSignature2020`): resolves `verificationMethod` (DID URL or https:// URL), binds the signing key to the credential issuer / presentation holder, enforces the proof purpose
  - `key_resolver.go` — Shared DID→key resolution, including verification-relationship enforcement (`authentication` / `assertionMethod`)
  - `https_issuer_resolver.go` — Key discovery for HTTPS-based issuer identifiers via `/.well-known/jwt-vc-issuer` (SD-JWT VC) with an OpenID4VCI + RFC 8414 fallback, plus a per-issuer JWKS cache
  - `credentialsConfig.go` — Credential configuration management

- **`openapi/`** — HTTP handlers generated from OpenAPI spec (`api/api.yaml`). Routes defined in `routers.go`. Handlers in `api_api.go` (token, authorization, authentication) and `api_frontend.go` (frontend endpoints, WebSocket polling).

- **`tir/`** — Trusted Issuers Registry client. Queries EBSI v3/v4 endpoints, caches results. Includes M2M auth via `tokenProvider.go` and `authorizationClient.go`.

- **`gaiax/`** — Gaia-X compliance client. did:web resolution, X.509 certificate chain validation, trust anchor verification.

- **`eidas/`** — ETSI TS 119 612 EU Trusted List support: XML parsing (`trustlist.go`), background LOTL/national-TL fetching (`fetcher.go`), the in-memory `TrustStore` (`trust_store.go`) and PKIX chain validation against trust-list CAs (`verify.go`). Replaces the former `jades/` package as the did:elsi trust anchor.

- **`config/`** — Configuration structs and YAML parsing. Test fixtures in `config/data/`.

- **`logging/`** — Zap-based structured logging with Gin middleware integration.

- **`common/`** — Shared types: cache interfaces (ServiceCache, TirEndpoints, IssuersCache), clock utilities, HTTP helpers, token signer interfaces.

- **`views/`** — HTML templates and static assets for QR code presentation frontend.

### Request Flow

1. Client hits OpenAPI endpoints (`/api/v1/authorization`, `/token`, etc.)
2. `openapi/` handlers delegate to `verifier/` for session management and credential exchange
3. Verifier validates presentations using the VC verification chain (parsing, signature validation, policy compliance, trust registry checks)
4. Trust anchors are consulted via `tir/` (EBSI) or `gaiax/` clients
5. On success, a JWT is issued to the client

## Testing Patterns

- Uses `github.com/stretchr/testify` for assertions
- Table-driven tests with `type test struct` and `t.Run()` loops
- Mock implementations within test files (e.g., `mockNonceGenerator`, `mockSessionCache`)
- Test fixtures in `config/data/` (YAML files)
- Logging is initialized in tests with a shared `LOGGING_CONFIG` variable

## Important Files

- **`main.go`** — Entry point; reads config, initializes verifier, sets up Gin router.
- **`config/config.go`** — All configuration structs (`Configuration`, `Verifier`, `Server`, etc.) with `mapstructure` tags and defaults.
- **`common/metadata.go`** — OAuth2 grant type and token type constants (`TYPE_CODE`, `TYPE_VP_TOKEN`, `TYPE_TOKEN_EXCHANGE`, `TYPE_ACCESS_TOKEN`).
- **`common/cache.go`** — `Cache` interface wrapping `patrickmn/go-cache` (Get/Set/Add/Delete/GetWithExpiration).
- **`common/tokenSigner.go`** — `TokenSigner` interface (Sign method using lestrrat-go/jwx).
- **`verifier/verifier.go`** — `Verifier` interface (lines 92-106) and `CredentialVerifier` implementation. Key methods: `GetToken` (authorization_code exchange, line 490), `GenerateToken` (VP token exchange, line 580), `AuthenticationResponse` (stores JWT in tokenCache, line 846), `generateJWT` (builds JWT with claims, line 1230).
- **`openapi/api_api.go`** — HTTP handlers: `GetToken` (line 97, routes by grant_type), `handleTokenTypeCode` (line 330), `handleTokenTypeVPToken` (line 290), `handleTokenTypeTokenExchange` (line 260), `verifiyVPToken` (line 309).
- **`openapi/model_token_response.go`** — `TokenResponse` struct with JSON tags.
- **`api/api.yaml`** — OpenAPI spec: `TokenRequest` schema (line 636), `TokenResponse` schema (line 676), `/token` endpoint (line 179).

### Token Flow Details

- **tokenStore** (verifier.go:248): Holds `jwt.Token` + `redirect_uri`, keyed by authorization code (random nonce) in `tokenCache`.
- **tokenCache**: Uses `patrickmn/go-cache` with `SessionExpiry`-based TTL. Tokens are **deleted after single retrieval** (get-then-delete pattern, line 498).
- **JWT signing**: RS256 or ES256 via `tokenSigner.Sign()` with `v.signingKey` (jwk.Key). Claims include issuer, audience, expiration (`jwtExpiration` duration), issuedAt, optional subject/nonce, and credential data.
- **Three grant types**: `authorization_code` (exchanges code for cached JWT), `vp_token` (direct VP token validation + JWT generation), `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693 token exchange via VP token).

## JSON-LD Proof Verification

JSON-LD (`ldp_vc`) presentations and credentials are cryptographically verified — see `docs/json-ld-proof-verification.md` for the full design. In short:

- `common/ldproof.go` implements `JsonWebSignature2020` signing and verification (URDNA2015 canonicalization, detached JWS with `b64=false`).
- Proof options are canonicalized under the document context **plus** `https://w3id.org/security/suites/jws-2020/v1`, so `created`, `verificationMethod`, `proofPurpose`, `challenge` and `domain` are covered by the signature. `assertProofOptionsCovered` fails closed if any of them does not survive canonicalization; it compares parsed N-Quads predicates (`common/nquads.go`), not raw text, so an IRI inside a literal cannot fake coverage.
- `verifier/ld_proof_checker.go` binds the proof key to the credential's `issuer` / the presentation's `holder`, requires the matching proof purpose, and requires the key to be authorized for the corresponding verification relationship.
- `VerifyLDVPProofBinding` requires one and the same proof to carry every expected binding (challenge + domain); a split across two proofs is rejected.
- `VerifyLDVPProofFreshness` bounds `proof.created` by `verifier.ldProofMaxAge` (default 300s) on the `vp_token` and token-exchange grants, which have no server-issued nonce. Missing, unparseable and future-dated timestamps are rejected.
- `verifyJSONLDHolderBinding` requires an identified `credentialSubject` to be the presentation's `holder` — the JSON-LD counterpart of the JWT `cnf` binding.
- Status lists (W3C and IETF) are bound to the issuer of the referencing credential; a credential with no issuer is rejected (`ErrorStatusListIssuerUnknown`).
- The security-relevant contexts are vendored in `common/contexts/` and served by `common.NewEmbeddedContextLoader`, so verification never depends on the network.
- `m2m.verificationMethod` has no default and must be an absolute DID URL — `InitM2MTokenProvider` fails at startup otherwise, since a relative reference can never produce a valid proof. `tir.signerForKeyType` keeps the signer and the advertised JWS algorithm in sync (`RSARS256` → PKCS#1 v1.5, `RSAPS256` → PSS).

## HTTPS-based Issuer Identifiers

Credential issuers may be identified by an HTTPS URL instead of a DID — see `docs/https-issuer-identifiers.md` for the full design. In short:

- An issuer identifier is treated as a generic URI. `isHttpsIssuer()` decides whether the key is discovered via `did.Registry` or via `verifier/https_issuer_resolver.go` (well-known metadata → JWKS).
- Three paths dispatch on it: the JWT `iss` claim (`jwt_proof_checker.go`), the JSON-LD proof `verificationMethod` (`ld_proof_checker.go`) and the status list `iss` claim (`credential_status_client.go`). Each fails closed with `ErrorHttpsIssuerNotSupported` when no resolver is configured.
- The resolver is created once in `InitPresentationParser` and shared via `GetHttpsIssuerResolver()`, so a single JWKS cache serves all three paths.
- Well-known paths follow their spec: SD-JWT VC and RFC 8414 **insert** the segment between host and path (`wellKnownURLInserted`), OpenID4VCI **appends** it (`wellKnownURLAppended`).
- The `issuer` of fetched metadata must equal the issuer URL the lookup started from (RFC 8414 §3.3) on every hop, compared after the same canonicalization on both sides. A mismatch surfaces as `ErrorIssuerMismatch` and is never retried through the other discovery path.
- Everything after the first request is named by attacker-influenced metadata, so `allowedMetadataURL` pins `jwks_uri` / `authorization_servers` to the issuer's scheme and host (plus `verifier.httpsIssuerAllowedHosts`), redirects may not leave the origin, bodies are `io.LimitReader`-bounded, and failures are negatively cached.
- The **first** hop is a host the token names, so it is guarded in the dialer instead: `verifier/https_issuer_dialer.go` resolves the host and refuses loopback, RFC 1918 / RFC 4193, link-local, multicast and reserved ranges (`ErrorAddressNotAllowed`), then connects to the address it checked, which is what closes DNS rebinding. `verifier.httpsIssuerAllowPrivateNetworks` lifts it for in-network issuers; the tests use `WithAllowPrivateAddresses(true)` for their loopback listeners.
- `parseIssuerURL` rejects an identifier carrying a query or fragment (RFC 8414 §2). Neither reaches the well-known URL, so accepting them would make one endpoint addressable under unboundedly many cache keys — a counter in the query would walk past the failure cache.
- `cachingOf` distinguishes "no `Cache-Control`" from a declared lifetime of zero (`max-age=0`, `no-store`, `no-cache`). The latter suppresses the cache write and drops any earlier entry: go-cache reads a zero TTL as *default expiration*, not *do not cache*.
- `ResolveIssuerKeys` returns **candidate** keys: the kid-matching keys, keys that declare no kid at all when none matches (a `kid` is only a hint), or every signature-capable key when no kid is available. Keys with a *different* kid are never returned — that is the signal a cached set is stale and drives the rotation refetch. Callers try each; `verifyJWSWithCandidateKeys` (`verifier/jws_verification.go`) pins the `alg` to an allowlist and to the key's own `alg`, and every JWS path goes through it, the status-list `x5c` fallback included.
- A cached key set missing the requested kid triggers one refetch per `MinJwksRefetchInterval`, so key rotation is picked up without waiting out the TTL. A failed refetch keeps the cached keys but re-arms the window (`postponeRefetch`, preserving the remaining TTL).
- Resolution is bounded twice: `httpClientTimeout` per request and `resolutionTimeout` for the whole discovery, with at most `maxAuthorizationServers` entries tried.
- `issuerCacheKey` lowercases only scheme and host and trims a trailing slash; the path keeps its case **and its percent-encoding** (`EscapedPath`), as does the well-known URL — decoding `%2F` would let one identifier read another's cached keys, before any identity check runs.
- In the JSON-LD path the JWKS `kid` is the **fragment** of the `verificationMethod` (`httpsJwksKeyId`), not the whole URI.
- Trust validation does **not** branch on the identifier shape. A trust-list entry is always a registry endpoint (`ebsi`, `ebsi-v5`, `gaia-x`), never an issuer identity, so an HTTPS issuer is trusted by being registered in one of the configured trusted-issuers-list APIs — or by the `*` wildcard. `tir.issuerPathSegment` percent-encodes only `/`, `?` and `#` so an HTTPS identifier stays one path segment while an already-encoded `did:web` is not encoded twice.

## Known Gaps

- **HTTPS issuers cannot have verification relationships enforced.** A JWKS has no `authentication` / `assertionMethod` distinction, so the LD-proof path logs a warning and accepts the key; `proofPurpose` and issuer/holder binding remain enforced.
- **An HTTPS issuer whose JWKS or authorization server lives on another host** is unresolvable until that host is added to `verifier.httpsIssuerAllowedHosts`.
- **An HTTPS issuer inside the verifier's own network** is unresolvable until `verifier.httpsIssuerAllowPrivateNetworks` is set — the address guard refuses non-routable targets for every issuer, not per issuer.
- **`validationMode: combined` and `jsonLd`** do not perform real JSON-LD validation — they only check that issuer and type fields are present. They are deprecated but still accepted.
- **Verification relationships are only enforced when the DID document declares them.** A `did:web` document that lists `verificationMethod` but neither `authentication` nor `assertionMethod` falls back to the flat method list with a warning.
- **Data Integrity suites other than `JsonWebSignature2020`** (`proofValue`-based cryptosuites) are parsed but not verified. VC 2.0 issuers are more likely to use these than `JsonWebSignature2020`.
- **VCDM 2.0's `confirmationMethod` is not implemented.** Holder binding on every JWT path, `vp+jwt` included, uses RFC 7800 `cnf`, which VC-JOSE-COSE §4.1.3 registers for exactly that. `confirmationMethod` is a *reserved* property in VCDM 2.0 with no defined semantics, so there is nothing to implement against yet; the choice is recorded in `docs/vc-jose-cose.md`.
- **A `vp+jwt` may carry bare JWT strings in `verifiableCredential`.** VCDM 2.0 §4.13 expects credentials in a 2.0 presentation to be `EnvelopedVerifiableCredential` objects. Accepting bare strings is a deliberate leniency, and it is what lets a v1.1 `jwt_vc` ride inside a 2.0 presentation.
- **COSE (`vc+cose`) is not supported.** Only the JOSE half of VC-JOSE-COSE is implemented.

## VC-JOSE-COSE

`vc+jwt` credentials, `vp+jwt` presentations and `EnvelopedVerifiableCredential` are supported — see `docs/vc-jose-cose.md`. In short:

- Neither format names its signer in the envelope, so neither can use `VerifyJWTAndReturnKey`, which derives the identity from `kid`/`iss`. `JWTProofChecker.VerifyJWTForIssuer(token, issuer)` takes the identity the caller read from the secured document instead: a `vc+jwt`'s `issuer` property, a `vp+jwt`'s `holder`. `VerifyJWTAndReturnKey` is a thin wrapper over the same code.
- Parsing is therefore two-pass (`parseVCJoseCredential`, `parseVPJosePresentation`): decode the payload unverified and read **nothing** from it but the identity, verify against a key belonging to that identity, then re-read the document from the payload verification returned. Lying in the first pass does not help a forger — it means resolving the claimed issuer's key, which will not verify their signature.
- A `vc+jwt` routinely carries no `kid`. `ResolveCandidateKeysFromDID` then treats every verification method the DID document declares as a candidate, mirroring what the HTTPS resolver does for a JWKS.
- Registered claims are **redundant copies**, never overrides (`reconcileRedundantClaim`). `iss`/`issuer`, `sub`/`credentialSubject.id` and `jti`/`id` must agree where both are present. `iat` is not mapped at all — §3.1.3 says `iat` and `exp` time the *signature*, not the credential — and `nbf`/`exp` may only narrow the payload's validity window.
- Dispatch on `typ` is **exhaustive** (`normalizeJOSEType`, `assertCredentialJWTType`, `assertPresentationJWTType`): an unrecognized type is rejected with `ErrorUnexpectedJWTType`, never reinterpreted as the legacy format. RFC 7515 §4.1.9 makes `vc+jwt` and `application/vc+jwt` the same type, in any case. A `cty` contradicting the `typ` is rejected too.
- An `EnvelopedVerifiableCredential`'s declared media type binds its contents: the token inside `data:application/vc+jwt,` must itself be a `vc+jwt`, since `parseJWTCredential` re-dispatches on the inner `typ`. The prefix is matched case-insensitively (RFC 2397); parameters and the `;base64` variant are rejected.
- `vc`/`vp` claims are rejected outright (§1.1.2.1), and a `vc+jwt` must carry the VCDM 2.0 base context regardless of `verifier.vcDataModelVersions` — that setting says which data models are acceptable, not what a `vc+jwt` is.
- `vc+jwt` status lists go through `VerifyStatusListJWTForIssuer` and have **no** fallback. The `x5c` fallback on `VerifyStatusListJWT` takes a key from the token's own certificate without validating a chain; it stays only for the IETF Token Status List path, which deliberately accepts issuerless lists.

## VC Data Model Versions

Credentials on both the v1.1 and v2.0 data models are accepted — see `docs/vc-data-model-versions.md`. In short:

- The version comes from the **first** `@context` entry (`common.DetectVCDataModelVersion`), as both data models require. A base context elsewhere in the array does not declare a version, and a document carrying both base contexts declares none.
- `verifier.vcDataModelVersions` is an allowlist over `"1.1"` / `"2.0"`, defaulting to both. An empty list means *all recognized versions*, not *gate disabled* — the check cannot be switched off. `common.NormalizeVCDataModelVersion` absorbs the `"1"` / `"2"` that YAML produces for an unquoted list.
- The gate is strict and keyed on the credential **format**: only SD-JWT VCs are exempt. An `ldp_vc`/`jwt_vc` with an absent or unrecognized base context is rejected, so it cannot be bypassed by omitting or mangling the `@context`. Both parsers run `@context` and `type` through `common.ToStringSlice`, so a string-valued spelling is not silently dropped.
- The gate covers incoming credentials only; the presentation envelope's own `@context` is not checked (and `Presentation.Context` is never populated).
- VC 2.0 status list types (`BitstringStatusListEntry` / `BitstringStatusListCredential`) are handled alongside `StatusList2021Entry`.

## Key Dependencies

- **gin-gonic/gin** — HTTP framework
- **lestrrat-go/jwx/v3** — JWT/JWS/JWK handling
- **piprate/json-gold** — JSON-LD processing (URDNA2015 canonicalization, document loading)
- **gookit/config** — Configuration management
- **foolin/goview** — Template rendering for Gin
- **patrickmn/go-cache** — In-memory cache with expiration (used for sessions, TIR results, document loader cache)
- **fiware/VCVerifier/did** — Custom DID resolution: did:key, did:web, did:jwk via `did.Registry`
