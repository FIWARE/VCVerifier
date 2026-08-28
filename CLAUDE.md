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
  - `jwt_proof_checker.go` — JWT signature verification via DID-resolved keys; also handles did:elsi via JAdES and HTTPS-based issuers via `HttpsIssuerResolver`
  - `ld_proof_checker.go` — JSON-LD Linked Data Proof verification (`JsonWebSignature2020`): resolves `verificationMethod` (DID URL or https:// URL), binds the signing key to the credential issuer / presentation holder, enforces the proof purpose
  - `key_resolver.go` — Shared DID→key resolution, including verification-relationship enforcement (`authentication` / `assertionMethod`)
  - `https_issuer_resolver.go` — Key discovery for HTTPS-based issuer identifiers via `/.well-known/jwt-vc-issuer` (SD-JWT VC) with an OpenID4VCI + RFC 8414 fallback, plus a per-issuer JWKS cache
  - `credentialsConfig.go` — Credential configuration management

- **`openapi/`** — HTTP handlers generated from OpenAPI spec (`api/api.yaml`). Routes defined in `routers.go`. Handlers in `api_api.go` (token, authorization, authentication) and `api_frontend.go` (frontend endpoints, WebSocket polling).

- **`tir/`** — Trusted Issuers Registry client. Queries EBSI v3/v4 endpoints, caches results. Includes M2M auth via `tokenProvider.go` and `authorizationClient.go`.

- **`gaiax/`** — Gaia-X compliance client. did:web resolution, X.509 certificate chain validation, trust anchor verification.

- **`jades/`** — JAdES signature validation for did:elsi credentials.

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
- The `issuer` field of fetched metadata must equal the issuer URL the lookup started from (RFC 8414 §3.3), otherwise `ErrorIssuerMismatch`.
- In the JSON-LD path the JWKS `kid` is the **fragment** of the `verificationMethod` (`httpsJwksKeyId`), not the whole URI.
- Trust validation adds no new list type: HTTPS issuers are matched by URL against the existing trusted-issuer / trusted-participant entries (`*` is a wildcard), never looked up in EBSI or Gaia-X.

## Known Gaps

- **HTTPS issuers cannot have verification relationships enforced.** A JWKS has no `authentication` / `assertionMethod` distinction, so the LD-proof path logs a warning and accepts the key; `proofPurpose` and issuer/holder binding remain enforced.
- **No end-to-end integration test covers the HTTPS issuer paths.** `integration_test/helpers/https_issuer_mock.go` provides the mock servers but nothing consumes them yet.
- **`validationMode: combined` and `jsonLd`** do not perform real JSON-LD validation — they only check that issuer and type fields are present. They are deprecated but still accepted.
- **Verification relationships are only enforced when the DID document declares them.** A `did:web` document that lists `verificationMethod` but neither `authentication` nor `assertionMethod` falls back to the flat method list with a warning.
- **Data Integrity suites other than `JsonWebSignature2020`** (`proofValue`-based cryptosuites) are parsed but not verified.

## Key Dependencies

- **gin-gonic/gin** — HTTP framework
- **lestrrat-go/jwx/v3** — JWT/JWS/JWK handling
- **piprate/json-gold** — JSON-LD processing (URDNA2015 canonicalization, document loading)
- **gookit/config** — Configuration management
- **foolin/goview** — Template rendering for Gin
- **patrickmn/go-cache** — In-memory cache with expiration (used for sessions, TIR results, document loader cache)
- **fiware/VCVerifier/did** — Custom DID resolution: did:key, did:web, did:jwk via `did.Registry`
