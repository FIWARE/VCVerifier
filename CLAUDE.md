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
  - `jwt_verifier.go` — VC validation with modes: `none`, `combined`, `jsonLd`, `baseContext`. DID verification method resolution for did:key, did:web, did:jwk
  - `trustedissuer.go` / `trustedparticipant.go` — EBSI registry verification
  - `compliance.go` — Policy compliance checking (signatures, dates, etc.)
  - `holder.go` — Holder verification
  - `gaiax.go` — Gaia-X compliance checks
  - `elsi_proof_checker.go` — JAdES signature validation for did:elsi
  - `credentialsConfig.go` — Credential configuration management
  - `caching_client.go` — HTTP caching layer

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

## Key Dependencies

- **trustbloc/vc-go, did-go, kms-go** — VC verification, DID resolution, key management
- **gin-gonic/gin** — HTTP framework
- **lestrrat-go/jwx/v3** — JWT/JWS/JWK handling
- **piprate/json-gold** — JSON-LD processing
- **gookit/config** — Configuration management
- **foolin/goview** — Template rendering for Gin
