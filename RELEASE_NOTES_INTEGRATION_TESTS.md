# Release Notes: Integration Test Framework

## Overview

A comprehensive black-box integration test framework for VCVerifier, treating the verifier as an opaque HTTP service. The test suite builds the verifier binary, launches it as a subprocess with generated YAML configs, and interacts purely over HTTP — no internal Go imports from verifier packages.

## New Files

### Test helpers (`integration_test/helpers/`)

- **`process.go`** — Build, launch, health-poll, and graceful shutdown of the verifier binary
- **`config.go`** — Fluent `ConfigBuilder` API for generating YAML configs with DCQL, holder verification, JWT inclusion, trusted participants
- **`identity.go`** — `TestIdentity` generation for `did:key` and `did:web` (ECDSA P-256)
- **`credentials.go`** — JWT-VC, SD-JWT, VP token, and DCQL response creation with cryptographic signing
- **`tir_mock.go`** — Mock Trusted Issuers Registry (`httptest.Server`) with percent-encoded DID support
- **`did_web_mock.go`** — Mock `did:web` TLS server with dynamic DID document serving

### Test files

- **`m2m_test.go`** — 7 parameterized M2M success tests (JWT-VC, SD-JWT, did:key, did:web, cnf holder, claim holder)
- **`m2m_failure_test.go`** — 6 parameterized M2M failure tests (wrong type, missing claims, untrusted issuer, invalid VP signature, invalid cnf, invalid claim holder)
- **`frontend_v2_test.go`** — 2 end-to-end Frontend V2 cross-device tests (byReference, byValue) with WebSocket
- **`deeplink_test.go`** — 2 end-to-end Deeplink same-device tests (byReference, byValue)
- **`endpoints_test.go`** — 8 endpoint validation tests (JWKS, OpenID config, health, error cases)
- **`helpers_test.go`** — Unit tests for the helper functions themselves

## Test Coverage Summary

| Category | Tests | Description |
|----------|-------|-------------|
| M2M Success | 7 | VP-token-to-JWT exchange with various credential formats and DID methods |
| M2M Failure | 6 | Rejection of invalid credentials, untrusted issuers, signature mismatches |
| Frontend V2 | 2 | Cross-device flow with QR code, WebSocket notifications, authorization code exchange |
| Deeplink | 2 | Same-device flow with openid4vp:// redirects and 302 authentication responses |
| Endpoints | 8 | JWKS, OpenID configuration, health check, and parameter validation errors |
| **Total** | **25** | |

## Dependencies Added (integration_test/go.mod only)

- `github.com/gorilla/websocket` — WebSocket client for Frontend V2 cross-device flow tests
- `github.com/lestrrat-go/jwx/v3` — JWT/JWK creation and verification
- `github.com/trustbloc/kms-go` — did:key identity generation
- `github.com/stretchr/testify` — Test assertions

## Running

```bash
# All integration tests
cd integration_test && go test -tags integration -v -count=1 ./...

# By category
go test -tags integration -v -count=1 -run TestM2M ./...
go test -tags integration -v -count=1 -run TestFrontendV2 ./...
go test -tags integration -v -count=1 -run TestDeeplink ./...
go test -tags integration -v -count=1 -run TestEndpoints ./...
```

The `integration` build tag ensures these tests don't run during regular `go test ./...`.
