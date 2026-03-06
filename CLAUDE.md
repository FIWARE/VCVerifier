# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
go test ./... -v

# Run tests with coverage
go test ./... -v -coverprofile=profile.cov ./...

# Run tests for a specific package
go test ./verifier/... -v
go test ./openapi/... -v

# Run a single test
go test ./verifier/... -v -run TestFunctionName

# Build the binary
go build -o VCVerifier .

# Build Docker image
docker build -t vcverifier .

# Run locally (requires server.yaml config)
./VCVerifier
# or with alternate config:
CONFIG_FILE=path/to/config.yaml ./VCVerifier
```

## Architecture

VCVerifier implements SIOP-2/OIDC4VP authentication flows. It acts as a Relying Party that receives Verifiable Presentations from wallets, verifies the credentials inside them, and issues signed JWTs for downstream use.

### Package structure

- **`main.go`**: Entry point. Reads config, initializes the verifier singleton and presentation parser, sets up the Gin HTTP server with routes from `openapi/routers.go`.
- **`openapi/`**: HTTP layer (generated from OpenAPI spec).
  - `routers.go`: Route definitions.
  - `api_api.go`: REST API handlers (token exchange, authentication response, JWKS, SIOP flows).
  - `api_frontend.go`: UI handlers (QR login page).
  - `websocket.go`: WebSocket support for cross-device flows.
- **`verifier/`**: Core business logic. The `Verifier` interface (implemented by `CredentialVerifier`) is the central abstraction.
  - `verifier.go`: Orchestrates the full flow — session management, QR/connection string generation, JWT issuance.
  - `presentation_parser.go`: Parses VP tokens (both JSON-LD and SD-JWT formats) using trustbloc libraries.
  - `trustedparticipant.go`: Validates credential issuer against Trusted Participants Lists (EBSI TIR or Gaia-X Registry).
  - `trustedissuer.go`: Validates issuer claims against Trusted Issuers Lists (EBSI TIR).
  - `compliance.go`: Validates Gaia-X compliance credentials via SHA-256 signature checking.
  - `holder.go`: Optional holder binding verification.
  - `jwt_verifier.go`: JWT signature verification.
  - `key_resolver.go`: DID key resolution (did:key, did:web, did:jwk).
  - `elsi_proof_checker.go`: JAdES proof checking for did:elsi.
  - `gaiax.go`: Gaia-X-specific credential validation logic.
  - `credentialsConfig.go`: Retrieves per-service credential/scope configuration.
  - `caching_client.go`: HTTP client with caching for JSON-LD document loading.
  - `request_object_client.go`: Stores/retrieves signed request objects for `byReference` mode.
- **`config/`**: Configuration model (`config.go`) and loading (`provider.go`). The `configClient.go` fetches service config from an external Credentials-Config-Service or falls back to static YAML.
- **`tir/`**: EBSI Trusted Issuers Registry client. `tirClient.go` checks participation/issuance rights. `tokenProvider.go` handles M2M OAuth tokens for TIR access.
- **`gaiax/`**: Gaia-X Digital Clearing House registry client (`gaiaXClient.go`, `registry.go`).
- **`jades/`**: JAdES signature validation for did:elsi support.
- **`common/`**: Shared utilities — `cache.go` (in-memory cache wrapper), `clock.go`, `httpUtils.go`, `tokenSigner.go`, `metadata.go` (OpenID provider metadata).
- **`logging/`**: Structured logging setup (zap-based) and Gin middleware.
- **`views/`**: HTML templates and static assets for the QR login page (`verifier_present_qr.html`).
- **`api/`**: OpenAPI spec (`api.yaml`) and supporting YAML specs.

### Key flows

**Cross-device flow** (wallet on separate device):
1. Frontend calls `/api/v1/loginQR` → verifier creates session, generates QR code containing `openid4vp://` URI
2. User scans QR with wallet → wallet POSTs VP to `/api/v1/authentication_response`
3. Verifier validates credentials (participant lists → issuer lists → optional compliance/holder checks)
4. Frontend polls via WebSocket or receives callback → exchanges authorization code for JWT at `/token`

**Same-device flow**:
1. Call `/api/v1/samedevice` → redirected to wallet with `openid4vp://` URI
2. Wallet POSTs to `/api/v1/authentication_response`
3. Response redirects back with `code` → exchange at `/token`

### Request modes

Three modes for the `openid4vp://` URI (configurable per request via `requestMode` param):
- `urlEncoded`: Parameters directly in URL
- `byValue`: Signed JWT request object embedded in URL
- `byReference`: Signed JWT served from `/api/v1/request/:id`

`byValue` and `byReference` require `verifier.clientIdentification` to be configured with a signing key.

### Configuration

Config file at `./server.yaml` (or `CONFIG_FILE` env var). Key sections:
- `verifier.did`: The verifier's DID
- `verifier.clientIdentification`: Key/cert for signing request objects
- `verifier.keyAlgorithm` / `verifier.generateKey`: JWT signing key setup
- `configRepo`: Either a `configEndpoint` (external Credentials-Config-Service) or static `services` list defining per-service credential trust and presentation definitions

### Singletons

`verifier.InitVerifier()` and `verifier.InitPresentationParser()` set package-level singletons accessed by the HTTP handlers. Tests must call these or set the singletons directly.

### Testing patterns

Tests use `github.com/stretchr/testify/assert` and table-driven test cases. Mock implementations of interfaces (e.g. `Verifier`, `TirClient`, `GaiaXClient`) are defined inline in test files. The `common.Cache` and `common.Clock` interfaces exist specifically to enable time-controlled testing.

## Gitea workflow

The repository has a local Gitea instance for code review. Use this for all branch pushes and pull requests.

- **Gitea URL**: `http://localhost:3000`
- **Repo**: `wistefan/verifier`
- **Credentials**: user `claude`, password `password`
- **Remote name**: `gitea` (configured with `http://claude:password@localhost:3000/wistefan/verifier.git`)
- **Base branch for PRs**: `trustbloc`

### Creating a step branch and PR

```bash
# Create branch from trustbloc
git checkout trustbloc
git checkout -b step-N-description

# ... make changes, commit ...

# Push to gitea
git push -u gitea step-N-description

# Create PR via Gitea API
curl -s -u claude:password -X POST \
  http://localhost:3000/api/v1/repos/wistefan/verifier/pulls \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "Step N: Description",
    "body": "...",
    "head": "step-N-description",
    "base": "trustbloc"
  }'
```

After a PR is merged, update the local `trustbloc` branch before creating the next step branch:
```bash
git checkout trustbloc
git pull gitea trustbloc
```
