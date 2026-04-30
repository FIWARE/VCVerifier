# Implementation Plan: Add support to refresh token in the verifier

## Overview

Add OAuth2 refresh token support (per [RFC 6749 Section 1.5](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5)) to VCVerifier's token endpoint. Currently, the `/token` endpoint returns only `access_token`, `token_type`, `issued_token_type`, and `expires_in`. This plan adds refresh token generation, a database-backed refresh token store (surviving restarts and supporting horizontal scaling), a `grant_type=refresh_token` exchange flow, and token rotation on refresh. The refresh token feature is opt-in via configuration so existing deployments are unaffected. The database storage follows the existing `ServiceRepository` / `SqlServiceRepository` pattern, supporting PostgreSQL, MySQL, and SQLite.

## Steps

### Step 1: Add refresh token configuration and constants

Add the configuration knobs and shared constants needed by subsequent steps.

**Files to modify:**
- `config/config.go` — Add fields to the `Verifier` struct:
  - `RefreshTokenEnabled` (`bool`, default `false`) — master toggle for the feature.
  - `RefreshTokenExpiration` (`int`, default `2880`, i.e. 48 hours in minutes) — lifetime of refresh tokens.
- `common/metadata.go` — Add a new constant `TYPE_REFRESH_TOKEN = "refresh_token"` for the grant type string.

**Acceptance criteria:**
- New config fields are parsed from YAML with sensible defaults.
- Existing tests still pass (no breaking changes to config parsing).
- New config fields are documented with Go comments following the existing style.
- Add a unit test in `config/config_test.go` that verifies the new defaults are applied when the fields are absent from the YAML input.

### Step 2: Add database-backed refresh token store and generation logic

Create the infrastructure for generating, storing, and retrieving refresh tokens using a database-backed storage layer. This ensures tokens survive restarts and work correctly with horizontal scaling (multiple replicas sharing the same database). Follows the existing `ServiceRepository` / `SqlServiceRepository` pattern in `database/`.

**Files to modify:**
- `database/schema.go`:
  - Add a `refresh_token` table to `InitSchema()` with columns:
    - `token` (`VARCHAR(255)` PRIMARY KEY) — the opaque refresh token string.
    - `client_id` (`VARCHAR(255)` NOT NULL).
    - `subject` (`VARCHAR(255)` NOT NULL).
    - `audience` (`VARCHAR(255)` NOT NULL).
    - `scopes` (`TEXT` NOT NULL) — JSON-serialized `[]string`.
    - `credentials` (`TEXT` NOT NULL) — JSON-serialized `[]map[string]interface{}`.
    - `flat_claims` (`BOOLEAN` NOT NULL DEFAULT FALSE).
    - `nonce` (`VARCHAR(255)` NOT NULL).
    - `expires_at` (`BIGINT` NOT NULL) — Unix timestamp for expiration.
  - Use `CREATE TABLE IF NOT EXISTS` (idempotent, same pattern as existing tables).
  - Adapt DDL per database driver (PostgreSQL, MySQL, SQLite) following the existing multi-driver pattern.

- `database/models.go`:
  - Add a `RefreshTokenRow` struct mapping to the `refresh_token` table columns, with JSON serialization helpers for `scopes` and `credentials` (similar to `ScopeEntryRow`).

- `database/repository.go`:
  - Add a `RefreshTokenRepository` interface:
    - `StoreRefreshToken(row RefreshTokenRow) error` — inserts a new refresh token row.
    - `GetAndDeleteRefreshToken(token string) (*RefreshTokenRow, error)` — atomically retrieves and deletes the token (single-use, same get-then-delete pattern as authorization codes). Returns `ErrRefreshTokenNotFound` if missing or expired.
    - `DeleteExpiredTokens() (int64, error)` — removes rows where `expires_at < now()` (housekeeping).
  - Add `SqlRefreshTokenRepository` struct implementing `RefreshTokenRepository`, with `*sql.DB` and `dbType` fields (same pattern as `SqlServiceRepository`).
  - Add sentinel error `ErrRefreshTokenNotFound`.

- `verifier/verifier.go`:
  - Add a `refreshTokenEnabled` bool field and `refreshTokenExpiration` `time.Duration` field to `CredentialVerifier`.
  - Add a `refreshTokenRepo` field (type `database.RefreshTokenRepository`) to `CredentialVerifier`, initialized in `InitVerifier` when `RefreshTokenEnabled` is `true` and a database connection is available.
  - Add a helper method `generateRefreshToken() string` that generates a cryptographically random opaque token (base64url-encoded, 32 bytes) using `crypto/rand`.
  - Add a method `StoreRefreshToken(...)` that builds a `RefreshTokenRow` (computing `expires_at` from current time + `refreshTokenExpiration`) and calls `refreshTokenRepo.StoreRefreshToken()`.
  - Add a method `ExchangeRefreshToken(refreshToken string) (jwtString string, expiration int64, newRefreshToken string, err error)` that:
    1. Calls `refreshTokenRepo.GetAndDeleteRefreshToken(refreshToken)` to atomically retrieve and delete (single-use).
    2. Checks `expires_at` against current time (defense in depth beyond the housekeeping query).
    3. Calls `generateJWT` with the stored claims to create a new access token.
    4. Signs the new access token.
    5. Generates a new refresh token (rotation) and stores it via the repository with the same session data.
    6. Returns the new access token, its expiration, and the new refresh token.
  - Add `ExchangeRefreshToken` to the `Verifier` interface.
  - Optionally start a background goroutine (or use the existing `chrono` scheduler) to periodically call `DeleteExpiredTokens()` for housekeeping.

- `main.go` (or `InitVerifier`):
  - When `RefreshTokenEnabled` is `true`, ensure a database connection is available (reuse the existing `database.NewConnection` call) and pass the `RefreshTokenRepository` to the verifier.
  - If `RefreshTokenEnabled` is `true` but no database is configured, log a clear error and fail fast at startup.

**Files to create:** None (all changes go in existing files following established patterns).

**Acceptance criteria:**
- Refresh token is a 32-byte cryptographically random base64url string.
- Refresh tokens are persisted in the database and survive process restarts.
- Multiple verifier replicas sharing the same database can issue and exchange each other's refresh tokens (horizontal scaling).
- Refresh tokens are single-use (atomically deleted on retrieval, rotated on each exchange).
- `ExchangeRefreshToken` returns a new access token JWT and a new refresh token.
- When `RefreshTokenEnabled` is `false`, `ExchangeRefreshToken` returns an appropriate error.
- Expired tokens are cleaned up (either on access or via periodic housekeeping).
- Unit tests cover: successful exchange, expired/missing token, rotation (old token invalid after use), disabled feature.
- Repository tests use an in-memory SQLite database (same pattern as existing `database/` tests).
- Follow existing mock patterns (`mockRefreshTokenRepository`) in verifier test files.

### Step 3: Update token response model and OpenAPI spec

Add the `refresh_token` field to the token response and update the OpenAPI spec to document the new `grant_type=refresh_token` flow.

**Files to modify:**
- `openapi/model_token_response.go` — Add `RefreshToken string` field with JSON tag `json:"refresh_token,omitempty"` to the `TokenResponse` struct.
- `api/api.yaml`:
  - Add `refresh_token` property (type `string`, description: "Refresh token to obtain new access tokens") to the `TokenResponse` schema.
  - Add `"refresh_token"` to the `grant_type` enum in the `TokenRequest` schema.
  - Add `refresh_token` property (type `string`, description: "The refresh token to exchange for a new access token") to the `TokenRequest` schema.

**Acceptance criteria:**
- `TokenResponse` serializes `refresh_token` only when non-empty (due to `omitempty`).
- OpenAPI spec is valid YAML and documents both the new grant type and the new response/request fields.
- Existing tests still pass unchanged.

### Step 4: Wire refresh token into token endpoint handlers

Connect the refresh token generation and exchange to the HTTP layer.

**Files to modify:**
- `openapi/api_api.go`:
  - In `GetToken()`, add a `case common.TYPE_REFRESH_TOKEN:` branch in the grant type switch that calls a new `handleTokenTypeRefreshToken(c)` function.
  - Create `handleTokenTypeRefreshToken(c *gin.Context)`:
    1. Extract `refresh_token` from the POST form.
    2. Call `getApiVerifier().ExchangeRefreshToken(refreshToken)`.
    3. Return a `TokenResponse` with the new access token, expiration, and new refresh token.
  - Modify `handleTokenTypeCode()`: after `GetToken()` succeeds, if refresh tokens are enabled, generate and store a refresh token, and include it in the `TokenResponse`.
  - Modify `verifiyVPToken()`: after `GenerateToken()` succeeds, if refresh tokens are enabled, generate and store a refresh token, and include it in the `TokenResponse`.
  - To check if refresh tokens are enabled from the openapi layer, add a method `IsRefreshTokenEnabled() bool` to the `Verifier` interface and implement it on `CredentialVerifier`.
  - To generate+store a refresh token from the openapi layer, add a method `CreateRefreshToken(clientId, subject, audience string, scopes []string, credentials []map[string]interface{}, flatClaims bool, nonce string) (string, error)` to the `Verifier` interface. This generates an opaque token, stores the session data in the refresh token cache, and returns the token string.

- `verifier/verifier.go`:
  - Implement `IsRefreshTokenEnabled()` and `CreateRefreshToken(...)` on `CredentialVerifier`.
  - Refactor `GenerateToken` to return the credential inclusion data (credentials list, flatClaims flag) alongside the signed JWT, so the openapi layer can pass them to `CreateRefreshToken`. Alternatively, have `GenerateToken` itself call `CreateRefreshToken` internally and return the refresh token as an additional return value. Choose the approach that minimizes interface changes — extending `GenerateToken` to return `(int64, string, string, error)` where the third string is the refresh token (empty when disabled) is cleanest.

**Note on `GetToken` (authorization_code flow):** This flow retrieves a pre-built JWT from the token cache. The claims data needed for refresh token storage must be captured at the time the token is stored (in `AuthenticationResponse`). Modify `tokenStore` to also hold the refresh-relevant session data (`clientId`, `subject`, `audience`, `scopes`, `credentials`, `flatClaims`, `nonce`), and after `GetToken` succeeds, generate and store the refresh token in the database via the `RefreshTokenRepository` if enabled.

**Acceptance criteria:**
- `POST /token` with `grant_type=refresh_token&refresh_token=<token>` returns 200 with new access + refresh tokens.
- `POST /token` with `grant_type=authorization_code` returns `refresh_token` in response when enabled.
- `POST /token` with `grant_type=vp_token` and `grant_type=token-exchange` return `refresh_token` in response when enabled.
- When `RefreshTokenEnabled` is `false`, no `refresh_token` field appears in any response.
- Invalid/expired refresh tokens return 403 with a descriptive error message.
- Error messages follow existing `ErrorMessage` pattern.

### Step 5: Comprehensive tests for refresh token flows

Add end-to-end and unit tests covering all refresh token scenarios.

**Files to modify:**
- `openapi/api_api_test.go`:
  - Add `mockRefreshToken string` field to `mockVerifier`.
  - Implement `ExchangeRefreshToken`, `IsRefreshTokenEnabled`, and `CreateRefreshToken` on `mockVerifier`.
  - Update `GenerateToken` mock to return refresh token as additional return value.
  - Add table-driven test cases to `TestGetToken` for:
    - `grant_type=refresh_token` with valid refresh token (200).
    - `grant_type=refresh_token` with missing refresh token (400).
    - `grant_type=refresh_token` with expired/invalid refresh token (403).
    - Existing grant types returning `refresh_token` in response when enabled.
    - Existing grant types NOT returning `refresh_token` when disabled.

- `verifier/verifier_test.go`:
  - Add `mockRefreshTokenRepository` implementing `database.RefreshTokenRepository`.
  - Add `TestExchangeRefreshToken` with table-driven cases:
    - Successful exchange returns new access + refresh tokens.
    - Missing/expired refresh token returns error.
    - Old refresh token is invalid after rotation (single-use).
    - Feature disabled returns error.
  - Add `TestCreateRefreshToken` verifying token generation and database storage.
  - Add `TestGenerateRefreshToken` verifying token format (base64url, 32 bytes).
  - Update existing `TestGenerateToken` cases to verify refresh token is returned when enabled and absent when disabled.

- `database/repository_test.go`:
  - Add `TestStoreRefreshToken` verifying token insertion and retrieval from SQLite.
  - Add `TestGetAndDeleteRefreshToken` verifying atomic get-and-delete (single-use).
  - Add `TestGetAndDeleteRefreshToken_NotFound` verifying error on missing token.
  - Add `TestDeleteExpiredTokens` verifying expired rows are removed.
  - Use in-memory SQLite database (same pattern as existing repository tests).

**Acceptance criteria:**
- All new tests pass.
- All existing tests pass without modification (backward compatible).
- Test coverage for refresh token code paths exceeds 80%.
- Tests use table-driven patterns consistent with the existing codebase.
- Tests use parameterized cases for enabled/disabled refresh token configuration.
