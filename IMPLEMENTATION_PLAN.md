# Implementation Plan: Add support to refresh token in the verifier

## Overview

Add OAuth2 refresh token support (per [RFC 6749 Section 1.5](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5)) to VCVerifier's token endpoint. Currently, the `/token` endpoint returns only `access_token`, `token_type`, `issued_token_type`, and `expires_in`. This plan adds refresh token generation, a dedicated refresh token store, a `grant_type=refresh_token` exchange flow, and token rotation on refresh. The refresh token feature is opt-in via configuration so existing deployments are unaffected.

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

### Step 2: Add refresh token store and generation logic in the verifier

Create the infrastructure for generating, storing, and retrieving refresh tokens.

**Files to modify:**
- `verifier/verifier.go`:
  - Add a `refreshTokenStore` struct to hold the data needed to reissue an access token on refresh: `clientId`, `subject`, `audience`, `scopes []string`, `credentials []map[string]interface{}`, `flatClaims bool`, and `nonce string`.
  - Add a new `refreshTokenCache` field (type `common.Cache`) to `CredentialVerifier`, initialized in `InitVerifier` with TTL derived from `RefreshTokenExpiration`. Only create the cache when `RefreshTokenEnabled` is `true`.
  - Add a `refreshTokenEnabled` bool field and `refreshTokenExpiration` `time.Duration` field to `CredentialVerifier`.
  - Add a helper method `generateRefreshToken() string` that generates a cryptographically random opaque token (base64url-encoded, 32 bytes) using `crypto/rand`.
  - Add a method `StoreRefreshToken(refreshToken string, store refreshTokenStore)` that stores the refresh token data in the cache.
  - Add a method `ExchangeRefreshToken(refreshToken string) (jwtString string, expiration int64, newRefreshToken string, err error)` that:
    1. Retrieves and deletes the refresh token from cache (one-time use, same pattern as authorization code).
    2. Calls `generateJWT` with the stored claims to create a new access token.
    3. Signs the new access token.
    4. Generates a new refresh token (rotation) and stores it in the cache with the same session data.
    5. Returns the new access token, its expiration, and the new refresh token.
  - Add `ExchangeRefreshToken` to the `Verifier` interface.

**Files to create:** None.

**Acceptance criteria:**
- Refresh token is a 32-byte cryptographically random base64url string.
- Refresh tokens are single-use (deleted after retrieval, rotated on each exchange).
- `ExchangeRefreshToken` returns a new access token JWT and a new refresh token.
- When `RefreshTokenEnabled` is `false`, the `refreshTokenCache` is `nil` and `ExchangeRefreshToken` returns an appropriate error.
- Unit tests cover: successful exchange, expired/missing token, rotation (old token invalid after use), disabled feature.
- Follow existing mock patterns (`mockRefreshTokenCache`) in the test file.

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

**Note on `GetToken` (authorization_code flow):** This flow retrieves a pre-built JWT from the token cache. The claims data needed for refresh token storage must be captured at the time the token is stored (in `AuthenticationResponse`). Modify `tokenStore` to also hold the refresh-relevant session data (`clientId`, `subject`, `audience`, `scopes`, `credentials`, `flatClaims`, `nonce`), and after `GetToken` succeeds, generate and store the refresh token if enabled.

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
  - Add `mockRefreshTokenCache` implementing `common.Cache`.
  - Add `TestExchangeRefreshToken` with table-driven cases:
    - Successful exchange returns new access + refresh tokens.
    - Missing/expired refresh token returns error.
    - Old refresh token is invalid after rotation (single-use).
    - Feature disabled returns error.
  - Add `TestCreateRefreshToken` verifying token generation and cache storage.
  - Add `TestGenerateRefreshToken` verifying token format (base64url, 32 bytes).
  - Update existing `TestGenerateToken` cases to verify refresh token is returned when enabled and absent when disabled.

**Acceptance criteria:**
- All new tests pass.
- All existing tests pass without modification (backward compatible).
- Test coverage for refresh token code paths exceeds 80%.
- Tests use table-driven patterns consistent with the existing codebase.
- Tests use parameterized cases for enabled/disabled refresh token configuration.
