# Implementation Plan: VCVerifier should allow to configure CORS headers

## Overview

The VCVerifier currently has a hardcoded CORS configuration in `main.go` (lines 51–57) that allows all origins (`*`), only `POST`/`GET` methods, and a fixed set of headers. The ticket requests making CORS origins configurable as part of the service configuration (`ConfiguredService` in `config/configClient.go`), including support for the wildcard origin. This plan adds an `AllowedOrigins` field to `ConfiguredService`, updates the CORS middleware to read from configuration, and preserves backward compatibility (wildcard by default when nothing is configured).

## Steps

### Step 1: Add CORS configuration field to ConfiguredService and update config parsing

**Goal:** Extend the `ConfiguredService` struct to accept an `allowedOrigins` list, so each service can declare which origins are permitted.

**Files to modify:**
- `config/configClient.go` — Add `AllowedOrigins []string` field (with `json:"allowedOrigins,omitempty" mapstructure:"allowedOrigins,omitempty"`) to the `ConfiguredService` struct (line 40).

**Acceptance criteria:**
- `ConfiguredService` has a new `AllowedOrigins []string` field with appropriate `json` and `mapstructure` tags.
- The field is optional (`omitempty`); when absent, it defaults to an empty/nil slice (meaning "no restriction specified by this service").
- The field is documented with a GoDoc comment explaining its purpose and that `["*"]` means allow all origins.

### Step 2: Wire CORS middleware to use configured origins from all services

**Goal:** Replace the hardcoded CORS config in `main.go` with logic that aggregates `AllowedOrigins` from all configured services and passes them to the `gin-contrib/cors` middleware. When no origins are configured anywhere (or no services exist), fall back to the current wildcard behavior for backward compatibility.

**Files to modify:**
- `main.go` — Update the CORS middleware setup (lines 51–57) to:
  1. Accept the `Configuration` struct.
  2. Collect all `AllowedOrigins` values from `configuration.ConfigRepo.Services`.
  3. Deduplicate the collected origins.
  4. If the aggregated list is empty (no services configured any origins), default to `["*"]` for backward compatibility.
  5. If `"*"` is present in the aggregated list, use `["*"]` (wildcard takes precedence).
  6. Pass the resolved origins to `cors.Config.AllowOrigins`.

**Design notes:**
- Extract the CORS origin resolution into a dedicated, exported helper function (e.g., `func ResolveAllowedOrigins(services []config.ConfiguredService) []string`) in `main.go` or a small utility so it can be unit-tested independently.
- Keep `AllowMethods`, `AllowHeaders`, and `AllowCredentials` at their current hardcoded values — the ticket only asks for origin configuration.
- Note: `gin-contrib/cors` does not allow `AllowCredentials: true` with `AllowOrigins: ["*"]`. The current code has this combination, which means credentials are effectively not sent cross-origin. Maintain this existing behavior for now — do not change `AllowCredentials`. If the wildcard is resolved, keep the same config as today.

**Acceptance criteria:**
- When no `allowedOrigins` are set on any service, CORS behaves identically to today (wildcard).
- When services specify origins, only those origins are allowed.
- When any service specifies `"*"`, the wildcard is used.
- The helper function is exported and documented.

### Step 3: Update test fixtures and add unit tests

**Goal:** Add test coverage for the new configuration field parsing and the CORS origin resolution logic.

**Files to modify/create:**
- `config/data/config_test.yaml` — Add `allowedOrigins` to the existing test service entry.
- `config/provider_test.go` — Update the `Test_ReadConfig` table-driven test's expected `ConfiguredService` to include the new `AllowedOrigins` field.
- `main_test.go` (new file, or add to existing test file if one exists) — Add parameterized tests for the `ResolveAllowedOrigins` helper function covering:
  - No services → returns `["*"]`
  - Services with no `allowedOrigins` set → returns `["*"]`
  - Single service with specific origins → returns those origins
  - Multiple services with different origins → returns deduplicated union
  - Any service includes `"*"` → returns `["*"]`
  - Duplicate origins across services → deduplicated

**Files to modify:**
- `config/data/config_test.yaml` — Add `allowedOrigins: ["https://example.com"]` under the test service.
- `config/provider_test.go` — Update expected struct to include `AllowedOrigins: []string{"https://example.com"}`.
- `main_test.go` — New file with parameterized table-driven tests for `ResolveAllowedOrigins`.

**Acceptance criteria:**
- `go test ./config/... -v` passes with the updated fixture and expected values.
- `go test ./... -v` passes, including the new `ResolveAllowedOrigins` tests.
- Tests cover all edge cases listed above using table-driven test pattern.

### Step 4: Update example configuration and documentation

**Goal:** Update `server.yaml` to document the new `allowedOrigins` option so operators know it exists.

**Files to modify:**
- `server.yaml` — Add a commented-out `allowedOrigins` example under the `configRepo.services` section showing usage (e.g., `# allowedOrigins: ["https://my-app.example.com"]`). If `configRepo.services` is not present in `server.yaml`, add a commented-out example block.

**Acceptance criteria:**
- `server.yaml` contains a clear, commented example showing how to configure `allowedOrigins` for a service, including a note that `["*"]` is the default when omitted.
- The application still starts correctly with the updated `server.yaml` (no parse errors from comments).
