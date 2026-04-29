# Implementation Plan: VCVerifier should integrate Credentials Config Service API directly

## Overview

Integrate the FIWARE Credentials Config Service (CCS) directly into VCVerifier, eliminating the external microservice dependency. VCVerifier will serve the CCS REST API on a separate configurable port, use a database-compatible schema for zero-downtime migration from the standalone CCS, and replace HTTP-based config fetching with direct database queries while maintaining backward compatibility.

## Reference: CCS Database Schema (Target)

The final CCS database schema (after all Liquibase/Flyway migrations through v2.0.3) consists of two tables:

**`service` table:**
| Column | Type | Constraints |
|---|---|---|
| `id` | varchar(255) | PRIMARY KEY, NOT NULL |
| `default_oidc_scope` | varchar(255) | nullable |
| `authorization_type` | varchar(255) | nullable |

**`scope_entry` table:**
| Column | Type | Constraints |
|---|---|---|
| `id` | bigserial | PRIMARY KEY, NOT NULL |
| `service_id` | varchar(255) | FK -> service.id, CASCADE DELETE |
| `scope_key` | varchar(255) | |
| `credentials` | text | NOT NULL (JSON array of Credential objects) |
| `presentation_definition` | text | nullable (JSON PresentationDefinition object) |
| `flat_claims` | boolean | NOT NULL, DEFAULT false |
| `dcql_query` | text | nullable (JSON DCQL object) |

## Steps

### Step 1: Database dependencies, configuration structs, and connection management

**Goal:** Add the foundational database layer — new Go dependencies, configuration structs for the database and the second HTTP server, and a `database/` package with connection lifecycle management.

**Files to create/modify:**
- `go.mod` / `go.sum` — Add `github.com/jackc/pgx/v5` (PostgreSQL driver), `modernc.org/sqlite` (pure-Go SQLite for testing, no CGO), `github.com/jmoiron/sqlx` (optional, for convenience over `database/sql`)
- `config/config.go` — Add `Database` struct (fields: `Host`, `Port`, `Name`, `User`, `Password`, `Type` [postgres/sqlite], `SSLMode`) and `ConfigServer` struct (fields: `Port`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `ShutdownTimeout`, `Enabled`). Add both to the root `Configuration` struct.
- `database/database.go` — Create package with `NewConnection(cfg config.Database) (*sql.DB, error)` function that builds a DSN from config and opens a connection pool. Support `postgres` and `sqlite` driver types. Include `Close()` helper and health-check ping.
- `database/database_test.go` — Unit tests: verify SQLite connection opens, verify invalid config returns error, verify ping works.

**Acceptance criteria:**
- `go build ./...` succeeds with new dependencies.
- `go test ./database/...` passes with SQLite-based connection tests.
- New config structs are parseable from YAML (add test fixture to `config/data/`).

---

### Step 2: Database schema initialization and repository layer

**Goal:** Create the schema initialization logic (DDL compatible with existing CCS databases) and a repository layer providing full CRUD operations for services and scope entries.

**Files to create/modify:**
- `database/schema.go` — DDL constants for `service` and `scope_entry` tables matching the CCS schema exactly (see Reference above). Function `InitSchema(db *sql.DB, dbType string) error` that creates tables if they don't exist (using `CREATE TABLE IF NOT EXISTS`). Use database-type-aware SQL for `bigserial` (Postgres) vs `INTEGER PRIMARY KEY AUTOINCREMENT` (SQLite).
- `database/models.go` — Go structs for DB rows: `ServiceRow` (`ID`, `DefaultOidcScope`, `AuthorizationType`), `ScopeEntryRow` (`ID`, `ServiceID`, `ScopeKey`, `Credentials` as `string`, `PresentationDefinition` as `*string`, `FlatClaims` as `bool`, `DcqlQuery` as `*string`). Include conversion functions to/from existing `config.ConfiguredService` and `config.ScopeEntry` types, handling JSON marshal/unmarshal for the text columns (`credentials`, `presentation_definition`, `dcql_query`).
- `database/repository.go` — Define `ServiceRepository` interface:
  ```go
  type ServiceRepository interface {
      CreateService(ctx context.Context, service config.ConfiguredService) error
      GetService(ctx context.Context, id string) (config.ConfiguredService, error)
      GetAllServices(ctx context.Context, page, pageSize int) ([]config.ConfiguredService, int, error)
      UpdateService(ctx context.Context, id string, service config.ConfiguredService) (config.ConfiguredService, error)
      DeleteService(ctx context.Context, id string) error
      GetServiceScopes(ctx context.Context, id string, oidcScope *string) ([]string, error)
      ServiceExists(ctx context.Context, id string) (bool, error)
  }
  ```
  Implement `SqlServiceRepository` using `database/sql`. All operations should be transactional where they touch both tables (e.g., CreateService inserts service row + scope_entry rows in one transaction). Use parameterized queries (no string interpolation).
- `database/repository_test.go` — Comprehensive tests using SQLite: test CRUD cycle, test pagination, test cascade delete, test JSON round-trip for credentials/presentationDefinition/dcqlQuery, test duplicate ID conflict, test not-found errors.
- `database/schema_test.go` — Test that `InitSchema` is idempotent (can run twice without error).

**Acceptance criteria:**
- All repository operations work correctly with SQLite in tests.
- JSON columns round-trip correctly (marshal Go structs to JSON text for storage, unmarshal back to typed Go structs on read).
- Schema DDL matches the CCS Liquibase-migrated schema so VCVerifier can point at an existing CCS database.
- `go test ./database/...` passes.

---

### Step 3: CCS REST API handlers

**Goal:** Implement HTTP handlers for all six CCS API endpoints, matching the CCS OpenAPI specification exactly for request/response formats.

**Files to create/modify:**
- `ccsapi/models.go` — Request/response types matching the CCS OpenAPI spec:
  - `ServiceRequest` (for POST/PUT body: `DefaultOidcScope`, `OidcScopes`, `AuthorizationType`)
  - `ServiceResponse` (for GET response: `Id`, `DefaultOidcScope`, `OidcScopes`, `AuthorizationType`)
  - `ServicesListResponse` (`Total`, `PageNumber`, `PageSize`, `Services`)
  - `ProblemDetails` (`Type`, `Title`, `Status`, `Detail`, `Instance`)
  - Include JSON tags matching exact CCS field names (`defaultOidcScope`, `oidcScopes`, `authorizationType`, etc.).
  - Include conversion functions between API models and `config.ConfiguredService`.
- `ccsapi/handlers.go` — Gin handler functions:
  - `CreateService(repo) gin.HandlerFunc` — POST /service: validate body, check for ID conflicts (409), persist, return 201 with Location header.
  - `GetAllServices(repo) gin.HandlerFunc` — GET /service: parse `page`/`pageSize` query params (defaults: page=0, pageSize=100), query repo, return paginated `ServicesListResponse`.
  - `GetService(repo) gin.HandlerFunc` — GET /service/:id: fetch by ID, return 200 or 404.
  - `UpdateService(repo) gin.HandlerFunc` — PUT /service/:id: validate body, check exists (404), full replace, return 200 with updated service.
  - `DeleteService(repo) gin.HandlerFunc` — DELETE /service/:id: check exists (404), delete, return 204.
  - `GetServiceScopes(repo) gin.HandlerFunc` — GET /service/:id/scope: parse optional `oidcScope` query param, return scope credential types or 404 with ProblemDetails.
  - All handlers accept `ServiceRepository` as a dependency (closure pattern).
- `ccsapi/routes.go` — Function `RegisterRoutes(router *gin.Engine, repo database.ServiceRepository)` that registers all routes under the `/service` path.
- `ccsapi/handlers_test.go` — Unit tests for each handler using `httptest.NewRecorder` and a mock `ServiceRepository`. Test: successful CRUD, validation errors (400), not found (404), conflict (409), pagination edge cases, ProblemDetails response format.

**Acceptance criteria:**
- All six CCS API endpoints return correct HTTP status codes and response bodies matching the CCS OpenAPI spec.
- Input validation rejects missing required fields (`defaultOidcScope`, `oidcScopes` with at least one credential per scope).
- Error responses use `ProblemDetails` JSON format.
- `go test ./ccsapi/...` passes.

---

### Step 4: Second HTTP server setup and routing

**Goal:** Launch a second Gin-based HTTP server on a configurable port to serve the CCS API, alongside the existing verifier server. Both servers share the same database connection and shut down gracefully.

**Files to modify:**
- `main.go` — Major changes:
  - After reading config, if `ConfigServer.Enabled` is true (or `Database` config is present), open a database connection via `database.NewConnection()`, run `database.InitSchema()`, and create a `SqlServiceRepository`.
  - Create a second Gin router, register CCS API routes via `ccsapi.RegisterRoutes()`, add `/health` endpoint, add CORS middleware.
  - Start the second server in a goroutine on `ConfigServer.Port`.
  - Update graceful shutdown to stop both servers on SIGINT/SIGTERM.
  - Pass the repository to the verifier initialization (for Step 5).
- `health.go` — Add a database health check component that pings the DB connection. Register it on the config server's health endpoint.
- `server.yaml` — Add example `database` and `configServer` sections (commented out by default for backward compatibility):
  ```yaml
  # database:
  #   type: postgres
  #   host: localhost
  #   port: 5432
  #   name: ccs
  #   user: ccs
  #   password: ccs
  #   sslMode: disable
  # configServer:
  #   enabled: true
  #   port: 8090
  ```

**Acceptance criteria:**
- When `configServer.enabled: true` and valid `database` config is present, VCVerifier starts two HTTP servers on different ports.
- The CCS API server responds to all six endpoints.
- Graceful shutdown stops both servers.
- When config server is not enabled, VCVerifier starts normally with only the verifier server (backward compatible).
- The application compiles and existing tests still pass: `go test ./... -v`.

---

### Step 5: Database-backed CredentialsConfig implementation and integration wiring

**Goal:** Create a new `CredentialsConfig` implementation that reads service configurations directly from the database (via the repository), replacing the HTTP-based `ServiceBackedCredentialsConfig` when database mode is active. Maintain backward compatibility with the existing external HTTP client and static config modes.

**Files to create/modify:**
- `verifier/db_credentials_config.go` — New file implementing `CredentialsConfig`:
  ```go
  type DbBackedCredentialsConfig struct {
      repo          database.ServiceRepository
      initialConfig *config.ConfigRepo
  }
  ```
  - Same caching strategy as `ServiceBackedCredentialsConfig`: use `common.GlobalCache.ServiceCache` with periodic refresh from DB (via `chrono` scheduler), falling back to static config from `ConfigRepo.Services` when DB is unavailable.
  - `fillCache()` queries `repo.GetAllServices()` and populates the cache (same as existing `fillCache` but reads from DB instead of HTTP).
  - All interface methods delegate to cache lookups (same pattern as existing implementation — reuse the same logic).
  - Constructor: `InitDbBackedCredentialsConfig(repoConfig *config.ConfigRepo, repo database.ServiceRepository) (CredentialsConfig, error)`.
- `verifier/credentialsConfig.go` — Refactor `InitServiceBackedCredentialsConfig` to add a mode parameter or create a factory function:
  ```go
  func InitCredentialsConfig(repoConfig *config.ConfigRepo, repo database.ServiceRepository) (CredentialsConfig, error)
  ```
  This function selects the implementation based on config: if `repo != nil` (database mode), use `DbBackedCredentialsConfig`; if `ConfigEndpoint != ""` (external mode), use existing `ServiceBackedCredentialsConfig`; otherwise, static-only mode.
- `verifier/verifier.go` — Update `InitVerifier()` to accept an optional `ServiceRepository` parameter (or use a config-based factory). Pass it through to `InitCredentialsConfig()`.
- `main.go` — Pass the `ServiceRepository` instance (created in Step 4) to `InitVerifier()`.
- `verifier/db_credentials_config_test.go` — Unit tests: mock `ServiceRepository`, verify cache population from DB, verify all `CredentialsConfig` interface methods work correctly, test fallback to static config, test periodic refresh behavior.

**Acceptance criteria:**
- When database mode is active, `CredentialsConfig` reads from the database via the repository.
- When a service is created/updated/deleted via the CCS API (Step 3), the changes are visible to the verifier within one cache refresh interval.
- Existing HTTP client mode (`configEndpoint` set) still works unchanged.
- Static-only mode (`configEndpoint` empty, no database) still works unchanged.
- `go test ./verifier/...` passes (existing tests unbroken, new tests pass).

---

### Step 6: End-to-end testing, backward compatibility validation, and documentation

**Goal:** Validate the full integration works end-to-end, ensure backward compatibility with existing deployments, verify schema compatibility with CCS databases, and update project documentation.

**Files to create/modify:**
- `integration_test.go` (or `database/integration_test.go`) — Integration tests that exercise the full flow:
  1. Start with empty SQLite database, create schema.
  2. Create a service via CCS API handler → verify it's persisted in DB.
  3. Verify the service appears in `DbBackedCredentialsConfig` after cache refresh.
  4. Update the service → verify changes propagate.
  5. Delete the service → verify removal.
  6. Test pagination with multiple services.
  7. Test that credential type lookups, presentation definitions, DCQL queries, holder verification, compliance requirements, and JWT inclusion settings all work through the full chain.
- `config/configClient_test.go` — Verify existing `HttpConfigClient` tests still pass (backward compatibility of external mode).
- `database/migration_compat_test.go` — Test that the Go DDL schema is compatible with the CCS Liquibase schema:
  - Create tables using Go's `InitSchema()`.
  - Insert sample data matching the CCS entity format.
  - Read it back using the Go repository and verify correct deserialization.
  - Verify all JSON column formats match what the CCS Java code produces (same field names, same structure).
- `CLAUDE.md` — Update with:
  - New `database/` package description.
  - New `ccsapi/` package description.
  - Updated architecture section describing the optional second HTTP server.
  - New configuration sections for `database` and `configServer`.
  - Updated build/test commands.
- Verify: `go build ./...` and `go test ./... -v` both pass cleanly.

**Acceptance criteria:**
- Full CRUD → cache → verifier flow works in integration tests.
- Existing tests pass without modification (backward compatibility).
- Schema compatibility with CCS database is validated.
- `go test ./... -v` passes with zero failures.
- CLAUDE.md accurately reflects the new architecture.
