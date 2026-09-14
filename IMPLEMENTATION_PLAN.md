# Implementation Plan: eIDAS 2.0 Conformant Credentials Verification

## Overview

Add eIDAS 2.0 conformant credential verification to VCVerifier by implementing an ETSI TS 119 612 trust list client, a new `eidas` validation service, per-credential-type eIDAS configuration, SD-JWT format enforcement for eIDAS-configured credentials, and removal of the legacy external JAdES/did:elsi validation path. The new trust framework slots into the existing `ValidationService` chain alongside `ebsi`, `ebsi-v5`, and `gaia-x`.

## Steps

### Step 1: ETSI TS 119 612 Trust List XML Parser

**Goal:** Create a new `eidas/` package that can parse ETSI TS 119 612 trust list XML documents into Go structs.

**What to do:**
- Create directory `eidas/` with a `trustlist.go` file.
- Define Go structs matching the ETSI TS 119 612 XML schema for trust lists: `TrustServiceStatusList` (root), `SchemeInformation` (territory, type, operator name, distribution points for LOTL), `TrustServiceProviderList`, `TrustServiceProvider`, `TSPService` (service type, status, digital identities/X.509 certificates, service information extensions).
- Use Go stdlib `encoding/xml` for parsing — no external XML library needed.
- Focus on the fields needed for trust validation: service type identifiers (e.g. `http://uri.etsi.org/TrstSvc/Svctype/...` for qualified/non-qualified services), service status URIs (granted, withdrawn, etc.), X.509 certificates embedded in `ServiceDigitalIdentity`, and the `SchemeTerritory` (ISO 3166-1 alpha-2 country code).
- Define constants for relevant ETSI service type URIs (QCert for ESig, QCert for ESeal, qualified and non-qualified certificate authority types per ETSI TS 119 612 §5.5.1).
- Define constants for service status URIs: `granted`, `withdrawn`, `recognisedatnationallevel`, etc.
- Write a `ParseTrustList(xmlData []byte) (*TrustServiceStatusList, error)` function.
- Add comprehensive unit tests in `eidas/trustlist_test.go` with test fixtures (small XML snippets) covering: valid trust list parsing, missing fields, multiple TSPs, multiple services per TSP, X.509 certificate extraction from `ServiceDigitalIdentity` elements.
- Document all exported types and functions.

**Files:**
- `eidas/trustlist.go` (new)
- `eidas/trustlist_test.go` (new)
- `eidas/testdata/` directory with XML fixture files (new)

**Acceptance criteria:**
- `go test ./eidas/... -v` passes with all parser tests green.
- Structs can represent both LOTL (contains distribution points to national TLs) and national TLs (contain TSPs and their services).
- X.509 certificates are extractable from parsed trust list entries as `*x509.Certificate`.

---

### Step 2: ETSI Trust List Fetcher with LOTL Resolution and Caching

**Goal:** Add a background trust list fetcher that downloads the EU LOTL, follows pointers to national TLs, parses them, and caches the resulting trust service data.

**What to do:**
- Add `eidas/fetcher.go` with a `TrustListFetcher` struct that:
  - Accepts a configurable LOTL URL (defaulting to the official EU LOTL URL: `https://ec.europa.eu/tools/lotl/eu-lotl.xml`).
  - Fetches the LOTL XML, parses it using `ParseTrustList()` from Step 1.
  - Extracts `SchemeInformation.PointersToOtherTSL` to find national TL URLs.
  - Filters national TLs by an optional list of allowed country codes (empty = all).
  - Fetches and parses each national TL concurrently (bounded concurrency via a worker pool).
  - Stores parsed TSPs and their services in an in-memory cache, keyed by country code.
  - Respects HTTP `Cache-Control` headers for TTL, with a configurable minimum/maximum refresh interval and a fallback default TTL (e.g. 24h).
  - Runs periodic background refresh using a `time.Ticker`.
  - Provides a `Stop()` method for graceful shutdown.
- Add `eidas/trust_store.go` with a `TrustStore` struct:
  - Thread-safe read access to cached trust service entries via `sync.RWMutex`.
  - `GetTrustedServices(countryCode string, serviceTypes []string, onlyGranted bool) []TrustedService` — returns services matching type and status filters.
  - `IsTrustedService(certificate *x509.Certificate, countryCode string, serviceTypes []string) bool` — checks if a given X.509 certificate is associated with any trusted service.
- Define `TrustedService` struct: country code, TSP name, service type URI, status URI, X.509 certificates, status start date.
- Unit tests in `eidas/fetcher_test.go` using `httptest.Server` to serve fixture XML.
- Unit tests in `eidas/trust_store_test.go` for filtering, thread-safety.

**Files:**
- `eidas/fetcher.go` (new)
- `eidas/trust_store.go` (new)
- `eidas/fetcher_test.go` (new)
- `eidas/trust_store_test.go` (new)
- `go.mod` / `go.sum` (updated if any new dependencies)

**Acceptance criteria:**
- `go test ./eidas/... -v` passes.
- Fetcher can resolve a LOTL → national TLs → TSPs hierarchy from test fixtures.
- Cache is populated and queryable by country code and service type.
- Background refresh runs on a timer and can be stopped cleanly.

---

### Step 3: eIDAS Configuration and SD-JWT Format Enforcement

**Goal:** Extend the configuration model to support eIDAS trust list entries on credentials and enforce that eIDAS-configured credentials use SD-JWT format only.

**What to do:**
- Add the `eidas` trust list type constant in `verifier/trustedparticipant.go` (alongside `typeEbsi`, `typeEbsiV5`, `typeGaiaX`):
  ```go
  const typeEidas = "eidas"
  ```
- Extend `config.Credential` in `config/configClient.go` with an optional eIDAS-specific configuration block:
  ```go
  type EidasConfig struct {
      // Enabled toggles eIDAS 2.0 trust list validation for this credential type.
      Enabled bool `json:"enabled" mapstructure:"enabled"`
      // AllowedCountries restricts which national trusted lists are consulted.
      // Empty means all countries from the LOTL are allowed.
      AllowedCountries []string `json:"allowedCountries,omitempty" mapstructure:"allowedCountries,omitempty"`
      // RequireQualified restricts to qualified trust services only (default: true).
      RequireQualified *bool `json:"requireQualified,omitempty" mapstructure:"requireQualified,omitempty"`
  }
  ```
  Add `EidasConfig *EidasConfig` field to the `Credential` struct.
- Add `eidas` section to the global `config.Configuration` struct:
  ```go
  type EidasGlobal struct {
      // LotlUrl is the URL of the EU List of Trusted Lists.
      LotlUrl string `mapstructure:"lotlUrl" default:"https://ec.europa.eu/tools/lotl/eu-lotl.xml"`
      // RefreshInterval is how often (in seconds) to re-fetch trust lists.
      RefreshInterval int `mapstructure:"refreshInterval" default:"86400"`
      // Countries is the global list of allowed country codes (can be overridden per-credential).
      Countries []string `mapstructure:"countries,omitempty"`
  }
  ```
- Add SD-JWT format enforcement: in the credential validation path (`verifier/verifier.go`), before running validation services for a credential whose `EidasConfig.Enabled` is true, check that the credential was parsed from an SD-JWT presentation. The `common.Credential` or `common.Presentation` needs a way to indicate its source format. Options:
  - Add a `Format` field to `common.Credential` (e.g. `"sd-jwt"`, `"jwt_vc"`, `"ldp_vc"`) set during parsing in `presentation_parser.go`.
  - Check the format in the eIDAS validation service and return an error (HTTP 400) if the credential is not SD-JWT.
- In `presentation_parser.go`, set the format on each credential during parsing:
  - `parseJWTPresentation` → `"jwt_vc"`
  - `parseJSONLDPresentation` → `"ldp_vc"`
  - `ParseWithSdJwt` → `"sd-jwt"`
- Add the `CredentialsConfig` interface method to retrieve eIDAS config: `GetEidasConfig(serviceIdentifier, scope, credentialType string) (*config.EidasConfig, error)`.
- Validate at config load time that eIDAS-enabled credential types are only used with SD-JWT presentation definitions (warn if the presentation definition format filter doesn't include SD-JWT).
- Add unit tests for config parsing and SD-JWT enforcement.

**Files:**
- `config/config.go` (modified — add `EidasGlobal` struct and field)
- `config/configClient.go` (modified — add `EidasConfig` struct and field on `Credential`)
- `verifier/trustedparticipant.go` (modified — add `typeEidas` constant)
- `common/credential.go` or equivalent (modified — add Format field if not present)
- `verifier/presentation_parser.go` (modified — set format on credentials during parsing)
- `verifier/credentialsConfig.go` (modified — add `GetEidasConfig` method to interface)
- `verifier/credentialsConfig_test.go` (modified/new — tests for eIDAS config retrieval)
- `config/data/` (new fixture YAML files for eIDAS config)

**Acceptance criteria:**
- `go test ./... -v` passes.
- Configuration with `eidas.enabled: true` on a credential type is parsed correctly.
- Credential format is tracked through the parsing pipeline.
- An eIDAS-configured credential presented as JSON-LD or plain JWT is rejected before trust validation runs.

---

### Step 4: eIDAS Validation Service

**Goal:** Implement the `EidasValidationService` that validates SD-JWT credentials against the cached ETSI trust lists.

**What to do:**
- Create `verifier/eidas_validation.go` with `EidasValidationService`:
  ```go
  type EidasValidationService struct {
      trustStore *eidas.TrustStore
  }
  ```
  Implements `ValidationService` interface.
- The `ValidateVC` method:
  1. Extract the validation context to get eIDAS config for the credential's type.
  2. If no eIDAS config is enabled for this credential type, return `true` (pass-through, same pattern as other services when no config is specified).
  3. Enforce SD-JWT format — reject with a descriptive error if the credential was not parsed from SD-JWT.
  4. Extract the issuer's X.509 certificate from the SD-JWT's key binding or header (the `x5c` header parameter).
  5. Query the `TrustStore` for matching trusted services, filtered by:
     - Country codes from the credential's `EidasConfig.AllowedCountries` (or global config).
     - Service type (qualified vs non-qualified, based on `RequireQualified`).
     - Service status (`granted` only).
  6. Verify the issuer's certificate against the trust service's certificates (certificate chain matching).
  7. Return `true` if a matching trusted service is found, `false` with an appropriate error otherwise.
- Create a new `EidasValidationContext` (or extend `TrustRegistriesValidationContext`) to carry eIDAS config per-credential-type into the validation service. Update `selectValidationContext` in `verifier.go` to route the eIDAS context to the eIDAS service.
- Wire the service into `InitVerifier` in `verifier.go`:
  - Initialize the `TrustListFetcher` from config.
  - Add `&eidasValidationService` to the `validationServices` slice (after trusted issuer, before credential status).
- Add unit tests in `verifier/eidas_validation_test.go` with mock `TrustStore`.

**Files:**
- `verifier/eidas_validation.go` (new)
- `verifier/eidas_validation_test.go` (new)
- `verifier/verifier.go` (modified — wire eIDAS service into `validationServices`, initialize fetcher)
- `verifier/verifier.go` (modified — extend `selectValidationContext` for eIDAS service)

**Acceptance criteria:**
- `go test ./verifier/... -v` passes.
- eIDAS validation service correctly validates/rejects credentials based on trust list data.
- Service is a no-op (pass-through) for credential types without eIDAS config.
- SD-JWT format is enforced with clear error messaging.

---

### Step 5: Remove Legacy JAdES/did:elsi External Validation

**Goal:** Remove the external JAdES validation service and did:elsi support, replacing it with the new eIDAS trust list validation.

**What to do:**
- Remove the `jades/` package entirely:
  - Delete `jades/jades_validator.go`
  - Delete `jades/jades_validator_test.go`
- Remove the `Elsi` config section from `config/config.go`:
  - Remove `Elsi` field from `Configuration` struct.
  - Remove `Elsi`, `ValidationEndpoint` structs.
- Update `verifier/presentation_parser.go`:
  - Remove `elsiConfig` handling from `InitPresentationParser`.
  - Remove `validateConfig(elsiConfig)` function.
  - Remove JAdES validator initialization and health check registration.
  - Simplify `NewJWTProofChecker` call to remove `jAdESValidator` parameter.
- Update `verifier/jwt_proof_checker.go`:
  - Remove `jAdESValidator` field from `JWTProofChecker` struct.
  - Remove `jades` import.
  - Remove `DidElsiPrefix` constant.
  - Remove `isDidElsiMethod()` function.
  - Remove `verifyElsiJWT()` method.
  - Remove did:elsi handling from `VerifyJWTAndReturnKey()`.
  - Remove `ErrorInvalidJAdESSignature` error variable.
  - Remove `extractX5CFromToken()` if only used by elsi path (check if shared with eIDAS).
- Update `verifier/ld_proof_checker.go`:
  - Remove `IsDidElsi` function.
  - Remove did:elsi rejection logic from `resolveProofKeys()` — simplify the flow.
  - Remove `ErrorDidElsiNotSupportedForLDProof` error variable.
- Update `verifier/key_resolver.go`:
  - Remove any did:elsi specific handling.
- Update tests:
  - Remove did:elsi test cases from `verifier/jwt_proof_checker_test.go`.
  - Remove did:elsi test cases from `verifier/ld_proof_checker_test.go`.
  - Remove did:elsi test cases from `verifier/presentation_parser_test.go`.
  - Remove `jades/jades_validator_test.go`.
- Update `main.go` if it references elsi config for health checks.
- Clean up `go.mod` / `go.sum` — remove any dependencies only used by jades.

**Files:**
- `jades/jades_validator.go` (deleted)
- `jades/jades_validator_test.go` (deleted)
- `config/config.go` (modified — remove Elsi structs)
- `verifier/presentation_parser.go` (modified — remove elsi init)
- `verifier/jwt_proof_checker.go` (modified — remove did:elsi)
- `verifier/ld_proof_checker.go` (modified — remove did:elsi)
- `verifier/key_resolver.go` (modified if needed)
- `verifier/jwt_proof_checker_test.go` (modified — remove elsi tests)
- `verifier/ld_proof_checker_test.go` (modified — remove elsi tests)
- `verifier/presentation_parser_test.go` (modified — remove elsi tests)
- `main.go` (modified if needed)
- `go.mod` / `go.sum` (updated)

**Acceptance criteria:**
- `go build ./...` succeeds with no references to `jades/` or did:elsi.
- `go test ./... -v` passes.
- No compilation errors from removed references.
- Config files without `elsi` section still work.
- The `jades/` directory no longer exists.

---

### Step 6: Integration Tests and Documentation

**Goal:** Add integration-level tests that exercise the full eIDAS validation flow and update documentation.

**What to do:**
- Create `verifier/eidas_integration_test.go`:
  - Test the full flow: SD-JWT presentation with an issuer certificate → eIDAS validation service → trust list lookup → pass/reject.
  - Use test fixtures with self-signed certificates and a mock trust list.
  - Table-driven tests covering:
    - Valid SD-JWT credential with matching trusted service → accepted.
    - Valid SD-JWT credential with no matching country → rejected.
    - Valid SD-JWT credential with withdrawn service status → rejected.
    - JSON-LD credential with eIDAS config → rejected (format enforcement).
    - JWT credential with eIDAS config → rejected (format enforcement).
    - Credential type without eIDAS config → pass-through (no eIDAS check).
    - eIDAS with `requireQualified: true` → only qualified services match.
    - eIDAS with `requireQualified: false` → non-qualified services also match.
    - Multiple allowed countries — service found in second country.
    - No allowed countries (empty list) — all countries searched.
- Create `eidas/fetcher_integration_test.go`:
  - Test LOTL → national TL resolution with `httptest` servers.
  - Test background refresh picks up changes.
  - Test cache expiry and re-fetch.
  - Test error handling: unavailable LOTL, malformed XML, unreachable national TL.
- Add config test fixtures:
  - `config/data/eidas-basic.yaml` — minimal eIDAS configuration.
  - `config/data/eidas-countries.yaml` — eIDAS with country filtering.
- Update `server.yaml` (or add a documented example section) with eIDAS config:
  ```yaml
  eidas:
    lotlUrl: "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
    refreshInterval: 86400
    countries: []
  ```
- Add config example showing per-credential eIDAS configuration in service scopes.
- Update the OpenAPI spec `api/credentials-config.yaml` if needed to add `eidasConfig` to the credential schema.
- Run the full test suite: `go test ./... -v`.

**Files:**
- `verifier/eidas_integration_test.go` (new)
- `eidas/fetcher_integration_test.go` (new)
- `config/data/eidas-basic.yaml` (new)
- `config/data/eidas-countries.yaml` (new)
- `server.yaml` (modified — add eidas section)
- `api/credentials-config.yaml` (modified if needed)

**Acceptance criteria:**
- `go test ./... -v` passes, including all new integration tests.
- Full eIDAS validation flow is exercised end-to-end in tests.
- Configuration examples are present and documented.
- No regressions in existing tests.
