# Implementation Plan: eIDAS 2.0 Conformant Credentials Verification

## Overview

Add eIDAS 2.0 conformant credential verification to VCVerifier by implementing an ETSI TS 119 612 trust list client, a new `eidas` validation service, per-credential-type eIDAS configuration, SD-JWT format enforcement for eIDAS-configured credentials, and removal of the legacy external JAdES/did:elsi validation path. The eIDAS validation is an **independent, additional validation step** — it does **not** replace or subsume the existing trusted participants / trusted issuers checks. When `eidasConfig` is present on a credential type in the credentials configuration, the eIDAS validation runs **in addition to** any configured `trustedParticipantsLists` and `trustedIssuersLists`.

> **Note on standard references:** The ticket references "ETSI TS 119 602"; this plan targets ETSI TS 119 612 ("EU Trusted Lists"), which is the standard defining the XML schema and trust list structure for the EU trust framework. TS 119 602 does not exist as a published standard — 119 612 is the correct reference.

### Scope — QEAA Extension Checks

The ticket requests "configuration of the Credential Types to be checked for eIDAS2.0 conformance and as extension checks for QEAA". In this plan, QEAA (Qualified Electronic Attestation of Attributes) support is scoped to **trust list–based validation**: checking that the credential's issuer certificate chains up to a qualified trust service listed in the EU Trusted Lists. Additional QEAA validation requirements that may emerge from the EUDI ARF (e.g., attestation schema validation, PID-specific checks, specific OID extension assertions) are **deliberately deferred** to a follow-up ticket once the base eIDAS trust list infrastructure is in place. The `RequireQualified` flag controls whether only qualified trust services (service type URIs ending in `/Qc*`) are accepted.

## Steps

### Step 1: ETSI TS 119 612 Trust List XML Parser

**Goal:** Create a new `eidas/` package that can parse ETSI TS 119 612 trust list XML documents into Go structs.

**What to do:**
- Create directory `eidas/` with a `trustlist.go` file.
- Define Go structs matching the ETSI TS 119 612 XML schema for trust lists: `TrustServiceStatusList` (root), `SchemeInformation` (territory, type, operator name, distribution points for LOTL), `TrustServiceProviderList`, `TrustServiceProvider`, `TSPService` (service type, status, digital identities/X.509 certificates, service information extensions).
- Use Go stdlib `encoding/xml` for parsing.
- Focus on the fields needed for trust validation: service type identifiers (e.g. `http://uri.etsi.org/TrstSvc/Svctype/...` for qualified/non-qualified services), service status URIs (granted, withdrawn, etc.), X.509 certificates embedded in `ServiceDigitalIdentity`, and the `SchemeTerritory` (ISO 3166-1 alpha-2 country code).
- **Known limitation — XML digital signatures:** ETSI TS 119 612 §5.7 requires trust lists to carry an XMLDSig enveloped signature, and a conformant consumer must verify it before trusting the content. Go's stdlib `encoding/xml` cannot verify XMLDSig. This plan **defers** XMLDSig verification to a follow-up: the initial implementation fetches trust lists over HTTPS only, relies on TLS for transport-level integrity, and logs a warning that XMLDSig verification is not performed. A follow-up ticket should add XMLDSig verification using a dedicated library (e.g. `russellhaering/goxmldsig` or similar) before production deployment. The `TrustListFetcher` should be structured so the signature verification step can be inserted without changing the caller interface.
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

### Step 3: eIDAS Configuration and Credential Format Tracking

**Goal:** Extend the configuration model to support per-credential-type eIDAS configuration as part of the credential config (alongside `trustedParticipantsLists`, `trustedIssuersLists`, etc.) and add credential format tracking through the parsing pipeline.

**Architecture note:** eIDAS is **not** a new trust list type like `ebsi` or `gaia-x`. It is an independent, additional validation step configured per credential type. When `eidasConfig.enabled` is true for a credential type, the eIDAS validation runs **in addition to** whatever `trustedParticipantsLists` / `trustedIssuersLists` are configured for that credential. Do **not** add any `typeEidas` constant to `trustedparticipant.go`.

**Global feature gate:** The global `eidas.enabled` flag in `config.Configuration` (added in Step 2) controls whether the eIDAS feature is active for the whole verifier. When `eidas.enabled` is `false` (the default), the trust list fetcher must **not** be started (no background resource consumption), and any per-credential `eidasConfig.enabled: true` in the credentials configuration must be **rejected with HTTP 400** during config validation/loading, with an error message indicating that the global eIDAS feature is disabled. This validation must be added to the `GetEidasConfig` method (or wherever per-credential eIDAS config is resolved) and to the Credentials Config Service's create/update endpoints.

**What to do:**
- Add `eidasConfig` to the `Credential` schema in `api/credentials-config.yaml` as a new optional property on the `Credential` object (line 188), alongside `trustedParticipantsLists`, `holderVerification`, etc.:
  ```yaml
  eidasConfig:
    $ref: '#/components/schemas/EidasConfig'
  ```
  Define the `EidasConfig` schema:
  ```yaml
  EidasConfig:
    type: object
    description: eIDAS 2.0 trust list validation configuration for this credential type.
    properties:
      enabled:
        type: boolean
        default: false
        description: Whether eIDAS 2.0 trust list validation is enabled for this credential type.
      allowedCountries:
        type: array
        description: Restrict which national trusted lists are consulted. Empty means all countries from the LOTL are allowed.
        items:
          type: string
        example: ["DE", "FR", "ES"]
      requireQualified:
        type: boolean
        default: true
        description: Whether to restrict to qualified trust services only.
  ```
- Mirror in Go: extend `config.Credential` in `config/configClient.go` with an optional eIDAS-specific configuration block:
  ```go
  type EidasConfig struct {
      // Enabled toggles eIDAS 2.0 trust list validation for this credential type.
      Enabled bool `json:"enabled" mapstructure:"enabled"`
      // AllowedCountries restricts which national trusted lists are consulted.
      // Empty means all countries from the LOTL are allowed.
      AllowedCountries []string `json:"allowedCountries,omitempty" mapstructure:"allowedCountries,omitempty"`
      // RequireQualified restricts to qualified trust services only.
      // Defaults to true — set programmatically, not via struct tag.
      RequireQualified *bool `json:"requireQualified,omitempty" mapstructure:"requireQualified,omitempty"`
  }
  ```
  Add `EidasConfig *EidasConfig` field to the `Credential` struct.
- Add `eidas` section to the global `config.Configuration` struct for LOTL fetch settings:
  ```go
  type EidasGlobal struct {
      // LotlUrl is the URL of the EU List of Trusted Lists.
      LotlUrl string `mapstructure:"lotlUrl"`
      // RefreshInterval is how often (in seconds) to re-fetch trust lists.
      RefreshInterval int `mapstructure:"refreshInterval"`
      // Countries is the global list of allowed country codes (can be overridden per-credential).
      Countries []string `mapstructure:"countries,omitempty"`
  }
  ```
  **Important:** Do not use `default:"..."` struct tags — gookit/config and mapstructure do not honor them. Instead, set defaults programmatically after `ReadConfig()` returns:
  ```go
  if cfg.Eidas.LotlUrl == "" {
      cfg.Eidas.LotlUrl = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
  }
  if cfg.Eidas.RefreshInterval == 0 {
      cfg.Eidas.RefreshInterval = 86400
  }
  ```
  Similarly, `RequireQualified` defaults to `true` when the pointer is nil.
- Add credential format tracking: add a `Format` field to `common.Credential` (e.g. `"sd-jwt"`, `"jwt_vc"`, `"ldp_vc"`) set during parsing in `presentation_parser.go`:
  - `parseJWTPresentation` → `"jwt_vc"`
  - `parseJSONLDPresentation` → `"ldp_vc"`
  - `ParseWithSdJwt` → `"sd-jwt"`
  Note: SD-JWT format enforcement itself is **not** done here — it belongs in the `EidasValidationService.ValidateVC` (Step 4), where the eIDAS config is consulted and where the rejection error originates.
- Add the `CredentialsConfig` interface method to retrieve eIDAS config: `GetEidasConfig(serviceIdentifier, scope, credentialType string) (*config.EidasConfig, error)`.
- Add unit tests for config parsing, format tracking, and eIDAS config retrieval.

**Files:**
- `api/credentials-config.yaml` (modified — add `eidasConfig` property and `EidasConfig` schema)
- `config/config.go` (modified — add `EidasGlobal` struct and field, programmatic defaults)
- `config/configClient.go` (modified — add `EidasConfig` struct and field on `Credential`)
- `common/credential.go` or equivalent (modified — add Format field if not present)
- `verifier/presentation_parser.go` (modified — set format on credentials during parsing)
- `verifier/credentialsConfig.go` (modified — add `GetEidasConfig` method to interface)
- `verifier/credentialsConfig_test.go` (modified/new — tests for eIDAS config retrieval)
- `config/data/` (new fixture YAML files for eIDAS config)

**Acceptance criteria:**
- `go test ./... -v` passes.
- `eidasConfig` is defined in `api/credentials-config.yaml` as part of the `Credential` schema.
- Configuration with `eidasConfig.enabled: true` on a credential type is parsed correctly.
- Credential format is tracked through the parsing pipeline (but format enforcement is deferred to Step 4).
- Programmatic defaults are applied for global eIDAS settings.

---

### Step 4: eIDAS Validation Service

**Goal:** Implement the `EidasValidationService` that validates SD-JWT credentials against the cached ETSI trust lists. This service runs **in addition to** any configured trusted participants / trusted issuers checks — it does not replace them.

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
  3. **Enforce SD-JWT format** — check the credential's `Format` field (set in Step 3). If the credential was not parsed from SD-JWT (`Format != "sd-jwt"`), reject with a descriptive error (HTTP 400). This is the **single location** for SD-JWT format enforcement — Step 3 only tracks the format, it does not enforce it.
  4. Extract the issuer's X.509 certificate from the SD-JWT's `x5c` header parameter. Note: check whether `extractX5CFromToken()` in `jwt_proof_checker.go` (currently used by the did:elsi path) can be reused or adapted before Step 5 deletes the elsi code.
  5. Query the `TrustStore` for matching trusted services, filtered by:
     - Country codes from the credential's `EidasConfig.AllowedCountries` (or global config if empty).
     - Service type (qualified vs non-qualified, based on `RequireQualified`).
     - Service status (`granted` only).
  6. **Verify the issuer's certificate against the trust list using PKIX chain building.** Real eIDAS trust lists publish CA certificates, not leaf certificates, so simple byte comparison will not work for most issuers. Use Go's `x509.Certificate.Verify()` with an `x509.VerifyOptions` whose `Roots` pool is populated from the trust service's X.509 certificates:
     ```go
     roots := x509.NewCertPool()
     for _, cert := range trustedService.Certificates {
         roots.AddCert(cert)
     }
     opts := x509.VerifyOptions{
         Roots: roots,
         // KeyUsages filtered as appropriate for the service type
     }
     _, err := issuerCert.Verify(opts)
     ```
     If the `x5c` header contains intermediate certificates, include them in `opts.Intermediates`. A successful `Verify()` call means the issuer certificate chains up to a trusted CA in the trust list.
  7. Return `true` if a matching trusted service is found and certificate validation passes, `false` with an appropriate error otherwise.
- Create a new `EidasValidationContext` (or extend `TrustRegistriesValidationContext`) to carry eIDAS config per-credential-type into the validation service. Update `selectValidationContext` in `verifier.go` to route the eIDAS context to the eIDAS service.
- Wire the service into `InitVerifier` in `verifier.go`:
  - **Check `config.Eidas.Enabled` first.** Only initialize the `TrustListFetcher` and start background refresh when the global flag is true. When false, do **not** create the fetcher — no background goroutines, no HTTP requests, no memory for the trust store.
  - Add `&eidasValidationService` to the `validationServices` slice. This runs independently of the trusted issuers / trusted participants services — both run for a given credential if both are configured.
- Add unit tests in `verifier/eidas_validation_test.go` with mock `TrustStore`, covering:
  - SD-JWT format rejection for JWT and JSON-LD credentials.
  - Certificate chain validation with CA certs (not just leaf matching).
  - Pass-through for credential types without eIDAS config.

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
- Certificate validation uses PKIX chain building (`x509.Certificate.Verify()`), not byte comparison.
- eIDAS validation runs independently of and in addition to trusted participants / trusted issuers checks.

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
- Verify that `api/credentials-config.yaml` has the `eidasConfig` property on the `Credential` schema (added in Step 3).
- Run the full test suite: `go test ./... -v`.

**Files:**
- `verifier/eidas_integration_test.go` (new)
- `eidas/fetcher_integration_test.go` (new)
- `config/data/eidas-basic.yaml` (new)
- `config/data/eidas-countries.yaml` (new)
- `server.yaml` (modified — add eidas section)
- `api/credentials-config.yaml` (verified — `eidasConfig` added in Step 3)

**Acceptance criteria:**
- `go test ./... -v` passes, including all new integration tests.
- Full eIDAS validation flow is exercised end-to-end in tests.
- Configuration examples are present and documented.
- No regressions in existing tests.
