# Implementation Plan: Document eIDAS 2.0 conformant credentials verification

## Overview

Add comprehensive user-facing documentation for the eIDAS 2.0 trust list verification feature in VCVerifier. The existing README only documents `did:elsi` verification under one subsection (lines 531-593) — this plan restructures and expands the eIDAS documentation to cover the full feature: global configuration (including undocumented `maxWorkers` and `fetchTimeout` fields), per-credential SD-JWT validation via `eidasConfig`, the `did:elsi` DID method, and operational guidance. All changes are documentation-only (Markdown files); no code changes are needed.

## Steps

### Step 1: Add comprehensive eIDAS 2.0 documentation to README and docs/

**Goal:** Restructure and expand the eIDAS documentation so operators can configure and use both SD-JWT eIDAS validation and did:elsi verification without reading source code.

**What to do:**

#### 1a. Create `docs/eidas-verification.md` — Detailed eIDAS 2.0 Reference

Create a new standalone documentation file with in-depth, user-focused coverage of the eIDAS 2.0 trust list verification feature. This file should cover the following sections:

**1. Introduction & Purpose**
- What eIDAS 2.0 trust list verification does in VCVerifier (1-2 paragraphs).
- Two verification paths: SD-JWT credentials (per-credential `eidasConfig`) and `did:elsi` credentials (automatic via global eIDAS toggle).
- Link to the [EU Trusted Lists browser](https://esignature.ec.europa.eu/efda/tl-browser/) and [ETSI TS 119 612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.02.01_60/ts_119612v020201p.pdf) spec for context.

**2. How It Works (conceptual overview for operators, not code-level)**
- Background trust list fetching: VCVerifier fetches the EU List of Trusted Lists (LOTL), discovers national trusted lists, and caches all trust service providers (TSPs) and their CA certificates in memory.
- Periodic refresh: trust lists are re-fetched on a configurable interval.
- Certificate chain validation: when a credential is presented, the issuer's X.509 certificate is validated against the cached trust store using standard PKIX chain building (the same mechanism browsers use for TLS).
- Qualified vs. non-qualified trust services: explain the distinction — qualified trust services (QTSPs) are subject to stricter EU regulatory oversight. The `requireQualified` field (default: `true`) controls whether only qualified service types (`CA/QC`, `NationalRootCA-QC`) or also non-qualified CAs (`CA/PKC`) are accepted.

**3. Global Configuration Reference**
- Full `eidas:` block in `server.yaml` with all six fields documented:
  - `enabled` (bool, default: `false`) — master toggle for the entire eIDAS feature
  - `lotlUrl` (string, default: `https://ec.europa.eu/tools/lotl/eu-lotl.xml`) — URL of the List of Trusted Lists
  - `refreshInterval` (int, default: `86400`) — seconds between background refreshes, clamped to [3600, 604800]
  - `countries` (string list, default: empty = all) — ISO 3166-1 alpha-2 country code filter
  - `maxWorkers` (int, default: `5`) — maximum concurrent national trust list fetches during refresh
  - `fetchTimeout` (int, default: `30`) — HTTP timeout in seconds per trust list fetch
- Annotated YAML example showing all fields.
- Explain what happens when `enabled: false` (default): no background fetching, no memory for trust store, `did:elsi` credentials rejected with error, per-credential `eidasConfig` rejected with HTTP 400.

**4. SD-JWT Credential Validation (per-credential eidasConfig)**
- Explain the use case: validating that an SD-JWT credential's issuer holds a certificate trusted by the EU Trusted Lists. This is the primary eIDAS 2.0 verification path for credentials that carry issuer certificates in the SD-JWT `x5c` header.
- Show the per-credential `eidasConfig` block that sits inside each credential entry (alongside `trustedParticipantsLists`, `trustedIssuersLists`, `holderVerification`, `credentialStatus`):
  ```yaml
  eidasConfig:
    enabled: true
    allowedCountries: ["DE", "FR"]
    requireQualified: true
  ```
- Document each field:
  - `enabled` (bool) — toggle eIDAS validation for this credential type
  - `allowedCountries` (string list, optional) — per-credential country filter; when non-empty, overrides the global `eidas.countries`; when empty, falls back to global
  - `requireQualified` (bool pointer, default: `true`) — when true, only qualified trust services (QTSPs) are accepted; when false, non-qualified CAs are also accepted
- Full annotated `server.yaml` example showing a service with two credential types: one with eIDAS enabled and one without.
- Note: eIDAS validation is an **additional** check — it runs alongside (not instead of) trusted participants/issuers list checks and revocation checks. All configured checks must pass.
- Note: eIDAS validation **requires SD-JWT format**. JWT-VC and JSON-LD credentials will be rejected with `eidas_validation_requires_sd_jwt_format` if `eidasConfig` is enabled for their type.
- Note: the global `eidas.enabled` must be `true` for per-credential `eidasConfig` to work. If the global toggle is off, attempting to enable `eidasConfig` on a credential type results in an HTTP 400 error.

**5. did:elsi Verification**
- Brief explanation of the `did:elsi` DID method (link to the README section for quick reference).
- Clarify that `did:elsi` verification is automatically enabled when the global `eidas.enabled` is `true` — no per-credential config needed.
- How it works: `x5c` header extraction → DID-to-certificate binding via `organizationIdentifier` OID 2.5.4.97 → JWT signature verification → certificate chain validation against trust store.
- `did:elsi` only supports JWT format; JSON-LD/Linked Data Proof presentations are explicitly rejected.
- `did:elsi` searches all countries and all certificate service types (qualified + non-qualified) — unlike per-credential eIDAS validation, there is no per-credential country or qualified filter for `did:elsi`.

**6. Interaction with Other Trust Anchors**
- eIDAS certificate chain validation is independent of EBSI TIR and Gaia-X Registry.
- A credential can be validated by both eIDAS and EBSI/Gaia-X if both are configured — all checks must pass.
- `did:elsi` issuers can also be registered in trusted participants/issuers lists if desired.

**7. Dynamic Configuration via Credentials Config Service**
- Note that `eidasConfig` is supported by the [Credentials Config Service](https://github.com/FIWARE/credentials-config-service) (version ≥2.0.0), allowing dynamic per-credential eIDAS configuration without restarts.
- The global `eidas:` settings (LOTL URL, refresh interval, etc.) remain in `server.yaml` and require a restart to change.

**8. Troubleshooting**
- Table of error messages with meanings and resolutions, covering both SD-JWT and `did:elsi` paths:
  - `eidas_validation_requires_sd_jwt_format` — `eidasConfig` enabled but credential is not SD-JWT format
  - `eidas_no_x5c_certificates_available` — SD-JWT credential lacks `x5c` certificates in header
  - `eidas_issuer_not_trusted_by_trust_list` — certificate doesn't chain to any trusted service
  - `eidas_trust_store_required_for_did_elsi` — global eIDAS disabled but `did:elsi` credential received
  - `did_elsi_issuer_validation_failed` — DID suffix doesn't match certificate's `organizationIdentifier`
  - `did_elsi_certificate_not_trusted` — `did:elsi` certificate not trusted by trust list
- Operational tips:
  - Initial trust list fetch may take 30-60 seconds on startup; watch logs for `TrustStore: updated N services for country XX` messages to confirm successful loading.
  - If no trust services are loaded, verify that the LOTL URL is reachable from the verifier's network and that the `countries` filter is not too restrictive.
  - The `maxWorkers` and `fetchTimeout` fields can be tuned for environments with slow or unreliable network access to the EU trust list servers.

#### 1b. Update README.md — Restructure eIDAS sections

**1. Update the Table of Contents** (currently lines 11-32):
- Add entries for the new eIDAS sections under "Trust Anchor Integration":
  - `eIDAS 2.0 Trust List Verification` (new umbrella section)
    - `Global eIDAS Configuration`
    - `SD-JWT Credential Validation`
    - `did:elsi — eIDAS Trust List Verification` (existing, relocated under umbrella)

**2. Add a new `### eIDAS 2.0 Trust List Verification` section** (replacing the current standalone `did:elsi` section at line 531):
- 2-3 paragraph overview: what eIDAS 2.0 trust list verification is, the two verification paths (SD-JWT per-credential and `did:elsi` automatic), and how to enable it.
- Quick-start configuration example (global `eidas:` block + one per-credential `eidasConfig` example).
- Link to `docs/eidas-verification.md` for the full reference.
- Subsection on **Global eIDAS Configuration** with all six config fields in a table.
- Subsection on **SD-JWT Credential Validation** with a minimal config example showing `eidasConfig` inside a credential entry.
- Relocate the existing **did:elsi** content (currently lines 531-593) as a subsection under the new eIDAS section. Update its introductory text to reference the broader eIDAS context. Change its heading level from `###` to `####` since it's now nested.

**3. Update the main Configuration section** (line ~83):
- Add the `eidas:` block to the main configuration YAML example (currently entirely absent from the README YAML — only in commented-out `server.yaml`). Include all six fields with comments.
- Add an `eidasConfig` example to the per-credential section (only `holderVerification` and `credentialStatus` are currently shown inline).

**4. Verify internal links** — Ensure all `#anchor` links in the Table of Contents and cross-references match the new heading structure.

**Files:**
- `docs/eidas-verification.md` (new)
- `README.md` (modified — restructured eIDAS sections, updated ToC, updated config examples)

**Acceptance criteria:**
- `docs/eidas-verification.md` exists and covers all eight topics listed above (introduction, how it works, global config, SD-JWT validation, did:elsi, interaction with other anchors, dynamic config, troubleshooting).
- README.md has an updated Table of Contents with eIDAS entries.
- README.md has a new `eIDAS 2.0 Trust List Verification` umbrella section with overview, quick-start config, and link to `docs/eidas-verification.md`.
- README.md main configuration YAML includes the `eidas:` block with all six fields.
- README.md per-credential example includes `eidasConfig`.
- The existing `did:elsi` section content is preserved and correctly positioned as a subsection within the broader eIDAS context.
- All six global config fields are documented (`enabled`, `lotlUrl`, `refreshInterval`, `countries`, `maxWorkers`, `fetchTimeout`).
- All three per-credential `eidasConfig` fields are documented (`enabled`, `allowedCountries`, `requireQualified`).
- No broken internal links (all `#anchor` references resolve correctly).
- All documentation is written for operators (how to configure and use), not developers (no code-level implementation details).
- No code changes — only Markdown files are modified or created.
