# Integration test

An integration test framework should be integrated as part of this project. It should use a full instance of the VCVerifier, with all other components being mocked or test-doubles/implementations being used. It should at least test the following flows.

## Flows

The following flows need to be tested. They should be tested for case:

### Success

- multiple JWT-VCs requested and presented
- One JWT-VC requested and presented
- multiple SD-JWT requested and presented
- One SD-JWT requested and presented
- issuer uses did:key as id
- issuer uses did:web as id
- correctly holder-bound credentials(cnf) presented
- correctly claim-based holder-bound credentials presented

### Failure

- wrong credentials presented
- credentials without the requested claims presented
- invalid credentials presented
- invalid signed presentation presented
- invalid cnf presented
- invalid claim-based holder binding presented

### Authorization flows to test

#### Frontend v2

- (Test)Frontend-Client initiates at /api/v1/authorization
- returns redirect for /api/v2/loginQR
- follows redirect, get QR
- scans QR, starts Cross-Device Flow
- handles authentication request:
    - byReference
    - byValue
- anwers request
- verifier redirects to application
- applications get JWT

#### Deeplink

- Client initiates at /api/v1/authorization
- returns redirect to openid-deeplink, to fullfil the same-device flow
- Test-Client follows redirect
- handles authentication request:
    - byReference
    - byValue
- anwers request
- client follows redirect, get JWT

## Implementation plan

### Analysis

#### Black-box approach

The integration tests treat the VCVerifier as an opaque HTTP service. The test suite:

1. **Builds** the verifier binary via `go build`
2. **Generates** a YAML config file at test setup time, pointing to mock HTTP servers
3. **Launches** the binary as a subprocess with `CONFIG_FILE=<path>` environment variable
4. **Interacts** with it purely over HTTP — no Go imports from any verifier-internal package
5. **Tears down** the process after each test group

This ensures the tests validate the actual shipped artifact and cannot accidentally depend on internal state, unexported functions, or in-process shortcuts. No source code changes to the verifier are required.

#### External dependencies — mock HTTP servers

The test harness starts lightweight `httptest.Server` instances before launching the verifier. Their URLs are injected into the generated YAML config.

- **TIR (Trusted Issuers Registry)** — mock server at a random port, handles `GET /v4/issuers/<did>` returning `TrustedIssuer` JSON or 404. Also handles `GET /v4/issuers` for IsTrustedParticipant calls (returns 200 if DID is trusted, 404 otherwise).
- **did:web resolution** — mock server serving `GET /.well-known/did.json` for the did:web issuer test case. The `did:web` DID is derived from the mock server's `localhost:<port>` address.
- (Gaia-X and JAdES mocks are not needed for the defined test flows — they can be added later.)

#### Config generation with DCQL

Each test group generates a `server.yaml` in a temp directory. Service scopes use **DCQL** (Digital Credentials Query Language) to define which credentials the verifier requests. The verifier embeds the DCQL query as `dcql_query` in the request object JWT (byValue/byReference modes). The wallet (test client) responds with a `vp_token` whose format depends on the DCQL query structure.

Example generated config:

```yaml
server:
  port: <free-port>
  host: "http://localhost:<free-port>"
  templateDir: "views/"
  staticDir: "views/static/"
logging:
  level: "DEBUG"
  jsonLogging: true
  logRequests: true
verifier:
  did: "did:key:<generated-verifier-did>"
  tirAddress: "http://localhost:<tir-mock-port>"
  validationMode: "none"
  keyAlgorithm: "ES256"
  generateKey: true
  sessionExpiry: 30
  jwtExpiration: 30
  supportedModes: ["byValue", "byReference"]
  clientIdentification:
    id: "did:key:<generated-verifier-did>"
    keyPath: "<path-to-generated-pem>"
    requestKeyAlgorithm: "ES256"
m2m:
  authEnabled: false
configRepo:
  services:
    - id: "<service-id>"
      defaultOidcScope: "<scope>"
      authorizationType: "<DEEPLINK|FRONTEND_V2>"
      oidcScopes:
        <scope>:
          credentials:
            - type: "<credential-type>"
              trustedIssuersLists:
                - "http://localhost:<tir-mock-port>"
              holderVerification:
                enabled: <true|false>
                claim: "<claim-path>"
          dcql:
            credentials:
              - id: "<query-id>"
                format: "jwt_vc_json"
                meta:
                  vct_values:
                    - "<credential-type>"
                claims:
                  - path: ["$.vc.credentialSubject.someField"]
```

For SD-JWT credential types, the `format` field in the DCQL query is `dc+sd-jwt` instead of `jwt_vc_json`.

The `clientIdentification.keyPath` points to a PEM file generated at test setup time (ECDSA P-256 key), which the verifier uses for signing request objects in byValue/byReference modes.

#### DCQL response format

When the verifier's request object contains a `dcql_query`, the wallet responds with a `vp_token` that is a **JSON map** keyed by credential query IDs from the DCQL query. Each value is a VP JWT (or SD-JWT) answering that query:

```json
{
  "query-id-1": "<vp-jwt-for-query-1>",
  "query-id-2": "<vp-jwt-for-query-2>"
}
```

The verifier's `getPresentationFromQuery` function parses this map, extracts each VP, and merges all credentials into a single presentation for validation.

For a **single credential query**, the map has one entry. For **multiple credential queries**, each query ID maps to its own VP JWT. The test helpers must construct this map format and base64-encode or JSON-encode it as the `vp_token` form value.

#### Test credential creation

The test helpers create real, cryptographically signed VCs and VPs using the same libraries the verifier depends on (trustbloc, lestrrat-go/jwx). These helpers are in a separate Go module under `integration_test/` to avoid polluting the main module's dependencies:

- **did:key identities**: Generate ECDSA P-256 key pairs, derive `did:key` DIDs using `trustbloc/did-go/method/key` Creator
- **JWT-VC signing**: Build JWT claims for a VC, sign with `jws.Sign()` using the issuer's private key, `kid` header set to the issuer's DID key ID
- **VP signing**: Build JWT claims wrapping VC JWTs in the `vp` claim, sign with the holder's private key
- **SD-JWT**: Construct SD-JWT strings (issuer JWT + disclosures + optional key binding JWT) following RFC 9449
- **DCQL vp_token map**: Build a `map[string]string` mapping DCQL credential query IDs to VP JWT strings, then JSON-encode it for the `vp_token` form value
- **did:web DID documents**: Build a DID document JSON containing the identity's public key, served by the did:web mock server

#### Process lifecycle management

```
TestMain (or suite setup)
  ├── go build -o <tmpdir>/vcverifier .
  │
  For each test group:
  ├── Start mock TIR server (httptest.Server)
  ├── Start mock did:web server if needed (httptest.Server)
  ├── Generate signing key PEM file
  ├── Generate server.yaml → <tmpdir>/server.yaml
  ├── Launch: CONFIG_FILE=<tmpdir>/server.yaml <tmpdir>/vcverifier
  ├── Wait for health check: poll GET /health until 200 (with timeout)
  ├── Run test cases against http://localhost:<port>
  ├── Send SIGTERM to verifier process
  └── Clean up temp files and mock servers
```

The verifier process is started fresh for each test group (not each individual test case) to keep test execution fast. Test groups that need different configurations (e.g., different `authorizationType`, different holder verification settings) each get their own process.

#### Health check wait

After launching the subprocess, poll `GET /health` with a short interval (100ms) and a timeout (10s). If the process exits before becoming healthy, capture stderr for diagnostics.

### Build tag

All integration test files use `//go:build integration` so they don't run during `go test ./...`. Run explicitly:

```bash
go test -tags integration ./integration_test/... -v -count=1
```

The `-count=1` disables test caching since integration tests depend on external processes.

### Package structure

```
integration_test/
    go.mod                 -- separate Go module (depends on trustbloc, jwx for credential creation)
    go.sum
    helpers/
        identity.go        -- TestIdentity struct, GenerateDidKeyIdentity(), GenerateDidWebIdentity()
        credentials.go     -- CreateJWTVC(), CreateVPToken(), CreateSDJWT(), CreateDCQLResponse()
        process.go         -- VerifierProcess: build, launch, health-wait, shutdown
        tir_mock.go        -- Mock TIR httptest.Server returning TrustedIssuer JSON
        did_web_mock.go    -- Mock did:web httptest.Server serving /.well-known/did.json
        config.go          -- YAML config generation with DCQL, free port allocation, PEM key file generation
    m2m_test.go            -- M2M success + failure flow tests (vp_token grant type)
    frontend_v2_test.go    -- Frontend v2 cross-device flow tests
    deeplink_test.go       -- Deeplink same-device flow tests
```

Using a separate `go.mod` ensures:
- The test helper dependencies (trustbloc for did:key creation, jwx for signing) don't leak into the main module if they diverge
- The integration tests are clearly decoupled from the verifier source
- `go test ./...` from the project root naturally skips them (separate module)

### Steps

#### Step 1: Test infrastructure and helpers

**Goal**: The build/launch/teardown harness and credential creation helpers that all tests depend on.

`helpers/process.go`:
- `BuildVerifier(projectRoot string) (binaryPath string, err error)` — runs `go build -o <tmpdir>/vcverifier .` in the project root
- `VerifierProcess` struct: holds `cmd *exec.Cmd`, `Port int`, `BaseURL string`, `configDir string`
- `StartVerifier(configYAML string, projectRoot string, binaryPath string) (*VerifierProcess, error)` — writes config to temp file, starts binary with `CONFIG_FILE` env var, polls `/health`
- `(*VerifierProcess) Stop()` — sends SIGTERM, waits with timeout, kills if needed, cleans temp dir
- `waitForHealthy(baseURL string, timeout time.Duration) error` — polls `GET /health`
- `GetFreePort() (int, error)` — binds to `:0`, reads the assigned port, closes

`helpers/config.go`:
- `ConfigBuilder` struct with fluent API for constructing the YAML config:
  - `NewConfigBuilder(verifierPort int, tirURL string) *ConfigBuilder`
  - `WithService(id, scope, authzType string) *ConfigBuilder`
  - `WithCredential(serviceId, scope, credType, tirURL string) *ConfigBuilder`
  - `WithHolderVerification(serviceId, scope, credType, claim string) *ConfigBuilder`
  - `WithDCQL(serviceId, scope string, dcql DCQLConfig) *ConfigBuilder`
  - `WithSigningKey(keyPath string) *ConfigBuilder`
  - `Build() string` — returns YAML string
- `DCQLConfig` struct: mirrors the DCQL YAML structure for config generation
  - `CredentialQuery` struct: `Id string`, `Format string`, `Meta *MetaConfig`, `Claims []ClaimConfig`
  - Helper: `NewJWTVCQuery(id, credType string) CredentialQuery`
  - Helper: `NewSDJWTQuery(id, vctValue string) CredentialQuery`
- `GenerateSigningKeyPEM(dir string) (keyPath string, err error)` — generates ECDSA P-256 key, writes PEM to file
- `GenerateVerifierDID() (did string, err error)` — generates a did:key for the verifier's identity

`helpers/identity.go`:
- `TestIdentity` struct: `PrivateKey crypto.Signer`, `PublicKeyJWK jwk.Key`, `DID string`, `KeyID string`
- `GenerateDidKeyIdentity() (*TestIdentity, error)` — ECDSA P-256 key → did:key DID via trustbloc Creator
- `GenerateDidWebIdentity(host string) (*TestIdentity, error)` — ECDSA P-256 key → did:web DID derived from host

`helpers/credentials.go`:
- `CreateJWTVC(issuer *TestIdentity, credType string, subject map[string]interface{}) (string, error)` — signed JWT-VC
- `CreateJWTVCWithHolder(issuer *TestIdentity, credType string, subject map[string]interface{}, holderDID string) (string, error)` — JWT-VC with claim-based holder binding (adds holder DID into credentialSubject)
- `CreateJWTVCWithCnf(issuer *TestIdentity, credType string, subject map[string]interface{}, holderJWK jwk.Key) (string, error)` — JWT-VC with `cnf` holder binding (adds `cnf.jwk` to the credential)
- `CreateVPToken(holder *TestIdentity, nonce string, audience string, vcJWTs ...string) (string, error)` — signed VP JWT wrapping one or more VC JWTs
- `CreateSDJWT(issuer *TestIdentity, vct string, claims map[string]interface{}, disclosedClaims []string) (string, error)` — SD-JWT credential string
- `CreateVPWithSDJWT(holder *TestIdentity, nonce string, audience string, sdJWTs ...string) (string, error)` — VP JWT containing SD-JWT credentials
- `CreateDCQLResponse(queryResponses map[string]string) (string, error)` — takes a map of DCQL credential query ID → VP JWT string, JSON-encodes it into the `vp_token` value expected by the verifier

`helpers/tir_mock.go`:
- `MockTIR` struct: maps DID → `TrustedIssuer` (struct defined locally in test helpers, mirroring the TIR JSON schema)
- `TrustedIssuer` struct: `Did string`, `Attributes []IssuerAttribute`
- `IssuerAttribute` struct: `Hash string`, `Body string` (base64-encoded JSON of credential config), `IssuerType string`, `Tao string`, `RootTao string`
- `NewMockTIR(issuers map[string]TrustedIssuer) *httptest.Server` — returns running mock
- Handles:
  - `GET /v4/issuers/<did>` → 200 with TrustedIssuer JSON, or 404
  - `GET /v4/issuers?page=<n>&size=<s>` → paginated list (for IsTrustedParticipant)
- `BuildIssuerAttribute(credentialType string, claims []string) IssuerAttribute` — helper to build properly base64-encoded attribute bodies

`helpers/did_web_mock.go`:
- `NewDidWebServer(identity *TestIdentity) *httptest.Server` — serves `GET /.well-known/did.json` with a DID document containing the identity's public key in JWK format

#### Step 2: M2M flow tests — success cases

**Goal**: Test the VP-token-to-JWT exchange via `POST /services/:service_id/token` (grant_type=vp_token). This exercises the full credential validation pipeline without session management.

**File**: `integration_test/m2m_test.go`

Table-driven parameterized tests. Each test case gets a fresh verifier process only if the config differs from the previous one (optimization: group cases that share the same config).

**DCQL config per test case**: Each test case defines its DCQL query in the service config. For single-credential tests, one `CredentialQuery` entry. For multi-credential tests, multiple `CredentialQuery` entries. The test client builds a DCQL response map matching the query IDs.

**Test cases**:

| Test name | Format | Count | Issuer DID | Holder binding | DCQL query |
|---|---|---|---|---|---|
| One JWT-VC with did:key issuer | JWT-VC | 1 | did:key | none | 1 query: `jwt_vc_json`, vct `CustomerCredential` |
| Multiple JWT-VCs with did:key issuer | JWT-VC | 2 | did:key | none | 2 queries: `jwt_vc_json`, vct `TypeA` + `TypeB` |
| One SD-JWT with did:key issuer | SD-JWT | 1 | did:key | none | 1 query: `dc+sd-jwt`, vct `CustomerCredential` |
| Multiple SD-JWTs with did:key issuer | SD-JWT | 2 | did:key | none | 2 queries: `dc+sd-jwt`, vct `TypeA` + `TypeB` |
| JWT-VC with did:web issuer | JWT-VC | 1 | did:web | none | 1 query: `jwt_vc_json`, vct `CustomerCredential` |
| JWT-VC with cnf holder binding | JWT-VC | 1 | did:key | cnf | 1 query: `jwt_vc_json`, vct `CustomerCredential` |
| JWT-VC with claim-based holder binding | JWT-VC | 1 | did:key | claim | 1 query: `jwt_vc_json`, vct `CustomerCredential` |

**Test pattern** (each case):
1. Generate issuer + holder identities (did:key or did:web)
2. Start mock TIR with trusted issuer entries allowing the credential type
3. If did:web: start mock did:web server
4. Generate verifier config YAML with DCQL query matching the credential format and type
5. Start verifier process
6. Create signed VCs (JWT-VC or SD-JWT)
7. Create signed VP(s) containing the VCs
8. Build DCQL response map: `{"<query-id>": "<vp-jwt>", ...}` and JSON-encode it via `CreateDCQLResponse()`
9. `POST http://localhost:<port>/services/{serviceId}/token` with form body `grant_type=vp_token&vp_token=<dcql-response>&scope=<scope>`
10. Assert HTTP 200, parse JSON response body as `{"token_type":"Bearer","access_token":"...","id_token":"...","expires_in":...}`
11. Verify the returned JWT: `GET http://localhost:<port>/.well-known/jwks`, parse JWKS, verify JWT signature, check claims
12. Stop verifier, close mocks

#### Step 3: M2M flow tests — failure cases

**Goal**: Test all failure scenarios for the VP-token exchange.

**File**: `integration_test/m2m_failure_test.go`

**Test cases**:

| Test name | Setup | Expected |
|---|---|---|
| Wrong credential type | DCQL requests `TypeA`, VP contains `TypeB` | 400 |
| Missing required claims | VC lacks claims that TIR requires in its attribute body | 400 |
| Untrusted issuer | VC signed by issuer whose DID is not in mock TIR | 400 |
| Invalid VP signature | VP JWT signed with a different key than the holder's | 400 |
| Invalid cnf binding | VC has cnf.jwk for holder A, but VP is signed by holder B | 400 |
| Invalid claim-based holder binding | VC's holder claim contains DID-A, but VP is signed by DID-B | 400 |

**Test pattern**: Same as Step 2, but the DCQL response map contains VPs with the invalid credentials. Assert non-200 status code and verify the error response body.

#### Step 4: Frontend v2 flow tests (cross-device)

**Goal**: End-to-end test of the frontend v2 cross-device flow, treating the verifier as a black box. Verifies that the `dcql_query` claim is present in the request object and that DCQL-formatted responses are accepted.

**File**: `integration_test/frontend_v2_test.go`

Configure the service with `authorizationType: "FRONTEND_V2"` and a DCQL query in the generated YAML.

Two sub-tests: `byReference` and `byValue`. Use an HTTP client configured with `CheckRedirect` returning `http.ErrUseLastResponse` to capture redirects without following them.

**Test flow (byReference)**:
1. `GET /api/v1/authorization?client_id=<svcId>&response_type=code&scope=<scope>&state=<state>&redirect_uri=<uri>&nonce=<nonce>`
2. Assert 302, parse Location header → confirm it points to `/api/v2/loginQR?state=...&client_id=...&redirect_uri=...&scope=...&nonce=...&request_mode=byReference`
3. `GET /api/v2/loginQR?<params>` — returns HTML page containing the `openid4vp://` URL
4. Parse the HTML response to extract the `openid4vp://` authentication request URL (regex or string scan for the protocol scheme)
5. Parse the `openid4vp://` URL → extract `request_uri` query parameter
6. `GET /api/v1/request/<id>` — fetch the request object (JWT string in response body)
7. Decode the request object JWT (without verification — it's the verifier's own JWT) to extract `response_uri`, `state`, `nonce`, and `dcql_query`
8. Assert `dcql_query` is present and matches the configured DCQL query structure (correct credential query IDs, format, vct_values)
9. Create valid VCs matching the DCQL query
10. Build DCQL response map keyed by the query IDs from step 7
11. Open WebSocket connection to `ws://localhost:<port>/ws?state=<state>` (using `gorilla/websocket` or `nhooyr.io/websocket`)
12. `POST /api/v1/authentication_response` with form body `state=<state>&vp_token=<dcql-response>`
13. Assert HTTP 200
14. Read WebSocket message — parse JSON to extract `redirectUrl` containing the authorization `code`
15. `POST /token` with form body `grant_type=authorization_code&code=<code>&redirect_uri=<uri>`
16. Assert HTTP 200 with valid JWT in response

**Test flow (byValue)**: Same but the request object JWT is embedded in the `openid4vp://` URL query parameter `request` instead of fetched by reference. Skip step 6; decode the JWT from the URL directly.

**Note on the QR/HTML step**: Since this is a black-box test, we must work with the HTML response from `/api/v2/loginQR`. The `openid4vp://` URL is embedded in the page for QR code rendering. Extracting it via string matching on the HTML is acceptable for integration tests.

#### Step 5: Deeplink flow tests (same-device)

**Goal**: End-to-end test of the deeplink/same-device flow. Same DCQL verification as Frontend v2 but using the same-device redirect pattern.

**File**: `integration_test/deeplink_test.go`

Configure the service with `authorizationType: "DEEPLINK"` and a DCQL query in the generated YAML.

Two sub-tests: `byReference` and `byValue`. The deeplink flow uses byReference by default from the authorization endpoint.

**Test flow (byReference)**:
1. `GET /api/v1/authorization?client_id=<svcId>&response_type=code&scope=<scope>&state=<state>&redirect_uri=<uri>&nonce=<nonce>`
2. Assert 302, parse Location header → confirm it starts with `openid4vp://`
3. Parse the `openid4vp://` URL → extract `request_uri` query parameter
4. `GET /api/v1/request/<id>` — fetch request object JWT
5. Decode JWT → extract `response_uri`, `state`, `nonce`, and `dcql_query`
6. Assert `dcql_query` is present with expected query structure
7. Create valid VCs matching the DCQL query, build DCQL response map
8. `POST <response_uri>` (= `http://localhost:<port>/api/v1/authentication_response`) with form body `state=<state>&vp_token=<dcql-response>`
9. Assert 302, parse Location header → extract `code` and `state` query parameters from the redirect URL
10. `POST /token` with form body `grant_type=authorization_code&code=<code>&redirect_uri=<uri>`
11. Assert HTTP 200 with valid JWT in response

**Test flow (byValue)**: Same but the `openid4vp://` URL from step 2 contains the request object JWT directly in a `request` parameter. Skip step 4.

#### Step 6: Cross-cutting concerns and edge cases

**Goal**: Additional tests not specific to one flow.

**File**: `integration_test/endpoints_test.go`

These tests run against a single verifier process with a basic config (including a DCQL query).

- `GET /.well-known/jwks` → 200, response is valid JWKS JSON with at least one key
- `GET /services/<id>/.well-known/openid-configuration` → 200, response contains `issuer`, `token_endpoint`, `jwks_uri`
- `GET /health` → 200
- `POST /token` without `grant_type` → 400
- `POST /token` with `grant_type=unsupported` → 400
- `GET /api/v1/authorization` without `client_id` → 400
- `GET /api/v1/authorization` without `scope` → 400
- `GET /api/v1/authorization` without `state` → 400

### Test execution summary

```bash
# Build + run all integration tests
go test -tags integration ./integration_test/... -v -count=1

# Run only M2M tests
go test -tags integration ./integration_test/... -v -count=1 -run TestM2M

# Run only deeplink tests
go test -tags integration ./integration_test/... -v -count=1 -run TestDeeplink
```

### Test matrix summary

The success/failure credential variations (Step 2 + 3) are tested via the M2M flow — this directly exercises the full credential validation pipeline without session management overhead. The authorization flow tests (Step 4 + 5) additionally verify that:
- The request object JWT contains a `dcql_query` claim matching the service config
- The test client can parse the DCQL query, construct a matching DCQL response map, and complete the flow

All tests use DCQL for credential query configuration. The `vp_token` is always submitted in the DCQL response map format (`{"<query-id>": "<vp-jwt>"}`). All tests are true black-box: they only interact with the verifier over HTTP and only depend on its public configuration contract (server.yaml + CONFIG_FILE env var).
