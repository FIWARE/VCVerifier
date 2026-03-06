# Plan: Replace trustbloc libraries with custom implementations

## Context

The VCVerifier project depends on three trustbloc libraries (`did-go`, `vc-go`, `kms-go`) for DID resolution, Verifiable Credential/Presentation handling, proof verification, and SD-JWT parsing. These libraries are no longer well maintained and need to be replaced with custom, in-project implementations. The replacement must be transparent to the rest of the codebase — the existing interfaces and data flow should remain unchanged wherever possible.

**Approach**: All replacements will be custom implementations (no new third-party DID or SD-JWT libraries). The M2M token provider (`tir/tokenProvider.go`) LD-proof creation will be the last step.

## Pre-work: Improve test coverage on trustbloc-dependent code

Before any replacement work begins, add tests for currently untested trustbloc-dependent code paths. This ensures we have a safety net for verifying functional equivalence after replacement.

### Step 0: Add missing tests

**0a.** `verifier/key_resolver.go` — `VdrKeyResolver.ResolvePublicKeyFromDID()`
- Zero test coverage today. Add tests with mocked VDR implementations:
  - Successful resolution with `kid` containing `#` fragment
  - Successful resolution with bare `did:key:...` (no fragment)
  - VDR resolution failure (all VDRs error)
  - Key ID not found in verification methods
  - JWK serialization error
- Create a mock VDR type implementing the `api.VDR` interface from `did-go/vdr/api` for test isolation.

**0b.** `verifier/jwt_verifier.go` — `TrustBlocValidator.ValidateVC()`
- Add tests for all validation modes: `"none"`, `"combined"`, `"jsonLd"`, `"baseContext"`
- Test error return paths when `ValidateCredential()` fails

**0c.** `verifier/presentation_parser.go` — `ConfigurableSdJwtParser.ParseWithSdJwt()`
- Test malformed base64 payload
- Test missing `vp` claim in JWT payload
- Test missing `verifiableCredential` in vp
- Test missing `holder` field
- Test proof check failure path

**0d.** `verifier/presentation_parser.go` — `ConfigurableSdJwtParser.ClaimsToCredential()`
- Test missing `iss` claim
- Test missing `vct` claim
- Test successful conversion with extra custom fields

**0e.** `verifier/trustedissuer.go` — `parseAttribute()` / `parseAttributes()`
- Test base64 decode errors
- Test JSON unmarshal errors
- Test empty attributes array

Files to modify:
- `verifier/key_resolver_test.go` (new or extend)
- `verifier/jwt_verifier_test.go` (extend)
- `verifier/presentation_parser_test.go` (extend)
- `verifier/trustedissuer_test.go` (extend)

Verification: `go test ./verifier/... -v` — all existing + new tests pass.

---

## Step 1: Introduce local credential/presentation types (`common/credential.go`)

Create project-local types that mirror the subset of trustbloc `verifiable` types actually used. These become the new domain types that the rest of the codebase will operate on.

**New file**: `common/credential.go`

Types to define:
```go
type Issuer struct { ID string }
type Subject struct { ID string; CustomFields map[string]interface{} }
type CustomFields map[string]interface{}
type JSONObject = map[string]interface{}

type CredentialContents struct {
    ID      string
    Types   []string
    Issuer  *Issuer
    Subject []Subject
}

type Credential struct { /* internal fields for contents, rawJSON, customFields */ }
// Methods: Contents(), ToRawJSON(), MarshalJSON(), ValidateCredential(opts...)

type Presentation struct {
    ID     string
    Holder string
    /* internal credentials slice */
}
// Methods: Credentials(), AddCredentials(), MarshalJSON()

func CreateCredential(contents CredentialContents, customFields CustomFields) (*Credential, error)
func NewPresentation(opts ...PresentationOpt) (*Presentation, error)
```

At this point, **no production code changes**. Just define the types and write unit tests for them.

Files to create: `common/credential.go`, `common/credential_test.go`

Verification: `go test ./common/... -v`

---

## Step 2: Custom DID resolution (`did/` package)

Create a new `did/` package with resolvers for `did:key`, `did:web`, and `did:jwk`.

**New files**:
- `did/resolver.go` — `Registry` interface + multi-method registry
- `did/document.go` — `Document`, `VerificationMethod`, `DocResolution` types
- `did/did_key.go` — `did:key` resolver (multicodec decode → JWK)
- `did/did_web.go` — `did:web` resolver (HTTP fetch → JSON parse)
- `did/did_jwk.go` — `did:jwk` resolver (base64url decode → JWK)
- `did/resolver_test.go`, `did/did_key_test.go`, `did/did_web_test.go`, `did/did_jwk_test.go`

Key interfaces:
```go
type VDR interface {
    Accept(method string) bool
    Read(did string, opts ...ResolveOption) (*DocResolution, error)
}

type Registry interface {
    Resolve(did string, opts ...ResolveOption) (*DocResolution, error)
}

type VerificationMethod struct {
    ID         string
    Type       string
    Controller string
    Value      []byte
    // JSONWebKey() returns *jose.JSONWebKey
}
```

The `VerificationMethod.JSONWebKey()` method must return a `go-jose` compatible JWK (or our own type that can be serialized to JSON and parsed by `lestrrat-go/jwx`).

Verification: `go test ./did/... -v` with real did:key/did:jwk test vectors and mocked HTTP for did:web.

---

## Step 3: Replace DID resolution in `verifier/jwt_verifier.go`

Switch `JWTVerfificationMethodResolver.ResolveVerificationMethod()` from trustbloc VDR to our custom `did/` package.

**Before** (current):
```go
import "github.com/trustbloc/did-go/method/web"
import "github.com/trustbloc/did-go/method/key"
import "github.com/trustbloc/did-go/method/jwk"
import "github.com/trustbloc/did-go/vdr"
import "github.com/trustbloc/vc-go/vermethod"

registry := vdr.New(vdr.WithVDR(web.New()), vdr.WithVDR(key.New()), vdr.WithVDR(jwk.New()))
didDocument, err := registry.Resolve(expectedProofIssuer)
```

**After**: Use `did.NewRegistry(did.WithVDR(...))` from step 2.

Also replace the `vermethod.VerificationMethod` return type. Define a local proof-checking compatible type.

Files to modify: `verifier/jwt_verifier.go`
Verification: All tests in `verifier/jwt_verifier_test.go` pass + new integration-style tests with the custom resolver.

---

## Step 4: Replace DID resolution in `verifier/key_resolver.go`

Switch `VdrKeyResolver` from `trustbloc/did-go/vdr/api.VDR` to our custom `did.VDR`.

**Before**: `Vdr []api.VDR` field using trustbloc's `did.DocResolution`, `did.VerificationMethod`
**After**: `Vdr []did.VDR` using our `did.DocResolution`, `did.VerificationMethod`

Files to modify: `verifier/key_resolver.go`, `verifier/key_resolver_test.go`
Also update: `verifier/request_object_client.go` (uses same VDR pattern), `openapi/api_api.go` (constructs `VdrKeyResolver`)
Verification: `go test ./verifier/... ./openapi/... -v`

---

## Step 5: Replace DID resolution in `gaiax/gaiaXClient.go`

Switch from trustbloc VDR to custom `did/` package.

Files to modify: `gaiax/gaiaXClient.go`, `gaiax/gaiaXClient_test.go`
Verification: `go test ./gaiax/... -v`

---

## Step 6: Migrate production code to local credential/presentation types

This is the largest step. Replace `trustbloc/vc-go/verifiable` types with `common.Credential`, `common.Presentation`, etc. across all production files.

Migrate in this order (each sub-step compilable):

**6a.** `verifier/presentation_parser.go` — Change `PresentationParser` and `SdJwtParser` interfaces to return `*common.Presentation` / `*common.Credential`. Update `ConfigurablePresentationParser` and `ConfigurableSdJwtParser`. Internally still call trustbloc parsing and convert to local types.

**6b.** `verifier/verifier.go` — Change `Verifier` interface and `CredentialVerifier` to use `*common.Credential`, `*common.Presentation`. Update `ValidationService` interface, `ValidationContext`, `extractCredentialTypes`, `buildInclusion`, `AuthenticationResponse`, `GenerateToken`.

**6c.** `verifier/holder.go`, `verifier/trustedissuer.go`, `verifier/trustedparticipant.go`, `verifier/compliance.go`, `verifier/gaiax.go` — Update `ValidateVC` methods to accept `*common.Credential`.

**6d.** `openapi/api_api.go`, `openapi/api_frontend.go` — Update handler code to use local types.

**6e.** Update all test files to use local types for credential/presentation creation.

At this point, the codebase uses local types everywhere but `presentation_parser.go` still internally calls trustbloc for parsing/proof-checking, and `jwt_verifier.go`'s `TrustBlocValidator` still calls trustbloc for content validation.

Files to modify: All files listed above + their test files.
Verification: `go test ./... -v` — full suite passes.

---

## Step 7: Custom VP/VC parsing (replace `verifiable.ParsePresentation`)

Implement JSON-LD VP parsing in the local types. A VP is a JWT or JSON object containing:
- `type`, `holder`, `verifiableCredential` (array of VCs — each a JWT string or JSON object)
- Proof (JWT signature or LD-proof)

The existing `ConfigurablePresentationParser.ParsePresentation()` currently delegates to `verifiable.ParsePresentation()`. Replace with custom logic:
1. Detect JWT vs JSON-LD format
2. For JWT: decode header+payload, verify signature using our DID resolver + `lestrrat-go/jwx`
3. Extract embedded credentials
4. For each VC: verify its JWT signature similarly
5. Return `*common.Presentation`

Files to modify: `verifier/presentation_parser.go`
New file: `common/vp_parser.go` (or in `common/credential.go`)
Verification: `go test ./verifier/... -v`

---

## Step 8: Custom SD-JWT verification (replace `vc-go/sdjwt/verifier`)

Implement SD-JWT parsing per the SD-JWT specification:
1. Split combined format by `~` separator
2. Verify issuer JWT signature (using lestrrat-go/jwx + our DID resolver)
3. Decode each disclosure (base64url → JSON array `[salt, claim_name, claim_value]`)
4. Reconstruct full claims map from `_sd` digests + disclosures
5. Optionally verify key binding JWT

New file: `common/sdjwt.go`, `common/sdjwt_test.go`
Files to modify: `verifier/presentation_parser.go` — replace `sdv.Parse()` call with custom implementation.
Verification: `go test ./common/... ./verifier/... -v`

---

## Step 9: Custom credential content validation (replace `TrustBlocValidator`)

Replace `verifiable.ValidateCredential()` calls in `jwt_verifier.go`. The validation modes are:
- `"none"`: no-op
- `"combined"`: basic JSON schema + JSON-LD validation
- `"jsonLd"`: JSON-LD only
- `"baseContext"`: validate only base context fields are present

Implement these as methods on `common.Credential`.

Files to modify: `verifier/jwt_verifier.go`, `common/credential.go`
Verification: `go test ./verifier/... ./common/... -v`

---

## Step 10: Custom proof checking (replace trustbloc proof checker)

Replace the `defaults.NewDefaultProofChecker()` and the `ElsiProofChecker` wrapper. The proof checker needs to:
1. For JWT proofs: extract `kid`/issuer from headers, resolve DID → JWK, verify signature using `lestrrat-go/jwx`
2. For did:elsi: delegate to JAdES validator (existing logic stays, just remove trustbloc checker dependency)

This also removes the dependency on `trustbloc/vc-go/proof/checker`, `trustbloc/vc-go/proof/defaults`, `trustbloc/kms-go/doc/jose`.

Files to modify: `verifier/elsi_proof_checker.go`, `verifier/presentation_parser.go`
New file: `common/proof_checker.go`
Verification: `go test ./verifier/... -v`

---

## Step 11: Replace trustbloc in `tir/tokenProvider.go` (M2M — last step)

Replace the LD-proof creation for M2M token signing:
- `verifiable.NewPresentation(WithCredentials(...))` → `common.NewPresentation()`
- `vp.AddLinkedDataProof(LinkedDataProofContext{...})` → custom LD-proof signing using `lestrrat-go/jwx` for JWS creation
- Remove `vc-go/proof/creator`, `vc-go/proof/jwtproofs/ps256`, `vc-go/proof/ldproofs/jsonwebsignature2020`, `kms-go/spi/kms`
- Also replace `verifiable.ParseCredential()` for loading the auth credential from file

Files to modify: `tir/tokenProvider.go`, `tir/tokenProvider_test.go`
Verification: `go test ./tir/... -v`

---

## Step 12: Remove trustbloc dependencies

1. Remove all trustbloc imports from every `.go` file
2. Run `go mod tidy` to remove unused dependencies from `go.mod`/`go.sum`
3. Verify clean build: `go build ./...`
4. Verify all tests: `go test ./... -v`

---

## Verification (end-to-end)

After each step:
```bash
go build ./...      # compiles
go test ./... -v    # all tests pass
```

After step 12 (final):
```bash
go mod tidy
grep -r "trustbloc" --include="*.go" .   # should return nothing
go build ./...
go test ./... -v -coverprofile=profile.cov
```
