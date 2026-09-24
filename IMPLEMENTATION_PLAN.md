# Implementation Plan: Implement the securing mechanism VCDM 2.0 defines for JOSE

## Overview

VCVerifier currently only handles JWT VCs/VPs using the VCDM 1.1 wrapper-claim pattern (a nested `vc` or `vp` JSON object inside the JWT payload). The W3C VC-JOSE-COSE specification (https://www.w3.org/TR/vc-jose-cose/) defines a new securing mechanism where the JWT payload **is** the credential or presentation directly (`typ: vc+jwt` / `vp+jwt`), and introduces `EnvelopedVerifiableCredential` as an embedding format inside VPs. This plan adds support for all three features while keeping the existing JWT-VC 1.1 path unchanged.

## Steps

### Step 1: Add VC-JOSE-COSE constants and `typ` header detection

**Goal:** Introduce the constants, format identifiers, and header-detection utilities that all later steps depend on.

**Files affected:**
- `common/credential.go` — Add new format constants and JWT `typ` header constants.
- `common/credential_test.go` — Tests for the new constants.
- `verifier/presentation_parser.go` — Add a `jwtMediaType()` helper that reads the `typ` header from a JWT (base64-decode the first segment, read `"typ"`) and returns it, plus a predicate `isVCJoseJWT(typ)` / `isVPJoseJWT(typ)`. Also add an `EnvelopedVerifiableCredential` type constant and a `dataURISchemeVCJWT` constant for the `data:application/vc+jwt,` prefix.
- `verifier/presentation_parser_test.go` — Unit tests for `jwtMediaType()` with valid and invalid inputs.

**Details:**

Add to `common/credential.go`:
```go
// FormatVCJWT identifies a vc+jwt Verifiable Credential (VC-JOSE-COSE).
FormatVCJWT = "vc+jwt"

// FormatVPJWT identifies a vp+jwt Verifiable Presentation (VC-JOSE-COSE).
FormatVPJWT = "vp+jwt"
```

Add JWT `typ` header constants:
```go
// JWTTypVCJWT is the JWT typ header value for VC-JOSE-COSE credentials.
JWTTypVCJWT = "vc+jwt"

// JWTTypVPJWT is the JWT typ header value for VC-JOSE-COSE presentations.
JWTTypVPJWT = "vp+jwt"
```

Add the `EnvelopedVerifiableCredential` type constant:
```go
// TypeEnvelopedVerifiableCredential is the JSON-LD type for credentials
// embedded inside a VP via a data: URI (VCDM 2.0 §4.13).
TypeEnvelopedVerifiableCredential = "EnvelopedVerifiableCredential"
```

The `jwtMediaType()` helper in `presentation_parser.go` should base64-decode the first `.`-delimited segment of the token, unmarshal it as JSON, and return the `"typ"` field. It must not fail on tokens without a `typ` header — it simply returns `""`.

**Acceptance criteria:**
- New constants compile and are tested.
- `jwtMediaType()` returns `"vc+jwt"` for a token with that typ, `"vp+jwt"` for vp+jwt, and `""` for a classic JWT-VC/VP token.
- No behavioral changes to existing parsing paths.

---

### Step 2: Implement `vc+jwt` credential parsing

**Goal:** Parse a JWT whose `typ` header is `vc+jwt` into a `common.Credential`. In a `vc+jwt` token, the JWT payload **is** the credential: the top-level claims include `@context`, `type`, `issuer`, `credentialSubject`, `validFrom`, `validUntil`, etc. — there is no wrapping `vc` claim.

**Files affected:**
- `verifier/presentation_parser.go` — Add `vcJwtClaimsToCredential(claims map[string]interface{}) (*common.Credential, error)` and update `parseJWTCredential` to dispatch on `typ`.
- `verifier/presentation_parser_test.go` — Tests for `vcJwtClaimsToCredential` with full claims, missing issuer, missing context, validity dates, and credentialStatus.

**Details:**

`vcJwtClaimsToCredential` maps top-level JWT claims to a credential:
- `iss` → `Issuer.ID` (the standard JWT `iss` claim is redundant with but takes precedence over the `issuer` field in the payload for VC-JOSE-COSE, per §3.3.1 of the spec; if only one is present, use that one; if both are present, use `iss`)
- `jti` → `ID` (same as JWT-VC 1.1)
- `@context` → `Context` (read directly from the payload, not from a `vc` wrapper)
- `type` → `Types` (read directly from the payload)
- `issuer` → fallback for `Issuer.ID` if `iss` is absent; handle both string and `{"id": "..."}` forms
- `credentialSubject` → `Subject` (same extraction as current `jwtClaimsToCredential` for the vc-claim sub-object)
- `credentialStatus` → `Status` (same extraction)
- `nbf`/`iat` → `ValidFrom`, `exp` → `ValidUntil` (same priority as existing)
- Also fall back to `validFrom`/`validUntil` strings in the payload itself (VCDM 2.0 uses these as top-level fields)
- `cnf` → preserved in custom fields for holder binding

Update `parseJWTCredential`:
- After calling `ProofChecker.VerifyJWT` (or `extractJWTPayload`), read the JWT `typ` header.
- If `typ == "vc+jwt"`, call `vcJwtClaimsToCredential` and set format to `FormatVCJWT`.
- Otherwise, fall through to the existing `jwtClaimsToCredential` path (format `FormatJWTVC`).

The `parseJWTCredential` method already parses the JWT and has access to the token bytes before the payload is unmarshalled. The `typ` check should be done by calling `jwtMediaType(tokenBytes)` from Step 1.

**Important:** For `rawJSON`, a `vc+jwt` credential stores the **entire payload** as the raw JSON (since the payload IS the credential), not just a `vc` sub-object. This means `cred.SetRawJSON(claims)` where `claims` is the full payload map.

**Acceptance criteria:**
- A `vc+jwt` token with top-level `@context`, `type`, `issuer`, `credentialSubject` is parsed into a correct `Credential` with format `FormatVCJWT`.
- A classic `jwt_vc` token (no `typ` or `typ != vc+jwt`) still parses via the old path.
- `vcJwtClaimsToCredential` handles both string and object `issuer` forms.
- Validity dates from both JWT standard claims and VCDM 2.0 payload fields are extracted.
- `credentialStatus` is extracted.
- Tests cover success, missing-context, missing-type, issuer-as-object, date handling.

---

### Step 3: Implement `vp+jwt` presentation parsing

**Goal:** Parse a JWT whose `typ` header is `vp+jwt` into a `common.Presentation`. In a `vp+jwt` token, the JWT payload **is** the presentation: the top-level claims include `@context`, `type`, `holder`, `verifiableCredential`, etc. — there is no wrapping `vp` claim.

**Files affected:**
- `verifier/presentation_parser.go` — Update `parseJWTPresentation` to detect `vp+jwt` and read top-level claims. Add a `parseVPJWTPresentation` helper method.
- `verifier/presentation_parser.go` — Update `ParseWithSdJwt` to not claim `vp+jwt` tokens (they don't have a `vp` claim and would currently hit the error path).
- `openapi/api_api.go` — The `tokenToPresentation` dispatch in `extractVpFromToken` may need adjustment to ensure `vp+jwt` tokens reach `ParsePresentation` without being misrouted through the SD-JWT path.
- `verifier/presentation_parser_test.go` — Tests for `vp+jwt` presentation parsing.

**Details:**

In `parseJWTPresentation`:
- After JWS verification (`ProofChecker.VerifyJWTAndReturnKey`), read the `typ` header via `jwtMediaType(tokenBytes)`.
- If `typ == "vp+jwt"`, unmarshal the payload and read `verifiableCredential`, `holder`, `@context`, `type` directly from top-level claims (no `vp` wrapper).
- The `iss` claim maps to `Holder` (the presenter is the signer).
- Iterate `verifiableCredential` array entries as before: strings are JWT VCs (either `jwt_vc` or `vc+jwt` — `parseJWTCredential` from Step 2 handles both transparently), maps are JSON-LD VCs.
- If `typ != "vp+jwt"` (or absent), fall through to the existing path that reads the `vp` claim.

In `tokenToPresentation` (openapi/api_api.go):
- The SD-JWT parser's `ParseWithSdJwt` tries to read a `vp` claim and fails when it's absent. A `vp+jwt` token would currently fail there, fall through, and reach `ParsePresentation`. Verify that this fallthrough works correctly by adding a test for a `vp+jwt` token going through `tokenToPresentation`. If the SD-JWT parser returns an error other than `ErrorPresentationNoCredentials` for a `vp+jwt` token (e.g., `ErrorInvalidProof`), short-circuit the fallthrough by checking the JWT `typ` before trying the SD-JWT path.

**Acceptance criteria:**
- A `vp+jwt` token with top-level `verifiableCredential`, `holder`, `@context`, `type` is parsed into a correct `Presentation`.
- Embedded `vc+jwt` credentials inside a `vp+jwt` presentation are parsed correctly.
- Embedded `jwt_vc` (old format) credentials inside a `vp+jwt` presentation still work.
- Embedded JSON-LD credentials inside a `vp+jwt` presentation still work.
- Holder key from JWS verification is set on the presentation.
- A classic JWT VP (no `typ` or `typ != vp+jwt`) still parses via the old `vp`-claim path.
- VP signature verification in `verifyVPSignatureIfRequired` works for `vp+jwt` (the signature was already verified during parsing, same as classic JWT VPs).
- Tests cover: `vp+jwt` with vc+jwt credentials, `vp+jwt` with jwt_vc credentials, `vp+jwt` with JSON-LD credentials, missing verifiableCredential, holder from iss, dispatch from `tokenToPresentation`.

---

### Step 4: Implement `EnvelopedVerifiableCredential` support

**Goal:** Recognize credentials embedded in a VP's `verifiableCredential` array as `EnvelopedVerifiableCredential` objects — JSON-LD objects with `"type": "EnvelopedVerifiableCredential"` and an `"id"` that is a `data:application/vc+jwt,<jwt>` URI. Extract the JWT from the data URI and parse it as a `vc+jwt` credential.

**Files affected:**
- `verifier/presentation_parser.go` — In both `parseJWTPresentation` and `parseJSONLDPresentation`, when iterating `verifiableCredential` entries of type `map[string]interface{}`, check if the entry is an `EnvelopedVerifiableCredential` before falling through to JSON-LD credential parsing. Add `parseEnvelopedCredential(vcMap map[string]interface{}) (*common.Credential, bool, error)`.
- `verifier/presentation_parser_test.go` — Tests for enveloped credential parsing.

**Details:**

Add `isEnvelopedCredential(vcMap map[string]interface{}) bool`:
- Check if `type` (or the single-valued type) is `"EnvelopedVerifiableCredential"`.
- Check if `id` starts with `"data:application/vc+jwt,"`.

Add `parseEnvelopedCredential(vcMap map[string]interface{}) (*common.Credential, bool, error)`:
- If `!isEnvelopedCredential(vcMap)`, return `nil, false, nil` (not enveloped, caller should try other parsers).
- Extract the JWT string after the `"data:application/vc+jwt,"` prefix from the `id` field.
- Call `cpp.parseJWTCredential([]byte(jwtString))` to parse and verify the credential. This reuses the Step 2 path, which handles both `vc+jwt` and classic `jwt_vc` by detecting the `typ` header.
- Return the credential, `true`, and any error.

Update the credential iteration in `parseJWTPresentation` (the `case map[string]interface{}:` branch):
```go
case map[string]interface{}:
    // Try EnvelopedVerifiableCredential first.
    if cred, isEnveloped, err := cpp.parseEnvelopedCredential(v); isEnveloped {
        if err != nil {
            return nil, err
        }
        // cnf binding check...
        pres.AddCredentials(cred)
        continue
    }
    // Fall through to JSON-LD credential parsing.
    cred, err := cpp.parseAndVerifyJSONLDCredential(v, pres.Holder)
    ...
```

Apply the same pattern in `parseJSONLDPresentation` and `parseVPJWTPresentation` (if Step 3 creates a separate method).

**Edge cases to handle:**
- The data URI must not have parameters (e.g., `data:application/vc+jwt;base64,...` is not valid for VC-JOSE-COSE — the JWT is placed directly, not base64-encoded again).
- The `@context` field of the enveloped object is ignored for parsing purposes (it's just the VC 2.0 context for JSON-LD processing).
- Holder binding: the extracted JWT credential gets the same cnf binding check as any other JWT credential in the VP.

**Acceptance criteria:**
- An `EnvelopedVerifiableCredential` with a valid `data:application/vc+jwt,<jwt>` id is extracted and parsed as a `vc+jwt` credential.
- The credential undergoes the same signature verification and content validation as direct JWT credentials.
- An enveloped credential inside a JSON-LD VP works (JSON-LD VP with enveloped JWT VCs).
- An enveloped credential inside a `vp+jwt` VP works.
- An enveloped credential inside a classic JWT VP works.
- Non-enveloped JSON-LD credentials still parse normally (no regression).
- Tests cover: valid enveloped credential, invalid data URI, missing type, enveloped in each VP type.

---

### Step 5: Update VC content validation and status-list parsing for `vc+jwt` format

**Goal:** Ensure the VC content validation pipeline (`jwt_verifier.go`) and the status-list credential parser correctly handle `vc+jwt`-format credentials.

**Files affected:**
- `verifier/jwt_verifier.go` — Update `isVersionedDataModelCredential` to include `FormatVCJWT` as a versioned credential format (it carries `@context`, unlike SD-JWT).
- `verifier/credential_status_client.go` — Update `parseStatusListCredentialBody` / `parseUnsignedJWTCredential` to handle `vc+jwt` status list credentials (where the JWT payload has top-level `@context`, `type`, `credentialSubject` instead of a `vc` wrapper).
- `verifier/jwt_verifier_test.go` — Tests for the version gate with `vc+jwt` credentials.
- `verifier/credential_status_client_test.go` — Tests for `vc+jwt` status list credential parsing.

**Details:**

**Version gate:**
`isVersionedDataModelCredential` currently exempts only `FormatSDJWT`. A `vc+jwt` credential carries `@context` and participates in the W3C data model versioning, so it should go through the version gate. No code change needed if `FormatVCJWT != FormatSDJWT` (already true). Verify with a test.

**Status-list parsing:**
`parseUnsignedJWTCredential` (called at line 326 of `credential_status_client.go`) calls `jwtClaimsToCredential`, which reads the `vc` claim. A VC-JOSE-COSE status-list credential (`typ: vc+jwt`) would have top-level claims. Update `parseUnsignedJWTCredential` to detect the `typ` header and dispatch to `vcJwtClaimsToCredential` (from Step 2) when `typ == "vc+jwt"`, otherwise fall through to the existing `jwtClaimsToCredential`.

**Acceptance criteria:**
- A `vc+jwt` credential is subject to the VC Data Model version gate (context must declare 2.0).
- A `vc+jwt` status list credential fetched by the status client is correctly parsed.
- A classic `jwt_vc` status list credential still parses correctly (no regression).
- Tests verify the version gate behavior for `FormatVCJWT` and `FormatVPJWT`.

---

### Step 6: Update documentation and remove "Known Gaps" entries

**Goal:** Update all documentation files that reference VC-JOSE-COSE as unsupported, add release notes for the new feature, and update the OpenAPI spec.

**Files affected:**
- `CLAUDE.md` — Remove the "VC-JOSE-COSE is not supported" and "EnvelopedVerifiableCredential not recognized" bullet points from Known Gaps. Add entries to Key Dependencies or Architecture sections if new patterns were introduced.
- `docs/vc-data-model-versions.md` — Update the compatibility table: mark `vc+jwt` / `vp+jwt` and `EnvelopedVerifiableCredential` as ✅. Update the "Not supported" section to remove these entries.
- `RELEASE_NOTES_VC_DATA_MODEL_2.md` — Move `vc+jwt` / `vp+jwt` and `EnvelopedVerifiableCredential` from the "Not supported" section to the "Supported" section.
- `api/api.yaml` — Update the `VerifiablePresentation` and `VerifiableCredential` schema descriptions to note that `vp+jwt` and `vc+jwt` are now supported. Remove the "not supported" disclaimers.
- `common/credential.go` — Ensure the doc comments on `FormatVCJWT` / `FormatVPJWT` reference the VC-JOSE-COSE spec.

**Acceptance criteria:**
- No documentation references VC-JOSE-COSE or EnvelopedVerifiableCredential as unsupported.
- The VC Data Model compatibility table is updated.
- The OpenAPI spec descriptions are accurate.
- `go test ./... -v` passes (documentation changes should not break anything, but verify).
