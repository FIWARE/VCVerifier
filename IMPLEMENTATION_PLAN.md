# Implementation Plan: Implement the securing mechanism VCDM 2.0 defines for JOSE

## Overview

VCVerifier currently only handles JWT VCs/VPs using the VCDM 1.1 wrapper-claim pattern (a nested `vc` or `vp` JSON object inside the JWT payload). The W3C VC-JOSE-COSE specification (https://www.w3.org/TR/vc-jose-cose/) defines a new securing mechanism where the JWT payload **is** the credential or presentation directly (`typ: vc+jwt` / `vp+jwt`), and introduces `EnvelopedVerifiableCredential` as an embedding format inside VPs. This plan adds support for all three features while keeping the existing JWT-VC 1.1 path unchanged.

## Supported Credential and Presentation Formats

This section documents all credential and presentation formats supported by VCVerifier — both the existing ones and the new VC-JOSE-COSE formats this plan adds. Examples use the VC Data Model 1.1 context (`https://www.w3.org/2018/credentials/v1`) for existing formats and the VC Data Model 2.0 context (`https://www.w3.org/ns/credentials/v2`) for the new JOSE formats.

### Credential Formats

#### 1. JWT VC (`jwt_vc`) — existing

A JWT-encoded Verifiable Credential where the JWT payload wraps the credential inside a `vc` claim. The issuer, dates, and subject are duplicated at the JWT top level using standard JWT claims (`iss`, `nbf`, `exp`, `sub`).

**JOSE header:**
```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "did:web:issuer.example.com#key-1"
}
```

**JWT payload:**
```json
{
  "iss": "did:web:issuer.example.com",
  "sub": "did:web:subject.example.com",
  "nbf": 1700000000,
  "exp": 1800000000,
  "iat": 1700000000,
  "jti": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential"],
    "credentialSubject": {
      "id": "did:web:subject.example.com",
      "name": "Alice"
    }
  }
}
```

**Key characteristics:**
- Format constant: `common.FormatJWTVC` (`"jwt_vc"`)
- The `vc` claim holds the JSON-LD credential structure without `issuer`, `issuanceDate`, or `expirationDate` — those are represented by `iss`, `nbf`, and `exp` at the JWT level.
- Parsed by `jwtClaimsToCredential` in `verifier/presentation_parser.go`.

#### 2. JSON-LD VC (`ldp_vc`) — existing

A JSON-LD Verifiable Credential secured with a Linked Data Proof (`JsonWebSignature2020`). The credential is a JSON-LD document with a `proof` object containing a detached JWS signature.

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "type": ["VerifiableCredential"],
  "id": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "issuer": "did:web:issuer.example.com",
  "issuanceDate": "2024-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:web:subject.example.com",
    "name": "Alice"
  },
  "proof": {
    "type": "JsonWebSignature2020",
    "created": "2024-01-01T00:00:00Z",
    "verificationMethod": "did:web:issuer.example.com#key-1",
    "proofPurpose": "assertionMethod",
    "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature"
  }
}
```

**Key characteristics:**
- Format constant: `common.FormatLDPVC` (`"ldp_vc"`)
- Uses URDNA2015 canonicalization for signature verification.
- The `proof.jws` is a detached JWS with `b64=false` (payload not base64-encoded).
- VC Data Model 1.1 uses `issuanceDate`/`expirationDate`; VC Data Model 2.0 uses `validFrom`/`validUntil`.
- Parsed by `parseAndVerifyJSONLDCredential` in `verifier/presentation_parser.go`.
- Proof verified by `ld_proof_checker.go`.

#### 3. SD-JWT VC (`sd-jwt`) — existing

An SD-JWT Verifiable Credential with selective disclosure. The JWT payload is the credential itself (no `vc` wrapper); selectively disclosable claims are replaced by hashes and appended as disclosures.

**JOSE header:**
```json
{
  "alg": "ES256",
  "kid": "did:web:issuer.example.com#key-1"
}
```

**JWT payload:**
```json
{
  "iss": "did:web:issuer.example.com",
  "vct": "VerifiableCredential",
  "iat": 1700000000,
  "name": "Alice",
  "_sd_alg": "sha-256",
  "_sd": ["hash-of-disclosed-claim"],
  "cnf": {
    "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
  }
}
```

**Wire format:**
```
<header>.<payload>.<signature>~<disclosure1>~<disclosure2>~
```

Each disclosure is a base64url-encoded JSON array `[salt, claim-name, claim-value]`. The trailing `~` separators delimit the disclosures.

**Key characteristics:**
- Format constant: `common.FormatSDJWT` (`"sd-jwt"`)
- Exempt from the VC Data Model version gate (no `@context`).
- Holder binding via `cnf` claim (confirmation method) rather than `holder`/`credentialSubject.id`.
- Parsed by `ConfigurableSdJwtParser.ParseWithSdJwt` in `verifier/presentation_parser.go`.

#### 4. `vc+jwt` — new (VC-JOSE-COSE)

A JWT-encoded Verifiable Credential per the W3C VC-JOSE-COSE specification. The JWT payload **is** the credential — there is no wrapping `vc` claim. Identified by the JOSE `typ` header value `vc+jwt`.

**JOSE header:**
```json
{
  "alg": "ES256",
  "typ": "vc+jwt",
  "kid": "did:web:issuer.example.com#key-1"
}
```

**JWT payload:**
```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential"],
  "issuer": "did:web:issuer.example.com",
  "validFrom": "2024-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:web:subject.example.com",
    "name": "Alice"
  }
}
```

**Key characteristics:**
- Format constant: `common.FormatVCJWT` (`"vc+jwt"`)
- The JWT payload IS the JSON-LD credential. No `vc` claim, no `iss`/`nbf`/`exp` duplication — the JSON-LD fields are authoritative.
- VC-JOSE-COSE §3.3.1: `iss` maps to `issuer`, `sub` maps to `credentialSubject[0].id`, `jti` maps to `id`, `nbf`/`iat` maps to `validFrom`, `exp` maps to `validUntil`. Both JWT-level and payload-level spellings are accepted.
- Subject to the VC Data Model version gate (carries `@context`).
- Parsed by `vcJwtClaimsToCredential` in `verifier/presentation_parser.go`.

#### 5. `EnvelopedVerifiableCredential` — new (VCDM 2.0)

A secured credential embedded inside a VP via a `data:` URI (VCDM 2.0 §4.13). The credential appears as a JSON-LD object in the VP's `verifiableCredential` array with type `EnvelopedVerifiableCredential` and an `id` that is a `data:application/vc+jwt,<compact-JWS>` URI.

```json
{
  "@context": "https://www.w3.org/ns/credentials/v2",
  "type": "EnvelopedVerifiableCredential",
  "id": "data:application/vc+jwt,eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK2p3dCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6d2ViOmlzc3Vlci5leGFtcGxlLmNvbSIsInZhbGlkRnJvbSI6IjIwMjQtMDEtMDFUMDA6MDA6MDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6d2ViOnN1YmplY3QuZXhhbXBsZS5jb20ifX0.signature"
}
```

**Key characteristics:**
- Not a separate format — the embedded JWT is parsed as a `vc+jwt` credential.
- The `data:` URI must not have parameters (no `data:application/vc+jwt;base64,...`).
- The `@context` on the envelope is for JSON-LD typing only — parsing uses the JWT inside the `id`.
- Can appear inside any VP type: JWT VP, JSON-LD VP, or `vp+jwt` VP.
- Parsed by `parseEnvelopedCredential` in `verifier/presentation_parser.go`.

### Presentation Formats

#### 1. JWT VP — existing

A JWT-encoded Verifiable Presentation where the JWT payload wraps the presentation inside a `vp` claim.

**JOSE header:**
```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "did:web:holder.example.com#key-1"
}
```

**JWT payload:**
```json
{
  "iss": "did:web:holder.example.com",
  "vp": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "holder": "did:web:holder.example.com",
    "verifiableCredential": [
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6d2ViOmlzc3Vlci5leGFtcGxlLmNvbSIsInZjIjp7fX0.signature"
    ]
  }
}
```

**Key characteristics:**
- The `vp` claim holds the JSON-LD presentation structure.
- `verifiableCredential` entries can be JWT VC strings, SD-JWT strings, or JSON-LD VC objects.
- `iss` at the JWT level maps to the holder.
- Parsed by `parseJWTPresentation` in `verifier/presentation_parser.go`.

#### 2. JSON-LD VP (`ldp_vp`) — existing

A JSON-LD Verifiable Presentation secured with a Linked Data Proof (`JsonWebSignature2020`).

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "type": ["VerifiablePresentation"],
  "holder": "did:web:holder.example.com",
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/jws-2020/v1"
      ],
      "type": ["VerifiableCredential"],
      "issuer": "did:web:issuer.example.com",
      "issuanceDate": "2024-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "did:web:subject.example.com",
        "name": "Alice"
      },
      "proof": {
        "type": "JsonWebSignature2020",
        "created": "2024-01-01T00:00:00Z",
        "verificationMethod": "did:web:issuer.example.com#key-1",
        "proofPurpose": "assertionMethod",
        "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..vc-signature"
      }
    }
  ],
  "proof": {
    "type": "JsonWebSignature2020",
    "created": "2024-01-01T00:00:00Z",
    "verificationMethod": "did:web:holder.example.com#key-1",
    "proofPurpose": "authentication",
    "challenge": "server-issued-nonce",
    "domain": "https://verifier.example.com",
    "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..vp-signature"
  }
}
```

**Key characteristics:**
- The VP proof uses `proofPurpose: "authentication"` and may carry `challenge` and `domain`.
- The credential proofs use `proofPurpose: "assertionMethod"`.
- Holder binding: `credentialSubject.id` must match `holder`.
- Parsed by `parseJSONLDPresentation` in `verifier/presentation_parser.go`.
- Proofs verified by `ld_proof_checker.go`.

#### 3. SD-JWT VP — existing

An SD-JWT Verifiable Presentation. The VP is a JWT with a `vp` claim containing SD-JWT credential strings. Holder binding uses a Key Binding JWT (KB-JWT) instead of a `holder` field.

**JOSE header:**
```json
{
  "alg": "ES256",
  "kid": "did:web:holder.example.com#key-1"
}
```

**JWT payload:**
```json
{
  "iss": "did:web:holder.example.com",
  "vp": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "verifiableCredential": [
      "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6d2ViOmlzc3Vlci5leGFtcGxlLmNvbSIsInZjdCI6IlZlcmlmaWFibGVDcmVkZW50aWFsIiwiX3NkX2FsZyI6InNoYS0yNTYifQ.signature~WyJzYWx0IiwibmFtZSIsIkFsaWNlIl0~"
    ]
  }
}
```

**Key characteristics:**
- VP structure is the same as a JWT VP (`vp` claim wrapper).
- Each `verifiableCredential` entry is an SD-JWT compact string (with `~`-delimited disclosures).
- Holder binding via KB-JWT appended after the final `~` separator.
- Parsed by `ConfigurableSdJwtParser.ParseWithSdJwt`.

#### 4. `vp+jwt` — new (VC-JOSE-COSE)

A JWT-encoded Verifiable Presentation per the W3C VC-JOSE-COSE specification. The JWT payload **is** the presentation — there is no wrapping `vp` claim. Identified by the JOSE `typ` header value `vp+jwt`.

**JOSE header:**
```json
{
  "alg": "ES256",
  "typ": "vp+jwt",
  "kid": "did:web:holder.example.com#key-1"
}
```

**JWT payload:**
```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiablePresentation"],
  "holder": "did:web:holder.example.com",
  "verifiableCredential": [
    {
      "@context": "https://www.w3.org/ns/credentials/v2",
      "type": "EnvelopedVerifiableCredential",
      "id": "data:application/vc+jwt,eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK2p3dCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXX0.signature"
    }
  ]
}
```

**Key characteristics:**
- Format constant: `common.FormatVPJWT` (`"vp+jwt"`)
- The JWT payload IS the JSON-LD presentation. No `vp` claim, no `iss` duplication — `holder` is read directly from the payload.
- `verifiableCredential` entries can be JWT VC strings (`jwt_vc` or `vc+jwt`), `EnvelopedVerifiableCredential` objects, or JSON-LD VC objects.
- VC-JOSE-COSE §3.3.2: `iss` maps to `holder`, `jti` maps to `id`.
- Parsed by `parseVPJWTPresentation` in `verifier/presentation_parser.go`.

### Format Dispatch Summary

| Token shape | `typ` header | Format | Parser |
|---|---|---|---|
| Compact JWT (no `~`) | absent / `JWT` | `jwt_vc` / JWT VP | `parseJWTCredential` / `parseJWTPresentation` |
| Compact JWT | `vc+jwt` | `vc+jwt` | `parseJWTCredential` → `vcJwtClaimsToCredential` |
| Compact JWT | `vp+jwt` | `vp+jwt` | `parseJWTPresentation` → `parseVPJWTPresentation` |
| Compact JWT with `~` disclosures | — | `sd-jwt` | `ParseWithSdJwt` |
| JSON object (`{...}`) | — | `ldp_vc` / `ldp_vp` | `parseJSONLDPresentation` / `parseAndVerifyJSONLDCredential` |
| JSON object with `type: EnvelopedVerifiableCredential` | — | embedded `vc+jwt` | `parseEnvelopedCredential` |

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
- `sub` → `credentialSubject[0].id` (VC-JOSE-COSE §3.3.1: `sub` MUST be set when the credential has a single `credentialSubject` with an `id` property; if both `sub` and `credentialSubject[0].id` are present, `sub` takes precedence)
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
- The SD-JWT parser's `ParseWithSdJwt` tries to read a `vp` claim and fails when it's absent. A `vp+jwt` token has no `vp` claim, so `ParseWithSdJwt` returns `ErrorPresentationNoCredentials`, which causes the existing fallthrough to `ParsePresentation` — this already works correctly without any code change. Add a test to confirm this behavior for a `vp+jwt` token going through `tokenToPresentation`.

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
- `verifier/presentation_parser.go` — The `parseUnsignedJWTCredential` function body lives here (called from `credential_status_client.go`). Update it to detect the `typ` header and dispatch to `vcJwtClaimsToCredential` for `vc+jwt` tokens.
- `verifier/credential_status_client.go` — Contains the call site for `parseUnsignedJWTCredential` (line 326). No code change needed here, but tests should verify the end-to-end flow.
- `verifier/jwt_verifier_test.go` — Tests for the version gate with `vc+jwt` credentials.
- `verifier/credential_status_client_test.go` — Tests for `vc+jwt` status list credential parsing.

**Details:**

**Version gate:**
`isVersionedDataModelCredential` currently exempts only `FormatSDJWT` — every other format is subject to the version gate (`credential.Format() != common.FormatSDJWT`). Since `FormatVCJWT` (`"vc+jwt"`) is not `FormatSDJWT` (`"sd-jwt"`), a `vc+jwt` credential is already subject to the version gate with no code change required. This is correct because `vc+jwt` carries `@context` and participates in the W3C data model versioning. This sub-step only requires adding a test to confirm the existing version gate handles `FormatVCJWT` correctly.

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
