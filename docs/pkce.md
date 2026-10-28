# PKCE for authorization codes

The authorization-code flow supports optional PKCE (RFC 7636). A relying party
may include `code_challenge` and `code_challenge_method` in its authorization
request. The verifier binds the challenge to the login session and then to the
issued authorization code. The RP must send the matching `code_verifier` to
`/token`; a missing or invalid verifier makes the exchange fail.

The challenge is also accepted by the same-device entry point
`/api/v1/samedevice` and by the legacy cross-device v1 entry points
`/api/v1/loginQR` and `/api/v1/startsiop`. The callback still receives only the
authorization code and state; the RP supplies its verifier separately to
`/token`. Requests that omit a challenge retain the existing behavior.

The supported methods are:

| Method | Behavior | Default |
| --- | --- | --- |
| `S256` | Compares the challenge with the unpadded Base64URL encoding of SHA-256 of the verifier. | Enabled |
| `plain` | Compares the challenge directly with the verifier. This method is not recommended. | Disabled |

Method names are case-insensitive in both authorization requests and
configuration; the verifier normalizes them to the canonical names shown above.

Configure the allowed methods in `server.yaml`:

```yaml
verifier:
  allowedCodeChallengeMethods:
    - S256
    # Enable only when a client cannot use S256:
    # - plain
```

When `allowedCodeChallengeMethods` is omitted or empty, only `S256` is enabled.
Specifying a list replaces that default; `plain` must be explicitly included to
be accepted. Unsupported configured methods cause verifier initialization to
fail rather than silently weakening PKCE.

If `code_challenge_method` is omitted from a request that has a
`code_challenge`, RFC 7636 treats the method as `plain`. Since `plain` is
disabled by default, such a request is rejected unless `plain` is explicitly
enabled. Supplying a method without a challenge is also rejected. Requests with
empty PKCE parameters are rejected. Requests with no challenge continue to use
the existing authorization-code behavior, as long as the token request sends no
`code_verifier` either: a verifier for a code issued without a challenge means
the challenge was stripped from the authorization request (a PKCE downgrade), so
the exchange is rejected (RFC 9700 §2.1.1). As with a wrong verifier, the code
stays available for the legitimate client.

A request passed by reference (`request_uri`) takes its challenge from the
request object only (RFC 9101 §6.3). A `code_challenge` in the query of such a
request is ignored, since it is not covered by the client's signature.

A code that cannot be exchanged is answered as RFC 6749 §5.2 requires, with
`400` and `{"error":"invalid_grant","error_description":...}`: an unknown,
expired or already used code, a `redirect_uri` other than the one the code was
issued for, and a missing or wrong `code_verifier` (RFC 7636 §4.6). A failure on
the verifier's side, such as signing the token, is `500` with
`{"error":"server_error"}`. Both apply to the `authorization_code` grant; a
token request that is missing its `code` is still `400` with the verifier's
`ErrorMessage`.

The implementation uses a method registry in `verifier/pkce.go`: adding a
future method requires implementing its challenge validation and verifier
comparison, registering its protocol name, updating the OpenAPI method enum,
and adding it to this configuration documentation.
