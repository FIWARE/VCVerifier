# PKCE for authorization codes

The authorization-code flow supports optional PKCE (RFC 7636). A relying party
may include `code_challenge` and `code_challenge_method` in its authorization
request. The verifier binds the challenge to the login session and then to the
issued authorization code. The RP must send the matching `code_verifier` to
`/token`; a missing or invalid verifier makes the exchange fail.

The challenge is also accepted by the legacy cross-device v1 entry points
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
the existing authorization-code behavior; a `code_verifier` in such an
exchange is ignored.

The implementation uses a method registry in `verifier/pkce.go`: adding a
future method requires implementing its challenge validation and verifier
comparison, registering its protocol name, updating the OpenAPI method enum,
and adding it to this configuration documentation.
