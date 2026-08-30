# Production authentication

CYPHERYN's public web deployment uses Auth0 Universal Login through OAuth2 Proxy and
Caddy. Development identity headers are disabled in production. Caddy removes any
client-supplied development identity headers and forwards only the ID token returned by
the authenticated proxy. The API validates the token signature, issuer, audience, and
expiry using Auth0's JWKS endpoint.

Required Auth0 application URLs:

- Login URI: `https://app.cypheryn.com/oauth2/start`
- Callback URL: `https://app.cypheryn.com/oauth2/callback`
- Logout URL: `https://app.cypheryn.com/`
- Web origin and CORS origin: `https://app.cypheryn.com`

Production secret files must contain only their value and must remain outside Git:

- `platform/.runtime/auth0-client-secret`
- `platform/.runtime/oauth2-cookie-secret`
- `platform/.runtime/authenticated-emails.txt`

The OAuth2 Proxy image runs as UID/GID `65532`. On a Linux production host, make the
three bind-mounted files readable only by that identity (`chown 65532:65532` and
`chmod 0400`). The cookie-secret file must contain exactly 16, 24, or 32 raw random
bytes; a base64-encoded 32-byte value is 44 bytes and is not valid when supplied by
`--cookie-secret-file`.

The authenticated-emails file is an allowlist with one email address per line. Keep the
default deployment restricted to named administrators rather than permitting an entire
public email domain.
