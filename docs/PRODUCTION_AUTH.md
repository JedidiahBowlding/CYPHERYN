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

The authenticated-emails file is an allowlist with one email address per line. Keep the
default deployment restricted to named administrators rather than permitting an entire
public email domain.
