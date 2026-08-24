# Troubleshooting

## `DJANGO_SECRET_KEY` missing

Settings intentionally reject missing or placeholder values. Set a real
process-environment value before invoking Django. For local PowerShell, see the
example in [development](development.md); do not put a real secret in
`.env.example` or source control.

## Fernet invalid key or incorrect padding

`DJANGO_ENCRYPTION_KEY` must be a valid Fernet key, not the `CHANGE_ME`
placeholder. For a brand-new environment, generate one using the documented
command. Never replace the key for an existing database with encrypted
credentials, SSO secrets, or webhook headers unless a rotation/migration plan
is in place.

## Environment variables disappeared

PowerShell variables last only for the current terminal. Start a new session by
setting them again or deliberately loading an ignored local `.env.local.ps1`.
Do not commit that helper or put production values in it.

## `DATABASE_URL` points to an external system locally

Safe local development and test workflows use SQLite with the variable absent:

```powershell
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
```

Confirm the active environment before `migrate`, tests, connection checks, or
other commands that could select a database. Do not use a real external DB for
routine tests.

## Migration dependency or order issue

Inspect state before changing anything:

```powershell
.\.venv\Scripts\python.exe manage.py showmigrations
```

`saml_auth` must remain installed because existing `sso_auth` migration history
depends on it. Do not delete migration files to bypass an ordering problem.

## Static files missing

In development, check `DEBUG`, `STATIC_URL`, and the source asset under
`static/`. In deployment, run `collectstatic` and ensure WhiteNoise or the web
server can serve `STATIC_ROOT` (`staticfiles/`). A browser 404 should be fixed
at the asset reference/build/deployment layer, not by copying user data into
`static/`.

## Protected uploaded file unavailable directly

This is expected for `media/uploads/`. Production must deny direct web-server
access; use the authorized Django file-download route with a permitted user.

## SSO provider not working

Confirm the provider is both enabled and active, then review its protocol
configuration, callback URL, issuer/discovery/JWKS or SAML certificates, and
the HTTPS/proxy settings. Do not disable OIDC token checks, SAML strictness,
signature requirements, state/nonce checks, or replay protection.

## SAML login fails after the IdP redirects back (session/cookie loss)

If the browser returns from the IdP but the app shows "SAML authentication
failed" instead of completing login, the session cookie set before redirect
to the IdP likely did not survive the trip back. Cross-site SAML ACS POSTs
need `DJANGO_SESSION_COOKIE_SAMESITE=None` with
`DJANGO_SESSION_COOKIE_SECURE=true`, served over real HTTPS. Startup itself
rejects `SameSite=None` without `Secure=true`; if the app fails to start with
a `DJANGO_SESSION_COOKIE_SAMESITE` configuration error, that is the fix, not
a bug to bypass. Local `Lax` + `Secure=false` is only valid for plain HTTP
development, not for a real cross-site SAML flow.

## Provider form rejects saving with a signing option enabled

Enabling `Sign AuthN Requests`, `Sign Logout Requests`, or `Sign Logout
Responses` on a SAML provider requires an SP certificate and private key to
also be configured. This is enforced both by the provider form and by
python3-saml's own settings validation (which runs for either SSO binding);
supply an SP certificate/private key, or leave the corresponding signing
option off.

## SAML response destination contains an internal port (`:8000`)

This is a reverse-proxy trust problem, not a provider-configuration problem.
The SP ACS URL configured on the provider — and registered with the IdP —
must be the externally visible HTTPS URL, for example
`https://app.example.com/sso/saml/acs/`. Never put the internal Django,
Gunicorn, or container port in it. Confirm `DJANGO_TRUST_X_FORWARDED_PROTO`
is set and the proxy actually sends `X-Forwarded-Proto`; the SAML request
adapter derives the public port from that trusted signal, not from
`SERVER_PORT`.

## SAML response/message signature missing

Some IdPs sign only the Assertion, not the outer Response. If the provider's
`Want Messages Signed` is enabled, an IdP that only signs the Assertion will
fail validation. Disable `Want Messages Signed` for that provider if it
matches the IdP's actual behavior — `Want Assertions Signed` stays mandatory
and is never affected by this setting.

## SAML NameID invalid / identity rejected

Compare the provider's `SAML Identity Policy` against what the IdP actually
sends. `Persistent NameID` requires the response's NameID format to be
exactly `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`; a
transient or emailAddress-format NameID is rejected by design.
`Configured immutable attribute` requires a non-empty value under the exact
attribute name configured on the provider. Do not switch either policy to
trust email or username as a substitute — that is the identity-spoofing risk
these policies exist to prevent.

## SSO provisioning denied for a new user

Check `Allow Registration` on the provider, and confirm the configured
`Attribute Mapping` (email/username/first name/last name attribute names)
matches the attribute names the IdP actually releases in the
assertion/userinfo response — not another provider's attribute names. A
missing email or username value, or an existing account with the same
email/username, denies registration by design (account collisions fail
closed) rather than silently linking accounts.

## External database connection failing

Check that the intended connection is configured, its encrypted credential can
be decrypted with the stable Fernet key, the required driver is installed, and
network/firewall/DNS access is approved. Confirm least-privilege database
grants. Do not “fix” a connection by relaxing TLS, query policy, or security
controls.

## Docker container exits immediately

The entrypoint requires `DATABASE_URL` and exits without it. It also executes
`collectstatic` and a default-database check before Gunicorn. Verify container
secrets, database reachability, and the selected `APP_ENV`; do not enable reset
or production-sync options as a diagnostic shortcut.
