# Deployment

Everything in this document is **deployment-wide environment configuration**.
It applies to every request regardless of which SSO provider is active.
Individual SAML/OIDC providers are never configured here — they are
configured through the SSO Management UI and persisted in the database; see
[SSO](sso.md) and the Configuration Model in [README](../README.md). Adding a
supported provider after deployment does not require changing anything in
this document or restarting with new environment variables.

## Production prerequisites

Provide deployment configuration or a secret store with real values for
`DJANGO_SECRET_KEY`, `DJANGO_ENCRYPTION_KEY`, `DJANGO_DEBUG=false`,
`DJANGO_ALLOWED_HOSTS`, and production PostgreSQL `DATABASE_URL`. Secrets and
the Fernet key must remain stable across restarts and migrations. Serve the
application over HTTPS.

The documented local runtime baseline is Python 3.13.x. The current
`Dockerfile` is independently pinned to `python:3.11-slim-bullseye`; validate
that runtime/dependency combination before treating the image as equivalent to
the local Python 3.13 baseline.

## Configuration examples

Placeholders only — substitute real values through the process environment or
an approved secret store, never by editing source.

**Local HTTP** (`DATABASE_URL` absent uses the local SQLite fallback):

```
DJANGO_DEBUG=true
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
DJANGO_SESSION_COOKIE_SAMESITE=Lax
DJANGO_SESSION_COOKIE_SECURE=false
```

**Production HTTPS / SAML-capable**:

```
DJANGO_DEBUG=false
DJANGO_ALLOWED_HOSTS=app.example.com
DJANGO_CSRF_TRUSTED_ORIGINS=https://app.example.com

DJANGO_SESSION_COOKIE_SAMESITE=None
DJANGO_SESSION_COOKIE_SECURE=true
DJANGO_TRUST_X_FORWARDED_PROTO=true

DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DATABASE
```

A production deployment additionally needs: TLS terminated at the reverse
proxy (or by Django itself), `collectstatic` run, direct `/media/uploads/`
access denied by the web server, reviewed migrations applied deliberately
(never as an automatic startup step), and a `DJANGO_ENCRYPTION_KEY` that
remains stable — rotating it without a planned migration makes existing
encrypted provider secrets and integration credentials undecryptable.

## Host and CSRF trusted origins

`DJANGO_ALLOWED_HOSTS` is a comma-separated list of hostnames/IPs (no scheme,
no wildcards) and is required whenever `DJANGO_DEBUG=false`.

`DJANGO_CSRF_TRUSTED_ORIGINS` is a comma-separated list of full origins
(`scheme://host[:port]`, no path). It is empty by default — most deployments
do not need it. Set it only when a deployment's reverse-proxy/HTTPS topology
makes the browser's `Origin`/`Referer` header not match `DJANGO_ALLOWED_HOSTS`
on its own; Django would otherwise reject same-origin POST submissions
(regular forms, the admin, provider management) as cross-site. This is
unrelated to SAML ACS handling, which is exempted from Django's CSRF check
because the assertion POST originates from the IdP, not the browser acting on
behalf of this site.

## HTTPS and proxy settings

These settings are opt-in because a reverse proxy topology must be known:

- `DJANGO_SECURE_SSL_REDIRECT`
- `DJANGO_TRUST_X_FORWARDED_PROTO`
- `DJANGO_ENABLE_HSTS`
- `DJANGO_HSTS_INCLUDE_SUBDOMAINS`
- `DJANGO_HSTS_PRELOAD`

`FORCE_HTTPS` remains a compatibility alias for
`DJANGO_SECURE_SSL_REDIRECT`. `SSO_FORCE_HTTPS` separately controls how SSO
callback URLs are constructed. Only trust `X-Forwarded-Proto` when the trusted
proxy sets it. Enable HSTS only after the HTTPS path and hostnames are verified.

This repository contains no nginx or Apache configuration. If a reverse proxy
terminates TLS, configure TLS there and ensure the above environment settings
match the deployed topology.

## Session cookie SameSite/Secure

`DJANGO_SESSION_COOKIE_SAMESITE` (`Lax`, `Strict`, or `None`; default `Lax`)
and `DJANGO_SESSION_COOKIE_SECURE` (default `false`) control the session
cookie. Neither is derived from `DJANGO_DEBUG`, because `DJANGO_DEBUG=true`
can still run behind HTTPS during tunnel/testing deployments. Startup fails
closed if `DJANGO_SESSION_COOKIE_SAMESITE=None` is set without
`DJANGO_SESSION_COOKIE_SECURE=true` — browsers reject such cookies outright.

- Local HTTP development: `DJANGO_SESSION_COOKIE_SAMESITE=Lax`,
  `DJANGO_SESSION_COOKIE_SECURE=false` (the defaults).
- HTTPS SAML deployment: a cross-site SAML ACS POST (IdP → browser → Django)
  requires the session cookie to survive that cross-site POST, which needs
  `DJANGO_SESSION_COOKIE_SAMESITE=None`, `DJANGO_SESSION_COOKIE_SECURE=true`,
  and (behind a trusted TLS-terminating proxy)
  `DJANGO_TRUST_X_FORWARDED_PROTO=true`.

`CSRF_COOKIE_SAMESITE`/`CSRF_COOKIE_SECURE` are configured separately in
`core/settings.py` and are not changed by these variables.

For SAML behind a trusted TLS-terminating proxy, the public ACS URL must use
the externally visible HTTPS hostname and path, not the internal Django,
Gunicorn, or container port. The SAML request adapter derives port 443 for a
trusted HTTPS request whose public host has no explicit port, derives port 80
for plain HTTP, and preserves an explicit public nonstandard port. It does not
reuse an internal `SERVER_PORT` when the public host has no port.

## Static files and media

`STATIC_ROOT` is `staticfiles/`; source assets are in `static/`. Run:

```bash
python manage.py collectstatic --noinput
```

WhiteNoise is enabled outside `DEBUG` and serves collected static assets.

`MEDIA_ROOT` is `media/`. Public branding media can be served according to the
deployment policy, but the production web server **must deny direct
`/media/uploads/` access**. Submitted files are protected records and must be
downloaded through the authorization-aware Django file-download route. Django's
DEBUG media serving is development-only and is not a production media policy.

## Migration sequence

Use a deliberate production release sequence:

1. Back up the database and verify restore capability.
2. Configure correct stable secrets and database URL.
3. Run `python manage.py showmigrations` and review unapplied migrations.
4. Apply reviewed migrations deliberately with `python manage.py migrate`.
5. Run `python manage.py collectstatic --noinput`.
6. Restart the application and smoke-test login, forms, integrations, SSO
   management, and protected downloads.

`migrate` is database-mutating. Do not turn it into an unreviewed diagnostic or
run it against the wrong selected database.

## Docker and entrypoint

The `Dockerfile` builds the application, installs runtime requirements plus
Unix ODBC/MS ODBC 17 and PostgreSQL 16 client packages, exposes port `8001`,
and starts `/app/entrypoint.sh`. Build it with:

```bash
docker build -t jhfre-integrator .
```

The entrypoint requires `DATABASE_URL`; it exits if absent. It runs
`collectstatic`, performs `manage.py check --database default`, then starts
Gunicorn on `0.0.0.0:${PORT:-8001}`. It defaults `APP_ENV` from the image to
`development` and defaults `AUTO_MIGRATE` to `false`.

When explicitly enabled, entrypoint options have material effects:

- `AUTO_MIGRATE=true` applies migrations.
- `DEV_RESET_DB=true` drops and recreates the PostgreSQL `public` schema once
  in the container's temporary state.
- `SYNC_DB_FROM_PROD=true` can copy `PROD_DATABASE_URL` into `DATABASE_URL`.
- `SUPERUSER_ON_BOOT=true` creates a superuser from Django superuser variables.

Do not enable the reset, sync, auto-migrate, or bootstrapped-superuser options
without an approved operational procedure. Docker deployment also requires
secrets and `DATABASE_URL` passed through the container platform; `.env.example`
is not automatically read by the application.
