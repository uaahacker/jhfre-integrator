# Deploying to Coolify

This is the step-by-step Coolify procedure for JHFRE Integrator. It assumes
the source code is already reachable from a Git remote that Coolify can pull
from (a separate step, handled outside this document) and covers everything
after that: provisioning the database, configuring the application resource,
required environment variables, storage, the first-deploy sequence, and
post-deploy verification.

Read [deployment.md](deployment.md) and [operations.md](operations.md) first
if you have not already — this document is the Coolify-specific walkthrough
of the same requirements, not a replacement for them.

## 1. Prerequisites

- A Coolify project/server ready to receive a new resource.
- The Git remote for this repository connected to Coolify (GitHub/GitLab App,
  or a deploy key + Git URL).
- Nothing in `.env` is used by the running application — it is documentation
  only ([README.md](../README.md#environment-variables)). Every real value
  below is entered directly into Coolify's environment variable UI for the
  application resource.

## 2. Provision PostgreSQL

The SQLite fallback (`db.sqlite3`) is a local development convenience only —
[core/settings.py](../core/settings.py) only uses it when `DATABASE_URL` is
unset, and [entrypoint.sh](../entrypoint.sh) refuses to boot without
`DATABASE_URL` set. A container's filesystem is not durable storage for a
real database either way.

1. In Coolify, add a **PostgreSQL** database resource (a managed Coolify
   service, or point at an external Postgres instance — either works).
2. Note the resulting connection string. Coolify's internal Postgres
   resources expose one directly; format it as:
   ```
   postgresql://USER:PASSWORD@HOST:5432/DATABASE
   ```
3. Do not reuse this database for anything else. `AUTO_MIGRATE` and manual
   `migrate` runs mutate it directly (see [database.md](database.md)).

## 3. Create the application resource

1. New Resource → **Dockerfile** (or "Application" pointing at this repo,
   build pack = Dockerfile) → select the connected Git repository/branch.
2. Coolify will build from the repository's [Dockerfile](../Dockerfile),
   which installs Python 3.11, the MS ODBC 17 driver, the PostgreSQL 16
   client, and the packages in `requirements.txt`, then runs
   `/app/entrypoint.sh`.
3. **Port**: set the exposed/health-check port to `8001` (the Dockerfile's
   `EXPOSE` and the entrypoint's default `PORT`). If you override `PORT` in
   the environment variables below, update this to match.
4. **Domain**: attach the domain/subdomain you want this deployment reachable
   at, and let Coolify issue the HTTPS certificate (it fronts the container
   with Traefik). Note the exact hostname — it feeds `DJANGO_ALLOWED_HOSTS`
   below.

## 4. Environment variables

Set these on the application resource in Coolify (**Environment Variables**
tab), not in any file in the repo.

### Required

| Variable | Value | Notes |
|---|---|---|
| `DJANGO_SECRET_KEY` | a real secret | Generate once, keep stable. See below. |
| `DJANGO_ENCRYPTION_KEY` | a valid Fernet key | Generate once, **never rotate casually** — it encrypts stored SSO/integration secrets. See below. |
| `DJANGO_ALLOWED_HOSTS` | e.g. `app.yourdomain.com` | Comma-separated hostnames only, no scheme. Must include the domain from step 3.4. |
| `DATABASE_URL` | from step 2 | `postgresql://USER:PASS@HOST:5432/DB` |

Generate the two secrets locally (or in Coolify's terminal once the resource
exists) and paste the output in — do not let anything auto-generate a new
value on every redeploy:

```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"          # DJANGO_SECRET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # DJANGO_ENCRYPTION_KEY
```

### Required because this is production (`DJANGO_DEBUG` is unset/false)

| Variable | Value |
|---|---|
| `DJANGO_DEBUG` | leave unset (defaults to `false`) |
| `DJANGO_TRUST_X_FORWARDED_PROTO` | `true` — Coolify's Traefik terminates TLS in front of the container; Django needs this to recognize the original request was HTTPS |

### Set if your topology needs them

| Variable | When |
|---|---|
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Only if same-origin POSTs (forms, admin, provider management) get rejected as cross-site — set to `https://app.yourdomain.com` |
| `DJANGO_SESSION_COOKIE_SAMESITE=None` + `DJANGO_SESSION_COOKIE_SECURE=true` | Only if you run SAML and the IdP's ACS POST needs to survive a cross-site redirect. Startup fails closed if `SameSite=None` is set without `Secure=true`. Leave both unset (defaults `Lax`/`false`) if you don't need this. |
| `DJANGO_SECURE_SSL_REDIRECT` | Optional, once HTTPS is verified working end-to-end |
| `DJANGO_ENABLE_HSTS` (+ `DJANGO_HSTS_INCLUDE_SUBDOMAINS`, `DJANGO_HSTS_PRELOAD`) | Optional, enable only after HTTPS/hostnames are confirmed stable |
| `SSO_FORCE_HTTPS` | Defaults to `true` automatically when `DEBUG` is false — only set explicitly if you need to override that |
| `PORT` | Only if you changed the exposed port in step 3.3 away from `8001` |

### Leave unset for normal production operation

`AUTO_MIGRATE`, `DEV_RESET_DB`, `SYNC_DB_FROM_PROD`, `SUPERUSER_ON_BOOT` all
default to `false`/off in [entrypoint.sh](../entrypoint.sh). Only turn one on
deliberately, for the specific deploy that needs it (see step 6), then turn
it back off.

## 5. Persistent storage for media

The container filesystem is ephemeral — anything written to `media/` during
a running container (company logo/favicon uploads, submitted files) is lost
on the next redeploy or restart unless it lives on a volume.

In the Coolify resource's **Storage** tab, add a persistent volume mounted at
the container path:

```
/app/media
```

This covers both the public branding assets (`company_logos/`,
`company_favicons/`, `form_logos/`, `integration_icons/` — served at
`MEDIA_URL`) and the protected submission uploads (`media/uploads/`, served
only through the authorization-checked download route, never directly).
Without this volume, uploaded logos and submitted files silently disappear
on the next deploy.

`STATIC_ROOT` (`staticfiles/`) does **not** need a volume — `collectstatic`
regenerates it from `static/` on every boot via the entrypoint, and
WhiteNoise serves it from there.

## 6. First deploy sequence

1. With everything above configured, trigger the first deploy.
2. The entrypoint will run `collectstatic`, check database connectivity, and
   then — because `AUTO_MIGRATE` defaults to `false` — **skip migrations**.
   An empty database means the app will not have its schema yet. For this
   first deploy only, do one of:
   - Temporarily set `AUTO_MIGRATE=true`, redeploy, then unset it once the
     schema is in place, or
   - Deploy once (it will boot against an unmigrated database — some pages
     will error), then use Coolify's terminal/exec on the running container
     to run `python manage.py migrate` directly, matching the deliberate
     sequence in [deployment.md](deployment.md#migration-sequence):
     ```bash
     python manage.py showmigrations
     python manage.py migrate
     ```
3. If you need an initial admin account and don't want to create one through
   the database directly, set `SUPERUSER_ON_BOOT=true` plus
   `DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_EMAIL`,
   `DJANGO_SUPERUSER_PASSWORD` for that one deploy, then remove all four
   afterward.

For every deploy *after* the first, decide deliberately per release whether
there are new migrations to apply — do not leave `AUTO_MIGRATE=true`
permanently as a substitute for reviewing what a migration does.

## 7. Post-deploy verification

Matches [operations.md](operations.md#after-deployment):

- Load the site over HTTPS at the configured domain; confirm no mixed-content
  or redirect-loop errors.
- Log in and load the dashboard.
- Confirm the company logo/branding renders (this specifically exercises the
  public-media route fixed for this deployment — see §9).
- Submit a test form.
- Open the SSO management page and an integrations page as an authorized
  user.
- Download a protected submitted file and confirm it only works when
  authenticated as a superuser — and confirm a direct request to
  `https://app.yourdomain.com/media/uploads/<anything>` returns 404 rather
  than the file.
- Check the Coolify application logs for startup warnings (missing env vars,
  static 404s, database connection issues).

## 8. Ongoing operations

- **Redeploys**: safe by default — migrations are skipped unless
  `AUTO_MIGRATE=true` is set for that deploy.
- **New migrations**: back up the database, review
  `python manage.py showmigrations`, then apply deliberately (either a
  one-time `AUTO_MIGRATE=true` deploy, or `migrate` via the Coolify
  terminal). Never run this against the wrong resource's database.
- **Secrets rotation**: `DJANGO_SECRET_KEY` rotation logs out every active
  session — expected, not a bug. `DJANGO_ENCRYPTION_KEY` rotation makes
  existing encrypted SSO/integration secrets undecryptable — do not rotate it
  without a planned re-encryption migration.
- **Backups**: back up the Postgres database on your normal schedule and
  actually test a restore — see [database.md](database.md#backups). The
  `media/` volume (uploaded files, branding assets) should be backed up
  separately from the database.
- **SSO providers**: added/edited entirely through `/sso/management/` by a
  superuser at runtime — never requires new environment variables or a
  redeploy. See [sso.md](sso.md).

## 9. What was fixed in this repository for Coolify readiness

These changes were made directly in the codebase as part of preparing this
deployment (not something you need to do yourself in Coolify):

- **`requirements.txt` was UTF-16-encoded** (most likely from a prior edit
  through Windows PowerShell's default output encoding) instead of UTF-8. It
  happened to still install correctly because modern `pip` detects the BOM,
  but it was non-standard and risked breaking with other tooling. Re-saved as
  plain UTF-8 with identical contents.
- **Added `.dockerignore`**, mirroring `.gitignore`, so a direct
  `docker build .` from this directory can never bake `.venv`, `db.sqlite3`,
  or `.env` into an image layer. (If Coolify builds from a Git checkout, this
  was already effectively true, since those paths are also gitignored — this
  is the safety net for building locally.)
- **Fixed public media routing in production** ([core/urls.py](../core/urls.py)).
  Previously, `/media/...` was only served when `DJANGO_DEBUG=true` — meaning
  company logos, favicons, form logos, and integration icons would silently
  404 in any real deployment. Production now serves `MEDIA_URL` directly
  while explicitly continuing to block `media/uploads/` at the routing level
  (submitted files remain reachable only through the authorization-checked
  `FileUploadDownloadView`). Verified with `manage.py check` under
  `DJANGO_DEBUG=false` and by exercising both routes through Django's test
  client.

Left untouched, deliberately:

- **Dockerfile's `python:3.11-slim-bullseye` base image.** The documented
  local baseline is Python 3.13, but the Dockerfile's Debian bullseye pin is
  tied to the Microsoft ODBC 17 repository configuration in the same file —
  changing the base image means also revalidating that repo config, and there
  was no Docker daemon available in this environment to test a rebuild. 3.11
  is a fully supported runtime for every pinned dependency; treat bumping the
  base image as a separate, tested change if you want local/production
  parity.
