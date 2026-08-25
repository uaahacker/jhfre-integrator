# Deploying to Coolify

This is the authoritative production deployment procedure for JHFRE
Integrator on Coolify, targeting `https://jhfre.vihub.site`. It assumes the
source code is reachable from a Git remote Coolify can pull from (handled
outside this document).

Read [deployment.md](deployment.md) and [operations.md](operations.md) too —
this document is the Coolify-specific, end-to-end walkthrough; those cover
the same environment-variable contract in more general terms.

## 1. Architecture overview

```text
GitHub repository
        |
        v
      Coolify
        |
        +--> Django Application (this repo's Dockerfile)
        |      Gunicorn, core.wsgi:application
        |      Listens internally on 8001
        |
        +--> PostgreSQL 16 -- separate Coolify resource
        |      Persistent volume, managed independently
        |      Private/internal network only, port 5432 never public
        |
        +--> Coolify Proxy (Traefik) -- HTTPS termination
               |
               v
        https://jhfre.vihub.site
```

PostgreSQL does **not** run inside the Django application container, and
production does **not** use `docker-compose.yml` to get a database —
`docker-compose.yml` in this repo is a local-development convenience only
(§19). Coolify creates PostgreSQL as its own resource and the application
receives its connection string as `DATABASE_URL` through Coolify's
environment variable UI, over Coolify's internal network.

## 2. Production components

| Component | What it is | Where it runs |
|---|---|---|
| Django application | This repository's `Dockerfile`, Gunicorn, `core.wsgi:application` | Coolify "Application" resource, internal port `8001` |
| PostgreSQL 16 | Primary application database | Separate Coolify "PostgreSQL" resource, persistent volume, internal network only |
| Reverse proxy / TLS | Coolify's built-in Traefik proxy | Fronts the application container, terminates HTTPS for `jhfre.vihub.site` |
| Static files | Collected at boot into `staticfiles/`, served by WhiteNoise | Inside the application container (ephemeral, regenerated every boot — see §15) |
| Media / uploads | `media/` on disk (logos, favicons, submitted files) | Needs a persistent volume — see §16 |
| SSO provider config | SAML/OIDC provider records, encrypted secrets | Stored in PostgreSQL, managed at `/sso/management/` — never in environment variables |

## 3. Prerequisites

- A Coolify project/server ready to receive resources.
- This repository connected to Coolify as a Git source (GitHub App, or a
  deploy key + Git URL) — see §4.
- DNS control for `jhfre.vihub.site` — see §11.
- Nothing in `.env` is loaded automatically by the application
  ([README.md](../README.md#environment-variables)); every real value below
  is entered directly into Coolify's environment variable UI.

## 4. GitHub repository preparation

1. Confirm the repository is pushed to the GitHub remote Coolify will use
   (this repo's own git setup/remote is managed outside this document).
2. Confirm `.gitignore` still excludes `.env`, `db.sqlite3`, `.venv/`,
   `staticfiles/`, and `media/uploads/` (it does — see the repo root
   `.gitignore`). Never commit a real `.env` file, secrets, or database
   dumps.
3. In Coolify: **New Resource → Application → GitHub** → select this
   repository and the `main` branch.
4. **Build Pack: Dockerfile.** Do not use Nixpacks or any Django
   auto-detection build pack — this application has native OS dependencies
   (ODBC, XML/SAML toolchain) that only the repository's own `Dockerfile`
   installs reproducibly.
   - Base Directory: `/`
   - Dockerfile Location: `/Dockerfile`
   - Internal application port: `8001`

## 5. Docker image architecture

The `Dockerfile`:

1. Starts from `python:3.11-slim-bullseye` (Debian 11 — pinned so the
   Microsoft ODBC 17 apt repository configuration matches; see §6).
2. Installs OS packages: build tools, the ODBC/PostgreSQL client toolchain,
   and the XML/SAML native toolchain (§6).
3. Installs Python dependencies from `requirements.txt`, forcing `lxml` and
   `xmlsec` to build from source (§6) — this is the fix for the
   `lxml & xmlsec libxml2 library version mismatch` failure (§27).
4. **Fails the build** if the XML/SAML stack doesn't import correctly
   (§6) — a broken SAML stack is caught at `docker build` time, not at the
   first login attempt in production.
5. Copies the application, makes `entrypoint.sh` executable, `EXPOSE 8001`,
   and runs `entrypoint.sh` as the container command.

Build it directly with:

```bash
docker build -t jhfre-integrator .
```

## 6. Native dependencies

This application is not a plain Django app — it depends on:

- **PostgreSQL** (`psycopg2-binary`) — primary application database.
- **Microsoft SQL Server** (`pyodbc` + the Microsoft ODBC 17 driver,
  installed from Microsoft's apt repo in the Dockerfile) — used for
  external-database integration features, not the application's own DB.
- **SAML** (`python3-saml`, which depends on `lxml` and `xmlsec`) — used by
  the active `sso_auth` app for SAML 2.0 SSO.

### The `lxml`/`xmlsec` fix

**Symptom** (previously encountered):

```text
xmlsec.InternalError: (-1, 'lxml & xmlsec libxml2 library version mismatch')
```

**Root cause**: `lxml` (pinned `lxml==5.3.0` in `requirements.txt`) publishes
a `manylinux` wheel that bundles its **own statically-linked libxml2**.
`xmlsec` (pinned `xmlsec==1.3.17`, the `pyxmlsec` binding) builds against the
**system** `libxmlsec1`, which itself links the **system** `libxml2`. If
`pip install` takes the prebuilt `lxml` wheel while `xmlsec` builds against a
different (system) `libxml2`, the two extensions disagree about the ABI of
the `libxml2` structures they pass to each other — `python3-saml` hits this
the moment it uses both together (parsing and then signing/verifying an XML
document), and it fails at SAML runtime, not at install time.

**Fix**, both parts required together, already applied in the `Dockerfile`:

1. Install the matching apt packages so a system `libxml2`/`libxmlsec1`
   exists to build against:
   ```text
   pkg-config libxml2-dev libxslt1-dev libxmlsec1-dev libxmlsec1-openssl zlib1g-dev
   ```
2. Force **both** `lxml` and `xmlsec` to build from source against that same
   system `libxml2`, instead of letting `lxml` take its prebuilt wheel:
   ```dockerfile
   RUN pip install --upgrade pip && \
       PIP_NO_BINARY=lxml,xmlsec pip install --no-cache-dir -r requirements.txt
   ```
3. Fail the build immediately if it's still broken:
   ```dockerfile
   RUN python -c "import xmlsec; from lxml import etree; print('XML stack OK - libxml2', etree.LIBXML_VERSION, '- xmlsec', xmlsec.__version__)"
   ```

If `requirements.txt`'s `lxml`/`xmlsec` pins are ever changed, re-verify this
still holds — the fix is about matching build toolchains, not about these
specific version numbers, but a very old/new pairing could still have its
own incompatibilities upstream.

### ODBC / PostgreSQL client tooling

Already handled by the Dockerfile and unaffected by the above: Microsoft's
apt repo provides `msodbcsql17`, and PostgreSQL's PGDG apt repo provides
`postgresql-client-16` (used for `pg_dump`/`psql`, e.g. by the
development-only `SYNC_DB_FROM_PROD` entrypoint feature). Nothing here needs
manual installation on the Coolify host — a fresh server deploys entirely
from this repository's `Dockerfile`.

## 7. PostgreSQL setup

1. In Coolify: **New Resource → Database → PostgreSQL → version 16.**
2. Enable persistent storage (Coolify does this by default for database
   resources) — verify a volume is attached before first use.
3. Keep it on Coolify's internal/private network. **Do not** expose port
   `5432` publicly, and do not create any public port mapping for it.
4. Copy the resource's **internal** connection string. It will look like:
   ```text
   postgresql://USER:PASSWORD@<internal-hostname>:5432/<database>
   ```
   The `<internal-hostname>` is Coolify's private network name for the
   resource (e.g. a service name resolvable only within Coolify's Docker
   network) — **never** the server's public IP, `localhost`, or `127.0.0.1`.
5. Paste that string as the application's `DATABASE_URL` (§9). Do not reuse
   this database for anything else — `AUTO_MIGRATE` and manual `migrate`
   runs mutate it directly.

`core/settings.py` parses `DATABASE_URL` with `dj_database_url.parse(...)`,
which accepts the standard `postgresql://` scheme Coolify generates; no code
changes are needed for this to work.

## 8. Coolify application setup

Recap of §4, as a checklist for the Application resource:

```text
Resource type:      Application
Git source:         GitHub
Repository:         this repository
Branch:              main
Build Pack:          Dockerfile
Base Directory:      /
Dockerfile Location: /Dockerfile
Internal port:       8001
```

## 9. Environment variables

Set these on the Application resource in Coolify's **Environment Variables**
tab — never in a file in the repository. `.env`/`.env.example` in this repo
are documentation only and are not loaded by the running application.

### Required — application will not start without valid values

| Variable | Example / value | Notes |
|---|---|---|
| `DJANGO_SECRET_KEY` | a real secret | Generate once, keep **stable** across redeploys — §10 |
| `DJANGO_ENCRYPTION_KEY` | a valid Fernet key | Generate once, keep **stable** — §10 |
| `DJANGO_ALLOWED_HOSTS` | `jhfre.vihub.site` | Comma-separated hostnames only, no scheme |
| `DATABASE_URL` | from §7 | Internal PostgreSQL URL |

### Required for this deployment's topology

| Variable | Value | Why |
|---|---|---|
| `APP_ENV` | `production` | Image default is `development` — must be set explicitly (§6/Dockerfile) |
| `PORT` | `8001` | Must match the Dockerfile `EXPOSE` and Coolify's configured internal port |
| `DJANGO_DEBUG` | leave unset (defaults `false`) | Never `true` in production |
| `DJANGO_TRUST_X_FORWARDED_PROTO` | `true` | Coolify's Traefik terminates TLS in front of the container |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | `https://jhfre.vihub.site` | This proxy topology needs it — see §11/§12 |
| `AUTO_MIGRATE` | `true` (recommended) | See §13/§14 for the reasoning |

### Required only if SAML is used (§17)

| Variable | Value | Why |
|---|---|---|
| `DJANGO_SESSION_COOKIE_SAMESITE` | `None` | A cross-site SAML ACS POST needs the session cookie to survive it |
| `DJANGO_SESSION_COOKIE_SECURE` | `true` | Required together with `SameSite=None` — startup fails closed otherwise |

If SAML is not used, leave both unset (defaults `Lax`/`false`).

### Optional, enable once HTTPS/hostnames are confirmed stable

| Variable | Notes |
|---|---|
| `DJANGO_SECURE_SSL_REDIRECT` | `true` to force HTTP→HTTPS at the Django layer (Coolify's proxy may already do this) |
| `DJANGO_ENABLE_HSTS` (+ `DJANGO_HSTS_INCLUDE_SUBDOMAINS`, `DJANGO_HSTS_PRELOAD`) | Enable only after HTTPS is verified working end-to-end |
| `SSO_FORCE_HTTPS` | Defaults to `true` automatically once `DJANGO_DEBUG` is false — only set explicitly to override |

### Optional, deployment-specific one-shots

| Variable | Notes |
|---|---|
| `SUPERUSER_ON_BOOT` + `DJANGO_SUPERUSER_USERNAME`/`_EMAIL`/`_PASSWORD` | One-time initial admin creation — unset all four again after use |
| `EXTERNAL_DB_PROCEDURE_*` | Optional bounds on external stored-procedure execution — see `.env.example` |

### Never set in production

`DEV_RESET_DB`, `SYNC_DB_FROM_PROD`, `PROD_DATABASE_URL` — development-only,
no-op outside `APP_ENV=development`.

### Not environment variables at all

SAML/OIDC provider configuration (IdP metadata, entity IDs, certificates,
attribute mappings) is **not** environment configuration — it is created and
edited by a superuser at `/sso/management/` and stored encrypted in
PostgreSQL. Adding or changing a provider never requires an environment
variable change or a redeploy. Do not convert provider settings into env
vars — that would fight the application's actual architecture. See
[sso.md](sso.md).

## 10. Secrets management

Store all secrets in Coolify's Environment Variables/Secrets for the
Application resource. Never commit `.env`, real secret values, database
passwords, or SSO provider secrets — `.gitignore` and `.dockerignore` both
already exclude `.env*` (except the placeholder `.env.example`) and
`db.sqlite3` from git and from the Docker build context respectively.

Generate the two required secrets once, and paste the output into Coolify
(don't let anything auto-generate a new value on every redeploy):

```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"          # DJANGO_SECRET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # DJANGO_ENCRYPTION_KEY
```

**`DJANGO_SECRET_KEY` must stay stable** across restarts and redeploys —
Django signs session cookies with it; changing it invalidates every existing
session (users get logged out; this is expected signature-verification
behavior, not a bug to fix in code).

**`DJANGO_ENCRYPTION_KEY` must stay stable** — SSO provider secrets and
integration credentials are encrypted at rest in PostgreSQL with this Fernet
key. Changing it makes all previously stored encrypted values permanently
undecryptable. There is no "rotate and re-encrypt" button; rotating this key
requires a planned migration you write yourself, decrypting with the old key
and re-encrypting with the new one before the old key is discarded.

## 11. Domain and DNS

Production domain: **`jhfre.vihub.site`**.

Point DNS for `jhfre.vihub.site` at the Coolify server's IP address (an `A`
record, or `CNAME` per your DNS provider's conventions for that server).
Coolify's proxy handles routing once the domain resolves and is attached to
the Application resource.

## 12. HTTPS / reverse proxy

```text
Internet --HTTPS:443--> Coolify Proxy (Traefik) --HTTP:8001--> Django container
```

- Attach `jhfre.vihub.site` to the Application resource in Coolify and let
  it issue/manage the TLS certificate (Let's Encrypt via Traefik).
- This repository contains no nginx/Apache config — if a reverse proxy
  terminates TLS in front of the app, `DJANGO_TRUST_X_FORWARDED_PROTO=true`
  is what tells Django to trust the `X-Forwarded-Proto` header from that
  trusted proxy (`core/settings.py` only sets `SECURE_PROXY_SSL_HEADER` when
  this is explicitly enabled — it is never assumed).
- `DJANGO_ALLOWED_HOSTS=jhfre.vihub.site` and
  `DJANGO_CSRF_TRUSTED_ORIGINS=https://jhfre.vihub.site` must both name the
  exact production hostname, or Django will reject the request (host header
  validation) or same-origin POSTs (CSRF) respectively.
- Session cookie policy (`DJANGO_SESSION_COOKIE_SAMESITE`/`_SECURE`) is
  independent of `DJANGO_DEBUG` and must be set correctly for whether SAML
  is in use — see §9/§17.

## 13. Initial deployment

1. Complete §4–§11 (repository connected, PostgreSQL provisioned, env vars
   set, domain attached).
2. Trigger the first deploy.
3. `entrypoint.sh` will, in order: print diagnostics, refuse to start if
   `DATABASE_URL` is unset, run `collectstatic`, check database
   connectivity, then apply migrations (because `AUTO_MIGRATE=true` per
   §9/§14), then start Gunicorn.
4. Watch the deploy logs for the `XML stack OK` build-time line (§6) and the
   migration output at boot.

## 14. Database migrations

**Chosen approach for this deployment: A — `entrypoint.sh` applies
migrations automatically via `AUTO_MIGRATE=true`.**

Why this is the safe choice here, not just the convenient one: this is a
single-environment Coolify deployment where `entrypoint.sh` *is* the release
step (there's no separate CI/CD release pipeline in front of it), and the
entrypoint's production migration failure handling has been hardened
specifically to make this safe —

```text
database available
        |
        v
  migrations (AUTO_MIGRATE=true)
   |
   +--> success --> start Gunicorn
   |
   +--> failure --> container exits non-zero, Gunicorn never starts
```

Previously, a failed migration in the production/staging path only logged a
warning and continued to start Gunicorn anyway — against a
partially-migrated database. `entrypoint.sh` now `exit`s with the
migration's own failure code in that case, so Coolify sees the deploy fail
instead of serving traffic against a broken schema. (The **development**
boot path intentionally keeps its more lenient "continue anyway" behavior —
that's an explicit, separate code path, not an oversight.)

If you'd rather apply migrations as a deliberate, separate release step
instead (**option B**) — e.g. once multiple environments or a CI/CD pipeline
are introduced — set `AUTO_MIGRATE=false` and, per deploy that has new
migrations, run manually via Coolify's terminal/exec on the running
container:

```bash
python manage.py showmigrations
python manage.py migrate
```

Either way: **before any migration that changes schema**, back up the
database (§20) and verify restore capability first.

## 15. Static files

`STATIC_ROOT` is `staticfiles/`, source assets are in `static/`. WhiteNoise
(already in `requirements.txt` and wired into `MIDDLEWARE` outside `DEBUG` in
`core/settings.py`) serves collected static assets directly from the
container — no separate static file server or CDN is required for this to
work.

`entrypoint.sh` already runs this on every boot:

```bash
python manage.py collectstatic --noinput
```

`staticfiles/` does not need a persistent volume — it's fully regenerated
from `static/` on every container start.

## 16. Media / user uploads

**Containers are disposable — the application container's filesystem is not
durable storage.** Anything written to `media/` while the container is
running (company logo/favicon uploads, submitted form files) is lost on the
next redeploy or restart unless it lives on a volume.

Current architecture: `MEDIA_ROOT` is local disk (`media/`), split into:

- Public branding assets (`company_logos/`, `company_favicons/`,
  `form_logos/`, `integration_icons/`) — served at `MEDIA_URL` in
  production (see the media-routing fix documented in §27's history).
- Protected submission uploads (`media/uploads/`) — served **only** through
  the authorization-checked `FileUploadDownloadView`, never as a direct
  static path; production routing explicitly 404s any direct
  `/media/uploads/...` request.

**Minimum requirement for this deployment**: attach a persistent volume to
the Application resource, mounted at the container path:

```text
/app/media
```

**For more serious production use**, consider migrating `MEDIA_ROOT` to
object storage (e.g. AWS S3) via `django-storages`, which is already listed
in `requirements.txt` but is **not currently configured** in
`core/settings.py` (no `STORAGES`/`DEFAULT_FILE_STORAGE` setting exists).
This would remove the dependency on any single container's/volume's disk
entirely and is the more scalable long-term answer, but it is a real
architecture change — it needs explicit design (bucket, credentials, how the
protected-download view continues to enforce authorization against
object-storage URLs) before implementing, not a silent swap. This document
flags it as a recommendation, not something already implemented.

## 17. SAML / OIDC configuration

The active SSO implementation is `sso_auth` (SAML 2.0 + OIDC). The legacy
`saml_auth` app is **not** active — its URLs are commented out in
`core/urls.py`, and it is kept installed only because an `sso_auth`
migration depends on its migration history. Do not re-enable or rely on it.

Provider configuration (SAML IdP metadata, OIDC client credentials,
certificates, attribute mappings) is created and managed entirely through
`/sso/management/` by a superuser, stored encrypted in PostgreSQL — see
[sso.md](sso.md) and `sso_auth/README.md`. Nothing here requires environment
variables or a redeploy to add a new provider.

**Environment requirements for SAML specifically** (§9): a cross-site SAML
ACS POST (IdP → browser → Django) needs the session cookie to survive that
cross-site POST, which requires:

```env
DJANGO_SESSION_COOKIE_SAMESITE=None
DJANGO_SESSION_COOKIE_SECURE=true
```

served over real HTTPS, with `DJANGO_TRUST_X_FORWARDED_PROTO=true` behind
Coolify's proxy. `core/settings.py` fails closed at startup if
`SameSite=None` is set without `Secure=true`.

**Post-deployment validation** (also in §26's checklist) — actually exercise
each of these, don't assume they work because the config was saved:

- Normal Django (non-SSO) login and logout.
- SAML login: initiate from `/sso/saml/login/<provider>/`, confirm the IdP
  redirect, confirm the ACS POST back to `https://jhfre.vihub.site/...`
  completes and creates/updates the user correctly (NameID, email, first
  name, last name mapped as configured).
- SAML logout (SLO) if configured.
- OIDC login: initiate, confirm the authorization redirect, confirm the
  callback exchanges the code and logs the user in with correct claims.
- Confirm session behavior matches the `SameSite`/`Secure` configuration
  above — a login that silently fails to persist a session is usually a
  cookie policy mismatch, not an IdP problem.

## 18. Health checks

`GET /healthz/` — added in this repository specifically for container
platform health checks. It returns a plain `200 OK "ok"` and deliberately
does **not** query the database, so a transient database hiccup doesn't get
a healthy application container killed by the platform. Database
reachability is verified separately, at boot, by `entrypoint.sh`'s
connectivity check and by migrations.

Configure Coolify's health check to `GET /healthz/` on the internal port
`8001`. Do not rely on "the process is running" alone — a Python process can
be alive while Gunicorn workers are wedged; hitting the actual HTTP endpoint
is the real test.

## 19. Local development

Two options, both still supported and neither required for production:

1. **Plain `runserver`** (the primary day-to-day workflow — see
   [README.md](../README.md#quick-local-setup) and
   [development.md](development.md)): SQLite by default, or point
   `DATABASE_URL` at a local/dev PostgreSQL if you need parity.
2. **`docker-compose.yml`** (new, this pass): brings up the actual
   production `Dockerfile` image plus a local PostgreSQL 16 container, for
   testing the real image locally:
   ```bash
   docker compose up --build
   ```
   This is a **local convenience only** — Coolify does not read this file,
   and production PostgreSQL is never the `docker-compose.yml` database
   resource. Its credentials are fixed, non-secret, local-only placeholders
   committed on purpose; never reuse them.

## 20. Backups

- **Database**: PostgreSQL is Coolify-managed with persistent storage (§7).
  Configure Coolify's backup feature for the PostgreSQL resource (scheduled
  dumps to Coolify's configured backup storage) — at minimum, define a
  schedule and a retention window appropriate to how much data loss would be
  acceptable. A backup that has never been restored is not a verified
  recovery plan: periodically actually restore a backup (to a scratch
  database, not production) and confirm the application boots against it.
- **Media volume**: back up the `/app/media` persistent volume (§16)
  separately from the database — it holds branding assets and submitted
  files that a database-only backup would not capture.
- **Secrets**: `DJANGO_SECRET_KEY` and `DJANGO_ENCRYPTION_KEY` are not in
  the database or the volume — they only exist in Coolify's environment
  variable store. Losing them without a separate record is equivalent to
  losing the ability to decrypt existing SSO/integration secrets and
  invalidating all sessions. Keep a copy in whatever secret store your team
  already uses outside Coolify.
- **Scaling beyond Coolify's managed Postgres**: because the application
  only ever consumes a `DATABASE_URL` connection string
  (`dj_database_url.parse(...)` in `core/settings.py`), migrating to a
  managed PostgreSQL provider (e.g. AWS RDS) later requires no Django
  application changes — only provisioning the new database, migrating the
  data, and updating `DATABASE_URL`.

## 21. Redeployment procedure

1. Push/merge to the branch Coolify is watching (`main`), or trigger a
   manual deploy in Coolify.
2. Coolify rebuilds the image from `Dockerfile` (§5–§6) — the build fails
   fast if the XML/SAML stack breaks (§6).
3. `entrypoint.sh` runs `collectstatic`, checks DB connectivity, applies
   migrations (fatal on failure — §14), then starts Gunicorn.
4. Confirm `/healthz/` and the actual site load correctly (§26).

## 22. Rollback procedure

1. In Coolify, redeploy the previous known-good image/commit for the
   Application resource.
2. If the failed deploy applied a new migration, verify whether the
   previous application version is still compatible with the now-migrated
   schema before rolling back the app alone — Django migrations are not
   automatically reversible in production without a plan. If the schema
   change is incompatible with the older app version, restore the database
   from the pre-migration backup (§20) as part of the rollback, not just the
   application image.
3. Re-verify with the checklist in §26 after rolling back.

## 23. Updating environment variables

1. Edit the variable(s) in Coolify's Environment Variables tab for the
   Application resource.
2. Redeploy/restart the Application resource so the new values take effect
   (environment variables are read at process start, in `core/settings.py`
   and `entrypoint.sh` — nothing in this application hot-reloads env vars).
3. Never change `DJANGO_SECRET_KEY` or `DJANGO_ENCRYPTION_KEY` as a routine
   update — see §10 for what breaks.

## 24. Updating the database schema

Follow §14's chosen procedure (A: `AUTO_MIGRATE=true`, hardened to fail
closed) for every deploy that includes new migrations. For any migration
that is non-trivial (data migration, column type change, anything not
purely additive):

1. Back up the database (§20) and verify the backup restores.
2. Review `python manage.py showmigrations` and the migration's own code —
   `makemigrations --check --dry-run` locally beforehand to confirm nothing
   unexpected is pending.
3. Deploy. `entrypoint.sh` now aborts the container if the migration fails,
   so a bad migration does not silently leave the app serving against a
   half-migrated schema.
4. Verify via §26.

## 25. Production security checklist

```text
[ ] DJANGO_DEBUG unset/false
[ ] DJANGO_SECRET_KEY set, real, stable across redeploys
[ ] DJANGO_ENCRYPTION_KEY set, real, stable across redeploys
[ ] DJANGO_ALLOWED_HOSTS = jhfre.vihub.site (exact hostname, no wildcards)
[ ] DJANGO_CSRF_TRUSTED_ORIGINS = https://jhfre.vihub.site
[ ] DJANGO_TRUST_X_FORWARDED_PROTO=true (Coolify proxy topology)
[ ] Session cookie SameSite/Secure correctly set for SAML usage (if used)
[ ] PostgreSQL port 5432 not publicly exposed
[ ] DATABASE_URL uses Coolify's internal hostname, not a public address
[ ] No secrets committed to git (.gitignore/.dockerignore verified)
[ ] /media/uploads/ confirmed NOT directly downloadable (404 via routing)
[ ] SUPERUSER_ON_BOOT and superuser vars unset after any one-time use
[ ] DEV_RESET_DB / SYNC_DB_FROM_PROD / PROD_DATABASE_URL unset in production
```

## 26. Post-deployment verification checklist

```text
[ ] Docker image builds successfully
[ ] xmlsec imports successfully during build (XML stack OK line in build log)
[ ] PostgreSQL resource running, persistent volume attached
[ ] DATABASE_URL points to the internal PostgreSQL resource
[ ] Migrations completed (entrypoint log, or manual `showmigrations`)
[ ] collectstatic completed without error
[ ] Gunicorn started using core.wsgi:application
[ ] Application listens on internal port 8001
[ ] Coolify reports the application healthy (GET /healthz/)
[ ] jhfre.vihub.site resolves to the Coolify server
[ ] HTTPS certificate valid for jhfre.vihub.site
[ ] Login page loads
[ ] Normal Django (non-SSO) login works
[ ] SAML login works (§17)
[ ] OIDC login works (§17)
[ ] SAML ACS POST completes and creates/updates the user correctly
[ ] Logout works (normal and SSO)
[ ] Static assets load (no 404s in browser devtools)
[ ] Company logo/branding image renders (exercises production media routing)
[ ] Uploaded files persist across a redeploy (media volume attached — §16)
[ ] Database survives an application redeploy (separate resource, as designed)
[ ] Secrets survive a redeploy (Coolify env vars, unchanged)
[ ] Backup schedule configured for PostgreSQL (§20)
[ ] A backup restore has actually been tested at least once (§20)
```

## 27. Common failures and fixes

### Wrong WSGI module

```text
Bad:     gunicorn config.wsgi:application
Correct: gunicorn core.wsgi:application
```

This repository's project package is `core`, not `config` — `entrypoint.sh`
already invokes `gunicorn core.wsgi:application` correctly. If you ever see
a `config.wsgi` reference anywhere (a copied snippet, an old note), it's
wrong for this repository.

### Missing `DATABASE_URL`

```text
!! DATABASE_URL is not set. Exiting.
```

`entrypoint.sh` refuses to boot without it, by design. Fix: provision the
PostgreSQL resource (§7) and set its internal connection string as
`DATABASE_URL` on the Application resource.

### `lxml`/`xmlsec` mismatch

```text
xmlsec.InternalError: (-1, 'lxml & xmlsec libxml2 library version mismatch')
```

Root cause and fix: §6. If this recurs after a dependency version bump,
confirm the `Dockerfile` still installs the `libxml2-dev`/`libxmlsec1-dev`
toolchain and still forces `PIP_NO_BINARY=lxml,xmlsec` — and confirm the
build-time `import xmlsec; from lxml import etree` check is still present
and still passing in the build log.

### Wrong application port

The container listens internally on `8001` (`EXPOSE 8001` in the
`Dockerfile`, `PORT` defaulting to `8001` in `entrypoint.sh`). The Coolify
Application resource's internal port and health check must both target
`8001` — if either is misconfigured (e.g. left at Coolify's `3000` default),
the proxy will report the app unreachable even though it's running fine.

### Database networking

```text
Do NOT use: localhost / 127.0.0.1 / the server's public IP
Use:        the PostgreSQL resource's internal Coolify hostname/URL
```

The application and the database resource are separate containers on
Coolify's internal network — `localhost` inside the app container is the app
container itself, not the database. Copy the exact internal connection
string Coolify generates for the PostgreSQL resource (§7).

### Migration failure at boot

Previously silent (`entrypoint.sh` logged a warning and started Gunicorn
anyway). Now: a migration failure in the production/staging boot path exits
the container non-zero and Gunicorn never starts (§14). If a deploy fails
here, check the migration output in the Coolify deploy logs, fix the
migration, and redeploy — do not work around this by disabling
`AUTO_MIGRATE` without also arranging to run `migrate` manually before
traffic reaches the new version.

## History: what was fixed in this repository for Coolify readiness

Kept for context — these were already applied, not something you need to
redo:

- `requirements.txt` re-saved as UTF-8 (was UTF-16, a Windows PowerShell
  editing artifact).
- Added `.dockerignore` so a direct local `docker build .` can't bake
  `.venv`, `db.sqlite3`, or `.env` into an image layer.
- Fixed public media routing so company logos/favicons/icons render outside
  `DJANGO_DEBUG` (§16), while `media/uploads/` stays blocked at the routing
  level.
- Added the `lxml`/`xmlsec` native-dependency fix and a build-time
  validation step to the `Dockerfile` (§6).
- Hardened `entrypoint.sh` so a failed production/staging migration aborts
  the container instead of starting Gunicorn against a broken schema (§14).
- Added `GET /healthz/` (§18).
- Documented all `entrypoint.sh`-level variables (`APP_ENV`, `PORT`,
  `AUTO_MIGRATE`, superuser bootstrap, dev-only sync/reset vars) in
  `.env.example`, which previously covered only Django-level settings.
- Added `docker-compose.yml` for local development only (§19).

Left untouched, deliberately: the Dockerfile's `python:3.11-slim-bullseye`
base image. The documented local baseline is Python 3.13, but the
Dockerfile's Debian bullseye pin is tied to the Microsoft ODBC 17 repository
configuration in the same file; changing the base image means also
revalidating that repo config end-to-end in a real build, which this
environment cannot do (no Docker daemon available here — see the
Validation section of the completion report). Treat a base-image bump as a
separate, tested change.
