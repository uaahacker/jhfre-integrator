# JHFRE Integrator

## Overview

JHFRE Integrator is a server-rendered Django application for dynamic forms,
protected submissions and uploads, managed integrations, external database
workflows, webhooks, user administration, and OIDC/SAML single sign-on.

## Technology Stack

- Python 3.13.x local runtime baseline; Django 5.1
- DjangoTemplates, Bootstrap, and Metronic HTML Demo 1 assets
- Vanilla JavaScript with Fetch/AJAX where a page needs an endpoint
- Django ORM; SQLite local fallback and PostgreSQL through `DATABASE_URL`
- Django session authentication, with OIDC and SAML SSO

This is not a React, Vue, Angular, Vite, or single-page application.

## Main Applications

- `core` — project settings, URLs, middleware, and shared configuration
- `accounts` — user profile and account settings
- `integrator` — forms, submissions, uploads, integrations, external database
  features, procedures, webhooks, and administration
- `sso_auth` — active OIDC/SAML provider configuration and authentication
- `saml_auth` — legacy migration-history dependency; not active runtime SSO

## Quick Local Setup

Create a Python 3.13 virtual environment, install dependencies, and provide
the required process environment. `.env.example` records variable names but is
not loaded automatically.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

$env:DJANGO_DEBUG="true"
$env:DJANGO_ALLOWED_HOSTS="127.0.0.1,localhost"
$env:DJANGO_SECRET_KEY="<local-development-secret>"
$env:DJANGO_ENCRYPTION_KEY="<existing-valid-fernet-key>"
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
```

For a brand-new local database only, initialize its schema deliberately:

```powershell
python manage.py migrate
python manage.py runserver
```

`migrate` changes the selected database. Read [Local development](docs/development.md)
before running it against an existing or shared database.

## Environment Variables

`DJANGO_SECRET_KEY` and `DJANGO_ENCRYPTION_KEY` are required at startup.
`DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`, and `DATABASE_URL` control runtime
configuration. Keep `DATABASE_URL` unset for local SQLite development. See
[development](docs/development.md) and [.env.example](.env.example).

## Configuration Model

Three separate places hold configuration, and each has a different owner:

### Deployment configuration — environment variables

Server/host-wide settings that apply to every request regardless of which SSO
provider is active: secrets, debug mode, allowed hosts, CSRF trusted origins,
session cookie policy, HTTPS/proxy/HSTS settings, and the database URL. Set
through the process environment or a deployment secret store. See
[.env.example](.env.example) and [deployment](docs/deployment.md).

### Provider configuration — SSO Management UI

Everything specific to one SAML or OIDC identity provider: IdP metadata,
entity IDs, endpoints, bindings, certificates, identity policy, attribute
mappings, and signature requirements. Configured by a superuser at
`/sso/management/`, never in `.env` or source code. See [SSO](docs/sso.md).

### Persistent application configuration — database

Provider records, encrypted provider secrets/private keys, SSO audit logs,
integration credentials, and application users are stored in the database and
survive application restarts. Restarting Django never requires re-entering
provider configuration.

| Need to configure | Where |
|---|---|
| Django secret key | Environment |
| Encryption key | Environment |
| Database URL | Environment |
| Allowed hosts | Environment |
| CSRF trusted origins | Environment |
| HTTPS/proxy/session cookie policy | Environment |
| SAML IdP | SSO Management UI |
| OIDC provider | SSO Management UI |
| Attribute mapping | SSO Management UI |
| SSO certificates | SSO Management UI |
| Integration credentials | Product UI / encrypted DB |
| Application users | Product UI / DB |

Adding a supported SAML/OIDC provider after deployment should normally
require **no source-code changes** — see [Adding a New SAML Provider After
Deployment](docs/sso.md#adding-a-new-saml-provider-after-deployment).

## Run the Application

```powershell
.\.venv\Scripts\python.exe manage.py runserver
```

Open <http://127.0.0.1:8000/>.

## Testing

Use Django's test runner only. It creates a disposable test database; do not
point local test runs at an external database or run historical root scripts.

```powershell
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run
.\.venv\Scripts\python.exe manage.py test
```

See [testing](docs/testing.md) for focused suites and database safety.

## Deployment

Production requires `DEBUG=false`, stable secrets, approved PostgreSQL
`DATABASE_URL`, allowed hosts, HTTPS/proxy configuration, controlled
migrations, `collectstatic`, and a rule that denies direct `/media/uploads/`
access. See [deployment](docs/deployment.md).

## Important Security Notes

Secrets are environment-managed and encrypted values require a stable Fernet
key. Administrative functions are server-authorized. Submitted files are
protected, SQL is read-only constrained, stored procedures are approval-gated,
and user-facing “My Submissions” is intentionally disabled because submissions
have no ownership relation. See [security](docs/security.md).

## Documentation

- [Project structure and contribution map](docs/project-structure.md)
- [Architecture](docs/architecture.md)
- [Local development](docs/development.md)
- [Frontend](docs/frontend.md)
- [Integrations](docs/integrations.md)
- [Database and migrations](docs/database.md)
- [Single sign-on](docs/sso.md)
- [Security](docs/security.md)
- [Testing](docs/testing.md)
- [Deployment](docs/deployment.md)
- [Coolify deployment guide](docs/coolify-deployment.md)
- [Operations](docs/operations.md)
- [Troubleshooting](docs/troubleshooting.md)
