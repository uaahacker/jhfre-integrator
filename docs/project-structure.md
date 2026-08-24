# Project structure

## Repository map

```text
project/
├── accounts/       User profile and account features
├── core/           Django project configuration and shared helpers
├── docs/           Operator and developer documentation
├── integrator/     Forms, submissions, integrations, external DBs, webhooks
├── saml_auth/      Legacy SAML migration-history application
├── sso_auth/       Active OIDC/SAML implementation
├── static/         Source static assets, including Metronic assets
├── templates/      DjangoTemplates HTML templates
├── .env.example    Variable-name reference; not loaded automatically
├── .gitignore      Excludes local environments, secrets, media uploads, output
├── Dockerfile      Container image definition
├── entrypoint.sh   Container startup and optional operational actions
├── manage.py       Django command entry point
├── pyproject.toml  Package metadata and optional development-tool settings
├── requirements.txt Pinned runtime dependency list
└── README.md       Project entry point
```

`db.sqlite3`, `media/`, `staticfiles/`, and `.venv/` are local/generated
artifacts and are intentionally ignored. Do not add one-off helper or debug
scripts at repository root.

## Major directories

### `accounts/`

Owns the Django `UserProfile` model, profile views and URLs, model signals,
admin registration, and account tests. Add an account-specific view in
`accounts/views.py`, its route in `accounts/urls.py`, its template under
`templates/pages/user-profile/` (or a focused account subdirectory), and a
test in `accounts/tests.py`.

### `core/`

Owns project-wide configuration:

- `settings.py` configures installed apps, DjangoTemplates, databases,
  static/media paths, upload limits, and security settings.
- `config.py` parses required secrets, booleans, hosts, and optional external
  file paths without source-controlled fallbacks.
- `urls.py` composes the active `accounts`, `integrator`, and `sso_auth`
  routes; `saml_auth` routes are not mounted.
- `middleware.py`, `image_upload_validation.py`, and `saml/` provide shared
  project behavior and legacy SAML support material.
- `tests/` contains global configuration and SAML-runtime tests.

Put a shared setting in `core/settings.py` and parsing/validation in
`core/config.py` when appropriate. Keep app-specific behavior in its app.

### `integrator/`

This is the main business application. Its models include `DynamicForm`,
`FormSubmission`, `FileUpload`, `Integration`, `IntegrationCredential`,
`DatabaseConnection`, `SavedQuery`, `ApprovedProcedure`,
`ApprovedProcedureParameter`, and `ProcedureExecutionAudit`.

`views.py` and `urls.py` provide dynamic-form delivery and management,
submission administration, protected file downloads, integration credentials,
external database configuration, saved queries, approved procedures, users,
and permission management. `tests.py` is the app-local automated suite.

Important helpers:

- `sql_policy.py` — conservative single read-only SELECT/read-only CTE policy.
- `query_execution.py` — external-query/procedure timeouts, limits, and
  read-only transaction support where the driver supports it.
- `procedure_execution.py` — approved-procedure identifiers, typed/bound
  parameters, and validation.
- `upload_validation.py` — configured-field, file count/type/size, and image
  validation for dynamic-form uploads.
- `webhook_security.py` — HTTPS/host validation and one-shot delivery policy.
- `webhook_headers.py` — header validation, masking, and sensitive-header
  encryption.
- `webhook_responses.py` — bounded response metadata without response bodies.
- `integration_credentials.py` — trusted field definitions and encrypted
  credential handling.
- `db_config.py` and `db_utils.py` — external database connection support.

Add new form, integration, SQL, procedure, upload, or webhook behavior here;
use the existing policy helpers rather than creating bypass paths.

### `sso_auth/`

The active SSO application. It owns provider forms, models, views, routes,
admin, tests, and templates. `secret_encryption.py` encrypts provider secrets,
`saml_replay.py` records hashed assertion identifiers for replay protection,
`utils.py` implements OIDC validation, provider/identity handling, and
minimal SSO audit data, `saml_post_binding.py` builds signed/unsigned
HTTP-POST AuthnRequests, and `saml_metadata_parser.py` securely parses pasted
IdP metadata XML for provider onboarding. See [SSO](sso.md).

### `saml_auth/`

**LEGACY / MIGRATION-HISTORY-REQUIRED.** This is not the primary active SAML
implementation: active SAML routes are under `sso_auth` and `/sso/`. It remains
installed because `sso_auth` migration `0002_migrate_saml_config` depends on
the `saml_auth` migration state and reads its historical configuration. Do not
remove this app or its migrations casually. Any retirement needs explicit
migration-state planning and a reviewed data strategy.

### `templates/`

DjangoTemplates HTML organized around `base.html`, shared `partials/`,
`pages/forms/`, `pages/integrations/`, `pages/Users/`,
`pages/configurations/`, `pages/user-profile/`, `pages/userside/`, and
`sso_auth/`. Active UI uses Metronic Demo 1, Bootstrap, and vanilla JavaScript.
Place a new page template next to its app/feature templates, extend
`base.html` when it needs the standard authenticated layout, and add only the
necessary script block behavior.

### `static/`

Contains source static CSS, JavaScript, fonts, images, and Metronic assets.
`collectstatic` copies these to `STATIC_ROOT` (`staticfiles/`). Static assets
are application code/assets; user uploads do **not** belong here.

### `docs/`

Contains the detailed guides linked by the README. Keep operational facts in
these files aligned with code and deployment configuration.

## Where do I add X?

| I want to add or change | Where to work |
|---|---|
| Django route | Target app `urls.py` and view |
| Page | App view, template under `templates/`, permissions, and test |
| JavaScript behavior | Existing template script block or focused `static/` JS |
| CSS | Project-specific styles under `static/` |
| Database model | Target app `models.py`, reviewed migration, and tests |
| Dynamic form behavior | `integrator/` and its tests |
| Integration or credential flow | `integrator/` and `integration_credentials.py` |
| External SQL read | `integrator/` using `sql_policy.py` and query limits |
| Stored-procedure approval | `integrator` approved-procedure architecture |
| SSO provider/configuration | `sso_auth/` |
| Account/profile feature | `accounts/` |
| Shared project setting | `core/settings.py` and `core/config.py` as needed |
| Automated test | Corresponding app test module/package |
| User upload | `integrator` upload-validation architecture |
| Webhook behavior | `integrator` webhook helpers |
| Documentation | `docs/` and this README index |
