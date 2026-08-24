# Architecture

JHFRE Integrator is a Django 5.1, server-rendered application with a Python
3.13 local-runtime baseline. It uses DjangoTemplates, Bootstrap, Metronic HTML
Demo 1 assets, and vanilla JavaScript. It is not a SPA or microservice system.

## Request flow

```text
Browser -> Django URL -> view -> Django template -> HTML/Bootstrap/Metronic
Browser JavaScript -> Django endpoint -> JSON response
```

`core.urls` mounts `accounts` and `integrator` at the root and the active SSO
application, `sso_auth`, below `/sso/`. Django admin is at `/admin/`.
`integrator` views provide most business workflows; `accounts` provides profile
screens; `sso_auth` provides provider management and sign-in callbacks.

## Database architecture

The Django application database uses local `db.sqlite3` when `DATABASE_URL` is
absent. `DATABASE_URL` selects the deployment database; production is intended
to use PostgreSQL. The Django ORM is used for application records.

External integration databases are separate from the application database.
They are configured through authorized integration views and have their own
credentials, connection types, query limits, SQL policy, and approved
procedure boundaries. They are never a substitute for Django's primary DB.

## Authentication

Django sessions authenticate local users. `sso_auth` adds OIDC and SAML. The
active provider must be both enabled and active. Identities are provider-plus-
subject based, not implicit email/username links. `saml_auth` is retained only
for historical migration compatibility; its routes are not mounted.

## Dynamic forms

```text
DynamicForm -> delivery policy -> FormSubmission -> optional FileUpload
                                             -> optional one-shot webhook
```

The form's configured delivery policy controls access. Upload validation runs
before records are saved. A protected application route, not direct media
exposure, delivers submitted files. Webhook delivery is controlled separately
from database work.

## Integration security boundaries

- **Application DB:** Django ORM data and migrations.
- **External DB:** separately configured credentials and constrained read/query
  or approved-procedure execution.
- **Stored procedures:** named, approved allowlist entries with a typed,
  validated parameter contract, bounds, and audit history.
- **Webhooks:** validated HTTPS targets with restricted headers, timeouts, no
  redirects, and bounded response metadata.

See [project structure](project-structure.md), [integrations](integrations.md),
and [security](security.md) for operational detail.
