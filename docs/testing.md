# Testing

## Safe automated verification

Use Django's test runner only. The old root-level manual `test_*.py`,
`debug_*.py`, and deployment/debug helpers were removed; they are not the
supported test interface and must not be recreated as a substitute.

For local safe testing, set required Django secrets and keep `DATABASE_URL`
unset. Django may create, write, and destroy a **disposable test database**;
it must not write the normal `db.sqlite3` or contact external databases,
providers, webhooks, or APIs.

```powershell
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run
.\.venv\Scripts\python.exe manage.py test
```

`check` and the migration-drift command are read-only. `test` is database
mutating only in Django's disposable test database.

## Fast smoke checks

```powershell
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run
```

## Focused app tests

```powershell
.\.venv\Scripts\python.exe manage.py test integrator
.\.venv\Scripts\python.exe manage.py test sso_auth
.\.venv\Scripts\python.exe manage.py test core.tests.test_config
.\.venv\Scripts\python.exe manage.py test core.tests.test_saml_runtime
```

New tests belong in the corresponding Django app test module/package and must
mock external integrations.

## Full safe regression

```powershell
.\.venv\Scripts\python.exe manage.py test
```

Historical stabilization checkpoints recorded 188/188 passing before later
frontend cleanup, and 180 `integrator` plus `sso_auth` tests passing after that
cleanup. These are validation snapshots, not a permanent expected count; the
test count may grow.

## Manual browser smoke testing

Automated tests do not replace browser checks. Verify the SSO provider protocol
toggle, SSO audit modal, integration credential modal, dynamic form builder,
sidebar/responsive layout, browser console, and static-file 404s. Do not use a
real SSO provider or external integration for routine local test runs.
