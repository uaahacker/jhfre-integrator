# Local development

## Requirements

The validated local baseline is Python 3.13.x and Django 5.1. Windows
PowerShell is the documented local workflow; Linux/macOS use the equivalent
standard virtual-environment commands. `pyproject.toml` declares broader
package metadata compatibility, but use 3.13 for this stabilized local setup.

## Virtual environment and dependencies

Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Linux/macOS:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

`requirements.txt` is the repository's runtime installation workflow.
`pyproject.toml` supplies metadata and optional tool configuration; it does
not define a separate required local install command.

## Environment variables

The application always requires real values for:

- `DJANGO_SECRET_KEY` — Django signing secret.
- `DJANGO_ENCRYPTION_KEY` — stable Fernet key used for encrypted credentials,
  SSO provider secrets, and sensitive webhook headers.

Runtime variables:

- `DJANGO_DEBUG` — use `true` for local development; defaults to `false`.
- `DJANGO_ALLOWED_HOSTS` — required when debug is false; a comma-separated
  hostname/IP list without URLs or wildcards.
- `DATABASE_URL` — when absent, the application uses root `db.sqlite3`;
  production should set an approved PostgreSQL URL.

Example safe local process setup:

```powershell
$env:DJANGO_DEBUG="true"
$env:DJANGO_ALLOWED_HOSTS="127.0.0.1,localhost"
$env:DJANGO_SECRET_KEY="<local-development-secret>"
$env:DJANGO_ENCRYPTION_KEY="<existing-valid-fernet-key>"
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
```

`.env.example` is a documented variable-name reference only; the project does
not load it automatically and does not require `python-dotenv`. PowerShell
environment variables disappear when that terminal closes. An optional local
`.env.local.ps1` helper is ignored by `.gitignore`; keep it outside commits and
load it deliberately in a new terminal. Use an approved deployment secret
store for shared and production environments.

For a **brand-new** environment, generate a Fernet key with:

```powershell
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Never generate a replacement key for an existing database holding encrypted
values. Without a planned key-rotation/data migration, existing ciphertext
will be undecryptable.

## Database initialization

For a brand-new local SQLite database, after setting the environment:

```powershell
.\.venv\Scripts\python.exe manage.py migrate
```

This command is **database-mutating**. For a stabilized, existing, shared, or
production database, inspect first:

```powershell
.\.venv\Scripts\python.exe manage.py showmigrations
```

Apply only reviewed migrations to the intentionally selected database. Do not
set `DATABASE_URL` during local safe test work.

## Run the server

```powershell
.\.venv\Scripts\python.exe manage.py runserver
```

Visit <http://127.0.0.1:8000/>. Django's development server serves static and
development media paths; that does not replace production static/media setup.

## Routine verification

```powershell
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run
```

See [testing](testing.md) before running tests and [database](database.md)
before any migration or external database action.
