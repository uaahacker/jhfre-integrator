# Database and migrations

## Application database

With `DATABASE_URL` absent, Django uses local SQLite at `db.sqlite3`. When the
variable is set, Django parses it as the primary application database; the
production target is PostgreSQL. Do not use a developer SQLite file as a
production database.

## External integration databases

External connections are separate from Django's application DB. The configured
connection types are Microsoft SQL Server, MySQL, PostgreSQL, and Oracle.
Connection credentials are separate, encrypted application data and must use
least-privilege database accounts. Local automated tests must mock them.

## Command safety

| Command/action | Classification |
|---|---|
| `python manage.py check` | Read-only |
| `python manage.py showmigrations` | Read-only |
| `python manage.py makemigrations --check --dry-run` | Read-only with respect to the database |
| `python manage.py test` | Mutating, disposable Django test database only |
| `python manage.py migrate` | Mutating selected application database |
| External `SELECT` | External database read, subject to policy and credentials |
| Approved procedure execution | Potential external side effects, depending on its approved behavior |

Never run migrations or external database commands casually against production.
For production, first back up the database, verify the restore procedure, set
the correct stable secrets, inspect `showmigrations`, review unapplied work,
then apply migrations deliberately.

## SQL and procedure boundaries

Saved external queries must pass the application-level policy: one read-only
`SELECT` or read-only CTE statement, with write/control keywords rejected.
Execution uses bounded timeouts and result limits. PostgreSQL and MySQL have
read-only transaction setup where supported; MSSQL has application-policy-only
enforcement. Database grants remain the primary least-privilege control.

Stored procedures are not arbitrary commands. An `ApprovedProcedure` records
the connection, engine, schema, procedure name, behavior (including
`READ_EXPECTED`), enabled/approval state, and typed parameter contract. Calls
use validated/bound parameters, limits, and persistent sanitized audit records.
A procedure can still have external effects if its reviewed behavior permits
them; treat execution as an operational action.

## Encryption-key-dependent data and migrations

`IntegrationCredential` secrets, SSO provider secrets, and sensitive webhook
headers use `DJANGO_ENCRYPTION_KEY`. Historical data/encryption migrations and
runtime ciphertext require the same stable Fernet key. Do not print it, commit
it, generate a new replacement during a migration, or rotate it without a
reviewed migration and recovery plan.

## Backups

Before reviewed production migrations, take a backup appropriate to the
database engine and test restoration operationally. A backup that has not been
restored successfully is not a verified recovery plan.
