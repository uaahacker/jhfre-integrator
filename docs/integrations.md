# Integrations and external databases

## Scope

`integrator` manages dynamic forms, integration records and credentials,
external database connections, saved queries, approved stored procedures,
webhooks, and dynamic option lookups. These external systems are separate from
the Django application database.

## Credentials and configuration

An `Integration` declares trusted field definitions. An `IntegrationCredential`
stores one user's configured values for that integration. Sensitive configured
credential fields are encrypted using `DJANGO_ENCRYPTION_KEY`; browser/API
responses show configured state rather than an existing secret. Do not export
or paste credentials into source, fixtures, or browser JavaScript.

`DatabaseConnection` stores separately encrypted external connection passwords.
The implemented connection types are Microsoft SQL Server, MySQL, PostgreSQL,
and Oracle. Use a distinct least-privilege account per external system; no
application-layer check replaces database grants or network controls.

## Query flow

```text
Configuration -> validated connection -> controlled query/procedure -> bounded results
```

Saved queries are constrained to one read-only SELECT/read-only CTE statement.
`sql_policy.py` rejects multiple statements, writes, and control operations.
`query_execution.py` supplies connection/query timeouts and bounded result
limits. PostgreSQL and MySQL use read-only transaction setup where available;
MSSQL is application-policy-only, so least privilege is essential.

Dynamic dropdown/radio/checkbox options can use the same controlled external
data path and have their own bounded result limit. Treat form configuration as
untrusted input at execution time and preserve the server validation boundary.

## Stored procedures

Discovery does not grant execution. A superuser must create/review an
`ApprovedProcedure` with the exact connection, engine, database, schema,
procedure, behavior, and enabled state. `ApprovedProcedureParameter` supplies
the server-side type, ordinal, direction, nullability, and length contract.

Execution accepts only the approved identity and bound, validated values. It
uses timeouts and per-result/total result limits, performs cleanup, and writes a
sanitized `ProcedureExecutionAudit` record. Raw submitted parameter values and
sensitive details are not audit content. A reviewed procedure may still be
mutating; its behavior classification is an operator approval decision.

## Webhooks

Each dynamic form can have an optional webhook URL and configured headers.
Webhook URLs require HTTPS and host/DNS validation; redirects are disabled,
TLS verification remains enabled, proxy environment settings are ignored, and
delivery has connect/read timeouts. Sensitive headers are encrypted at rest and
masked for display. Only safe response status metadata is retained; remote
response bodies are not retained.

Webhook delivery is one-shot. There is no retry queue, idempotency key store,
or delivery worker. Do not treat it as a guaranteed asynchronous integration.

## Operational use

Only authorized management users should configure these features. Do not run
external connection tests, queries, procedures, or webhooks as a local
diagnostic shortcut. Normal Django tests mock external systems. See
[security](security.md) and [database](database.md) for the policy boundaries.
