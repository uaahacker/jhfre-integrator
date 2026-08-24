# Operations checklist

## Before starting

- Confirm approved environment configuration and allowed hosts.
- Confirm the selected application database is available.
- Confirm `DJANGO_SECRET_KEY` and the stable `DJANGO_ENCRYPTION_KEY` are set.
- Confirm production HTTPS/proxy settings and protected-media rule.

## Startup verification

```bash
python manage.py check
python manage.py showmigrations
```

Run these with the intended deployment environment. Do not run migration,
external query, procedure, or webhook commands as a generic startup check.

## Before deployment

- Back up the application database and verify restore capability.
- Review migration state and planned migration impact.
- Apply migrations only through an approved procedure.
- Run `python manage.py collectstatic --noinput`.
- Confirm direct `/media/uploads/` access is denied by the production server.
- Confirm TLS, proxy-forwarded HTTPS, and HSTS settings match the topology.

## After deployment

- Log in and load the dashboard.
- Check a permitted form workflow.
- Confirm integrations and SSO management pages render for an authorized user.
- Verify a protected uploaded file can be downloaded only through its
  authorization-aware route.
- Review application/server logs for configuration errors or static-file 404s.

Do not test a production external database, IdP, or webhook endpoint without
the applicable change and operational authorization.

## Periodic checks

- Verify database backups and restore exercises.
- Monitor disk and protected-media growth.
- Review application database and approved external DB connectivity.
- Review SSO certificates, provider status, callback configuration, and audit
  events.
- Review webhook delivery failures and expected one-shot behavior.
- Apply security updates through the normal dependency/release process.
