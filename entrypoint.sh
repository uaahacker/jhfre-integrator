#!/usr/bin/env bash
set -euo pipefail

# -------- Env & defaults --------
export PYTHONPATH="${PYTHONPATH:-/app}"
export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-core.settings}"

APP_ENV="${APP_ENV:-production}"            # production | development | staging
AUTO_MIGRATE="${AUTO_MIGRATE:-false}"       # prod/staging usually false
DEV_RESET_DB="${DEV_RESET_DB:-false}"       # dev-only, one-time schema nuke
SUPERUSER_ON_BOOT="${SUPERUSER_ON_BOOT:-false}"
SYNC_DB_FROM_PROD="${SYNC_DB_FROM_PROD:-false}"   # dev-only, prod -> dev copy
PORT="${PORT:-8001}"

echo ">> ENV: ${APP_ENV}"
echo ">> AUTO_MIGRATE: ${AUTO_MIGRATE}"
echo ">> DJANGO_SETTINGS_MODULE=${DJANGO_SETTINGS_MODULE}"

# ODBC Diagnostics
echo ">> ODBC Diagnostics:"
echo ">> Available ODBC drivers:"
odbcinst -q -d || echo ">> No ODBC drivers found or odbcinst failed"

# Fail early if DB URL missing
if [ -z "${DATABASE_URL:-}" ]; then
  echo "!! DATABASE_URL is not set. Exiting."
  exit 1
fi

# -------- Static --------
echo ">> Collecting static files…"
python manage.py collectstatic --noinput

# -------- Database connectivity check --------
echo ">> Testing database connectivity..."
if python manage.py check --database default; then
  echo ">> Database connectivity confirmed"
else
  echo "!! Database connectivity check failed"
  echo ">> Attempting to continue anyway..."
fi

# -------- Dev path --------
if [ "${APP_ENV}" = "development" ]; then
  echo ">> Development boot sequence"

  # one-time schema reset in dev (guarded)
  if [ "${DEV_RESET_DB}" = "true" ] && [ ! -f /tmp/dev_schema_reset_done ]; then
    echo ">> WARNING: Dropping and recreating public schema (dev only)…"
    python - <<'PY'
import django; django.setup()
from django.db import connection
with connection.cursor() as c:
    c.execute('DROP SCHEMA IF EXISTS public CASCADE;')
    c.execute('CREATE SCHEMA public;')
print("Schema reset complete")
PY
    touch /tmp/dev_schema_reset_done
  fi

  # optional: sync from prod (dev only; one-shot + safe failure)
  if [ "${SYNC_DB_FROM_PROD}" = "true" ] && [ ! -f /tmp/prod_sync_done ]; then
    if [ -z "${PROD_DATABASE_URL:-}" ]; then
      echo "!! SYNC_DB_FROM_PROD=true but PROD_DATABASE_URL is not set; skipping sync."
    else
      PROD_HOST="$(echo "${PROD_DATABASE_URL}" | sed -E 's|.*@([^:/?]+).*|\1|')"
      echo ">> Syncing dev DB from production (one-shot)…"
      echo ">> PROD host: ${PROD_HOST:-unknown}"

      # quick connectivity checks (quiet)
      if psql "${PROD_DATABASE_URL}" -Atqc "select 1" >/dev/null 2>&1; then
        if psql "${DATABASE_URL}" -Atqc "select 1" >/dev/null 2>&1; then
          if pg_dump --clean --if-exists --no-owner --no-privileges "${PROD_DATABASE_URL}" \
             | psql "${DATABASE_URL}"; then
            echo ">> DB sync complete."
            touch /tmp/prod_sync_done
          else
            echo "!! DB sync failed (dump|restore error). Continuing without aborting."
          fi
        else
          echo "!! Cannot connect to dev DATABASE_URL; skipping DB sync."
        fi
      else
        echo "!! Cannot connect to PROD_DATABASE_URL; skipping DB sync."
      fi
    fi
  fi

  # Run migrations in development - respect AUTO_MIGRATE setting
  if [ "${AUTO_MIGRATE:-true}" = "true" ]; then
    echo ">> Running migrations (dev - AUTO_MIGRATE=${AUTO_MIGRATE:-true})…"
    echo ">> Checking current migration status..."
    python manage.py showmigrations integrator || echo ">> Failed to show migrations"
    
    echo ">> Running migrations with verbose output..."
    if python manage.py migrate --noinput -v 3; then
      echo ">> Migrations completed successfully"
      echo ">> Final migration status:"
      python manage.py showmigrations integrator || echo ">> Failed to show final migration status"
    else
      echo "!! Migration failed with exit code $?"
      echo ">> Attempting to show migration status after failure:"
      python manage.py showmigrations integrator || echo ">> Failed to show migration status after failure"
      echo "!! Continuing anyway, but this may cause issues..."
    fi
  else
    echo ">> Skipping migrations in dev (AUTO_MIGRATE=${AUTO_MIGRATE:-true})"
  fi

# -------- Prod/Staging path --------
else
  echo ">> Production/Staging boot sequence"
  if [ "${AUTO_MIGRATE}" = "true" ]; then
    echo ">> AUTO_MIGRATE=true -> applying migrations…"
    echo ">> Checking current migration status..."
    python manage.py showmigrations integrator || echo ">> Failed to show migrations"

    echo ">> Running migrations with verbose output..."
    if python manage.py migrate --noinput -v 3; then
      echo ">> Migrations completed successfully"
      echo ">> Final migration status:"
      python manage.py showmigrations integrator || echo ">> Failed to show final migration status"
    else
      migrate_status=$?
      echo "!! Migration failed with exit code ${migrate_status}"
      echo ">> Migration status at time of failure:"
      python manage.py showmigrations integrator || echo ">> Failed to show migration status after failure"
      echo "!! Refusing to start Gunicorn against a database with a failed/partial migration."
      echo "!! Fix the migration, then redeploy. (Development boot has separate, more lenient behavior.)"
      exit "${migrate_status}"
    fi
  else
    echo ">> Skipping migrations (set AUTO_MIGRATE=true to enable)"
  fi
fi

# -------- Optional superuser --------
if [ "${SUPERUSER_ON_BOOT}" = "true" ]; then
  echo ">> Ensuring superuser exists…"
  python manage.py shell -c "
from django.contrib.auth import get_user_model
import os
U = get_user_model()
u = os.environ.get('DJANGO_SUPERUSER_USERNAME')
e = os.environ.get('DJANGO_SUPERUSER_EMAIL')
p = os.environ.get('DJANGO_SUPERUSER_PASSWORD')
assert u and e and p, 'SUPERUSER envs missing'
U.objects.filter(username=u).exists() or U.objects.create_superuser(u, e, p)
print('Superuser ready:', u)
"
fi

# -------- Start server --------
echo ">> Starting Gunicorn on 0.0.0.0:${PORT}…"
exec gunicorn core.wsgi:application --bind "0.0.0.0:${PORT}" --timeout 120
