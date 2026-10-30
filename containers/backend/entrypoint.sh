#!/bin/bash
# =======================================================
# SCYTHE Backend — Container Entrypoint
# 1. Ensure execution as scythe (drop privileges if root)
# 2. Wait for Postgres to be ready
# 3. Run Alembic migrations, safely recognizing known legacy schema revisions
# 4. Start Uvicorn
# =======================================================
set -e

# Privilege drop / non-root enforcement:
# Ensure we do not execute as root. If running as root, drop privileges to scythe.
if [ "$(id -u)" = "0" ]; then
    echo "[entrypoint] Running as root; dropping privileges to scythe..."
    if command -v gosu >/dev/null 2>&1; then
        exec gosu scythe "$0" "$@"
    elif command -v su-exec >/dev/null 2>&1; then
        exec su-exec scythe "$0" "$@"
    elif command -v runuser >/dev/null 2>&1; then
        exec runuser -u scythe -- "$0" "$@"
    else
        exec su -s /bin/bash scythe -c "\"$0\" \"\$@\"" -- "$@"
    fi
fi

echo "[entrypoint] Waiting for PostgreSQL..."
until python -c "
import psycopg2, sys
from config import settings
try:
    psycopg2.connect(settings.DATABASE_URL.replace('+psycopg2', ''))
    print('PostgreSQL is ready.')
except Exception:
    print('PostgreSQL connection not ready yet...', file=sys.stderr)
    sys.exit(1)
"; do
    echo "[entrypoint] PostgreSQL not ready yet, retrying in 2s..."
    sleep 2
done

echo "[entrypoint] Running database migrations (Alembic)..."
python - <<'PY'
import psycopg2
from config import settings
from alembic.config import Config
from alembic import command

url = settings.DATABASE_URL.replace('+psycopg2', '')
conn = psycopg2.connect(url)
cur = conn.cursor()
cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
tables = {row[0] for row in cur.fetchall()}
users_exists = 'users' in tables
alembic_exists = 'alembic_version' in tables
user_columns = set()
if users_exists:
    cur.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='users'")
    user_columns = {row[0] for row in cur.fetchall()}
cur.close()
conn.close()

alembic_cfg = Config('alembic.ini')
if users_exists and not alembic_exists:
    required_tables = {
        'statistics', 'users', 'scans', 'incidents', 'iocs', 'downloads',
        'evasion_techniques', 'form_metrics', 'network_activity', 'redirects',
        'tls_connections',
    }
    required_user_columns = {'id', 'email', 'hashed_password', 'is_active', 'created_at', 'is_superuser'}
    if not required_tables.issubset(tables) or not required_user_columns.issubset(user_columns):
        raise RuntimeError(
            'Existing unversioned database schema is not a recognized SCYTHE revision. '
            'Startup stopped without changing the database; back it up and reconcile its schema before retrying.'
        )

    has_verified = 'is_verified' in user_columns
    has_revoked = 'revoked_tokens' in tables
    has_updated_at = 'updated_at' in user_columns
    if has_verified != has_revoked:
        raise RuntimeError(
            'Existing unversioned database has a partial auth migration. '
            'Startup stopped without changing the database; inspect it before retrying.'
        )
    if has_verified and has_revoked and has_updated_at:
        baseline = 'f2b4c6d8e0a1'
    elif has_verified and has_revoked:
        baseline = 'e1a34b678901'
    elif not has_verified and not has_revoked:
        baseline = 'd2575a9c427f'
    else:
        raise RuntimeError('Could not identify an existing database migration baseline safely.')

    print(f'Existing SCYTHE schema recognized at {baseline}; recording that revision before upgrading.')
    command.stamp(alembic_cfg, baseline)

print('Running alembic upgrade head...')
command.upgrade(alembic_cfg, 'head')
PY

echo "[entrypoint] Starting Uvicorn..."
exec "$@"
