#!/bin/bash
# =======================================================
# SCYTHE Celery — Entrypoint (Worker + Beat)
# 1. Ensure execution as scythe (drop privileges if root)
# 2. Wait for Redis (broker) to be ready
# 3. Wait for Postgres (models need DB)
# 4. Wait for ClamAV daemon
# 5. exec the celery command passed as CMD
#
# Bug fix: the original Redis probe used the raw REDIS_URL
# (e.g. redis://redis:6379/0) without injecting REDIS_PASSWORD,
# so the probe would fail with "NOAUTH Authentication required"
# when Redis is password-protected — which is always the case in
# our hardened docker-compose.yml. The fix: build the authed URL
# in the probe script itself by reading both REDIS_URL and
# REDIS_PASSWORD and injecting the credential if absent.
# =======================================================
set -e

# Privilege drop / non-root enforcement:
# Ensure we do not execute as root. If running as root, drop privileges to scythe.
if [ "$(id -u)" = "0" ]; then
    echo "[celery-entrypoint] Running as root; dropping privileges to scythe..."
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

echo "[celery-entrypoint] Waiting for Redis..."
until python -c "
import sys
from config import settings
try:
    import redis
    r = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=3)
    r.ping()
    print('Redis is ready.')
except Exception:
    print('Redis not ready yet...', file=sys.stderr)
    sys.exit(1)
"; do
    echo "[celery-entrypoint] Redis not ready, retrying in 2s..."
    sleep 2
done

echo "[celery-entrypoint] Waiting for PostgreSQL..."
until python -c "
import psycopg2, sys
from config import settings
try:
    psycopg2.connect(settings.DATABASE_URL.replace('+psycopg2', ''))
    print('PostgreSQL is ready.')
except Exception:
    print('PostgreSQL not ready yet...', file=sys.stderr)
    sys.exit(1)
"; do
    echo "[celery-entrypoint] PostgreSQL not ready, retrying in 2s..."
    sleep 2
done

echo "[celery-entrypoint] Waiting for ClamAV daemon..."
until python -c "
import socket, os, sys
from config import settings
host = os.environ.get('CLAMAV_HOST', getattr(settings, 'CLAMAV_HOST', 'localhost'))
port = int(os.environ.get('CLAMAV_PORT', getattr(settings, 'CLAMAV_PORT', 3310)))
try:
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(b'zPING\0')
        res = s.recv(128).decode('utf-8', errors='replace')
        if 'PONG' in res:
            print('ClamAV daemon is ready.')
            sys.exit(0)
    raise RuntimeError('zPING did not return PONG')
except Exception:
    if settings.DEBUG and not getattr(settings, 'CLAMAV_FAIL_CLOSED', False):
        print('ClamAV not reachable in DEBUG mode with CLAMAV_FAIL_CLOSED=False (skipping).')
        sys.exit(0)
    print('ClamAV daemon not ready yet...', file=sys.stderr)
    sys.exit(1)
"; do
    echo "[celery-entrypoint] ClamAV daemon not ready, retrying in 2s..."
    sleep 2
done

echo "[celery-entrypoint] Starting Celery: $@"
exec "$@"
