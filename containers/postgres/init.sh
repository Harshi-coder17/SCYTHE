#!/bin/sh
# ===================================================
# SCYTHE PostgreSQL Init Script
# Runs ONCE when the postgres container first starts
# (placed in /docker-entrypoint-initdb.d/)
#
# Reads SCYTHE_DB_PASSWORD from the environment (set in
# docker-compose.yml, sourced from the root .env) instead of
# embedding it as a literal in this file. Only the app user's
# password moves here -- the superuser password is still handled
# natively by the postgres:16-alpine image via POSTGRES_PASSWORD.
# ===================================================
set -e

: "${SCYTHE_DB_PASSWORD:?SCYTHE_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" \
     -v scythe_pass="$SCYTHE_DB_PASSWORD" <<-'EOSQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'scythe_user') THEN
        CREATE ROLE scythe_user LOGIN;
    END IF;
END
$$;

SELECT format('ALTER ROLE scythe_user WITH PASSWORD %L;', :'scythe_pass') \gexec

SELECT 'CREATE DATABASE scythe_db OWNER scythe_user'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'scythe_db')\gexec
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "scythe_db" <<-'EOSQL'
GRANT ALL PRIVILEGES ON DATABASE scythe_db TO scythe_user;
GRANT ALL ON SCHEMA public TO scythe_user;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
EOSQL

echo "SCYTHE database initialized successfully."