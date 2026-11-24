#!/bin/sh
# Runs once on an empty data volume. Creates the app and read-only roles with passwords from Docker secrets.
set -eu
APP_PW="$(cat /run/secrets/pg_app_password)"
RO_PW="$(cat /run/secrets/pg_readonly_password)"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_pw="$APP_PW" -v ro_pw="$RO_PW" <<'SQL'
CREATE ROLE platform_app LOGIN PASSWORD :'app_pw';
CREATE ROLE platform_readonly LOGIN PASSWORD :'ro_pw';
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
