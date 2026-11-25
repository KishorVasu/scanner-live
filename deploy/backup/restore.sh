#!/bin/sh
# Restore an encrypted backup into a NEW database and verify it. Never touches the live `platform` database: switching
# over is a deliberate manual step (SELF_HOSTED_DEPLOYMENT.md §8). The age private key is brought in for the restore
# only and removed afterwards.
#
#   deploy/backup/restore.sh /var/backups/sp/platform-20261124T020000Z.dump.age /path/to/backup-key.txt [target_db]
set -eu
umask 077
file="${1:?backup file}"; key="${2:?age identity file}"; db="${3:-platform_restore_$(date -u +%Y%m%d%H%M%S)}"
case "$db" in platform) echo "restore: refusing to restore over the live database" >&2; exit 2;; esac
case "$db" in *[!a-z0-9_]*) echo "restore: database name must be [a-z0-9_]" >&2; exit 2;; esac
HERE="$(cd "$(dirname "$0")" && pwd)"
# Overridable for CI, which restores into a disposable Postgres directly.
OWNER_EXEC="docker compose -f $HERE/../docker-compose.yml exec -T postgres sh -c"
SP_PSQL="${SP_PSQL:-$OWNER_EXEC 'PGPASSWORD=\"\$(cat /run/secrets/pg_owner_password)\" exec psql -h 127.0.0.1 -U platform_owner -v ON_ERROR_STOP=1 \"\$@\"' psql}"
SP_PG_RESTORE="${SP_PG_RESTORE:-$OWNER_EXEC 'PGPASSWORD=\"\$(cat /run/secrets/pg_owner_password)\" exec pg_restore -h 127.0.0.1 -U platform_owner --exit-on-error \"\$@\"' pg_restore}"

if [ -f "$file.sha256" ]; then (cd "$(dirname "$file")" && sha256sum -c "$(basename "$file").sha256"); fi
eval "$SP_PSQL -d postgres -c 'CREATE DATABASE $db'"
age -d -i "$key" "$file" | eval "$SP_PG_RESTORE -d $db"
eval "$SP_PSQL -d $db" < "$HERE/verify_restore.sql"
echo "restore: $file restored into $db and verified"
