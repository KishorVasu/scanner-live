#!/bin/sh
# Restore drill (Phase 6 exit criterion, then quarterly; SELF_HOSTED_DEPLOYMENT.md §8). Run as root on the server:
#   sudo deploy/server/restore_drill.sh /path/to/platform-<UTC>.dump.age /path/to/backup-key.txt [--keep]
# Use a backup fetched back from the OFF-SITE copy, not the local one: the drill proves the off-site path too.
# Restores into a new database (restore.sh refuses `platform`), verifies it, compares row counts with the live DB,
# appends the result to /var/log/sp-restore-drills.log, then drops the drill database unless --keep is given.
# The age private key is needed only for this run: remove it from the server afterwards.
set -eu
file="${1:?backup file}"; key="${2:?age identity file}"; keep="${3:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
db="platform_drill_$(date -u +%Y%m%d%H%M%S)"
log=/var/log/sp-restore-drills.log
psql_owner() {
  docker compose -f "$HERE/../docker-compose.yml" exec -T postgres sh -c \
    'PGPASSWORD="$(cat /run/secrets/pg_owner_password)" exec psql -h 127.0.0.1 -U platform_owner -v ON_ERROR_STOP=1 -At "$@"' psql "$@"
}
counts="SELECT string_agg(t || '=' || n, ' ' ORDER BY t) FROM (SELECT 'users' t, count(*) n FROM users UNION ALL
  SELECT 'projects', count(*) FROM projects UNION ALL SELECT 'security_findings', count(*) FROM security_findings UNION ALL
  SELECT 'reports', count(*) FROM reports UNION ALL SELECT 'audit_logs', count(*) FROM audit_logs) x"

start=$(date +%s)
status=ok
"$HERE/../backup/restore.sh" "$file" "$key" "$db" || status=FAILED
secs=$(( $(date +%s) - start ))
restored="-"; live="-"
if [ "$status" = ok ]; then
  restored=$(psql_owner -d "$db" -c "$counts")
  live=$(psql_owner -d platform -c "$counts")
fi
line="$(date -u +%FT%TZ) drill=$status file=$(basename "$file") size=$(stat -c %s "$file") seconds=$secs db=$db restored[$restored] live_now[$live]"
echo "$line" | tee -a "$log"
if [ "$keep" != --keep ]; then psql_owner -d postgres -c "DROP DATABASE IF EXISTS $db" >/dev/null; echo "dropped $db"; fi
echo "Restored counts can be lower than live ones (rows written since the backup), never higher."
[ "$status" = ok ]
