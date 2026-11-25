#!/bin/sh
# Daily encrypted backup of the platform database (SELF_HOSTED_DEPLOYMENT.md §8). Run on the host from cron or a
# systemd timer. Needs `age` on the host and the backup PUBLIC key in $SP_BACKUP_RECIPIENTS; the private key stays
# off this server. The master key and Docker secrets are never part of a backup.
#
#   SP_BACKUP_DIR=/var/backups/sp SP_BACKUP_RECIPIENTS=/etc/sp/backup-recipients.txt deploy/backup/backup.sh
#
# Output: $SP_BACKUP_DIR/platform-<UTC timestamp>.dump.age (pg_dump custom format, then age) plus a .sha256 file.
# Retention: dailies kept 30 days; the first backup of each month kept 365 days. Off-site copy is a separate step
# (see SELF_HOSTED_DEPLOYMENT.md §8) so this script never holds remote-storage credentials.
set -eu
umask 077

: "${SP_BACKUP_DIR:?set SP_BACKUP_DIR}"
: "${SP_BACKUP_RECIPIENTS:?set SP_BACKUP_RECIPIENTS (age public keys, one per line)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# Dumps as platform_readonly over TCP inside the postgres container, so the password comes from the Docker secret
# and never appears on a command line. CI overrides SP_PG_DUMP to dump a disposable database directly.
SP_PG_DUMP="${SP_PG_DUMP:-docker compose -f $HERE/../docker-compose.yml exec -T postgres sh -c 'PGPASSWORD=\"\$(cat /run/secrets/pg_readonly_password)\" exec pg_dump -h 127.0.0.1 -U platform_readonly -d platform -Fc'}"

mkdir -p "$SP_BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$SP_BACKUP_DIR/platform-$stamp.dump.age"
tmp="$out.partial"
trap 'rm -f "$tmp"' EXIT

# set -e does not see a failure on the left of a pipe; a marker file does.
fail="$SP_BACKUP_DIR/.dump-failed"
rm -f "$fail"
{ eval "$SP_PG_DUMP" || touch "$fail"; } | age -R "$SP_BACKUP_RECIPIENTS" -o "$tmp"
if [ -e "$fail" ]; then rm -f "$fail"; echo "backup: pg_dump failed; no backup written" >&2; exit 1; fi
[ -s "$tmp" ] || { echo "backup: empty output" >&2; exit 1; }
mv "$tmp" "$out"
(cd "$SP_BACKUP_DIR" && sha256sum "$(basename "$out")" > "$(basename "$out").sha256")
echo "backup: wrote $out"

# ponytail: retention by file age and name; a month's first backup is the one whose day is the lowest present.
find "$SP_BACKUP_DIR" -name 'platform-*.dump.age' -mtime +30 | while read -r f; do
  month="$(basename "$f" | cut -c10-15)"
  first="$(ls "$SP_BACKUP_DIR"/platform-"$month"*.dump.age | head -n 1)"
  if [ "$f" != "$first" ] || [ -n "$(find "$f" -mtime +365)" ]; then rm -f "$f" "$f.sha256"; fi
done
