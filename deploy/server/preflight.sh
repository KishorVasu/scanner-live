#!/bin/sh
# Read-only host check before the first `docker compose up` and after host changes (SELF_HOSTED_DEPLOYMENT.md §14).
# Changes nothing. Run as root from the repository:  sudo SITE_ADDRESS=sp.example.internal deploy/server/preflight.sh
# FAIL lines block deployment (exit 1). WARN lines need a decision, and the runbook says which.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SECRETS="$HERE/../secrets"
fails=0
ok()   { echo "PASS  $*"; }
warn() { echo "WARN  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" = 0 ] || { echo "run as root (secrets are root-owned, mode 0400)"; exit 2; }

# --- container runtime
if have docker && docker info >/dev/null 2>&1; then ok "docker $(docker version -f '{{.Server.Version}}')"; else fail "docker engine not running"; fi
if docker compose version >/dev/null 2>&1; then ok "$(docker compose version --short 2>/dev/null | sed 's/^/compose /')"; else fail "docker compose v2 missing"; fi
if docker info -f '{{.LiveRestoreEnabled}}' 2>/dev/null | grep -q true; then ok "daemon live-restore on"; else warn "daemon live-restore off (/etc/docker/daemon.json: \"live-restore\": true)"; fi
if [ "${SP_SCANNER_RUNTIME:-}" = runsc ]; then
  if docker info -f '{{json .Runtimes}}' 2>/dev/null | grep -q '"runsc"'; then ok "gVisor runtime runsc registered"; else fail "SP_SCANNER_RUNTIME=runsc but runsc is not registered with Docker"; fi
fi

# --- size against the budget (8 vCPU, 16 GB RAM, 200 GB disk; revisit after the server load test)
cpus=$(nproc); mem_gb=$(awk '/MemTotal/ {printf "%d", $2/1048576}' /proc/meminfo)
root=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)
disk_gb=$(df -BG --output=avail "$root" 2>/dev/null | tail -n 1 | tr -dc 0-9)
[ "$cpus" -ge 8 ] && ok "$cpus vCPU" || warn "$cpus vCPU (budget 8)"
[ "$mem_gb" -ge 15 ] && ok "${mem_gb} GB RAM" || warn "${mem_gb} GB RAM (budget 16)"
[ "${disk_gb:-0}" -ge 200 ] && ok "${disk_gb} GB free under $root" || warn "${disk_gb:-?} GB free under $root (budget 200)"

# --- secrets (deploy/secrets/README.md): present, root-owned, not group/world readable
for s in pg_owner_password pg_app_password pg_readonly_password redis_password master_key redaction_salt \
         grafana_admin_password anthropic_api_key; do
  f="$SECRETS/$s"
  if [ ! -f "$f" ]; then fail "secret $s missing"; continue; fi
  perm=$(stat -c '%a %U' "$f")
  case "$perm" in 400\ root|600\ root) ;; *) fail "secret $s is '$perm' (want 400 root)";; esac
  if [ ! -s "$f" ] && [ "$s" != anthropic_api_key ]; then fail "secret $s is empty"; fi
done
if [ -f "$SECRETS/master_key" ]; then
  n=$(base64 -d "$SECRETS/master_key" 2>/dev/null | wc -c)
  [ "$n" = 32 ] && ok "master_key decodes to 32 bytes" || fail "master_key decodes to $n bytes (want 32)"
fi
[ -s "$SECRETS/anthropic_api_key" ] || warn "anthropic_api_key empty: LLM steps are refused, rules decide alone (allowed)"
[ -n "${SITE_ADDRESS:-}" ] && ok "SITE_ADDRESS=$SITE_ADDRESS" || fail "SITE_ADDRESS not set"

# --- backups (§8)
have age && ok "age installed" || fail "age missing (apt install age)"
if [ -n "${SP_BACKUP_RECIPIENTS:-}" ]; then
  grep -q '^age1' "$SP_BACKUP_RECIPIENTS" 2>/dev/null && ok "backup recipients file has an age public key" \
    || fail "SP_BACKUP_RECIPIENTS has no age1... public key"
  grep -q 'AGE-SECRET-KEY' "$SP_BACKUP_RECIPIENTS" 2>/dev/null && fail "backup recipients file contains a PRIVATE key"
else
  warn "SP_BACKUP_RECIPIENTS not set: backups not configured yet"
fi
crontab -l 2>/dev/null | grep -q 'deploy/backup/backup.sh' || systemctl list-timers 2>/dev/null | grep -q sp-backup \
  && ok "backup schedule found" || warn "no cron entry or sp-backup timer for backup.sh"

# --- host hardening
if have sshd; then
  sshd -T 2>/dev/null | grep -qi '^passwordauthentication no' && ok "ssh: password login off" || fail "ssh: password login on"
  sshd -T 2>/dev/null | grep -Eqi '^permitrootlogin (no|prohibit-password)' && ok "ssh: no root password login" || fail "ssh: root password login allowed"
fi
if have ufw; then
  if ufw status 2>/dev/null | grep -q 'Status: active'; then
    extra=$(ufw status | awk '/ALLOW/ {print $1}' | grep -Ev '^(22|80|443)(/tcp)?$' | sort -u | tr '\n' ' ')
    [ -z "$extra" ] && ok "ufw active: only 22/80/443" || warn "ufw allows more than 22/80/443: $extra"
  else
    fail "ufw installed but inactive"
  fi
else
  warn "ufw not installed: confirm another firewall allows only 22 (admin IPs), 80, 443"
fi
# Docker-published ports bypass ufw; anything listening beyond loopback other than 22/80/443 is a finding.
public=$(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Ev '^(127\.|\[::1\]|::1)' | sed 's/.*://' | grep -Ev '^(22|80|443)$' | sort -u | tr '\n' ' ')
[ -z "$public" ] && ok "nothing else listens beyond loopback" || warn "listening beyond loopback: $public"
timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes && ok "clock NTP-synchronised (TOTP needs it)" \
  || fail "clock not NTP-synchronised (TOTP codes will fail)"
if dpkg -s unattended-upgrades >/dev/null 2>&1; then ok "unattended-upgrades installed"; else warn "unattended-upgrades not installed"; fi

echo "preflight: $fails failure(s)"
[ "$fails" = 0 ]
