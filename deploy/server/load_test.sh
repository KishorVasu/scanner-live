#!/bin/sh
# Server load test (Phase 6 exit criterion; SELF_HOSTED_DEPLOYMENT.md §12). Run as root from the repository:
#   sudo deploy/server/load_test.sh [seconds=300] [users=10]
# Starts the isolated stack in loadtest.compose.yml (own Postgres, own API, internal network, project sp-loadtest),
# seeds 20 synthetic projects, runs scripts/load_test.py, samples `docker stats` for every container on the host
# (production included, so a run during the 02:00 scan cycle shows contention), then removes the stack.
# Output: /var/log/sp-loadtest/<UTC>/ with load-test-report.json and docker-stats.txt.
set -eu
seconds="${1:-300}"; users="${2:-10}"
HERE="$(cd "$(dirname "$0")" && pwd)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="/var/log/sp-loadtest/$stamp"
mkdir -p "$out"
LT_WORK="$(mktemp -d)"; chown 10001:10001 "$LT_WORK"; chmod 700 "$LT_WORK"
LT_PG_PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -dc A-Za-z0-9)"
export LT_WORK LT_PG_PASSWORD
dc() { docker compose -p sp-loadtest -f "$HERE/loadtest.compose.yml" "$@"; }
cleanup() { [ -n "${stats_pid:-}" ] && kill "$stats_pid" 2>/dev/null; dc --profile runner down -v --remove-orphans >/dev/null 2>&1; rm -rf "$LT_WORK"; }
trap cleanup EXIT

dc up -d --build --wait lt-postgres
dc --profile runner run --rm lt-runner sh -c '
  head -c 32 /dev/urandom | base64 > master_key && head -c 48 /dev/urandom | base64 > redaction_salt &&
  python /repo/scripts/e2e_seed.py /work/creds.json | tail -n 1 > /work/app_url'
dc up -d --wait lt-api

(while :; do date -u +%H:%M:%S; docker stats --no-stream --format '{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}'; sleep 10; done) \
  > "$out/docker-stats.txt" 2>&1 &
stats_pid=$!

status=0
dc --profile runner run --rm lt-runner python /repo/scripts/load_test.py \
  --owner-url "postgresql+asyncpg://postgres:$LT_PG_PASSWORD@lt-postgres:5432/sp_e2e" --creds /work/creds.json \
  --base http://lt-api:8000 --users "$users" --seconds "$seconds" --out /work/load-test-report.json || status=$?
cp "$LT_WORK/load-test-report.json" "$out/" 2>/dev/null || true
echo "load_test: exit $status; report and docker stats in $out"
exit "$status"
