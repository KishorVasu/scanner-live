# Self-Hosted Deployment

Status: approved design; Phase 6 additions (backups, observability, load budget, rollout) 2026-11-25. Server location is open (OQ-1).

## 1. Target

- One Linux server (Ubuntu LTS or Debian stable) running Docker Engine and Docker Compose v2.
- Sizing estimate for 20 projects: 8 vCPU, 16 GB RAM, 200 GB SSD (raw reports and the vulnerability DB mirror dominate disk). Revisit after the Phase 6 load test.
- Only port 443 (and 80 for ACME redirect) is open to the internet or the office network. SSH restricted to admin IPs, key-only.

Development decision (2026-11-24): the Windows 10 development PC does **not** run Docker. The architecture is unchanged
(scanners still run only in disposable containers, deployment is still Docker Compose on the Linux server). Locally:
unit and DB tests (embedded Postgres), no containers. Container work is verified in GitHub CI on Linux runners
(`scanner-live` job: pinned scanner images against synthetic fixture repositories) and on the server itself.

## 2. Services

| Service | Networks | Published ports | Notes |
| --- | --- | --- | --- |
| `caddy` | public, app | 443, 80 | TLS (automatic ACME or internal CA), security headers, body-size limits. Stock Caddy has no rate limiter: every unauthenticated endpoint is rate-limited in the API (`SECURITY_REVIEW.md` #13). |
| `web` | app | none | Next.js production server. Talks only to `api`. |
| `api` | app, data, fetch, monitoring | none | FastAPI (Uvicorn). `/metrics` for Prometheus; OTLP traces to Tempo. |
| `worker` | data, scan-control, fetch, monitoring | none | Celery worker. Calls scan-runner; never touches the Docker socket. Needs egress to the Anthropic API, GitHub API and allowlisted advisory feeds (see §4). |
| `beat` | data | none | Celery beat. Schedules only. |
| `scan-runner` | scan-control | none | Only service with access to the container runtime. Accepts only allowlisted digests and fixed templates. |
| `postgres` | data | none | Daily encrypted backup. |
| `redis` | data | none | Password-protected; `protected-mode yes`; no persistence of secrets. |
| `fetch-proxy` | fetch, fetch-egress | none | Squid allowlisting forward proxy, the only egress for `api` and `worker` (§4). Unprivileged (uid 13), read-only. |
| `scan-proxy` | scan, scan-egress | none | Squid allowlisting forward proxy, the only egress for scanner and DB-sync containers (`SCANNING_STRATEGY.md` §4.1). Unprivileged (uid 13), read-only. |
| scanner containers | `scan` (or none) | none | Created per job by scan-runner, deleted after. |
| `prometheus` | monitoring | none | Phase 6. Scrapes api, worker, tempo; 30-day retention. |
| `tempo` | monitoring | none | Phase 6. Receives OTLP/HTTP traces (already redacted by the API). Distroless image: health is `up{job="tempo"}`. |
| `grafana` | monitoring, grafana-host | `127.0.0.1:3001` only | Phase 6. Dashboards and trace search. Reached through an SSH tunnel; admin password from a Docker secret; sign-up and anonymous access off. |

## 3. Networks

| Network | Members | Purpose |
| --- | --- | --- |
| `public` | caddy | Ingress only. |
| `fetch` | api, worker, fetch-proxy | `internal: true`; the only way out is `fetch-proxy` (§4). |
| `fetch-egress` | fetch-proxy | Outbound for fetch-proxy alone. |
| `app` | caddy, web, api | HTTP between proxy, dashboard and API. |
| `data` | api, worker, beat, postgres, redis | `internal: true`; no published ports. |
| `scan-control` | worker, scan-runner | `internal: true`; job requests and report return. |
| `scan` | scanner and DB-sync containers (when egress is needed), scan-proxy | `internal: true`, named `sp-scan` (scan-runner attaches containers by name); the only way out is `scan-proxy` (`SCANNING_STRATEGY.md` §4). |
| `scan-egress` | scan-proxy | Outbound for the proxy alone (named `sp-scan-egress`). |
| `monitoring` | prometheus, tempo, grafana, api, worker | `internal: true`; scrapes and OTLP only. |
| `grafana-host` | grafana | Exists only so Docker can publish Grafana on the host loopback. |

## 4. Egress

`api` and `worker` sit on the internal `fetch` network; their only way out is `fetch-proxy` (Squid,
`deploy/fetch-proxy/squid.conf`), which allows HTTPS to `api.osv.dev`, `www.cisa.gov`, `services.nvd.nist.gov`,
`api.github.com` and `api.anthropic.com` only (Phase 4 decision 1, 2026-11-24). Scanner and DB-sync containers use the
separate `scan-proxy` (`SCANNING_STRATEGY.md` §4). No other service has egress. Advisory fetch code also enforces its
host allowlist itself (`app/intel/sources.py`).

## 5. Container hardening (all services)

- Non-root user; `read_only: true` where the service allows it; `tmpfs` for scratch.
- `cap_drop: [ALL]` (add back only what a service provably needs, e.g. `NET_BIND_SERVICE` for caddy).
- `security_opt: [no-new-privileges:true]`.
- CPU, memory and PID limits on every container.
- Health checks on every service; `restart: unless-stopped`.
- Images pinned by digest. Base images updated through reviewed PRs.
- Every app service sets an explicit non-root `user:` in compose (policy test), in addition to the image's `USER`.
- **The Docker socket is never mounted into api, worker, beat, web or any agent.** scan-runner is the only exception, and only through the opt-in override `deploy/docker-compose.scan-exec.yml` (policy test: it touches scan-runner alone). Enable it once the `images.lock` entries are reviewed. A stronger option for later: run scan-runner with rootless Podman or gVisor (server, OQ-1).

## 6. Secrets and keys

| Secret | Storage |
| --- | --- |
| Postgres passwords (`platform_owner`, `platform_app`, `platform_readonly`) | Docker secrets |
| Redis password | Docker secret |
| Master encryption key (envelope encryption for `_enc` columns) | Docker secret file, `0400`, outside the DB volume and outside backups |
| GitHub App private key | Docker secret (file), read only by api |
| GitHub webhook secret | Docker secret |
| Anthropic API key | Docker secret, read only by worker |
| Redaction salt (HMAC for secret match hashes) | Docker secret |

- `.env.example` contains variable names and placeholders only. No real values anywhere in the repo or docs.
- Secret rotation is a manual, documented admin procedure. The platform has no tool that rotates credentials.

## 7. TLS and headers

Caddy sets:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy` (strict, nonce-based for Next.js; no `unsafe-eval`)
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` (and `frame-ancestors 'none'`), `Permissions-Policy` minimal.
- Request body size limits; webhook route limits.

If the server is not reachable from the internet (office machine), use an internal CA and expose the webhook endpoint through a narrowly scoped tunnel or relay. This depends on OQ-1.

## 8. Backups

Scripts in `deploy/backup/` (Phase 6). Encryption: [age](https://age-encryption.org). The server holds only the
**public** recipient key. The private key stays off the server and is brought in only for a restore.

- `backup.sh`: daily, from cron or a systemd timer on the host.
  - Runs `pg_dump -Fc` as `platform_readonly` inside the postgres container; the password comes from the Docker secret.
  - Pipes the dump straight into `age`, so no plaintext dump touches disk.
  - Writes `platform-<UTC>.dump.age` and a `.sha256`.
  - A failed dump writes nothing and exits non-zero.
  - Retention: 30 days of dailies, plus the first backup of each month for 365 days.
- `restore.sh <file> <age-key> [db]`:
  - Checks the `.sha256`.
  - Restores into a **new** database (it refuses `platform`).
  - Runs `verify_restore.sql`: Alembic head, the append-only audit triggers, `platform_app` still unable to modify `audit_logs`, and row counts.
  - Switching the live database over is a deliberate manual step.
- Reports are stored in Postgres, so the dump covers them. Redis holds no state worth backing up.
- The master key and Docker secrets are never part of a backup.
  - Keep the master key in the same off-server place as the age private key.
  - Without the master key, TOTP secrets and the GitHub App key are unreadable: users re-enrol.
- **Off-site copy** (needs the user): copy the `.age` files to storage outside the server, with credentials that live outside the platform. The script deliberately holds no remote-storage credentials.
- **Tested:**
  - CI job `backup-restore` (real age, Postgres 16) does: backup, then a failed backup that leaves nothing, then restore, verify, and refusal to restore over `platform`.
  - Still open: a drill on the server from the off-site copy (Phase 6 exit criterion, needs OQ-1), then quarterly.
    - Command: `sudo deploy/server/restore_drill.sh <file fetched back from off-site> <age key> [--keep]`.
    - It restores into `platform_drill_<UTC>`, verifies, and compares row counts with the live database.
    - It appends one line to `/var/log/sp-restore-drills.log`, then drops the drill database.

Example cron line (host):

```
15 2 * * * SP_BACKUP_DIR=/var/backups/sp SP_BACKUP_RECIPIENTS=/etc/sp/backup-recipients.txt /opt/sp/deploy/backup/backup.sh
```

## 9. Observability

- **Logs:** structured JSON to stdout, through the redaction filter, rotated by Docker's json-file driver.
- **Metrics:** Prometheus scrapes `api:8000/metrics/`, `worker:9100` and Tempo.
  - The worker's prefork children write multiprocess files under `/tmp/prom`; its main process serves the merged view.
  - Labels are route templates and fixed enums only, never IDs, paths or names.
  - Metric names:
    - `sp_http_request_seconds`
    - `sp_scan_jobs_total{scanner,status}`
    - `sp_agent_runs_total{agent,status}`
    - `sp_llm_tokens_total{agent,direction}`
    - `sp_celery_tasks_total{task,state}`
- **Traces:** OpenTelemetry SDK in api (FastAPI) and worker (Celery), OTLP/HTTP to Tempo.
  - Health checks and `/metrics` are excluded.
  - No bodies or headers are captured.
  - Every span attribute and event (exception messages included) passes the redactor before export (`app/core/tracing.py`).
  - Tracing is off when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset.
- **Grafana:**
  - Provisioned Prometheus and Tempo datasources, plus the "Security Platform" dashboard: request rate and p95 per route, 5xx, scan jobs, agent runs, LLM tokens, failed tasks, targets up.
  - Access: `ssh -L 3001:127.0.0.1:3001 <server>`, then `http://localhost:3001` as `admin` with the `grafana_admin_password` secret.
- **Alerts:** none yet. The channel is OQ-5. Until it is answered, look at the dashboard and the `up` panel.
- **Tested:** CI job `monitoring-stack` starts the pinned images with these configs, sends an OTLP span, checks that Prometheus scrapes Tempo, and checks both Grafana datasources and the dashboard.

## 10. Upgrades

- All changes through PRs with CI (tests, OSV-Scanner, Gitleaks, Actions pinned by SHA).
- Alembic migrations run by a one-shot `migrate` job using `platform_owner`; application services use `platform_app`.
- Rollback: previous image digests kept; DB migrations written to be reversible where practical.

## 11. Repository layout (deployment parts)

```
deploy/
  docker-compose.yml
  docker-compose.scan-exec.yml   # opt-in: Docker socket for scan-runner only
  Caddyfile
  backup/            # backup.sh, restore.sh, verify_restore.sql
  prometheus/ tempo/ grafana/    # Phase 6 observability configs
  secrets/README.md  # how to create the Docker secrets; no secret files committed
scanners/images/
  images.lock
  <scanner>/Dockerfile
```

## 12. Load test and resource budget

`scripts/load_test.py` seeds 20 synthetic projects (60 repositories, 6,000 findings with evidence) into a throwaway
database. It then runs concurrent dashboard reads for a fixed time and fails on any error or on an endpoint p95 over the
budget (default 1 s).

- **CI** (job `load-test`): 10 readers for 60 s against one API process. The job's report artifact holds the numbers.
- **Dev PC** (2026-11-25, embedded Postgres, 10 readers for 20 s): 1,392 requests, 0 errors, worst endpoint p95 341 ms.
- **Server** (needs OQ-1). This is the Phase 6 exit run: `sudo deploy/server/load_test.sh 300 10`.
  - It starts an isolated stack (`deploy/server/loadtest.compose.yml`, project `sp-loadtest`) with its own Postgres, its own API with the production image and limits, and an internal network.
  - It seeds the 20 projects, runs the test, and samples `docker stats` for every container every 10 s, production included.
  - Results go to `/var/log/sp-loadtest/<UTC>/`. The stack is removed afterwards.
  - Run it once on an idle host and once during the 02:00 scan cycle.
  - Then confirm or revise the 8 vCPU / 16 GB / 200 GB estimate in §1.
  - `scripts/e2e_seed.py` resets the `platform_app` password of the Postgres it targets. That is why it only ever runs inside this isolated stack, never against the live database.
- Worker and scan throughput depend on scanner runtime, so they are measured only on the server.

## 13. Rollout

Pilot, then all projects (roadmap Phase 6). Each step needs the user.

1. Name the GitHub org and approve the read-only App installation (OQ-2). Set `reviewed_by` in `images.lock` after reviewing the CI `scanner-live` report, then enable `docker-compose.scan-exec.yml`.
2. Pilot: register the three pilot projects with their components and repositories.
   - Wait for a full daily and weekly scan cycle.
   - Review the findings and impacts with each project owner: false positives, noise, and missing "not scanned" coverage.
   - Write the pilot review and fix what it finds.
3. Onboard the rest in batches of about five, using the same checklist as the pilot:
   - Every component and repository is registered, and the project has an owner (developers triage only projects they own).
   - The first scan of each scanner succeeded, or the failure is understood.
   - Local agents are enrolled only for folders an administrator approved.
   - The owner has seen the project's Overview row and knows what "not scanned" means.
4. Exit: every project onboarded, the server load test within budget, and a restore drill done from the off-site copy.

## 14. First deployment (server runbook)

Each step marked **(user)** is the user's to do or approve; the rest is mechanical. No step touches a project repository.

1. **Host (user):**
   - Ubuntu LTS or Debian stable, sized per §1.
   - SSH key-only from admin IPs.
   - `ufw` allowing 22 (admin IPs), 80 and 443.
   - Install `unattended-upgrades` and keep NTP on: TOTP needs a correct clock.
   - Docker Engine with the compose plugin.
   - `/etc/docker/daemon.json`: `{"live-restore": true, "log-driver": "json-file", "log-opts": {"max-size": "20m", "max-file": "5"}}`.
2. **Optional gVisor for scanners:**
   - Install `runsc` from gVisor's apt repository, then `runsc install` (adds the runtime to `daemon.json`) and restart Docker.
   - Set `SP_SCANNER_RUNTIME=runsc` for the scan-exec override.
   - scan-runner accepts only `runc` or `runsc`; anything else refuses to start a container (`test_gvisor_runtime_is_opt_in_and_allowlisted`).
   - Validate on the server with one `scanner-live`-style scan before relying on it: some scanners may need syscalls gVisor lacks.
   - Rootless Podman is the other option. It replaces Docker for scan-runner only and needs its own design review.
3. **Code:** clone the repository at the approved commit. Create `deploy/secrets/*` per `deploy/secrets/README.md`, root-owned, mode 0400.
4. **Backup keys (user):**
   - Run `age-keygen` on a machine that is **not** the server.
   - Put only the `age1...` public line in `/etc/sp/backup-recipients.txt` on the server.
   - Store the private key and a copy of `master_key` together off-server.
   - Choose the off-site copy target.
5. **Preflight:** `sudo SITE_ADDRESS=<host> SP_BACKUP_RECIPIENTS=/etc/sp/backup-recipients.txt deploy/server/preflight.sh`. It is read-only. Fix every FAIL line, and decide on each WARN line.
6. **Start:**
   - `cd deploy && SITE_ADDRESS=<host> docker compose up -d --build`.
   - The `migrate` job runs first. Wait for every service to report `healthy` (`docker compose ps`).
7. **First admin:**
   - `docker compose exec -it api python -m app.cli create-admin --email <admin>`. The password is read from the terminal.
   - Sign in, enrol TOTP, and check the Audit Log shows `users.create_admin`.
8. **Smoke checks:**
   - `https://<host>/login` loads with HSTS and CSP headers.
   - `https://<host>/metrics` returns 404.
   - Grafana through `ssh -L 3001:127.0.0.1:3001 <server>`: all targets `up`.
9. **Backups:**
   - Add the cron line in §8. Run `deploy/backup/backup.sh` once by hand.
   - Copy the file off-site, then run the restore drill from the off-site copy.
10. **Load test:** `sudo deploy/server/load_test.sh 300 10`, on an idle host and again during the 02:00 scan cycle. Record the results in the roadmap.
11. **Scanning (user):**
    - Set `reviewed_by` in `images.lock` after reading the CI `scanner-live` report.
    - Start scan-runner with the socket: `DOCKER_GID=$(getent group docker | cut -d: -f3) docker compose -f docker-compose.yml -f docker-compose.scan-exec.yml up -d scan-runner`.
    - Then continue with the rollout in §13.
