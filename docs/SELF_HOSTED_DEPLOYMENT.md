# Self-Hosted Deployment

Status: Phase 0 draft, awaiting approval. Server location is open (OQ-1).

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
| `caddy` | public, app | 443, 80 | TLS (automatic ACME or internal CA), security headers, rate limit on `/api/webhooks/*` and `/api/agents/*`. |
| `web` | app | none | Next.js production server. Talks only to `api`. |
| `api` | app, data | none | FastAPI (Uvicorn). |
| `worker` | data, scan-control | none | Celery worker. Calls scan-runner; never touches the Docker socket. Needs egress to the Anthropic API, GitHub API and allowlisted advisory feeds (see §4). |
| `beat` | data | none | Celery beat. Schedules only. |
| `scan-runner` | scan-control | none | Only service with access to the container runtime. Accepts only allowlisted digests and fixed templates. |
| `postgres` | data | none | Daily encrypted backup. |
| `redis` | data | none | Password-protected; `protected-mode yes`; no persistence of secrets. |
| scanner containers | `scan` (or none) | none | Created per job by scan-runner, deleted after. |

## 3. Networks

| Network | Members | Purpose |
| --- | --- | --- |
| `public` | caddy | Ingress only. |
| `app` | caddy, web, api | HTTP between proxy, dashboard and API. |
| `data` | api, worker, beat, postgres, redis | `internal: true`; no published ports. |
| `scan-control` | worker, scan-runner | `internal: true`; job requests and report return. |
| `scan` | scanner containers (when egress is needed) | Egress restricted to the per-scanner allowlist (`SCANNING_STRATEGY.md` §4, OQ-9). |

## 4. Egress

`worker` needs outbound HTTPS to: `api.anthropic.com`, `api.github.com`, and the advisory hosts in `advisory_sources`. Enforce with a host firewall egress policy for the worker's network, or route through the same allowlisting proxy chosen in OQ-9. `api` needs outbound HTTPS only to `api.github.com` (installation token minting). No other service needs egress.

## 5. Container hardening (all services)

- Non-root user; `read_only: true` where the service allows it; `tmpfs` for scratch.
- `cap_drop: [ALL]` (add back only what a service provably needs, e.g. `NET_BIND_SERVICE` for caddy).
- `security_opt: [no-new-privileges:true]`.
- CPU, memory and PID limits on every container.
- Health checks on every service; `restart: unless-stopped`.
- Images pinned by digest. Base images updated through reviewed PRs.
- **The Docker socket is never mounted into api, worker, beat, web or any agent.** scan-runner is the only exception. A stronger option for later: run scan-runner with rootless Podman or gVisor.

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

- Daily `pg_dump` (custom format) by `platform_readonly`, encrypted (age or GPG, key held off-server), copied off-site.
- Raw scan reports directory backed up weekly with the same encryption.
- Retention: 30 daily, 12 monthly (assumption; adjust).
- Restore tested quarterly and in Phase 6.
- Backups never contain the master encryption key.

## 9. Observability

- Phases 1–5: structured JSON logs to stdout (collected by Docker's log driver with rotation), Prometheus `/metrics` on api and worker (internal network only).
- Phase 6: Grafana dashboards and OpenTelemetry tracing.
- Logs pass through the redaction filter. No secrets, tokens or raw evidence in logs.

## 10. Upgrades

- All changes through PRs with CI (tests, OSV-Scanner, Gitleaks, Actions pinned by SHA).
- Alembic migrations run by a one-shot `migrate` job using `platform_owner`; application services use `platform_app`.
- Rollback: previous image digests kept; DB migrations written to be reversible where practical.

## 11. Repository layout (deployment parts)

```
deploy/
  docker-compose.yml
  Caddyfile
  backup/            # backup and restore scripts
  secrets/README.md  # how to create the Docker secrets; no secret files committed
scanners/images/
  images.lock
  <scanner>/Dockerfile
```
