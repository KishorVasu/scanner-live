# Security Platform

Self-hosted security monitoring for the company's projects. Read-only by design. Rules: [CLAUDE.md](CLAUDE.md). Design: [docs/](docs/).

Status: Phase 3 (Scanning) approved; live scanner behaviour is verified in CI (`scanner-live`). Phase 4 (Intelligence) approved. Phase 5 (Dashboard and reports) approved. Phase 6 (Validation and rollout) built and green in CI; the server, pilot and onboarding steps are open (`docs/IMPLEMENTATION_ROADMAP.md`). Learning Notes was removed from scope.

## Layout

| Path | What |
| --- | --- |
| `apps/api` | FastAPI API, Celery worker/beat, PolicyEngine, Tool Gateway, agent orchestrator, registry, GitHub App, local-agent API, Project Discovery agent |
| `apps/web` | Next.js dashboard |
| `libs/inventory` | `sp_inventory`: technology detection, manifest/lockfile parsers, inventory hashes (stdlib only; shared by API and local agent) |
| `local-agent` | `security-agent` CLI for administrator-approved folders on developer machines and servers |
| `scan-runner` | Container launcher: request validation, images.lock allowlist, sandboxed `docker run` (execution off until Docker is available) |
| `scanners/images/images.lock` | Pinned scanner digests (all null until pinned by review; unpinned scanners cannot run) |
| `deploy` | Docker Compose, Caddyfile, Postgres init, secrets README |
| `scripts` | Repo checks (Action SHA pins) |

## API development

```sh
cd apps/api
python -m venv .venv
.venv/Scripts/python -m pip install --require-hashes -r requirements.lock -r requirements-test.lock   # Windows; .venv/bin/python on Linux/macOS
.venv/Scripts/python -m pip install --no-deps -e .
.venv/Scripts/python -m pytest -q -rs
```

DB tests run against a throwaway embedded Postgres (`pgserver`, test-only) started and deleted by the test session,
so no local database or password is needed. To use another server instead, set `TEST_PG_ADMIN_URL` (CI does) or put it
in the gitignored `apps/api/.env.test` (`scripts/new-test-env.ps1` writes it with a masked prompt). That server gets a
temporary database and a `platform_app` role. In CI the DB tests fail instead of skipping when no database is available.

Migrations run as the owner: `SP_MIGRATION_DATABASE_URL=... alembic upgrade head`.
First admin: `python -m app.cli create-admin --email you@company` (TOTP enrolment happens at first login).

The API also needs the shared library: `.venv/Scripts/python -m pip install --no-deps -e ../../libs/inventory`.

### Lockfiles

Python lockfiles are hashed and universal (Linux, macOS, Windows), compiled with `uv` from the `requirements*.in`
files. Edit the `.in` file, then recompile from the repository root, for example:

```sh
uv pip compile --universal --generate-hashes --python-version 3.12 --no-header apps/api/requirements.in -o apps/api/requirements.lock
```

Add `--upgrade-package NAME` to move one package; without it uv keeps the versions already in the lockfile.
`requirements-test.lock` is constrained by `requirements.lock` (`-c`), so compile it from `apps/api`.
Every install uses `--require-hashes`.

## Local agent

```sh
cd local-agent
python -m venv .venv
.venv/Scripts/python -m pip install --require-hashes -r requirements.lock
.venv/Scripts/python -m pip install --no-deps -e ../libs/inventory -e .
.venv/Scripts/python -m pytest -q -rs        # symlink tests skip on Windows without symlink rights
```

Enrol: an admin creates the agent and its approved roots (`POST /api/agents`) and gets a one-time code. On the machine:
`security-agent register --server https://<server> --allow <folder> [--allow <folder> ...]` (code is prompted, hidden).
The private key goes to the OS keychain. `security-agent scan` then inventories the server's approved roots, but only
those inside the machine's own `--allow` list. It uploads dependency lists and hashes, never file contents, and never
opens `.env*`, key or credential files.

## Web development

```sh
cd apps/web
npm ci --ignore-scripts
npm test
npm run dev          # proxies /api to http://127.0.0.1:8000
```

## Deploy

See [docs/SELF_HOSTED_DEPLOYMENT.md](docs/SELF_HOSTED_DEPLOYMENT.md) and [deploy/secrets/README.md](deploy/secrets/README.md), then
`docker compose -f deploy/docker-compose.yml up -d --build`.
