# Implementation Roadmap

Status: Phase 0 draft, awaiting approval.

Seven phases, each ending at an approval gate. Claude Code stops after every phase and waits for explicit approval ("Phase N approved").

Estimate for one developer with Claude Code: 12 to 14 weeks. Planning guess, not a commitment.

| Phase | Name | Estimate |
| --- | --- | --- |
| 0 | Inspection and design | ~3 days |
| 1 | Foundation | 2 weeks |
| 2 | Registry and access | 2 weeks |
| 3 | Scanning | 3 weeks |
| 4 | Intelligence | 2 weeks |
| 5 | Dashboard and reports | 2 weeks |
| 6 | Validation and rollout | 2 weeks |

Useful security output starts at the end of Phase 3.

Pilot: three projects with different stacks for Phases 2–5 (suggested: AIMess — Next.js + Node.js + iOS + Android; one Flutter app; one PHP or Python site). Onboard the rest only in Phase 6.

Hard constraint: no external project repository is touched in Phases 0–2 beyond read-only access set up and approved in Phase 2.

## Working method per phase

1. Inspect existing code.
2. Explain planned changes; list files to create or modify.
3. Name security and operational risks.
4. Implement only approved scope.
5. Run tests in-session and show the output.
6. Review own diff for security problems; fix within scope.
7. Report done / not done.
8. Stop for approval.

## Phase 0 — Inspection and design

**Scope:** inspect workspace; write the eight design docs; define permissions, agents, schema, threat model.

**Exit criteria:**
- [ ] `SYSTEM_ARCHITECTURE`, `IMPLEMENTATION_ROADMAP`, `AGENT_SPECIFICATIONS`, `SECURITY_POLICIES`, `DATABASE_SCHEMA`, `SCANNING_STRATEGY`, `SELF_HOSTED_DEPLOYMENT`, `TESTING_STRATEGY` in `docs/`.
- [ ] Open questions answered or explicitly deferred with an assumption.
- [ ] Proposed changes and additions approved or rejected.
- [ ] User replies "Phase 0 approved".

## Phase 1 — Foundation

**Scope:**
- Monorepo layout (see §Folder structure).
- FastAPI app: settings, JSON logging, health, `/metrics`.
- Postgres + Alembic baseline migration: access tables, `policies`, `approvals`, `agent_runs`, `audit_logs` (with grants and trigger).
- Auth: argon2id, mandatory TOTP, server-side sessions, CSRF, rate limits.
- RBAC: roles, permissions, API dependency checks.
- Audit log service.
- PolicyEngine (deny by default) and Tool Gateway skeleton with redactor; agent spec model and orchestrator refusal on incomplete specs. No real tools yet.
- Next.js app shell: login, TOTP, layout, empty pages for every section.
- Docker Compose for all services (scan-runner as a stub), networks, limits, health checks.
- CI: tests, lint, OSV-Scanner and Gitleaks on this repo; every Action pinned by SHA; CI check that rejects tag references.

**Dependencies to approve (libraries required by features the spec already names):**
- Python: `fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `sqlalchemy[asyncio]`, `asyncpg`, `alembic`, `argon2-cffi`, `pyotp`, `cryptography`, `httpx`, `celery`, `redis`, `prometheus-client`, `anthropic` (Phase 4), `weasyprint` (Phase 5), `typer` + `keyring` (local agent, Phase 2); test: `pytest`, `pytest-asyncio`.
- Node: `next`, `react`, `typescript`, `primereact`, `sass`; test: `vitest` + `@testing-library/react`, `@playwright/test`.
- As installed (2026-11-24): Next 16.4.6, React 19.3.1, **PrimeReact pinned to 10.9.9** (MIT, styled components). PrimeReact 11 is an unstyled-primitives rewrite under the "PrimeUI License"; moving to it needs a licence review and approval. Test tooling also needs `jsdom` and `@vitejs/plugin-react`. Python versions are frozen in `apps/api/requirements.lock`.

**Exit criteria:**
- [ ] `docker compose up` starts all services healthy (on a machine with Docker).
- [ ] Login with TOTP works; RBAC tests pass.
- [ ] `audit_logs` UPDATE/DELETE rejected for the app role (test).
- [ ] PolicyEngine denies unknown actions; gateway refuses forbidden tools; orchestrator refuses incomplete specs (tests).
- [ ] Redactor test: known fake secret never reaches a prompt, log or API response.
- [ ] No Docker socket outside scan-runner (compose test).
- [ ] CI green with SHA-pinned Actions.

## Phase 2 — Registry and access

**Scope:** project / component / repository CRUD; scan policies; GitHub App (read-only) install flow, webhooks with signature check, delivery idempotency, per-repo rate limit, `force_push` events; local agent CLI (`register`, session tokens, revocation, approved roots, path resolution, technology detection, inventory upload); Project Discovery agent; dependency inventory and hashes.

**Exit criteria:**
- [ ] Three pilot projects registered with all their repositories.
- [ ] Webhook signature and idempotency tests pass.
- [ ] Local-agent boundary tests pass: traversal, symlink escape, unapproved folder, absolute path outside root.
- [ ] Revoked agent rejected immediately.
- [ ] Inventory and hashes stored for every pilot repository.
- [ ] GitHub App permissions verified read-only (no Workflows permission).

## Phase 3 — Scanning

**Scope:** scan-runner with image allowlist and fixed templates; pinned images and `images.lock`; adapters for OSV-Scanner, npm audit, pip-audit, Gitleaks, Semgrep, Trivy (CodeQL behind licence flag); integrity checks; findings with fingerprints and evidence history; scheduling and dedup; failure semantics.

**Exit criteria:**
- [ ] Every scanner runs on safe fixtures and on the pilots; findings stored with fingerprints.
- [ ] Failed / partial / skipped scans never close findings (tests).
- [ ] Integrity checks detect each synthetic fixture case.
- [ ] Secret findings contain no secret values anywhere (test).
- [ ] Sandbox profile verified: read-only mount, non-root, no network unless allowlisted, container removed.

## Phase 4 — Intelligence

**Scope:** advisory ingestion (OSV, GHSA, NVD, CISA KEV, vendor feeds; allowlisted); deterministic inventory matching; Security Research and Impact Analysis agents on the Messages API; targeted rescans; impact matrix.

**Exit criteria:**
- [ ] Advisories stored with vendor facts separate from AI interpretation.
- [ ] Impact classification rules enforced deterministically (no `confirmed_affected` on name/version alone with extra conditions; no `not_affected_on_evidence` on incomplete inventory).
- [ ] Prompt-injection fixture in a README does not change tools or output.
- [ ] Unknown source IDs in LLM output fail validation.
- [ ] `llm_allowed = false` projects never reach the LLM (test).

## Phase 5 — Dashboard and reports

**Scope:** Overview, Projects, project detail, Security Intelligence, Scans & Findings (triage), Repository Integrity, Approvals, Reports (draft to approved, PDF via WeasyPrint), Settings, Audit Log.

**Exit criteria:**
- [ ] "Not scanned" and "no findings" visually distinct everywhere.
- [ ] Approval UI blocks self-approval; expired approvals cannot execute (backend tests + e2e).
- [ ] PDF report drafts render; approval required to mark approved.
- [ ] Playwright e2e for main flows; accessibility basics (keyboard, labels, contrast).

## Phase 6 — Validation and rollout

**Scope:** security review of the platform; permission and load tests; Grafana and OpenTelemetry; hardening (optional rootless Podman / gVisor for scan-runner); backup restore test; pilot review; onboard remaining projects.

**Exit criteria:**
- [ ] Security review findings fixed or accepted with an owner.
- [ ] Load test at 20 projects within resource budget.
- [ ] Restore from backup tested.
- [ ] All projects onboarded.

## Folder structure

```
security-platform/
  apps/
    web/                     # Next.js dashboard
    api/
      app/
        core/                # config, security, logging, policy engine
        db/                  # models, session, alembic/
        modules/             # auth, rbac, projects, components, repositories, local_agents,
                             # github_app, scans, findings, advisories, impacts,
                             # approvals, reports, audit
        agents/              # orchestrator, tool gateway, specs, tools, prompts
        scanners/            # one adapter per scanner + parsers
        integrations/        # github_app, local_agent_api, advisory feeds
        workers/             # celery app, tasks, schedules
      tests/
  local-agent/               # Python CLI (Typer) + tests
  scan-runner/               # container launcher with image allowlist + tests
  scanners/images/           # pinned Dockerfiles, images.lock
  deploy/                    # docker-compose.yml, Caddyfile, backup scripts
  docs/                      # the 13 documents
  .github/workflows/         # CI, actions pinned by SHA
```

## Open questions

| ID | Question | Default assumption until answered |
| --- | --- | --- |
| OQ-1 | Where will the server run: office machine, VPS, or AWS/GCP? | VPS reachable from GitHub for webhooks. |
| OQ-2 | Which GitHub org(s) get the App, and who approves the installation? | One org; installation approved by an admin. |
| OQ-3 | GitHub Code Security licence available? | No; CodeQL off for private repos; Semgrep primary. |
| OQ-4 | Who is the security owner (approves incidents and DAST)? Must differ from requesters. | Unassigned; incident actions blocked until set. |
| OQ-5 | Critical alerts: email, Zulip bot, or both? | Dashboard only until decided. |
| OQ-6 | Do any client contracts forbid sending redacted findings to an external LLM? | `llm_allowed = true` default; per-project override. |
| OQ-7 | Load the 19 November GitHub incident and the MERN server compromise as first incident records? | Yes, as tuning input for integrity checks, once evidence is supplied. |
| OQ-8 | Approve the three proposed changes: Grafana/OTel to Phase 6; in-house orchestrator instead of Claude Agent SDK; Semgrep CE default with Opengrep fallback. | Treated as approved in these docs. |
| OQ-9 | Scanner egress enforcement: allowlisting forward proxy (new component), host firewall, or offline DBs? | **Decided 2026-11-24:** offline DBs for OSV/Trivy + allowlisting forward proxy for npm/pip audit (new component approved; design before build). |
| OQ-10 | Approve the library list in Phase 1. | Pending. |
| OQ-11 | Approve the six supporting tables in `DATABASE_SCHEMA.md` §7. | Pending. |
| OQ-12 | Local agent: dev machine is Windows. Keep macOS/Linux first and run boundary tests in Linux CI? | Yes. |
| OQ-13 | `Installed Skills and Tools.pdf` was not found. Supply it or skip? | Skipped; `installed-skills-and-tools.md` used. |
| OQ-14 | Semgrep rule packs to bake into the scanner image. | **Decided 2026-11-24:** p/default, p/owasp-top-ten, p/secrets, plus language packs for the company stacks. |
| OQ-15 | Hashed Python lockfiles: uv or pip-tools? | **Decided 2026-11-24:** uv (`uv pip compile --universal --generate-hashes`). pip-tools was picked first, but it can only lock for the OS it runs on (Windows dev PC, Linux targets); the user then left the choice to the lead engineer. uv is a dev tool only, not a runtime dependency. |
