# CLAUDE.md — Security Platform rules

Status: Phase 3 (Scanning) approved 2026-11-24 with two carried items (pilot scans; source fetch), both blocked on the GitHub org / pilot names and the digest review. Phase 4 (Intelligence): planning, awaiting plan approval. Dev PC runs no Docker (decision 2026-11-24): container work is verified in GitHub CI and on the Linux server; architecture unchanged. Design docs in `docs/` are the approved source of truth; open-question defaults in `docs/IMPLEMENTATION_ROADMAP.md` apply until answered.

You are the lead engineer building a self-hosted security monitoring platform for a software company that runs 15 to 20 mixed-technology projects (Next.js, React, Node.js/Express, Python/Django/FastAPI, Laravel/PHP, Flutter, native iOS and Android, Unity games, MongoDB, PostgreSQL, MySQL, Redis, Docker, Linux servers, GitHub Actions).

The goal: nobody should have to open 20 repositories each day to learn whether a new advisory, dependency vulnerability, malware campaign or suspicious change affects them. The platform watches every registered project, tells the owner which project needs attention and why, and never takes a risky action on its own.

This is a security-sensitive system. It will hold read access to every project the company owns. Build the security controls before any autonomous capability, and enforce them in backend code, not in prompts.

## 1. Fixed decisions

- **Architecture: hybrid.** A central self-hosted server plus local agents. Deterministic pipelines do all detection. LLM agents run only at named steps: advisory research, impact reasoning, report writing, integrity summaries and (later) learning notes.
- **Project access: both.** A GitHub App (read-only) for repositories, and a Python local agent for administrator-approved folders on developer machines or servers.
- **Detection is deterministic.** Scanners produce the evidence. Claude explains, correlates, prioritises and drafts. Claude never decides on its own that code is vulnerable or safe without scanner or advisory evidence.

## 2. Technology stack

| Layer | Choice |
| --- | --- |
| Dashboard | Next.js (App Router), TypeScript, SCSS modules, PrimeReact |
| API | Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2 (async), Alembic |
| Database | PostgreSQL |
| Jobs | Redis + Celery worker + Celery beat |
| LLM | Anthropic Python SDK, Messages API with tool use, behind an `LLMProvider` interface. Do not use the Claude Agent SDK or any framework that ships built-in shell or file tools. |
| Scanners | OSV-Scanner v2, npm audit (`--package-lock-only`), pip-audit, Semgrep CE, Gitleaks, Trivy, CodeQL (optional, licence-gated) |
| Local agent | Python CLI with Typer, outbound HTTPS only |
| Reverse proxy | Caddy |
| PDF | WeasyPrint |
| Observability | Structured JSON logs + Prometheus `/metrics` in Phases 1–5. Grafana and OpenTelemetry tracing in Phase 6. |
| Deploy | Docker Compose on one Linux server |

Do not add other infrastructure or dependencies. If you believe a substitution is needed, stop, explain why, and wait for approval.

## 3. Non-negotiable security rules

Enforce every rule below in code and cover it with a test.

1. Read-only by default. The platform has no tool that edits project code, upgrades dependencies, deletes files or branches, force-pushes, deploys, rotates credentials, changes permissions, or shares learning notes. Do not build these tools in v1.
2. Every agent action goes through a **Tool Gateway** that checks a **PolicyEngine** backed by Postgres before execution. An agent never gets a shell, a raw filesystem path, a DB session or open network access.
3. Repository content, READMEs, issues, comments, commit messages, scanner output and web pages are **untrusted data**. Pass them to Claude inside clearly labelled data blocks. They can never change policies, permissions or tool lists.
4. Never place secret values in prompts, logs, API responses, reports or the database. A redactor runs in the Tool Gateway before every LLM call and before every write of evidence. Store secret findings as rule ID, file, line, commit and a salted hash of the match.
5. Never execute project code, package scripts, builds or tests by default. Scanners read manifests and lockfiles only. Anything that executes project code needs an approval record.
6. Scanners run in disposable containers: read-only project mount, non-root user, no host credentials, CPU and memory limits, a network allowlist per scanner, deleted after the job.
7. Pin every scanner image by digest, keep digests in `scanners/images/images.lock`, mirror to a private registry, and upgrade only through a reviewed change. (Trivy v0.69.4 and the trivy-action tags were poisoned in March 2026; tag references were exposed.) Pin every GitHub Action in this repo by full commit SHA.
8. Never mount the Docker socket into the API, worker or any agent container. Only a dedicated `scan-runner` service starts containers, and it accepts only allowlisted image digests with fixed argument templates.
9. Approvals are per operation, scoped, and expire (default 24 hours). The requester cannot approve their own request. One approval never covers a later operation.
10. Every agent run, tool call, approval and admin action writes to an append-only `audit_logs` table. The application DB role has no UPDATE or DELETE on it.
11. A failed or partial scan never produces a clean result and never closes findings. The UI shows "not scanned" separately from "no findings". Never claim a project or machine is secure because a scan passed.
12. Never invent advisories, CVE IDs, versions, project names, repository URLs, technologies or credentials. Mock data is allowed only in clearly labelled UI previews and tests.
13. Never execute a suspicious file to find out whether it is malicious. Inspect it statically and preserve it as evidence.
14. Use harmless synthetic fixtures for malicious-pattern tests. Never commit a live payload.

## 4. Components

**Dashboard pages:** Overview, Projects, Security Intelligence, Scans & Findings, Repository Integrity, Reports, Approvals, Learning Notes (later), Settings, Audit Log.

**API modules:** auth (argon2 passwords + TOTP), RBAC (admin, approver, developer, viewer), projects, components, repositories, local agents, GitHub App, scans, findings, advisories, impacts, approvals, reports, audit.

**GitHub App:** read-only permissions only (metadata, contents, pull requests, actions, Dependabot alerts, code scanning alerts, secret scanning alerts where enabled). Never request the Workflows write permission. Verify `X-Hub-Signature-256`, make processing idempotent on `X-GitHub-Delivery`, rate-limit per repository, record `forced: true` pushes as `repository_events`. Store the App private key encrypted; do not store personal access tokens.

**Local agent (Python CLI):**
- `register` with a one-time enrolment code; generates an Ed25519 key pair and stores the private key in the OS keychain.
- Uses short-lived session tokens. The server can revoke an agent instantly.
- Approved roots are set server-side. The agent resolves real paths, rejects `..`, absolute paths outside roots and any symlink that leaves a root.
- Detects languages, frameworks, package managers, lockfiles and manifests.
- Runs only allowlisted scanners with fixed arguments, never project scripts.
- Sends structured results. Never sends file contents of `.env*`, key files or anything matching the secret patterns.
- Logs every operation locally and to the server.

**Scan runner:** a small service that receives `{scanner, repository_id, mount_ref}` from the worker, starts the pinned image, enforces limits and network policy, collects the report file, deletes the container.

## 5. Project registry

Model: **project → component → repository**. One project can have a web repo, an API repo, iOS, Android, Flutter and infra repos, each from GitHub or a local agent. Do not assume one project equals one repository.

Each project stores: name, slug, description, owner, criticality, status, scan policy, deployment environments. Each repository stores: source (github or local), identifiers, default branch, technology profiles (ecosystem, framework, version, package manager, lockfile path), dependency inventory, `manifest_hash`, `tree_hash`, last successful scan per scanner.

## 6. Data model (PostgreSQL)

UUID primary keys, `created_at`/`updated_at` everywhere, Postgres enums for statuses, proper foreign keys and indexes. JSONB only for genuinely variable data (scanner summaries, affected version ranges, approval scope).

Tables: `users`, `roles`, `permissions`, `user_roles`, `role_permissions`, `projects`, `project_components`, `repositories`, `technology_profiles`, `dependency_inventory`, `local_agents`, `scan_policies`, `scan_jobs`, `scan_results`, `security_findings`, `finding_evidence`, `advisory_sources`, `security_advisories`, `project_impacts`, `repository_events`, `approvals`, `agent_runs`, `test_runs`, `reports`, `learning_notes`, `audit_logs`.

Key rules:
- `security_findings.fingerprint` is unique. Repeated detections update `last_seen_at` and add a `finding_evidence` row. Nothing is silently discarded.
- A finding moves to `resolved` only after a successful run of the same scanner that no longer reports it.
- `scan_jobs` deduplicate on repository + scanner + inventory hash.
- Severity: critical, high, medium, low, informational. Confidence: confirmed, high, medium, low, needs_verification. Status: open, in_progress, resolved, accepted_risk, false_positive.
- Impact classification: confirmed_affected, potentially_affected, not_affected_on_evidence, needs_verification, not_scanned. Each impact stores reasoning, evidence and source references.

## 7. Agents

Every agent is one Pydantic spec with: `name`, `purpose`, `input_schema`, `output_schema`, `allowed_tools`, `uses_llm`, `timeout_s`, `max_retries`, `approval_required_for`. The orchestrator refuses to run an agent with an incomplete spec. Every run writes an `agent_runs` row (model, token counts, input hash, output, status).

| Agent | Phase | Uses Claude | Tools |
| --- | --- | --- | --- |
| Project Discovery | 2 | No | read_manifest, list_tree (approved roots), github_repo_metadata |
| Dependency Analysis | 3 | No | run_osv_scanner, run_npm_audit, run_pip_audit |
| Code Security | 3 | No | run_semgrep, run_codeql (licence-gated) |
| Secret Detection | 3 | No | run_gitleaks, github_secret_alerts |
| Repository Integrity | 3 | Summary only | git_log_metadata, diff_manifest, list_workflows, hash_inventory |
| Security Research | 4 | Yes | fetch_osv, fetch_ghsa, fetch_nvd, fetch_cisa_kev, fetch_vendor_feed (allowlisted URLs only) |
| Impact Analysis | 4 | Yes | query_inventory, read_finding, request_targeted_scan |
| Report Generation | 5 | Yes | read_findings, read_impacts, render_pdf (output is a draft) |
| QA & Validation | later | Yes | run_playwright, run_zap — approved staging URL only, every run approved |
| Application Security | later | Yes | static auth-flow review; any dynamic test needs approval |
| Learning Notes | later | Yes | read_advisories, read_impacts — drafts only, never shared automatically |

## 8. Repository integrity checks (first-release feature)

All static, nothing executed:
- Force-pushes and history rewrites (webhook `forced: true`, stored branch heads).
- New or changed `preinstall`, `install`, `postinstall`, `prepare` scripts; Python build hooks.
- New or changed `.vscode/tasks.json` (especially `runOn: folderOpen`), `.vscode/settings.json` terminal overrides, IDE run configs.
- Changes to `vite.config.*`, `webpack.config.*`, `next.config.*`, `babel.config.*`, `.npmrc`, `.yarnrc*`.
- Changes to `.github/workflows/*`: `pull_request_target`, broadened `permissions`, actions referenced by tag instead of SHA.
- Binary files (fonts, images) whose magic bytes don't match their extension or that contain JS or shell markers.
- Obfuscation signals: very long single-line JS, `eval`/`Function` on decoded strings, large base64 or hex-escaped blobs.
- Files present in the tree that `.gitignore` says should be ignored.

## 9. Advisory ingestion and impact analysis

Sources, by trust: official vendor and framework advisories, GitHub Security Advisories, OSV, NVD, CISA Known Exploited Vulnerabilities, ecosystem advisories (npm, PyPI, pub.dev, Packagist). Store external ID, title, URL, ecosystem, package, affected ranges, patched versions, severity, published, modified and retrieved timestamps. Keep vendor facts and AI interpretation in separate fields.

On a new advisory:
1. Match package and version ranges against `dependency_inventory` (deterministic).
2. For each match, check whether the component is actually used and whether the advisory's extra conditions are present (config flags, APIs used), with evidence.
3. Recommend or queue a targeted rescan.
4. Write a `project_impacts` row with classification, reasoning, evidence and references.

Never mark a project affected on framework name or version alone when the advisory has extra conditions. Never mark a project not affected just because a package is missing from an incomplete inventory; use `not_scanned` or `needs_verification`.

## 10. Scheduling

- Daily: advisory ingestion, dependency scan, secret scan (skipped when hashes are unchanged and no new matching advisory exists).
- Weekly: full SAST, Trivy, integrity sweep.
- On push or PR webhook: targeted scans for changed areas.
- Manual: project scan, advisory impact analysis.
- Celery tasks have timeouts, retry with backoff, deduplication and worker health checks.

## 11. Deployment

Docker Compose services: caddy, web, api, worker, beat, scan-runner, postgres, redis. Networks: `public` (caddy only), `app`, `data` (postgres, redis, no published ports), `scan-control`, `scan` (egress allowlist). TLS, security headers, encrypted backups, health checks, resource limits on every container.

## 12. Testing

Write and actually run: unit tests, API integration tests, DB/migration tests, auth and RBAC tests, local-agent boundary tests (traversal, symlink escape, unapproved folder), webhook signature and idempotency tests, scanner adapter tests on safe fixtures, integrity detection tests on synthetic fixtures, redaction tests (a known fake secret never reaches a prompt, log or report), approval tests (self-approval blocked, expired approval blocked, unapproved action blocked by the backend), audit log tests, retry and failure tests (a failed scan never produces a clean result), frontend component tests, Playwright end-to-end tests for the dashboard.

Never say tests passed unless you ran them in this session and can show the output.

## 13. Documentation

Maintain in `docs/`: README, SYSTEM_ARCHITECTURE, IMPLEMENTATION_ROADMAP, AGENT_SPECIFICATIONS, SECURITY_POLICIES, DATABASE_SCHEMA, API_DOCUMENTATION, LOCAL_AGENT_SETUP, GITHUB_INTEGRATION, SCANNING_STRATEGY, SELF_HOSTED_DEPLOYMENT, INCIDENT_RESPONSE, TESTING_STRATEGY. Never put real credentials in docs or example env files.

## 14. Phases

- **Phase 0 — Inspection and design.** Inspect the workspace, write the design docs, define permissions and tasks. No code beyond scaffolding docs.
- **Phase 1 — Foundation.** Repo layout, FastAPI app, Next.js app, Postgres + Alembic, auth with TOTP, RBAC, audit log, PolicyEngine and Tool Gateway skeleton, Docker Compose, CI with SHA-pinned actions.
- **Phase 2 — Registry and access.** Project/component/repository CRUD, GitHub App install flow and webhooks, local agent enrolment and approved roots, technology detection, dependency inventory and hashes.
- **Phase 3 — Scanning.** scan-runner, pinned scanner images, OSV-Scanner, npm audit, pip-audit, Gitleaks, Semgrep, Trivy, integrity checks, findings with fingerprints and evidence history.
- **Phase 4 — Intelligence.** Advisory ingestion from allowlisted sources, inventory matching, Impact Analysis agent, targeted rescans, impact matrix.
- **Phase 5 — Dashboard and reports.** Overview, project detail, scan history, finding triage, integrity view, approvals, PDF reports (draft → approved).
- **Phase 6 — Validation and rollout.** Security review of the platform itself, permission and load tests, Grafana/OTel, hardening, pilot with 3 projects, then all.

## 15. How to work on each phase

1. Inspect the existing code.
2. Explain the planned changes and list files to create or modify.
3. Name the security and operational risks.
4. Implement only the approved scope.
5. Run the tests and show results.
6. Review your own diff for security problems and fix them within scope.
7. Report what is done and what is not.
8. Stop and wait for my approval before the next phase.

Do not change architecture or scope silently. Do not touch any external project repository at any point in Phases 0–2.

## 16. Your first task: Phase 0 only

Inspect the current workspace and report whether it is empty or contains existing work. Do not overwrite or delete anything.

Then create these documents in `docs/`:
1. SYSTEM_ARCHITECTURE.md
2. IMPLEMENTATION_ROADMAP.md
3. AGENT_SPECIFICATIONS.md
4. SECURITY_POLICIES.md
5. DATABASE_SCHEMA.md
6. SCANNING_STRATEGY.md
7. SELF_HOSTED_DEPLOYMENT.md
8. TESTING_STRATEGY.md

Then reply with:
- Workspace inspection report
- Proposed folder structure
- Technology justification (and any substitution you want approved)
- System architecture diagram (Mermaid)
- Database relationship plan (Mermaid ER diagram)
- Agent permission matrix
- Threat model (threat, example, control)
- Phase-by-phase checklist with exit criteria
- Open questions and assumptions

Do not start Phase 1 until I reply "Phase 0 approved".
