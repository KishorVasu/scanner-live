# Scanning Strategy

Status: Phase 0 draft, awaiting approval.

Scanners produce all detection evidence. Nothing in this document executes project code.

## 1. Scanners

| Scanner | Finds | Schedule | Network in sandbox | Notes |
| --- | --- | --- | --- | --- |
| OSV-Scanner v2 | Vulnerable dependencies from lockfiles, all ecosystems | Daily + on manifest change | `api.osv.dev` only (or none with offline DB, see §4) | Primary SCA. Reads lockfiles; never installs. |
| npm audit | npm advisories | Daily for JS repos | npm registry only | `--package-lock-only`, so no install scripts run. |
| pip-audit | PyPI advisories | Daily for Python repos | PyPI + OSV only | From requirements / lock files, no install (`--no-deps` / disabled resolution where needed). |
| Semgrep CE | XSS, injection, SSRF, path traversal, weak crypto, unsafe deserialisation | Weekly + on PR | None (rules baked into image) | Per-language rule packs; custom rules for our Express and Next.js patterns. Rules licence limits use to internal, non-SaaS; Opengrep is the fallback. |
| CodeQL | Deeper data-flow bugs | Weekly, opt-in per repo | None | Off by default. Licence check required for private repos. Compiled languages need a build, which executes project code, so those runs are approval-tier. |
| Gitleaks | Secrets in files and git history | Daily + on push | None | Stores rule, file, line, commit, salted match hash; never the value. |
| Trivy | Container images, Dockerfiles, IaC misconfiguration | Weekly + on Dockerfile change | Internal vulnerability DB mirror only | Pinned by digest. Never `latest` or a tag. |
| Integrity checks (in-house) | Tampering signals, §6 | Every push webhook + daily | None | Pure static inspection. |

## 2. Execution model

### 2.1 GitHub repositories

1. Worker calls the Tool Gateway (e.g. `run_osv_scanner(repository_id)`). PolicyEngine decides; audit row written.
2. Worker sends `scan-runner` a request: `{scanner, repository_id, mount_ref, template}`. `template` is a name, never arguments.
3. `scan-runner` obtains a short-lived, single-repo, `contents:read` installation token from the API's GitHub integration, fetches the repository into an ephemeral volume with hooks disabled (`core.hooksPath=/dev/null`, no submodules, no LFS smudge, `protocol.file.allow=never`), then discards the token. Gitleaks jobs fetch full history; others fetch a shallow checkout.
4. `scan-runner` starts the pinned image with the sandbox profile (§3), project volume mounted read-only, report directory as the only writable mount.
5. On exit (or timeout), it collects the report file, records its SHA-256, deletes the container and volume, and returns `{status, report_path, exit_code}`.
6. The scanner adapter parses the report into normalised findings (§7).

### 2.2 Local repositories

1. The local agent pulls a job from the server.
2. It resolves the real path of the requested alias inside its approved roots; rejects `..`, absolute paths outside roots and symlinks that leave a root.
3. It runs only allowlisted scanner binaries (versions and SHA-256 checksums published by the server) with fixed argument templates, never project scripts.
4. It parses manifests and lockfiles locally and uploads structured results: dependency inventory, findings with redacted evidence, scan coverage. It never uploads `.env*`, key files or anything matching secret patterns.
5. Every operation is logged locally and to the server.

## 3. Sandbox profile (every scanner container)

- Image referenced by digest from `scanners/images/images.lock`; digest must match the allowlist.
- `user` non-root (fixed UID), `read_only: true` root filesystem, `tmpfs` for `/tmp`.
- Project volume mounted read-only; report directory the only writable bind.
- `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, default seccomp profile.
- CPU and memory limits per scanner; PID limit; wall-clock timeout enforced by scan-runner.
- No host credentials, no environment secrets, no Docker socket, no host network.
- Network: `none` unless the scanner's allowlist requires egress; then attached to the `scan` network, whose egress is restricted to that scanner's hosts (§4).
- Container and volume removed after every job, including on failure.

## 4. Network allowlists

| Scanner | Allowed egress |
| --- | --- |
| OSV-Scanner | `api.osv.dev` (or none, using an offline DB refreshed by a separate job) |
| npm audit | `registry.npmjs.org` |
| pip-audit | `pypi.org`, `api.osv.dev` |
| Trivy | internal DB mirror host only |
| Semgrep, Gitleaks, CodeQL, integrity | none |

Enforcement mechanism is an open decision (OQ-9): Docker networks cannot filter by hostname on their own. Options:
1. A small allowlisting forward proxy on the `scan` network (new component, needs approval).
2. Host firewall rules (`DOCKER-USER` chain) on resolved IPs (fragile when CDN IPs change).
3. Offline databases wherever the scanner supports them (OSV-Scanner offline mode, Trivy mirror), leaving only npm audit and pip-audit needing egress.

Recommendation: option 3 for OSV-Scanner and Trivy, plus option 1 for npm audit and pip-audit.

## 5. Image pinning

- `scanners/images/images.lock` lists `name`, `upstream version`, `digest`, `mirrored digest`, `verified_at`, `reviewer`.
- Images are pulled from upstream once, verified (signature where the project publishes one, checksum, release notes), and pushed to the private registry. scan-runner pulls only from the private registry by digest.
- Upgrades go through a reviewed PR that updates `images.lock`.
- Trivy: pin only a release that advisory GHSA-69fq-xp46-6x23 lists as safe, verified at pin time. v0.69.4 is explicitly excluded.

## 6. Repository integrity checks

All static. Each produces a `repository_events` row and, above informational severity, a finding.

| Check | Signal | Default severity |
| --- | --- | --- |
| Force push | Webhook `forced: true` | high |
| History rewrite | New head is not a descendant of the stored branch head | high |
| Lifecycle scripts | New or changed `preinstall`, `install`, `postinstall`, `prepare` in any `package.json`; build hooks in `setup.py`, `pyproject.toml` (`[build-system]`, custom backends) | high (new), medium (changed) |
| VS Code tasks | New or changed `.vscode/tasks.json`, especially `runOptions.runOn: folderOpen` | high for `folderOpen`, medium otherwise |
| Editor settings | `.vscode/settings.json` terminal / shell overrides; `.idea` run configurations | medium |
| Build config | Changes to `vite.config.*`, `webpack.config.*`, `next.config.*`, `babel.config.*`, `.npmrc`, `.yarnrc*` | medium |
| Workflows | Changes to `.github/workflows/*`: `pull_request_target`, broadened `permissions` (e.g. `write-all`), actions referenced by tag instead of full SHA | high for `pull_request_target` + checkout of PR head; medium otherwise |
| Binary mismatch | Font, image or other binary whose magic bytes do not match the extension, or that contains JavaScript or shell markers | high |
| Obfuscation | Very long single-line JS (threshold configurable), `eval` / `Function` on decoded strings, large base64 blobs, hex-escaped strings | medium |
| Ignored file committed | A path matching `.gitignore` present in the tree | low (high if it matches a secret pattern) |

Flagged files are preserved as evidence (hash + location) and never executed. A high-severity event can be escalated to the incident workflow (`SECURITY_POLICIES.md` §12).

## 7. Normalisation and lifecycle

- Every adapter maps tool output to one `Finding` model: scanner, rule_id, category, title, severity, confidence, file_path, line, package, package_version, advisory external ID, redacted evidence, fingerprint (`DATABASE_SCHEMA.md` §5).
- Severity mapping is per scanner and documented in the adapter. Unknown severity maps to `medium` with `confidence = needs_verification`, never to `informational`.
- Scanner output is untrusted data. Adapters parse with strict schemas and size limits; unparseable output marks the job `failed`.

## 8. Failure semantics

- Non-zero exit that is not the scanner's documented "findings present" code, timeout, parse error or missing report: job `failed`. No findings are closed.
- Some targets scanned, others not: job `partial`; coverage recorded. No findings are closed outside the covered set.
- Unchanged hashes: job `skipped_unchanged`; the UI shows the last successful result with its date.
- The dashboard shows "not scanned" (no successful job for that scanner) separately from "no findings" (successful job, zero findings).
- No report or UI text ever says a project is "secure".

## 9. Avoiding redundant scans

1. Each repository keeps `manifest_hash` (lockfiles and manifests) and `tree_hash` (source files).
2. Scheduled jobs compare hashes first. No change and no new matching advisory: skip, keep last result.
3. A new advisory triggers a targeted scan only on repositories whose `dependency_inventory` contains the affected package.
4. Jobs dedupe on repository + scanner + inventory hash, so ten pushes in an hour produce one scan.

## 10. Schedules

| When | What |
| --- | --- |
| Daily | Advisory ingestion; dependency scan; secret scan (skipped when hashes unchanged and no new matching advisory) |
| Weekly | Full SAST (Semgrep, CodeQL where enabled), Trivy, integrity sweep |
| On push / PR webhook | Targeted scans for changed areas; integrity checks on the diff |
| Manual | Project scan; advisory impact analysis |

Celery tasks: per-task time limits, retry with exponential backoff and jitter, deduplication, worker health checks.
