# Platform Security Review (Phase 6)

Date: 2026-11-25. Scope: this repository at the Phase 5 commit plus the Phase 6 changes: API, dashboard, local agent,
scan-runner, deploy configuration, CI. Method: a read-only review against `CLAUDE.md` §3 (rules 1–14), the threat model
in `SECURITY_POLICIES.md` and `SYSTEM_ARCHITECTURE.md`. Every finding was traced through the code end to end, and a
fix was accepted only once a test covering it passed. Dynamic testing (DAST, penetration test) was **not** done: it
needs the deployed server (OQ-1).

Exit criterion: every finding is fixed or accepted with an owner. OQ-4 (security owner) is still unassigned, so the
accepted items below name the **platform administrator** as interim owner. They need the user's sign-off.

## Findings

| # | Sev. | Finding | Status | Fix and test |
| --- | --- | --- | --- | --- |
| 1 | Medium | Local agent: a symlink inside the root that points at `.env` (e.g. `requirements-dev.txt -> .env`) was read as a manifest. Its values would be uploaded as "packages". | Fixed | `local-agent/security_agent/paths.py`: the resolved target is checked against the secret patterns in `safe_join` and `walk`. `test_symlink_inside_root_to_secret_file_refused` (runs in Linux CI; symlinks skip on Windows). |
| 2 | Medium | `GET /api/findings?project_id=` returned `scanned: true` for a never-scanned project once any other project had a scan, so it read as "no findings" (rule 11). | Fixed | `scanned` is scoped to the project's repositories. `test_scanned_flag_separates_not_scanned_from_no_findings`. |
| 3 | Medium | Webhook replay: `X-GitHub-Delivery` is not signed, so an old signed body sent with a new delivery ID was processed again (false history rewrites, replayed force pushes). | Fixed | Migration 0006 adds a unique `webhook_deliveries.body_sha256`; a replayed body is answered `duplicate`. `test_webhook_replayed_body_with_new_delivery_id_is_duplicate`. |
| 4 | Medium | Developers could triage findings of any project; `SECURITY_POLICIES.md` §4 limits them to their own. | Fixed | Without `findings:accept_risk`, the project's `owner_user_id` must be the caller. `test_triage_rules`. |
| 5 | Low | An admin could remove their own admin role, which could leave no admin. | Fixed | Self-demotion is refused. The caller is always an active admin, so at least one remains. `test_admin_cannot_remove_own_admin_role`. |
| 6 | Low | The login limit was per email only, so password spraying across many emails was never throttled. | Fixed | Added a per-IP failure limit (`login_max_failures_per_ip`, 30 per 15 min). `test_rate_limit_per_ip_stops_password_spraying`. |
| 7 | Low | Each unsigned webhook call wrote an append-only audit row, so an unauthenticated flood could grow `audit_logs` without bound. | Fixed | At most 10 bad-signature audit rows per IP per minute; the 401 is always sent. `test_bad_signature_audit_rows_are_capped_per_ip`. |
| 8 | Low | Anyone who knew an `agent_id` could lock that agent out through the per-agent session-failure counter. | Fixed | Session failures are counted per IP only. An Ed25519 signature cannot be guessed, so a per-agent counter only enabled denial of service. `test_session_failures_limit_the_attacker_ip_not_the_agent`. |
| 9 | Low | The redactor missed secrets held as JSON values under secret-looking keys (`{"password": "..."}`), e.g. in agent log `detail`. | Fixed | `redact_obj` redacts string values whose key matches the secret-key pattern. `test_redact_obj_secret_named_keys`. |
| 10 | Low | scan-runner buffers all of `npm audit`'s stdout before the size cap. | **Accepted** (owner: platform administrator, pending OQ-4) | Fails closed: a huge output exhausts scan-runner's 256 MB limit, the scan fails, and findings are untouched (rule 11). Output size is bounded by the lockfile. Upgrade path: stream stdout with a cap. |
| 11 | Low | A challenge flood (`/api/agents/challenge`, per-agent limit per minute) can delay a real agent's session by up to one minute. | **Accepted** (owner: platform administrator, pending OQ-4) | The impact is a one-minute delay with no data exposure; the per-IP limits still apply. |
| 12 | Info | Once enabled, scan-runner's Docker socket is root-equivalent on the host. | **Accepted** (owner: platform administrator, pending OQ-4) | Opt-in override `deploy/docker-compose.scan-exec.yml`, scan-runner only (policy test). Controls: digest allowlist, reviewed images, fixed argument templates, no shell. Upgrade path: rootless Podman or gVisor (needs the server, OQ-1). |
| 13 | Info | Caddy has no rate limiter (stock Caddy ships none). `SELF_HOSTED_DEPLOYMENT.md` had claimed one. | **Accepted**, doc corrected | All unauthenticated endpoints are rate-limited in the API under advisory locks. Upgrade path: a Caddy build with a rate-limit module (a new component, so it needs approval). |

## Checked and sound

- Client IP: Caddy's `reverse_proxy` replaces a client-supplied `X-Forwarded-For` (no `trusted_proxies`), and `api` is reachable only on the internal `app` network.
- Sessions:
  - A new token is issued at login and at TOTP confirmation.
  - TOTP replay is blocked by a conditional update of `totp_last_step`.
  - CSRF uses an HMAC of the session token, compared in constant time.
  - Cookies are HttpOnly, Secure and SameSite=Strict.
  - Deactivated users and revoked agents are refused on every request.
- Approvals:
  - Requester ≠ approver (reports also have a DB check).
  - Single use (`FOR UPDATE`), scope-hash bound, expiring.
  - Approving needs a fresh TOTP.
- Gateway and LLM:
  - Deny-by-default policy; fixed tool lists; extra input fields forbidden.
  - Redaction before every LLM call.
  - The `llm_allowed` taint is applied before any project data is returned.
  - Untrusted text is escaped inside data blocks.
- scan-runner:
  - No shell; validated targets.
  - `mount_ref` must equal `sp-src-<job>`.
  - Images must be digest-pinned and reviewed.
  - Report readback is capped.
- Egress:
  - Advisory fetchers allow three HTTPS hosts and do not follow redirects.
  - The Squid proxies allow `CONNECT :443` to listed hosts only.
  - WeasyPrint's URL fetcher refuses every fetch, and report HTML is escaped.
- Audit and deploy:
  - The audit log has an append-only trigger and INSERT/SELECT-only grants.
  - `/metrics` is blocked at Caddy.
  - The API sends `default-src 'none'`; the dashboard uses a nonce CSP.
  - Actions are pinned by SHA; no socket is mounted by default.
- Route × role authorisation: `tests/test_authz_matrix.py` walks every API route. It fails when a route is added or re-guarded without updating the reviewed access table, and it checks every role against every permission-guarded route (403 exactly when the role lacks the permission). Every guarded route returns 401 to anonymous callers.
- Phase 6 additions:
  - Traces are redacted before export (`RedactingExporter`, `test_spans_are_redacted_before_export`).
  - Metric labels are route templates and fixed enums only (`test_http_metrics_use_route_templates_not_raw_paths`).
  - Grafana is bound to `127.0.0.1` with sign-up and anonymous access disabled.
  - Observability services sit on the internal `monitoring` network.

## Not covered (needs the server or the user)

- DAST or a penetration test of the deployed stack (OQ-1). Dynamic tests need an approval record per run (`CLAUDE.md` §7).
- Host hardening: SSH, firewall, Docker daemon configuration, automatic updates.
- Review of the GitHub App installation scope in the real org (OQ-2).
