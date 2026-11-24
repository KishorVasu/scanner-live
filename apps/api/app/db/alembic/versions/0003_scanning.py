"""Scan jobs, results, findings, evidence; grants; scanner tool policies.

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

APP_ROLE = "platform_app"
UUID = pg.UUID(as_uuid=True)
TZ = sa.DateTime(timezone=True)

ENUMS = {
    "scanner": ("osv_scanner", "npm_audit", "pip_audit", "semgrep", "codeql", "gitleaks", "trivy", "integrity"),
    "scan_trigger": ("schedule", "webhook", "advisory", "manual"),
    "scan_status": ("queued", "running", "succeeded", "failed", "partial", "skipped_unchanged", "cancelled"),
    "confidence": ("confirmed", "high", "medium", "low", "needs_verification"),
    "finding_status": ("open", "in_progress", "resolved", "accepted_risk", "false_positive"),
}

# Static scans run automatically; CodeQL may need a build, which executes project code (rule R5).
POLICIES = {
    "run_osv_scanner": "allowed", "run_npm_audit": "allowed", "run_pip_audit": "allowed", "run_semgrep": "allowed",
    "run_gitleaks": "allowed", "run_trivy": "allowed", "run_integrity_checks": "allowed",
    "read_repository_profile": "allowed",
    "run_codeql": "approval_required",
}

GRANTS = {
    "scan_jobs": "SELECT, INSERT, UPDATE",
    "scan_results": "SELECT, INSERT",
    "security_findings": "SELECT, INSERT, UPDATE",
    "finding_evidence": "SELECT, INSERT",  # evidence history is append-only
}


def _ts() -> list[sa.Column]:
    return [
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", TZ, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TZ, nullable=False, server_default=sa.func.now()),
    ]


def _e(name: str) -> pg.ENUM:
    return pg.ENUM(*ENUMS.get(name, ()), name=name, create_type=False)


def _fk(target: str, name: str, nullable: bool = False, **kw) -> sa.Column:
    return sa.Column(name, UUID, sa.ForeignKey(f"{target}.id", ondelete="RESTRICT"), nullable=nullable, **kw)


def upgrade() -> None:
    for name, values in ENUMS.items():
        pg.ENUM(*values, name=name).create(op.get_bind())

    op.create_table(
        "scan_jobs", *_ts(),
        _fk("repositories", "repository_id", index=True),
        sa.Column("scanner", _e("scanner"), nullable=False),
        sa.Column("trigger", _e("scan_trigger"), nullable=False),
        sa.Column("inventory_hash", sa.String(64), nullable=False),
        sa.Column("status", _e("scan_status"), nullable=False),
        sa.Column("started_at", TZ),
        sa.Column("finished_at", TZ),
        sa.Column("error", sa.Text),
        _fk("approvals", "approval_id", nullable=True),
        _fk("agent_runs", "requested_by_run_id", nullable=True),
    )
    op.create_index("uq_scan_jobs_active", "scan_jobs", ["repository_id", "scanner", "inventory_hash"], unique=True,
                    postgresql_where=sa.text("status IN ('queued', 'running')"))
    op.create_table(
        "scan_results", *_ts(),
        _fk("scan_jobs", "scan_job_id", unique=True),
        sa.Column("raw_report_path", sa.String(500)),
        sa.Column("raw_report_sha256", sa.String(64)),
        sa.Column("summary", pg.JSONB, nullable=False),
        sa.Column("coverage", pg.JSONB, nullable=False),
    )
    op.create_table(
        "security_findings", *_ts(),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        _fk("projects", "project_id"),
        _fk("repositories", "repository_id"),
        sa.Column("scanner", _e("scanner"), nullable=False),
        sa.Column("rule_id", sa.String(255), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", pg.ENUM(name="severity", create_type=False), nullable=False),
        sa.Column("confidence", _e("confidence"), nullable=False),
        sa.Column("status", _e("finding_status"), nullable=False),
        sa.Column("file_path", sa.String(1000)),
        sa.Column("line", sa.Integer),
        sa.Column("package", sa.String(500)),
        sa.Column("package_version", sa.String(128)),
        sa.Column("advisory_ids", pg.JSONB),
        sa.Column("first_seen_at", TZ, nullable=False),
        sa.Column("last_seen_at", TZ, nullable=False),
        sa.Column("resolved_at", TZ),
        _fk("scan_jobs", "resolved_by_scan_job_id", nullable=True),
        sa.Column("triage_note", sa.Text),
    )
    op.create_index("ix_findings_project_status", "security_findings", ["project_id", "status", "severity"])
    op.create_index("ix_findings_repo_scanner_status", "security_findings", ["repository_id", "scanner", "status"])
    op.create_table(
        "finding_evidence", *_ts(),
        _fk("security_findings", "finding_id", index=True),
        _fk("scan_jobs", "scan_job_id"),
        sa.Column("evidence_redacted", sa.Text, nullable=False),
        sa.Column("match_hash", sa.String(64)),
        sa.Column("commit_sha", sa.String(64)),
        sa.Column("captured_at", TZ, nullable=False),
    )

    for table in GRANTS:
        op.execute(f"CREATE TRIGGER trg_{table}_updated_at BEFORE UPDATE ON {table} FOR EACH ROW "
                   "EXECUTE FUNCTION set_updated_at()")
    grants = "\n".join(f"GRANT {p} ON {t} TO {APP_ROLE};" for t, p in GRANTS.items())
    op.execute(f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN {grants} END IF; END $$")
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'platform_readonly') THEN "
               "GRANT SELECT ON ALL TABLES IN SCHEMA public TO platform_readonly; END IF; END $$")

    policies = sa.table("policies", sa.column("action", sa.String),
                        sa.column("tier", pg.ENUM(name="policy_tier", create_type=False)), sa.column("description", sa.Text))
    op.bulk_insert(policies, [{"action": a, "tier": t, "description": "Scanning (Phase 3)"} for a, t in POLICIES.items()])


def downgrade() -> None:
    op.execute("DELETE FROM policies WHERE action IN (" + ",".join(f"'{a}'" for a in POLICIES) + ")")
    for table in reversed(list(GRANTS)):
        op.drop_table(table)
    for name in reversed(list(ENUMS)):
        op.execute(f"DROP TYPE IF EXISTS {name}")
