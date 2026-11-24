"""Phase 3 tables: scan jobs, results, findings and their evidence history."""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base, Timestamps, pg_enum
from app.db.registry import Severity


class Scanner(enum.StrEnum):
    osv_scanner = "osv_scanner"
    npm_audit = "npm_audit"
    pip_audit = "pip_audit"
    semgrep = "semgrep"
    codeql = "codeql"
    gitleaks = "gitleaks"
    trivy = "trivy"
    integrity = "integrity"


class ScanTrigger(enum.StrEnum):
    schedule = "schedule"
    webhook = "webhook"
    advisory = "advisory"
    manual = "manual"


class ScanStatus(enum.StrEnum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    partial = "partial"
    skipped_unchanged = "skipped_unchanged"
    cancelled = "cancelled"


class Confidence(enum.StrEnum):
    confirmed = "confirmed"
    high = "high"
    medium = "medium"
    low = "low"
    needs_verification = "needs_verification"


class FindingStatus(enum.StrEnum):
    open = "open"
    in_progress = "in_progress"
    resolved = "resolved"
    accepted_risk = "accepted_risk"
    false_positive = "false_positive"


class ScanJob(Timestamps, Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("uq_scan_jobs_active", "repository_id", "scanner", "inventory_hash", unique=True,
              postgresql_where=text("status IN ('queued', 'running')")),
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="RESTRICT"), index=True)
    scanner: Mapped[Scanner] = mapped_column(pg_enum(Scanner, "scanner"))
    trigger: Mapped[ScanTrigger] = mapped_column(pg_enum(ScanTrigger, "scan_trigger"))
    inventory_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[ScanStatus] = mapped_column(pg_enum(ScanStatus, "scan_status"))
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    error: Mapped[str | None] = mapped_column(Text)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("approvals.id", ondelete="RESTRICT"))
    requested_by_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_runs.id", ondelete="RESTRICT"))


class ScanResult(Timestamps, Base):
    __tablename__ = "scan_results"
    scan_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_jobs.id", ondelete="RESTRICT"), unique=True)
    raw_report_path: Mapped[str | None] = mapped_column(String(500))  # redacted copy on disk, never in the DB
    raw_report_sha256: Mapped[str | None] = mapped_column(String(64))
    summary: Mapped[dict[str, Any]]
    coverage: Mapped[dict[str, Any]]  # {"all": bool, "paths": [...]} — what this run actually looked at


class SecurityFinding(Timestamps, Base):
    __tablename__ = "security_findings"
    __table_args__ = (
        Index("ix_findings_project_status", "project_id", "status", "severity"),
        Index("ix_findings_repo_scanner_status", "repository_id", "scanner", "status"),
    )
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"))
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="RESTRICT"))
    scanner: Mapped[Scanner] = mapped_column(pg_enum(Scanner, "scanner"))
    rule_id: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(32))  # dependency | code | secret | misconfiguration | integrity
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[Severity] = mapped_column(pg_enum(Severity, "severity"))
    confidence: Mapped[Confidence] = mapped_column(pg_enum(Confidence, "confidence"))
    status: Mapped[FindingStatus] = mapped_column(pg_enum(FindingStatus, "finding_status"))
    file_path: Mapped[str | None] = mapped_column(String(1000))
    line: Mapped[int | None] = mapped_column(Integer)
    package: Mapped[str | None] = mapped_column(String(500))
    package_version: Mapped[str | None] = mapped_column(String(128))
    advisory_ids: Mapped[list[str] | None] = mapped_column(JSONB)  # scanner-reported IDs; matched to advisories in Phase 4
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    resolved_at: Mapped[datetime | None]
    resolved_by_scan_job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_jobs.id", ondelete="RESTRICT"))
    triage_note: Mapped[str | None] = mapped_column(Text)


class FindingEvidence(Timestamps, Base):
    __tablename__ = "finding_evidence"
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_findings.id", ondelete="RESTRICT"), index=True)
    scan_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_jobs.id", ondelete="RESTRICT"))
    evidence_redacted: Mapped[str] = mapped_column(Text)
    match_hash: Mapped[str | None] = mapped_column(String(64))  # secrets: HMAC of the match, never the value
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    captured_at: Mapped[datetime]
