"""Phase 4 tables: advisory sources, advisories (vendor facts kept apart from AI interpretation), project impacts."""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base, Timestamps, pg_enum
from app.db.registry import Severity


class SourceTrust(enum.StrEnum):
    vendor = "vendor"
    ghsa = "ghsa"
    osv = "osv"
    nvd = "nvd"
    cisa_kev = "cisa_kev"
    ecosystem = "ecosystem"


class ImpactClassification(enum.StrEnum):
    confirmed_affected = "confirmed_affected"
    potentially_affected = "potentially_affected"
    not_affected_on_evidence = "not_affected_on_evidence"
    needs_verification = "needs_verification"
    not_scanned = "not_scanned"


class AdvisorySource(Timestamps, Base):
    __tablename__ = "advisory_sources"
    name: Mapped[str] = mapped_column(String(64), unique=True)
    url: Mapped[str] = mapped_column(String(500))
    kind: Mapped[str] = mapped_column(String(32))
    trust_level: Mapped[SourceTrust] = mapped_column(pg_enum(SourceTrust, "source_trust"))
    active: Mapped[bool]
    last_polled_at: Mapped[datetime | None]
    cursor: Mapped[str | None] = mapped_column(String(255))


class SecurityAdvisory(Timestamps, Base):
    __tablename__ = "security_advisories"
    __table_args__ = (
        UniqueConstraint("source_id", "external_id"),
        Index("ix_advisories_pkg", "ecosystem", "package"),
    )
    source_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("advisory_sources.id", ondelete="RESTRICT"))
    external_id: Mapped[str] = mapped_column(String(128))
    aliases: Mapped[list[str]] = mapped_column(ARRAY(String(128)))
    title: Mapped[str] = mapped_column(String(500))
    url: Mapped[str | None] = mapped_column(String(500))
    ecosystem: Mapped[str | None] = mapped_column(String(32))
    package: Mapped[str | None] = mapped_column(String(500))
    affected_ranges: Mapped[list[Any]] = mapped_column(JSONB)
    patched_versions: Mapped[list[str]] = mapped_column(JSONB)
    severity: Mapped[Severity | None] = mapped_column(pg_enum(Severity, "severity"))
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    known_exploited: Mapped[bool]
    vendor_facts: Mapped[str] = mapped_column(Text)  # source text as published; never rewritten by the LLM
    ai_interpretation: Mapped[str | None] = mapped_column(Text)  # LLM summary, always labelled as such
    extra_conditions: Mapped[list[Any] | None] = mapped_column(JSONB)  # [{condition, quote}], quotes verbatim from vendor_facts
    published_at: Mapped[datetime | None]
    modified_at: Mapped[datetime | None]
    retrieved_at: Mapped[datetime]


class ProjectImpact(Timestamps, Base):
    __tablename__ = "project_impacts"
    __table_args__ = (UniqueConstraint("advisory_id", "repository_id"),)
    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_advisories.id", ondelete="RESTRICT"), index=True)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="RESTRICT"), index=True)
    classification: Mapped[ImpactClassification] = mapped_column(pg_enum(ImpactClassification, "impact_classification"))
    reasoning: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[str]] = mapped_column(JSONB)  # dependency_inventory / security_findings IDs
    references: Mapped[list[str]] = mapped_column(JSONB)  # advisory external ID and aliases
    decided_by_rule: Mapped[str | None] = mapped_column(String(64))
    decided_by_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_runs.id", ondelete="RESTRICT"))
    decided_at: Mapped[datetime]


class ReportStatus(enum.StrEnum):
    draft = "draft"
    approved = "approved"


class Report(Timestamps, Base):
    """Phase 5. Content is frozen at generation; the PDF is rendered from it. DB constraints forbid self-approval."""

    __tablename__ = "reports"
    kind: Mapped[str] = mapped_column(String(16))
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[ReportStatus] = mapped_column(pg_enum(ReportStatus, "report_status"))
    content: Mapped[dict[str, Any]] = mapped_column(JSONB)
    narrative: Mapped[str | None] = mapped_column(Text)
    narrative_note: Mapped[str | None] = mapped_column(String(300))
    generated_by_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_runs.id", ondelete="RESTRICT"))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    approved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    approved_at: Mapped[datetime | None]
