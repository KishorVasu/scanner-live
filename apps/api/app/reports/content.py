"""Deterministic report content (no LLM) and the safety-claim check for narratives (CLAUDE.md rule 11, §7 5.8)."""

import re
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.intel import ProjectImpact, SecurityAdvisory
from app.db.registry import Project, ProjectComponent, ProjectStatus, Repository, RepositoryEvent
from app.db.scanning import FindingStatus, ScanJob, ScanStatus, SecurityFinding

STATEMENT = ("This report lists what the platform's scanners and advisory matching found. It does not show that any "
             "project is secure. Repositories listed under \"Not scanned\" were not examined at all.")
TOP = 25

# A narrative must never claim safety (CLAUDE.md rule 11). Deterministic, deliberately broad; a false hit only drops
# the narrative, the tables stay.
UNSAFE_CLAIMS = re.compile(
    r"\b(is|are|was|were|be|remains?)\s+(now\s+)?(fully\s+|completely\s+)?(secure|safe|protected|invulnerable)\b"
    r"|\bno\s+(known\s+)?(vulnerabilit|risk|issue|threat)|\bnot\s+vulnerable\b|\bfree\s+(of|from)\s+vulnerabilit"
    r"|\bguarantee|\bfully\s+(secure|protected|compliant)\b|\ball\s+clear\b",
    re.IGNORECASE)


def unsafe_claim(text: str) -> str | None:
    m = UNSAFE_CLAIMS.search(text or "")
    return m.group(0) if m else None


async def build(db: AsyncSession, project_id: uuid.UUID | None) -> tuple[dict, list[uuid.UUID]]:
    """Returns (content, project_ids). Everything here is read from the database and frozen into the report."""
    q = select(Project).where(Project.status != ProjectStatus.archived).order_by(Project.name)
    if project_id:
        q = select(Project).where(Project.id == project_id)
    projects = list(await db.scalars(q))
    if project_id and not projects:
        raise LookupError("project not found")
    since = datetime.now(UTC) - timedelta(days=30)
    out, not_scanned = [], []
    for p in projects:
        repos = list((await db.execute(
            select(Repository, ProjectComponent.name).join(ProjectComponent, ProjectComponent.id == Repository.component_id)
            .where(ProjectComponent.project_id == p.id).order_by(ProjectComponent.name, Repository.id))).all())
        repo_rows = []
        for r, comp in repos:
            last = dict((await db.execute(
                select(ScanJob.scanner, func.max(ScanJob.finished_at))
                .where(ScanJob.repository_id == r.id, ScanJob.status.in_([ScanStatus.succeeded, ScanStatus.partial]))
                .group_by(ScanJob.scanner))).all())
            label = f"{p.name} / {comp} / {r.full_name or r.local_path_alias or str(r.id)[:8]}"
            if not last:
                not_scanned.append(label)
            repo_rows.append({
                "repository": label,
                "inventory": "never" if r.inventory_complete is None else ("complete" if r.inventory_complete else "partial"),
                "last_successful_scan": {s.value: t.date().isoformat() if t else None for s, t in last.items()},
            })
        open_q = select(SecurityFinding).where(SecurityFinding.project_id == p.id, SecurityFinding.status.in_(
            [FindingStatus.open, FindingStatus.in_progress]))
        by_sev = dict((await db.execute(
            select(SecurityFinding.severity, func.count()).where(SecurityFinding.project_id == p.id,
                                                                 SecurityFinding.status.in_([FindingStatus.open, FindingStatus.in_progress]))
            .group_by(SecurityFinding.severity))).all())
        top = list(await db.scalars(open_q.order_by(SecurityFinding.severity, SecurityFinding.last_seen_at.desc()).limit(TOP)))
        impacts = (await db.execute(
            select(ProjectImpact.classification, SecurityAdvisory.external_id, SecurityAdvisory.title,
                   SecurityAdvisory.package, SecurityAdvisory.known_exploited, SecurityAdvisory.patched_versions)
            .join(SecurityAdvisory, SecurityAdvisory.id == ProjectImpact.advisory_id)
            .join(Repository, Repository.id == ProjectImpact.repository_id)
            .join(ProjectComponent, ProjectComponent.id == Repository.component_id)
            .where(ProjectComponent.project_id == p.id,
                   ProjectImpact.classification.in_(["confirmed_affected", "potentially_affected", "needs_verification"]))
            .order_by(SecurityAdvisory.known_exploited.desc(), SecurityAdvisory.severity).limit(TOP))).all()
        events = await db.scalar(
            select(func.count()).select_from(RepositoryEvent).join(Repository, Repository.id == RepositoryEvent.repository_id)
            .join(ProjectComponent, ProjectComponent.id == Repository.component_id)
            .where(ProjectComponent.project_id == p.id, RepositoryEvent.created_at >= since))
        out.append({
            "project": p.name, "criticality": p.criticality.value, "repositories": repo_rows,
            "open_findings_by_severity": {s.value: n for s, n in by_sev.items()},
            "top_findings": [{"severity": f.severity.value, "title": f.title, "rule_id": f.rule_id,
                              "location": f.package and f"{f.package}@{f.package_version}" or f.file_path,
                              "scanner": f.scanner.value, "status": f.status.value} for f in top],
            "advisory_impacts": [{"classification": c.value, "advisory": eid, "title": t, "package": pkg,
                                  "known_exploited": kev, "fixed_in": fixed} for c, eid, t, pkg, kev, fixed in impacts],
            "integrity_events_30d": events or 0,
        })
    content = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "scope": "project" if project_id else "portfolio",
        "statement": STATEMENT,
        "not_scanned": not_scanned,
        "projects": out,
    }
    return content, [p.id for p in projects]
