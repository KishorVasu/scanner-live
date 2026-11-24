"""Findings list for the dashboard (read-only; triage endpoints come with the triage UI). Needs dashboard:view."""

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.registry import Project, Severity
from app.db.scanning import FindingStatus, ScanJob, ScanStatus, Scanner, SecurityFinding
from app.db.session import get_db
from app.modules.auth.deps import Principal, require

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("")
async def list_findings(
    status: list[FindingStatus] = Query(default=[]),
    severity: list[Severity] = Query(default=[]),
    scanner: Scanner | None = None,
    project_id: uuid.UUID | None = None,
    offset: int = Query(0, ge=0, le=100_000),
    limit: int = Query(25, ge=1, le=100),
    _: Principal = Depends(require("dashboard:view")),
    db: AsyncSession = Depends(get_db),
):
    # ponytail: offset paging with a total, which a page-number paginator needs; switch to keyset if findings
    # ever reach the hundreds of thousands.
    where = []
    if status:
        where.append(SecurityFinding.status.in_(status))
    if severity:
        where.append(SecurityFinding.severity.in_(severity))
    if scanner:
        where.append(SecurityFinding.scanner == scanner)
    if project_id:
        where.append(SecurityFinding.project_id == project_id)
    total = await db.scalar(select(func.count()).select_from(SecurityFinding).where(*where))
    rows = await db.execute(
        select(SecurityFinding, Project.name)
        .join(Project, Project.id == SecurityFinding.project_id)
        .where(*where)
        # Postgres orders enums by declaration: critical first.
        .order_by(SecurityFinding.severity, SecurityFinding.last_seen_at.desc(), SecurityFinding.id)
        .offset(offset).limit(limit)
    )
    # Rule 11: "nothing found" and "nothing scanned" must look different in the UI.
    scanned = await db.scalar(select(exists().where(ScanJob.status.in_([ScanStatus.succeeded, ScanStatus.partial]))))
    return {
        "total": total, "offset": offset, "limit": limit, "scanned": scanned,
        "items": [
            {
                "id": str(f.id), "project_id": str(f.project_id), "project": name,
                "repository_id": str(f.repository_id), "scanner": f.scanner.value, "rule_id": f.rule_id,
                "category": f.category, "title": f.title, "severity": f.severity.value,
                "confidence": f.confidence.value, "status": f.status.value, "file_path": f.file_path, "line": f.line,
                "package": f.package, "package_version": f.package_version,
                "first_seen_at": f.first_seen_at.isoformat(), "last_seen_at": f.last_seen_at.isoformat(),
            }
            for f, name in rows
        ],
    }
