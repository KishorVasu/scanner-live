"""Findings: list, detail with evidence history, and triage (Phase 5). Reads need dashboard:view; see TRIAGE_ROLE."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi import status as http
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.registry import Project, Severity
from app.core.redaction import get_redactor
from app.db.models import ActorType
from app.db.scanning import FindingEvidence, FindingStatus, ScanJob, ScanStatus, Scanner, SecurityFinding
from app.db.session import get_db
from app.modules.audit.service import record
from app.modules.auth.deps import Principal, client_ip, require

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


# ---------- detail and triage (Phase 5) ----------

TRIAGE_ROLE = {  # target status -> permission. `resolved` is never set by hand: only a successful scan resolves.
    FindingStatus.open: "findings:triage",
    FindingStatus.in_progress: "findings:triage",
    FindingStatus.false_positive: "findings:accept_risk",
    FindingStatus.accepted_risk: "findings:accept_risk",
}


class TriageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: FindingStatus
    note: str = Field(default="", max_length=4000)


@router.get("/{finding_id}")
async def get_finding(finding_id: uuid.UUID, _: Principal = Depends(require("dashboard:view")),
                      db: AsyncSession = Depends(get_db)):
    f = await db.get(SecurityFinding, finding_id)
    if f is None:
        raise HTTPException(http.HTTP_404_NOT_FOUND, "finding not found")
    evidence = await db.scalars(select(FindingEvidence).where(FindingEvidence.finding_id == f.id)
                                .order_by(FindingEvidence.captured_at.desc()).limit(50))
    return {
        "id": str(f.id), "project_id": str(f.project_id), "repository_id": str(f.repository_id),
        "scanner": f.scanner.value, "rule_id": f.rule_id, "category": f.category, "title": f.title,
        "severity": f.severity.value, "confidence": f.confidence.value, "status": f.status.value,
        "file_path": f.file_path, "line": f.line, "package": f.package, "package_version": f.package_version,
        "advisory_ids": f.advisory_ids or [], "triage_note": f.triage_note,
        "first_seen_at": f.first_seen_at.isoformat(), "last_seen_at": f.last_seen_at.isoformat(),
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        # evidence_redacted is already redacted at write time; secrets are stored as a salted hash only (rule R4).
        "evidence": [{"captured_at": e.captured_at.isoformat(), "evidence": e.evidence_redacted,
                      "commit_sha": e.commit_sha, "scan_job_id": str(e.scan_job_id)} for e in evidence],
    }


@router.patch("/{finding_id}")
async def triage(finding_id: uuid.UUID, body: TriageIn, request: Request,
                 p: Principal = Depends(require("findings:triage")), db: AsyncSession = Depends(get_db)):
    needed = TRIAGE_ROLE.get(body.status)
    if needed is None:
        raise HTTPException(http.HTTP_422_UNPROCESSABLE_ENTITY, "only a successful scan can resolve a finding")
    if needed not in p.permissions:
        raise HTTPException(http.HTTP_403_FORBIDDEN, f"{body.status.value} needs {needed}")
    if needed == "findings:accept_risk" and len(body.note.strip()) < 10:
        raise HTTPException(http.HTTP_422_UNPROCESSABLE_ENTITY, "a note of at least 10 characters is required")
    f = await db.get(SecurityFinding, finding_id)
    if f is None:
        raise HTTPException(http.HTTP_404_NOT_FOUND, "finding not found")
    if f.status == FindingStatus.resolved:
        raise HTTPException(http.HTTP_409_CONFLICT, "resolved findings reopen only when a scan reports them again")
    before = f.status.value
    f.status = body.status
    if body.note.strip():
        f.triage_note = get_redactor().redact(body.note.strip())
    record(db, actor_type=ActorType.user, actor_id=p.id, action="finding.triage", outcome="success",
           target_type="finding", target_id=f.id, ip=client_ip(request),
           detail={"from": before, "to": body.status.value})
    await db.commit()
    return {"id": str(f.id), "status": f.status.value}
