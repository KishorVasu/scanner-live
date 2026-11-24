"""Reports (Phase 5): request a draft, list, view, download PDF, approve.

- Generating runs the Report Generation agent on the worker (needs scans:trigger: it starts work and may use the LLM).
- Approving needs reports:approve, a fresh TOTP code, and a different user from the one who requested the draft; the
  database enforces the last rule too (ck_reports_not_self_approved). Approved reports are immutable.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi import status as http
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.intel import Report, ReportStatus
from app.db.models import ActorType
from app.db.session import get_db
from app.modules.audit.service import record
from app.modules.auth.deps import Principal, client_ip, require
from app.modules.auth.router import check_totp, failures_since, lock_key

router = APIRouter(prefix="/api/reports", tags=["reports"])


class GenerateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: uuid.UUID | None = None  # None = portfolio


class ApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    totp_code: str = Field(max_length=6)


def _out(r: Report, full: bool = False) -> dict:
    out = {"id": str(r.id), "kind": r.kind, "project_id": str(r.project_id) if r.project_id else None,
           "title": r.title, "status": r.status.value, "created_at": r.created_at.isoformat(),
           "created_by": str(r.created_by), "approved_by": str(r.approved_by) if r.approved_by else None,
           "approved_at": r.approved_at.isoformat() if r.approved_at else None,
           "has_narrative": r.narrative is not None, "narrative_note": r.narrative_note}
    if full:
        out |= {"content": r.content, "narrative": r.narrative}  # narrative is AI-written; the UI labels it
    return out


async def _get(db: AsyncSession, report_id: uuid.UUID) -> Report:
    r = await db.get(Report, report_id)
    if r is None:
        raise HTTPException(http.HTTP_404_NOT_FOUND, "report not found")
    return r


@router.post("", status_code=202)
async def generate(body: GenerateIn, request: Request, p: Principal = Depends(require("scans:trigger")),
                   db: AsyncSession = Depends(get_db)):
    record(db, actor_type=ActorType.user, actor_id=p.id, action="report.request", outcome="success",
           target_type="project" if body.project_id else "portfolio", target_id=body.project_id, ip=client_ip(request))
    await db.commit()
    try:
        from app.workers.celery_app import celery

        celery.send_task("reports.generate", args=[str(body.project_id) if body.project_id else None, str(p.id)],
                         retry=False)
    except Exception:  # noqa: BLE001 - broker down: say so instead of pretending a report is coming
        raise HTTPException(http.HTTP_503_SERVICE_UNAVAILABLE, "report worker unavailable") from None
    return {"queued": True}


@router.get("")
async def list_reports(offset: int = Query(0, ge=0, le=100_000), limit: int = Query(25, ge=1, le=100),
                       _: Principal = Depends(require("dashboard:view")), db: AsyncSession = Depends(get_db)):
    total = await db.scalar(select(func.count()).select_from(Report))
    rows = await db.scalars(select(Report).order_by(Report.created_at.desc(), Report.id).offset(offset).limit(limit))
    return {"total": total, "offset": offset, "limit": limit, "items": [_out(r) for r in rows]}


@router.get("/{report_id}")
async def get_report(report_id: uuid.UUID, _: Principal = Depends(require("dashboard:view")),
                     db: AsyncSession = Depends(get_db)):
    return _out(await _get(db, report_id), full=True)


@router.get("/{report_id}/pdf")
async def get_pdf(report_id: uuid.UUID, _: Principal = Depends(require("dashboard:view")),
                  db: AsyncSession = Depends(get_db)):
    from app.reports.render import pdf

    r = await _get(db, report_id)
    data = pdf(r)
    suffix = "" if r.status == ReportStatus.approved else "-DRAFT"
    return Response(data, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="security-report-{str(r.id)[:8]}{suffix}.pdf"',
        "Cache-Control": "no-store"})


@router.post("/{report_id}/approve")
async def approve(report_id: uuid.UUID, body: ApproveIn, request: Request,
                  p: Principal = Depends(require("reports:approve")), db: AsyncSession = Depends(get_db)):
    ip, s = client_ip(request), get_settings()
    await lock_key(db, f"reauth:{p.id}")
    if await failures_since(db, "reports.reauth", "failure", str(p.id), s.login_window_minutes) >= s.login_max_failures:
        p.session.revoked_at = datetime.now(UTC)
        record(db, actor_type=ActorType.user, actor_id=p.id, action="reports.reauth", outcome="locked",
               target_type="user", target_id=p.id, ip=ip)
        await db.commit()
        raise HTTPException(http.HTTP_429_TOO_MANY_REQUESTS, "too many attempts, sign in again later")
    if not await check_totp(db, p.user, body.totp_code):
        record(db, actor_type=ActorType.user, actor_id=p.id, action="reports.reauth", outcome="failure",
               target_type="user", target_id=p.id, ip=ip, detail={"report_id": str(report_id)})
        await db.commit()
        raise HTTPException(http.HTTP_401_UNAUTHORIZED, "invalid code")
    r = await _get(db, report_id)
    problem = ("already approved" if r.status == ReportStatus.approved
               else "the requester cannot approve their own report" if r.created_by == p.id else None)
    if problem:
        record(db, actor_type=ActorType.user, actor_id=p.id, action="report.approve", outcome="rejected",
               target_type="report", target_id=r.id, ip=ip, detail={"error": problem})
        await db.commit()
        raise HTTPException(http.HTTP_409_CONFLICT, problem)
    r.status, r.approved_by, r.approved_at = ReportStatus.approved, p.id, datetime.now(UTC)
    record(db, actor_type=ActorType.user, actor_id=p.id, action="report.approve", outcome="success",
           target_type="report", target_id=r.id, ip=ip)
    await db.commit()
    return _out(r)
