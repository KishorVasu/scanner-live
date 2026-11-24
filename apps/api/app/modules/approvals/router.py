import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.redaction import get_redactor
from app.db.models import ActorType, Approval, ApprovalStatus, Policy, PolicyTier
from app.db.session import get_db
from app.modules.approvals import service
from app.modules.audit.service import record
from app.modules.auth.deps import Principal, client_ip, require
from app.modules.auth.router import check_totp, failures_since, lock_key

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


class RequestIn(BaseModel):
    action: str = Field(max_length=128)
    scope: dict[str, Any]
    reason: str = Field(min_length=1, max_length=4000)
    risks: str = Field(default="", max_length=4000)


class DecisionIn(BaseModel):
    totp_code: str = Field(max_length=6)  # re-authentication before every decision
    approve: bool


def _out(a: Approval) -> dict:
    return {
        "id": str(a.id), "action": a.action, "scope": a.scope, "reason": a.reason, "risks": a.risks,
        "status": a.status.value, "requested_by": str(a.requested_by),
        "approver_id": str(a.approver_id) if a.approver_id else None,
        "expires_at": a.expires_at.isoformat(), "executed_at": a.executed_at.isoformat() if a.executed_at else None,
    }


@router.post("", status_code=201)
async def request_approval(body: RequestIn, request: Request, p: Principal = Depends(require("approvals:request")),
                           db: AsyncSession = Depends(get_db)):
    policy = await db.scalar(select(Policy).where(Policy.action == body.action, Policy.active.is_(True)))
    if policy is None or policy.tier != PolicyTier.approval_required:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "action is not approvable")
    r = get_redactor()
    if r.redact_obj(body.scope) != body.scope:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "scope looks like it contains a secret")
    # Free text is shown to every dashboard viewer, so it is redacted before storage (rule R4).
    # Scope is not redacted (it must match the operation's arguments exactly); secret-looking scopes are refused above.
    approval = service.create(db, action=body.action, scope=body.scope, reason=r.redact(body.reason),
                              risks=r.redact(body.risks), requested_by=p.id)
    await db.flush()
    record(db, actor_type=ActorType.user, actor_id=p.id, action="approvals.request", outcome="success",
           target_type="approval", target_id=approval.id, ip=client_ip(request), detail={"action": body.action})
    await db.commit()
    return _out(approval)


@router.get("")
async def list_approvals(status_filter: ApprovalStatus | None = None, _: Principal = Depends(require("dashboard:view")),
                         db: AsyncSession = Depends(get_db)):
    q = select(Approval).order_by(Approval.created_at.desc()).limit(200)
    if status_filter:
        q = q.where(Approval.status == status_filter)
    return [_out(a) for a in await db.scalars(q)]


@router.post("/{approval_id}/decision")
async def decide(approval_id: uuid.UUID, body: DecisionIn, request: Request,
                 p: Principal = Depends(require("approvals:decide")), db: AsyncSession = Depends(get_db)):
    ip = client_ip(request)
    s = get_settings()
    await lock_key(db, f"reauth:{p.id}")
    if await failures_since(db, "approvals.reauth", "failure", str(p.id), s.login_window_minutes) >= s.login_max_failures:
        p.session.revoked_at = datetime.now(UTC)  # repeated bad codes on a live session: end the session
        record(db, actor_type=ActorType.user, actor_id=p.id, action="approvals.reauth", outcome="locked",
               target_type="user", target_id=p.id, ip=ip)
        await db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts, sign in again later")
    if not await check_totp(db, p.user, body.totp_code):
        record(db, actor_type=ActorType.user, actor_id=p.id, action="approvals.reauth", outcome="failure",
               target_type="user", target_id=p.id, ip=ip, detail={"approval_id": str(approval_id)})
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
    try:
        approval = await service.decide(db, approval_id, p.id, body.approve)
    except service.ApprovalError as e:
        record(db, actor_type=ActorType.user, actor_id=p.id, action="approvals.decide", outcome="rejected",
               target_type="approval", target_id=approval_id, ip=ip, detail={"error": str(e)})
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from None
    record(db, actor_type=ActorType.user, actor_id=p.id, action="approvals.decide", outcome="success",
           target_type="approval", target_id=approval.id, ip=ip, detail={"status": approval.status.value})
    await db.commit()
    return _out(approval)
