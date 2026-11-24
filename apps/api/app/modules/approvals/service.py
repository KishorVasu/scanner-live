"""Approvals: per operation, scoped, expiring, single use, never self-approved (rule R9)."""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models import Approval, ApprovalStatus


class ApprovalError(Exception):
    pass


def canonical(scope: dict[str, Any]) -> str:
    return json.dumps(scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def scope_hash(action: str, scope: dict[str, Any]) -> str:
    return hashlib.sha256(f"{action}\n{canonical(scope)}".encode()).hexdigest()


def create(session: AsyncSession, *, action: str, scope: dict[str, Any], reason: str, risks: str,
           requested_by: uuid.UUID, requested_by_run_id: uuid.UUID | None = None) -> Approval:
    approval = Approval(
        action=action,
        scope=json.loads(canonical(scope)),
        scope_hash=scope_hash(action, scope),
        reason=reason,
        risks=risks,
        requested_by=requested_by,
        requested_by_run_id=requested_by_run_id,
        status=ApprovalStatus.pending,
        expires_at=datetime.now(UTC) + timedelta(hours=get_settings().approval_ttl_hours),
    )
    session.add(approval)
    return approval


async def decide(session: AsyncSession, approval_id: uuid.UUID, approver_id: uuid.UUID, approve: bool) -> Approval:
    approval = await session.scalar(select(Approval).where(Approval.id == approval_id).with_for_update())
    if approval is None:
        raise ApprovalError("not found")
    if approval.requested_by == approver_id:
        raise ApprovalError("requester cannot approve their own request")
    if approval.status != ApprovalStatus.pending:
        raise ApprovalError(f"approval is {approval.status}")
    now = datetime.now(UTC)
    if approval.expires_at <= now:
        approval.status = ApprovalStatus.expired
        raise ApprovalError("approval expired")
    approval.status = ApprovalStatus.approved if approve else ApprovalStatus.rejected
    approval.approver_id = approver_id
    approval.decided_at = now
    return approval


async def consume(session: AsyncSession, action: str, scope: dict[str, Any], run_id: uuid.UUID | None = None) -> Approval | None:
    """Mark one matching, approved, unexpired approval as executed. Returns None if there is none.

    An approval requested by a specific agent run can only be used by that run.
    """
    approval = await session.scalar(
        select(Approval)
        .where(
            Approval.scope_hash == scope_hash(action, scope),
            Approval.action == action,
            Approval.status == ApprovalStatus.approved,
            Approval.expires_at > datetime.now(UTC),
            or_(Approval.requested_by_run_id.is_(None), Approval.requested_by_run_id == run_id),
        )
        .order_by(Approval.decided_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if approval is not None:
        approval.status = ApprovalStatus.executed
        approval.executed_at = datetime.now(UTC)
    return approval


async def expire_stale(session: AsyncSession) -> int:
    result = await session.execute(
        update(Approval)
        .where(Approval.status.in_([ApprovalStatus.pending, ApprovalStatus.approved]), Approval.expires_at <= datetime.now(UTC))
        .values(status=ApprovalStatus.expired)
    )
    return result.rowcount or 0
