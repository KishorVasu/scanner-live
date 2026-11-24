from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog
from app.db.session import get_db
from app.modules.auth.deps import Principal, require

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def list_audit(before: datetime | None = None, limit: int = Query(100, ge=1, le=500),
                     _: Principal = Depends(require("audit:view")), db: AsyncSession = Depends(get_db)):
    q = select(AuditLog).order_by(AuditLog.at.desc()).limit(limit)
    if before:
        q = q.where(AuditLog.at < before)
    return [
        {
            "id": str(r.id), "at": r.at.isoformat(), "actor_type": r.actor_type.value, "actor_id": r.actor_id,
            "action": r.action, "target_type": r.target_type, "target_id": r.target_id,
            "outcome": r.outcome, "ip": r.ip, "detail": r.detail,
        }
        for r in await db.scalars(q)
    ]
