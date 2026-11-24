from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redaction import get_redactor
from app.db.models import ActorType, AuditLog


def record(
    session: AsyncSession,
    *,
    actor_type: ActorType,
    actor_id: object | None,
    action: str,
    outcome: str,
    target_type: str | None = None,
    target_id: object | None = None,
    ip: str | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    """Add an audit row to the session. The caller commits (on failure paths too)."""
    row = AuditLog(
        actor_type=actor_type,
        actor_id=str(actor_id) if actor_id is not None else None,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        ip=ip,
        detail=get_redactor().redact_obj(detail or {}),
    )
    session.add(row)
    return row
