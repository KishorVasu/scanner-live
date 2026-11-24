"""User administration (admin only). New users enrol TOTP themselves on first login."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import MIN_PASSWORD_LENGTH, hash_password
from app.db.models import ActorType, Role, User, UserSession
from app.db.session import get_db
from app.modules.audit.service import record
from app.modules.auth.deps import Principal, client_ip, require
from app.modules.rbac.catalog import ROLES

router = APIRouter(prefix="/api/users", tags=["users"])


class UserIn(BaseModel):
    email: str = Field(max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=1024)
    roles: list[str]


class RolesIn(BaseModel):
    roles: list[str]


def _out(u: User) -> dict:
    return {
        "id": str(u.id), "email": u.email, "roles": sorted(r.name for r in u.roles),
        "is_active": u.is_active, "totp_enrolled": u.totp_confirmed_at is not None,
    }


async def _roles(db: AsyncSession, names: list[str]) -> list[Role]:
    if not names or any(n not in ROLES for n in names):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"roles must be a non-empty subset of {ROLES}")
    return list(await db.scalars(select(Role).where(Role.name.in_(names))))


@router.get("")
async def list_users(_: Principal = Depends(require("users:manage")), db: AsyncSession = Depends(get_db)):
    return [_out(u) for u in await db.scalars(select(User).order_by(User.email))]


@router.post("", status_code=201)
async def create_user(body: UserIn, request: Request, p: Principal = Depends(require("users:manage")),
                      db: AsyncSession = Depends(get_db)):
    email = body.email.strip().lower()
    if await db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "user exists")
    pw_hash = await run_in_threadpool(hash_password, body.password)  # argon2 off the event loop
    user = User(email=email, password_hash=pw_hash, roles=await _roles(db, body.roles))
    db.add(user)
    await db.flush()
    record(db, actor_type=ActorType.user, actor_id=p.id, action="users.create", outcome="success",
           target_type="user", target_id=user.id, ip=client_ip(request), detail={"roles": body.roles})
    await db.commit()
    return _out(user)


@router.put("/{user_id}/roles")
async def set_roles(user_id: uuid.UUID, body: RolesIn, request: Request,
                    p: Principal = Depends(require("users:manage")), db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    before = sorted(r.name for r in user.roles)
    user.roles = await _roles(db, body.roles)
    record(db, actor_type=ActorType.user, actor_id=p.id, action="users.set_roles", outcome="success",
           target_type="user", target_id=user.id, ip=client_ip(request),
           detail={"before": before, "after": sorted(body.roles)})
    await db.commit()
    return _out(user)


@router.post("/{user_id}/deactivate")
async def deactivate(user_id: uuid.UUID, request: Request, p: Principal = Depends(require("users:manage")),
                     db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    if user.id == p.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "cannot deactivate yourself")
    user.is_active = False
    for s in await db.scalars(select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))):
        s.revoked_at = datetime.now(UTC)
    record(db, actor_type=ActorType.user, actor_id=p.id, action="users.deactivate", outcome="success",
           target_type="user", target_id=user.id, ip=client_ip(request))
    await db.commit()
    return _out(user)
