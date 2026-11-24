"""Request authentication, CSRF and permission checks. The UI is never the control."""

import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import csrf_for, token_hash
from app.db.models import SessionScope, User, UserSession
from app.db.session import get_db

SESSION_COOKIE = "sp_session"
CSRF_COOKIE = "sp_csrf"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class Principal:
    user: User
    session: UserSession
    permissions: frozenset[str]

    @property
    def id(self):
        return self.user.id


def client_ip(request: Request) -> str | None:
    # ponytail: Caddy is the only ingress; trust its X-Forwarded-For. Revisit if another proxy is added.
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else None)


async def _load(request: Request, db: AsyncSession, scope: SessionScope) -> Principal:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    now = datetime.now(UTC)
    sess = await db.scalar(select(UserSession).where(UserSession.token_hash == token_hash(token)))
    if sess is None or sess.revoked_at is not None or sess.expires_at <= now or sess.scope != scope:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    user = await db.get(User, sess.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not hmac.compare_digest(sent, csrf_for(token)):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "csrf check failed")
    if scope == SessionScope.full:
        idle = timedelta(minutes=get_settings().session_idle_minutes)
        sess.expires_at = min(now + idle, sess.absolute_expires_at)
        await db.commit()
    perms = frozenset(p.key for r in user.roles for p in r.permissions)
    return Principal(user=user, session=sess, permissions=perms)


async def current_principal(request: Request, db: AsyncSession = Depends(get_db)) -> Principal:
    return await _load(request, db, SessionScope.full)


async def setup_principal(request: Request, db: AsyncSession = Depends(get_db)) -> Principal:
    return await _load(request, db, SessionScope.totp_setup)


def require(permission: str):
    async def dep(principal: Principal = Depends(current_principal)) -> Principal:
        if permission not in principal.permissions:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "permission denied")
        return principal

    return dep
