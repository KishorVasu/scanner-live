"""Login (password + mandatory TOTP), first-login TOTP enrolment, logout, me."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.core.config import get_settings
from app.core.security import (
    csrf_for,
    get_cipher,
    new_token,
    new_totp_secret,
    token_hash,
    totp_uri,
    verify_password,
    verify_totp,
)
from app.db.models import ActorType, AuditLog, SessionScope, User, UserSession
from app.db.session import get_db
from app.modules.audit.service import record
from app.modules.auth.deps import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    Principal,
    client_ip,
    current_principal,
    setup_principal,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
TOTP_CONTEXT = "users.totp_secret_enc"
GENERIC_FAIL = "invalid credentials"


class LoginIn(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)
    totp_code: str | None = Field(default=None, max_length=6)


class CodeIn(BaseModel):
    code: str = Field(max_length=6)


def totp_secret_of(user: User) -> str:
    assert user.totp_secret_enc is not None
    return get_cipher().decrypt(user.totp_secret_enc, f"{TOTP_CONTEXT}:{user.id}").decode()


async def check_totp(db: AsyncSession, user: User, code: str | None) -> bool:
    """Verify and consume a TOTP code for a confirmed user.

    The step is claimed with one conditional UPDATE, so two concurrent requests cannot both use the same code.
    """
    if not code or user.totp_secret_enc is None or user.totp_confirmed_at is None:
        return False
    step = verify_totp(totp_secret_of(user), code, user.totp_last_step)
    if step is None:
        return False
    claimed = await db.execute(
        update(User)
        .where(User.id == user.id, or_(User.totp_last_step.is_(None), User.totp_last_step < step))
        .values(totp_last_step=step)
        .execution_options(synchronize_session=False)
    )
    if claimed.rowcount != 1:
        return False
    set_committed_value(user, "totp_last_step", step)
    return True


async def lock_key(db: AsyncSession, key: str) -> None:
    """Serialise attempts for one key until the transaction ends (closes the check-then-act race)."""
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": key})


async def failures_since(db: AsyncSession, action: str, outcome: str, target_id: str, minutes: int) -> int:
    since = datetime.now(UTC) - timedelta(minutes=minutes)
    return await db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.action == action, AuditLog.outcome == outcome, AuditLog.target_id == target_id,
               AuditLog.at >= since)
    ) or 0


async def _open_session(db: AsyncSession, response: Response, request: Request, user: User, scope: SessionScope) -> None:
    s = get_settings()
    now = datetime.now(UTC)
    token = new_token()
    if scope == SessionScope.full:
        expires, absolute = now + timedelta(minutes=s.session_idle_minutes), now + timedelta(hours=s.session_absolute_hours)
    else:
        expires = absolute = now + timedelta(minutes=s.totp_setup_minutes)
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=token_hash(token),
            scope=scope,
            expires_at=expires,
            absolute_expires_at=absolute,
            ip=client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:512],
        )
    )
    common = {"secure": s.cookie_secure, "samesite": "strict", "path": "/"}
    response.set_cookie(SESSION_COOKIE, token, httponly=True, **common)
    response.set_cookie(CSRF_COOKIE, csrf_for(token), httponly=False, **common)


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    email = body.email.strip().lower()
    ip = client_ip(request)
    s = get_settings()
    # ponytail: rate limit counted from the audit log under a per-email advisory lock; Redis counters if volume grows.
    await lock_key(db, f"login:{email}")
    if await failures_since(db, "auth.login", "failure", email, s.login_window_minutes) >= s.login_max_failures:
        record(db, actor_type=ActorType.user, actor_id=None, action="auth.login", outcome="rate_limited",
               target_type="email", target_id=email, ip=ip)
        await db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts, try later")

    user = await db.scalar(select(User).where(User.email == email))
    # argon2 is CPU-bound; keep it off the event loop.
    ok = await run_in_threadpool(verify_password, user.password_hash if user else None, body.password)
    ok = ok and user is not None and user.is_active

    if ok and user.totp_confirmed_at is None:
        await _open_session(db, response, request, user, SessionScope.totp_setup)
        record(db, actor_type=ActorType.user, actor_id=user.id, action="auth.login", outcome="totp_setup_required",
               target_type="email", target_id=email, ip=ip)
        await db.commit()
        return {"status": "totp_setup_required"}

    if ok and not await check_totp(db, user, body.totp_code):
        ok = False

    if not ok:
        record(db, actor_type=ActorType.user, actor_id=user.id if user else None, action="auth.login",
               outcome="failure", target_type="email", target_id=email, ip=ip)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC_FAIL)

    user.last_login_at = datetime.now(UTC)
    await _open_session(db, response, request, user, SessionScope.full)
    record(db, actor_type=ActorType.user, actor_id=user.id, action="auth.login", outcome="success",
           target_type="email", target_id=email, ip=ip)
    await db.commit()
    return {"status": "ok"}


@router.post("/totp/setup")
async def totp_setup(request: Request, principal: Principal = Depends(setup_principal), db: AsyncSession = Depends(get_db)):
    user = principal.user
    if user.totp_confirmed_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "totp already configured")
    secret = new_totp_secret()
    user.totp_secret_enc = get_cipher().encrypt(secret.encode(), f"{TOTP_CONTEXT}:{user.id}")
    record(db, actor_type=ActorType.user, actor_id=user.id, action="auth.totp_setup", outcome="success",
           target_type="user", target_id=user.id, ip=client_ip(request))
    await db.commit()
    # Shown once to the user themself; never logged (the URI contains the secret).
    return {"otpauth_uri": totp_uri(secret, user.email)}


@router.post("/totp/confirm")
async def totp_confirm(
    body: CodeIn, request: Request, response: Response,
    principal: Principal = Depends(setup_principal), db: AsyncSession = Depends(get_db),
):
    user = principal.user
    if user.totp_secret_enc is None or user.totp_confirmed_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "run totp setup first")
    step = verify_totp(totp_secret_of(user), body.code, None)
    if step is None:
        record(db, actor_type=ActorType.user, actor_id=user.id, action="auth.totp_confirm", outcome="failure",
               target_type="user", target_id=user.id, ip=client_ip(request))
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
    now = datetime.now(UTC)
    user.totp_confirmed_at, user.totp_last_step, user.last_login_at = now, step, now
    principal.session.revoked_at = now
    await _open_session(db, response, request, user, SessionScope.full)
    record(db, actor_type=ActorType.user, actor_id=user.id, action="auth.totp_confirm", outcome="success",
           target_type="user", target_id=user.id, ip=client_ip(request))
    await db.commit()
    return {"status": "ok"}


@router.post("/logout")
async def logout(request: Request, response: Response, principal: Principal = Depends(current_principal),
                 db: AsyncSession = Depends(get_db)):
    principal.session.revoked_at = datetime.now(UTC)
    record(db, actor_type=ActorType.user, actor_id=principal.id, action="auth.logout", outcome="success",
           target_type="user", target_id=principal.id, ip=client_ip(request))
    await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"status": "ok"}


@router.get("/me")
async def me(principal: Principal = Depends(current_principal)):
    return {
        "id": str(principal.id),
        "email": principal.user.email,
        "roles": sorted(r.name for r in principal.user.roles),
        "permissions": sorted(principal.permissions),
    }
