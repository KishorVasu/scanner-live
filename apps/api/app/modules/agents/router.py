"""Local agents: admin enrolment and roots, Ed25519 challenge-response sessions, inventory upload, operation log.

Agent routes authenticate with a short-lived bearer token (no cookies, so no CSRF). Revocation is checked on every call.
"""

import base64
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, StringConstraints, field_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import token_hash
from app.db.models import ActorType, AuditLog
from app.db.registry import (
    AgentEnrolmentCode,
    DependencyInventory,
    LocalAgent,
    LocalAgentChallenge,
    LocalAgentSession,
    Repository,
    RepoSource,
    TechnologyProfile,
)
from app.db.session import get_db
from app.modules.audit.service import record
from app.modules.auth.deps import Principal, client_ip, require
from app.modules.auth.router import lock_key

router = APIRouter(prefix="/api/agents", tags=["agents"])
SESSION_CONTEXT = b"sp-agent-session:"

Alias = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")]
Short = Annotated[str, StringConstraints(max_length=500)]


class Root(BaseModel):
    alias: Alias
    path: str = Field(min_length=1, max_length=1000)


class RootsIn(BaseModel):
    approved_roots: list[Root] = Field(max_length=50)

    @field_validator("approved_roots")
    @classmethod
    def unique_aliases(cls, v: list[Root]) -> list[Root]:
        if len({r.alias for r in v}) != len(v):
            raise ValueError("aliases must be unique")
        return v


class AgentIn(RootsIn):
    name: str = Field(min_length=1, max_length=200)


class RegisterIn(BaseModel):
    code: str = Field(min_length=20, max_length=100)
    public_key: str = Field(max_length=100)  # base64 of the raw 32-byte Ed25519 key
    host_fingerprint: str = Field(default="", max_length=128)
    os: str = Field(default="", max_length=64)
    agent_version: str = Field(default="", max_length=32)


class ChallengeIn(BaseModel):
    agent_id: uuid.UUID


class SessionIn(BaseModel):
    agent_id: uuid.UUID
    nonce: str = Field(max_length=100)
    signature: str = Field(max_length=200)


class ProfileIn(BaseModel):
    ecosystem: Short
    directory: Short
    package_manager: Short
    manifest_path: Short | None = None
    lockfile_path: Short | None = None
    framework: Short | None = None
    framework_version: Short | None = None


class DepIn(BaseModel):
    ecosystem: Annotated[str, StringConstraints(max_length=32)]
    package: Short
    version: Annotated[str, StringConstraints(max_length=128)] | None = None
    version_spec: Annotated[str, StringConstraints(max_length=255)] | None = None
    direct: bool
    manifest_path: Short | None = None


class CoverageIn(BaseModel):
    path: Short
    status: Literal["parsed", "not_read", "too_large", "unsupported", "parse_error"]
    entries: int = Field(ge=0)


class InventoryIn(BaseModel):
    alias: Alias
    manifest_hash: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    tree_hash: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    complete: bool
    profiles: list[ProfileIn] = Field(max_length=500)
    dependencies: list[DepIn] = Field(max_length=50_000)
    coverage: list[CoverageIn] = Field(max_length=2000)


class LogEvent(BaseModel):
    action: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_.]{1,64}$")]
    outcome: Annotated[str, StringConstraints(max_length=32)]
    detail: dict = Field(default_factory=dict)


class LogIn(BaseModel):
    events: list[LogEvent] = Field(max_length=200)


def _now() -> datetime:
    return datetime.now(UTC)


def _agent_out(a: LocalAgent) -> dict:
    return {"id": str(a.id), "name": a.name, "approved_roots": a.approved_roots.get("roots", []),
            "registered": a.public_key is not None, "revoked": a.revoked_at is not None, "os": a.os,
            "agent_version": a.agent_version, "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None}


def _new_code(db: AsyncSession, agent: LocalAgent, user_id) -> tuple[str, datetime]:
    code = secrets.token_urlsafe(32)
    expires = _now() + timedelta(hours=get_settings().agent_enrolment_hours)
    db.add(AgentEnrolmentCode(code_hash=token_hash(code), local_agent_id=agent.id, created_by=user_id, expires_at=expires))
    return code, expires


# ---------- admin ----------

@router.get("")
async def list_agents(_: Principal = Depends(require("agents:manage")), db: AsyncSession = Depends(get_db)):
    return [_agent_out(a) for a in await db.scalars(select(LocalAgent).order_by(LocalAgent.name))]


@router.post("", status_code=201)
async def create_agent(body: AgentIn, request: Request, p: Principal = Depends(require("agents:manage")),
                       db: AsyncSession = Depends(get_db)):
    agent = LocalAgent(name=body.name, approved_roots={"roots": [r.model_dump() for r in body.approved_roots]})
    db.add(agent)
    await db.flush()
    code, expires = _new_code(db, agent, p.id)
    record(db, actor_type=ActorType.user, actor_id=p.id, action="agents.create", outcome="success",
           target_type="local_agent", target_id=agent.id, ip=client_ip(request),
           detail={"aliases": [r.alias for r in body.approved_roots]})
    await db.commit()
    # The code is shown once; only its hash is stored.
    return {**_agent_out(agent), "enrolment_code": code, "enrolment_expires_at": expires.isoformat()}


@router.put("/{agent_id}/roots")
async def set_roots(agent_id: uuid.UUID, body: RootsIn, request: Request, p: Principal = Depends(require("agents:manage")),
                    db: AsyncSession = Depends(get_db)):
    agent = await db.get(LocalAgent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    before = [r["alias"] for r in agent.approved_roots.get("roots", [])]
    agent.approved_roots = {"roots": [r.model_dump() for r in body.approved_roots]}
    record(db, actor_type=ActorType.user, actor_id=p.id, action="agents.set_roots", outcome="success",
           target_type="local_agent", target_id=agent.id, ip=client_ip(request),
           detail={"before": before, "after": [r.alias for r in body.approved_roots]})
    await db.commit()
    return _agent_out(agent)


@router.post("/{agent_id}/revoke")
async def revoke(agent_id: uuid.UUID, request: Request, p: Principal = Depends(require("agents:manage")),
                 db: AsyncSession = Depends(get_db)):
    agent = await db.get(LocalAgent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    now = _now()
    agent.revoked_at = agent.revoked_at or now
    await db.execute(update(LocalAgentSession).where(LocalAgentSession.local_agent_id == agent.id,
                                                     LocalAgentSession.revoked_at.is_(None)).values(revoked_at=now))
    record(db, actor_type=ActorType.user, actor_id=p.id, action="agents.revoke", outcome="success",
           target_type="local_agent", target_id=agent.id, ip=client_ip(request))
    await db.commit()
    return _agent_out(agent)


# ---------- enrolment and sessions (called by the agent) ----------
# These endpoints are unauthenticated, so each is rate-limited under an advisory lock (no check-then-act race).
# ponytail: counts come from the audit log and challenge table; move to Redis counters if volume grows.

async def _failures(db: AsyncSession, action: str, *, ip: str | None = None, target_id: str | None = None) -> int:
    since = _now() - timedelta(minutes=get_settings().login_window_minutes)
    q = select(func.count()).select_from(AuditLog).where(
        AuditLog.action == action, AuditLog.outcome == "failure", AuditLog.at >= since)
    q = q.where(AuditLog.ip == ip) if ip is not None else q.where(AuditLog.target_id == target_id)
    return await db.scalar(q) or 0


async def _too_many(db: AsyncSession, action: str, request: Request, target_id=None) -> HTTPException:
    record(db, actor_type=ActorType.agent, actor_id=None, action=action, outcome="rate_limited",
           target_type="local_agent" if target_id else None, target_id=target_id, ip=client_ip(request))
    await db.commit()
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts, try later")


@router.post("/register")
async def register(body: RegisterIn, request: Request, db: AsyncSession = Depends(get_db)):
    ip = client_ip(request) or "unknown"
    await lock_key(db, f"agent-register:{ip}")
    if await _failures(db, "agents.register", ip=ip) >= get_settings().agent_register_failures_per_ip:
        raise await _too_many(db, "agents.register", request)
    try:
        raw = base64.b64decode(body.public_key, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "public_key must be a base64 raw Ed25519 key") from None
    code = await db.scalar(select(AgentEnrolmentCode).where(AgentEnrolmentCode.code_hash == token_hash(body.code))
                           .with_for_update())
    agent = await db.get(LocalAgent, code.local_agent_id) if code else None
    ok = code is not None and code.used_at is None and code.expires_at > _now() and agent is not None \
        and agent.revoked_at is None and agent.public_key is None
    if not ok:
        record(db, actor_type=ActorType.agent, actor_id=None, action="agents.register", outcome="failure",
               ip=client_ip(request))
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or used enrolment code")
    code.used_at = _now()
    agent.public_key, agent.registered_at = raw, _now()
    agent.host_fingerprint, agent.os, agent.agent_version = body.host_fingerprint, body.os, body.agent_version
    record(db, actor_type=ActorType.agent, actor_id=agent.id, action="agents.register", outcome="success",
           target_type="local_agent", target_id=agent.id, ip=client_ip(request), detail={"os": body.os})
    await db.commit()
    return {"agent_id": str(agent.id)}


async def _active_agent(db: AsyncSession, agent_id: uuid.UUID) -> LocalAgent | None:
    agent = await db.get(LocalAgent, agent_id)
    return agent if agent and agent.revoked_at is None and agent.public_key is not None else None


@router.post("/challenge")
async def challenge(body: ChallengeIn, request: Request, db: AsyncSession = Depends(get_db)):
    if await _active_agent(db, body.agent_id) is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown or revoked agent")  # writes nothing
    await lock_key(db, f"agent-challenge:{body.agent_id}")
    recent = await db.scalar(select(func.count()).select_from(LocalAgentChallenge).where(
        LocalAgentChallenge.local_agent_id == body.agent_id,
        LocalAgentChallenge.created_at >= _now() - timedelta(minutes=1)))
    if recent >= get_settings().agent_challenges_per_minute:
        raise await _too_many(db, "agents.challenge", request, body.agent_id)
    nonce = secrets.token_urlsafe(32)
    db.add(LocalAgentChallenge(local_agent_id=body.agent_id, nonce_hash=token_hash(nonce),
                               expires_at=_now() + timedelta(seconds=get_settings().agent_challenge_seconds)))
    await db.commit()
    return {"nonce": nonce}


def signing_message(nonce: str, agent_id: uuid.UUID) -> bytes:
    return SESSION_CONTEXT + nonce.encode() + b":" + str(agent_id).encode()


@router.post("/session")
async def open_session(body: SessionIn, request: Request, db: AsyncSession = Depends(get_db)):
    s = get_settings()
    ip = client_ip(request) or "unknown"
    # Per IP only: an Ed25519 signature cannot be guessed, so a per-agent counter would only let anyone who knows an
    # agent_id lock that agent out (review finding 8).
    await lock_key(db, f"agent-session-ip:{ip}")
    if await _failures(db, "agents.session", ip=ip) >= s.agent_session_failures_per_ip:
        raise await _too_many(db, "agents.session", request, body.agent_id)
    agent = await _active_agent(db, body.agent_id)
    ch = await db.scalar(select(LocalAgentChallenge).where(
        LocalAgentChallenge.nonce_hash == token_hash(body.nonce),
        LocalAgentChallenge.local_agent_id == body.agent_id).with_for_update())
    usable = ch is not None and ch.used_at is None and ch.expires_at > _now()
    if ch is not None:
        ch.used_at = ch.used_at or _now()  # single use, whatever the outcome
    valid = False
    if agent is not None and usable:
        try:
            Ed25519PublicKey.from_public_bytes(agent.public_key).verify(
                base64.b64decode(body.signature), signing_message(body.nonce, body.agent_id))
            valid = True
        except (InvalidSignature, ValueError):
            valid = False
    if not valid:
        record(db, actor_type=ActorType.agent, actor_id=body.agent_id, action="agents.session", outcome="failure",
               target_type="local_agent", target_id=body.agent_id, ip=client_ip(request))
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "challenge failed")
    token = secrets.token_urlsafe(32)
    expires = _now() + timedelta(minutes=get_settings().agent_session_minutes)
    db.add(LocalAgentSession(local_agent_id=agent.id, token_hash=token_hash(token), expires_at=expires))
    agent.last_seen_at = _now()
    record(db, actor_type=ActorType.agent, actor_id=agent.id, action="agents.session", outcome="success",
           target_type="local_agent", target_id=agent.id, ip=client_ip(request))
    await db.commit()
    return {"token": token, "expires_at": expires.isoformat()}


async def current_agent(authorization: str = Header(default=""), db: AsyncSession = Depends(get_db)) -> LocalAgent:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "agent token required")
    sess = await db.scalar(select(LocalAgentSession).where(LocalAgentSession.token_hash == token_hash(token)))
    if sess is None or sess.revoked_at is not None or sess.expires_at <= _now():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid agent session")
    agent = await _active_agent(db, sess.local_agent_id)  # revocation takes effect on the next call
    if agent is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "agent revoked")
    agent.last_seen_at = _now()
    return agent


# ---------- agent operations ----------

@router.get("/me/config")
async def my_config(agent: LocalAgent = Depends(current_agent), db: AsyncSession = Depends(get_db)):
    await db.commit()
    return {"agent_id": str(agent.id), "approved_roots": agent.approved_roots.get("roots", [])}


@router.post("/me/inventory")
async def upload_inventory(body: InventoryIn, agent: LocalAgent = Depends(current_agent),
                           db: AsyncSession = Depends(get_db)):
    if agent.root(body.alias) is None:
        record(db, actor_type=ActorType.agent, actor_id=agent.id, action="agents.inventory", outcome="denied",
               target_type="alias", target_id=body.alias, detail={"reason": "alias not approved"})
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "alias is not an approved root")
    repo = await db.scalar(select(Repository).where(Repository.source == RepoSource.local,
                                                    Repository.local_agent_id == agent.id,
                                                    Repository.local_path_alias == body.alias))
    if repo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no registered repository for this alias")
    await store_inventory(db, repo, body.model_dump())
    record(db, actor_type=ActorType.agent, actor_id=agent.id, action="agents.inventory", outcome="success",
           target_type="repository", target_id=repo.id,
           detail={"dependencies": len(body.dependencies), "complete": body.complete})
    await db.commit()
    return {"repository_id": str(repo.id), "dependencies": len(body.dependencies), "complete": body.complete}


async def store_inventory(db: AsyncSession, repo: Repository, inv: dict) -> None:
    """Replace a repository's profiles and dependency inventory in the caller's transaction."""
    now = _now()
    await db.execute(delete(TechnologyProfile).where(TechnologyProfile.repository_id == repo.id))
    await db.execute(delete(DependencyInventory).where(DependencyInventory.repository_id == repo.id))
    for p in inv["profiles"]:
        db.add(TechnologyProfile(repository_id=repo.id, ecosystem=p["ecosystem"], directory=p["directory"],
                                 framework=p.get("framework"), version=p.get("framework_version"),
                                 package_manager=p["package_manager"], manifest_path=p.get("manifest_path"),
                                 lockfile_path=p.get("lockfile_path"), detected_at=now))
    for d in inv["dependencies"]:
        db.add(DependencyInventory(repository_id=repo.id, ecosystem=d["ecosystem"], package=d["package"],
                                   version=d.get("version"), version_spec=d.get("version_spec"), direct=d["direct"],
                                   manifest_path=d.get("manifest_path"), manifest_hash=inv["manifest_hash"]))
    repo.manifest_hash, repo.tree_hash = inv["manifest_hash"], inv.get("tree_hash")
    repo.inventory_complete, repo.inventory_coverage = inv["complete"], {"files": inv["coverage"]}
    repo.last_inventory_at = now


@router.post("/me/log")
async def upload_log(body: LogIn, agent: LocalAgent = Depends(current_agent), db: AsyncSession = Depends(get_db)):
    for e in body.events:
        record(db, actor_type=ActorType.agent, actor_id=agent.id, action=f"local_agent.{e.action}",
               outcome=e.outcome, target_type="local_agent", target_id=agent.id, detail=e.detail)
    await db.commit()
    return {"accepted": len(body.events)}
