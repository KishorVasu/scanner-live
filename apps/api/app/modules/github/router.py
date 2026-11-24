"""GitHub App install flow and webhooks. Metadata only: commit messages and file contents are never stored here."""

import hashlib
import hmac
import json
import re
import time
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sp_inventory import manifest_paths

from app.agents.discovery import enqueue_discovery
from app.agents.scanning import enqueue_agent
from app.core.config import get_settings, master_key
from app.db.models import ActorType
from app.db.registry import (
    GithubInstallation,
    GithubInstallationRepo,
    RepoEventKind,
    Repository,
    RepositoryBranchHead,
    RepositoryEvent,
    Severity,
    WebhookDelivery,
)
from app.db.session import get_db
from app.integrations.github import GitHubError, GitHubNotConfigured, get_github, is_read_only, webhook_secret
from app.modules.audit.service import record
from app.modules.auth.deps import Principal, client_ip, require

router = APIRouter(tags=["github"])
MAX_WEBHOOK_BYTES = 1024 * 1024
STATE_TTL_S = 3600


# ---------- install flow ----------

def _state_sig(user_id: str, ts: int) -> str:
    return hmac.new(master_key(), f"github-install:{user_id}:{ts}".encode(), hashlib.sha256).hexdigest()


def make_state(user_id: uuid.UUID, now: float | None = None) -> str:
    ts = int(now if now is not None else time.time())
    return f"{user_id}.{ts}.{_state_sig(str(user_id), ts)}"


def check_state(state: str, user_id: uuid.UUID, now: float | None = None) -> bool:
    try:
        uid, ts_s, sig = state.split(".")
        ts = int(ts_s)
    except ValueError:
        return False
    fresh = 0 <= (now if now is not None else time.time()) - ts <= STATE_TTL_S
    return uid == str(user_id) and fresh and hmac.compare_digest(sig, _state_sig(uid, ts))


class InstallationIn(BaseModel):
    installation_id: int = Field(gt=0)
    state: str = Field(max_length=200)


def _configured() -> None:
    s = get_settings()
    if not (s.github_app_id and s.github_app_slug and s.github_private_key_file):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub App is not configured")


@router.get("/api/github/install")
async def install_url(p: Principal = Depends(require("github:manage"))):
    _configured()
    slug = get_settings().github_app_slug
    return {"url": f"https://github.com/apps/{slug}/installations/new?state={make_state(p.id)}"}


async def _sync_installation(db: AsyncSession, data: dict) -> GithubInstallation:
    """Upsert an installation from GitHub's payload; read_only is recomputed every time."""
    perms = data.get("permissions") or {}
    inst = await db.scalar(select(GithubInstallation).where(GithubInstallation.installation_id == data["id"]))
    if inst is None:
        inst = GithubInstallation(installation_id=data["id"])
        db.add(inst)
    inst.account_login = str((data.get("account") or {}).get("login", ""))
    inst.account_type = str((data.get("account") or {}).get("type", ""))
    inst.permissions = perms
    inst.read_only = is_read_only(perms)
    if data.get("suspended_at"):
        inst.suspended_at = inst.suspended_at or datetime.now(UTC)
    await db.flush()
    return inst


async def _sync_repos(db: AsyncSession, inst: GithubInstallation, repos: list[dict], removed: list[dict] = ()) -> None:
    for r in repos:
        row = await db.scalar(select(GithubInstallationRepo).where(GithubInstallationRepo.github_repo_id == r["id"]))
        if row is None:
            row = GithubInstallationRepo(github_repo_id=r["id"], installation_ref=inst.id)
            db.add(row)
        row.installation_ref, row.full_name, row.private, row.removed_at = inst.id, r["full_name"], bool(r.get("private", True)), None
    for r in removed:
        row = await db.scalar(select(GithubInstallationRepo).where(GithubInstallationRepo.github_repo_id == r["id"]))
        if row is not None:
            row.removed_at = datetime.now(UTC)


@router.post("/api/github/installations", status_code=201)
async def register_installation(body: InstallationIn, request: Request, p: Principal = Depends(require("github:manage")),
                                db: AsyncSession = Depends(get_db)):
    _configured()
    if not check_state(body.state, p.id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired state")
    gh = get_github()
    try:
        data = await gh.installation(body.installation_id)
    except GitHubError:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "could not read installation from GitHub") from None
    inst = await _sync_installation(db, data)
    if not inst.read_only:
        record(db, actor_type=ActorType.user, actor_id=p.id, action="github.install", outcome="refused_not_read_only",
               target_type="github_installation", target_id=inst.installation_id, ip=client_ip(request),
               detail={"permissions": inst.permissions})
        await db.commit()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            "installation has write permissions; reinstall the App with read-only permissions")
    await _sync_repos(db, inst, await gh.installation_repos(body.installation_id))
    record(db, actor_type=ActorType.user, actor_id=p.id, action="github.install", outcome="success",
           target_type="github_installation", target_id=inst.installation_id, ip=client_ip(request))
    await db.commit()
    return {"installation_id": inst.installation_id, "account": inst.account_login, "read_only": inst.read_only}


@router.get("/api/github/installations")
async def list_installations(_: Principal = Depends(require("github:manage")), db: AsyncSession = Depends(get_db)):
    out = []
    for inst in await db.scalars(select(GithubInstallation).order_by(GithubInstallation.account_login)):
        repos = await db.scalars(select(GithubInstallationRepo).where(
            GithubInstallationRepo.installation_ref == inst.id, GithubInstallationRepo.removed_at.is_(None)))
        out.append({"installation_id": inst.installation_id, "account": inst.account_login, "read_only": inst.read_only,
                    "suspended": inst.suspended_at is not None,
                    "repositories": [{"github_repo_id": r.github_repo_id, "full_name": r.full_name} for r in repos]})
    return out


# ---------- webhooks ----------

def _audit(db, event: str, outcome: str, delivery: str | None, detail: dict | None = None) -> None:
    record(db, actor_type=ActorType.system, actor_id="github-webhook", action=f"webhook.{event}", outcome=outcome,
           target_type="delivery", target_id=delivery, detail=detail)


@router.post("/api/webhooks/github", status_code=202)
async def github_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        secret = webhook_secret()
    except GitHubNotConfigured:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub webhooks are not configured") from None
    body = await request.body()
    if len(body) > MAX_WEBHOOK_BYTES:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "payload too large")
    sent = request.headers.get("x-hub-signature-256", "")
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    delivery = request.headers.get("x-github-delivery", "")[:64]
    event = request.headers.get("x-github-event", "")[:64]
    if not hmac.compare_digest(sent.encode(), expected.encode()):
        _audit(db, event or "unknown", "bad_signature", delivery or None, {"ip": client_ip(request)})
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid signature")
    if not delivery or not event:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing delivery or event header")
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid JSON") from None

    gh_repo_id = (payload.get("repository") or {}).get("id")
    inserted = await db.scalar(
        pg_insert(WebhookDelivery)
        .values(delivery_id=delivery, event=event, github_repo_id=gh_repo_id, status="received")
        .on_conflict_do_nothing(index_elements=["delivery_id"])
        .returning(WebhookDelivery.id)
    )
    if inserted is None:
        await db.commit()
        return {"status": "duplicate"}

    if gh_repo_id is not None:
        since = datetime.now(UTC) - timedelta(minutes=1)
        recent = await db.scalar(select(func.count()).select_from(WebhookDelivery).where(
            WebhookDelivery.github_repo_id == gh_repo_id, WebhookDelivery.created_at >= since))
        if recent > get_settings().webhook_repo_limit_per_minute:
            await _finish(db, inserted, "rate_limited")
            _audit(db, event, "rate_limited", delivery, {"github_repo_id": gh_repo_id})
            await db.commit()
            return {"status": "rate_limited"}

    handler = {"push": _on_push, "installation": _on_installation,
               "installation_repositories": _on_installation_repos}.get(event)
    outcome = await handler(db, payload, delivery) if handler else ("ok" if event == "ping" else "ignored")
    await _finish(db, inserted, outcome)
    _audit(db, event, outcome, delivery, {"github_repo_id": gh_repo_id, "action": payload.get("action")})
    await db.commit()
    return {"status": outcome}


async def _finish(db: AsyncSession, delivery_row_id, outcome: str) -> None:
    row = await db.get(WebhookDelivery, delivery_row_id)
    row.status, row.processed_at = outcome, datetime.now(UTC)


async def _on_push(db: AsyncSession, payload: dict, delivery: str) -> str:
    repo = await db.scalar(select(Repository).where(Repository.github_repo_id == payload["repository"]["id"]))
    if repo is None:
        return "ignored_unregistered"
    ref = str(payload.get("ref", ""))[:255]
    before, after = payload.get("before"), payload.get("after")
    pusher = (payload.get("pusher") or {}).get("name")
    base_detail = {"pusher": pusher, "commit_count": len(payload.get("commits") or [])}
    if payload.get("forced"):
        db.add(RepositoryEvent(repository_id=repo.id, kind=RepoEventKind.force_push, severity=Severity.high, ref=ref,
                               before_sha=before, after_sha=after, detail=base_detail, source="webhook",
                               delivery_id=delivery))
    if not ref.startswith("refs/heads/") or payload.get("deleted"):
        return "processed"
    branch = ref.removeprefix("refs/heads/")
    head = await db.scalar(select(RepositoryBranchHead).where(
        RepositoryBranchHead.repository_id == repo.id, RepositoryBranchHead.branch == branch))
    if head is not None and before and head.head_sha != before and not payload.get("forced"):
        # The push does not continue from the last head we saw: history changed outside our view.
        db.add(RepositoryEvent(repository_id=repo.id, kind=RepoEventKind.history_rewrite, severity=Severity.medium,
                               ref=ref, before_sha=head.head_sha, after_sha=after,
                               detail={**base_detail, "reason": "push does not continue from last observed head"},
                               source="webhook", delivery_id=delivery))
    if head is None:
        head = RepositoryBranchHead(repository_id=repo.id, branch=branch, head_sha=after, observed_at=datetime.now(UTC))
        db.add(head)
    else:
        head.head_sha, head.observed_at = after, datetime.now(UTC)

    default = repo.default_branch or (payload.get("repository") or {}).get("default_branch")
    changed = {p for c in payload.get("commits") or [] for k in ("added", "modified", "removed") for p in c.get(k) or []}
    if branch == default and (manifest_paths(sorted(changed)) or payload.get("forced")):
        if not enqueue_discovery(repo.id):
            _audit(db, "push", "discovery_queue_failed", delivery, {"repository_id": str(repo.id)})
    sha = re.compile(r"^[0-9a-f]{40}$")
    if changed and sha.match(before or "") and sha.match(after or "") and set(before) != {"0"}:
        payload_args = {"repository_id": str(repo.id), "before": before, "after": after, "paths": sorted(changed)[:3000]}
        if not enqueue_agent("repository_integrity", payload_args):
            _audit(db, "push", "integrity_queue_failed", delivery, {"repository_id": str(repo.id)})
    return "processed"


async def _on_installation(db: AsyncSession, payload: dict, delivery: str) -> str:
    data = payload.get("installation") or {}
    if "id" not in data:
        return "ignored"
    inst = await _sync_installation(db, data)
    action = payload.get("action")
    if action in ("deleted", "suspend"):
        inst.suspended_at = inst.suspended_at or datetime.now(UTC)
    elif action == "unsuspend":
        inst.suspended_at = None
    if action == "created":
        await _sync_repos(db, inst, payload.get("repositories") or [])
    return "processed" if inst.read_only else "processed_not_read_only"


async def _on_installation_repos(db: AsyncSession, payload: dict, delivery: str) -> str:
    data = payload.get("installation") or {}
    if "id" not in data:
        return "ignored"
    inst = await _sync_installation(db, data)
    await _sync_repos(db, inst, payload.get("repositories_added") or [], payload.get("repositories_removed") or [])
    return "processed" if inst.read_only else "processed_not_read_only"


