"""DB tests for the Phase 1 review findings: each one fails if its fix regresses."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, text

from app.agents.gateway import ApprovalRequired, RunState, ToolGateway
from app.agents.registry import Tool, ToolRegistry
from app.agents.spec import AgentSpec
from app.core import policy
from app.core.redaction import Redactor
from app.db.models import Approval, ApprovalStatus, Policy, PolicyTier, UserSession
from app.modules.approvals import service
from tests.conftest import login


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo: str


class Result(BaseModel):
    ok: bool = True


async def ok_tool(ctx, args):
    return Result()


async def broken_tool(ctx, args):
    raise RuntimeError("tool crashed")


async def _policy(db, tier: PolicyTier) -> str:
    action = f"t_{uuid.uuid4().hex[:8]}"
    db.add(Policy(action=action, tier=tier))
    await db.commit()
    return action


def _gw(*tools: Tool) -> ToolGateway:
    reg = ToolRegistry()
    for t in tools:
        reg.register(t)
    return ToolGateway(reg, Redactor(b"r" * 32))


def _state(db, names, approval_required_for=()) -> RunState:
    spec = AgentSpec(name="review_agent", purpose="t", input_schema=Args, output_schema=Result,
                     allowed_tools=tuple(names), uses_llm=False, timeout_s=5, max_retries=0,
                     approval_required_for=tuple(approval_required_for))
    return RunState(run_id=uuid.uuid4(), spec=spec, session=db)


async def _approve(db, make_user, action, scope, run_id=None) -> Approval:
    dev, appr = await make_user("developer"), await make_user("approver")
    a = service.create(db, action=action, scope=scope, reason="r", risks="", requested_by=dev.id,
                       requested_by_run_id=run_id)
    await db.flush()
    await service.decide(db, a.id, appr.id, True)
    await db.commit()
    return a


# --- privileges (rule R10 proven by grants, not only by the trigger) ---

async def test_app_role_has_no_update_or_delete_on_audit(owner_db):
    for priv in ("UPDATE", "DELETE", "TRUNCATE"):
        assert not await owner_db.scalar(
            text("SELECT has_table_privilege('platform_app', 'audit_logs', :p)").bindparams(p=priv)
        ), priv
    assert await owner_db.scalar(text("SELECT has_table_privilege('platform_app', 'audit_logs', 'INSERT')"))


# --- policy and gateway ---

async def test_forbidden_action_denied_even_if_db_says_allowed(owner_db):
    await owner_db.execute(text("UPDATE policies SET tier='allowed' WHERE action='deploy'"))
    try:
        assert (await policy.decide(owner_db, "deploy")).outcome == policy.Outcome.deny
    finally:
        await owner_db.rollback()


@pytest.mark.parametrize("db_tier,tool_tier,in_spec", [
    (PolicyTier.approval_required, PolicyTier.allowed, False),  # DB stricter
    (PolicyTier.allowed, PolicyTier.approval_required, True),  # tool stricter
    (PolicyTier.allowed, PolicyTier.allowed, True),  # spec stricter (approval_required_for)
])
async def test_strictest_tier_wins(app_db, owner_db, db_tier, tool_tier, in_spec):
    action = await _policy(owner_db, db_tier)
    gw = _gw(Tool(action, tool_tier, "read", Args, Result, ok_tool))
    st = _state(app_db, [action], [action] if in_spec else [])
    with pytest.raises(ApprovalRequired):
        await gw.call(st, action, {"repo": "r"})


async def test_tool_failure_marks_approval_failed(app_db, owner_db, make_user):
    action = await _policy(owner_db, PolicyTier.approval_required)
    gw = _gw(Tool(action, PolicyTier.allowed, "read", Args, Result, broken_tool))
    a = await _approve(owner_db, make_user, action, {"repo": "r"})
    with pytest.raises(RuntimeError):
        await gw.call(_state(app_db, [action]), action, {"repo": "r"})
    status = await owner_db.scalar(text("SELECT status FROM approvals WHERE id=:i").bindparams(i=a.id))
    assert status == ApprovalStatus.failed.value


async def test_run_bound_approval_only_for_that_run(owner_db, make_user):
    action = f"bound_{uuid.uuid4().hex[:6]}"
    run_id = await owner_db.scalar(text(
        "INSERT INTO agent_runs (agent_name, input_hash, input, status) VALUES ('a','h','{}','running') RETURNING id"))
    await owner_db.commit()
    await _approve(owner_db, make_user, action, {"repo": "r"}, run_id=run_id)
    assert await service.consume(owner_db, action, {"repo": "r"}, uuid.uuid4()) is None
    assert await service.consume(owner_db, action, {"repo": "r"}, run_id) is not None
    await owner_db.commit()


async def test_audit_rows_committed_before_tool_runs(app_db, owner_db, owner_session_factory):
    action = await _policy(owner_db, PolicyTier.allowed)
    st = None

    async def peeking_tool(ctx, args):
        async with owner_session_factory() as other:  # a separate connection sees only committed rows
            n = await other.scalar(text("SELECT count(*) FROM audit_logs WHERE actor_id=:a").bindparams(a=str(st.run_id)))
        assert n == 1
        return Result()

    gw = _gw(Tool(action, PolicyTier.allowed, "read", Args, Result, peeking_tool))
    st = _state(app_db, [action])
    await gw.call(st, action, {"repo": "r"})


# --- auth ---

async def test_concurrent_login_burst_is_capped(db_urls, make_user):
    from app.main import app

    u = await make_user("viewer")

    async def attempt():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/auth/login", json={"email": u.email, "password": "wrong-password"})
            return r.status_code

    codes = await asyncio.gather(*[attempt() for _ in range(12)])
    assert codes.count(401) == 5 and codes.count(429) == 7, codes


async def test_approval_reauth_is_rate_limited_and_ends_session(client, make_user, owner_db):
    action = await _policy(owner_db, PolicyTier.approval_required)
    dev, appr = await make_user("developer"), await make_user("approver")
    a = service.create(owner_db, action=action, scope={}, reason="r", risks="", requested_by=dev.id)
    await owner_db.commit()
    csrf = await login(client, appr)
    url = f"/api/approvals/{a.id}/decision"
    for _ in range(5):
        assert (await client.post(url, headers=csrf, json={"totp_code": "000000", "approve": True})).status_code == 401
    assert (await client.post(url, headers=csrf, json={"totp_code": appr.code(1), "approve": True})).status_code == 429
    assert (await client.get("/api/auth/me")).status_code == 401  # session revoked


async def test_expired_session_rejected(client, make_user, owner_db):
    u = await make_user("viewer")
    await login(client, u)
    await owner_db.execute(text("UPDATE user_sessions SET expires_at = now() - interval '1 second' WHERE user_id=:u")
                           .bindparams(u=u.id))
    await owner_db.commit()
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_absolute_expiry_caps_sliding_window(client, make_user, owner_db):
    u = await make_user("viewer")
    await login(client, u)
    soon = datetime.now(UTC) + timedelta(seconds=30)
    await owner_db.execute(text("UPDATE user_sessions SET absolute_expires_at=:t WHERE user_id=:u")
                           .bindparams(t=soon, u=u.id))
    await owner_db.commit()
    assert (await client.get("/api/auth/me")).status_code == 200
    sess = await owner_db.scalar(select(UserSession).where(UserSession.user_id == u.id)
                                 .execution_options(populate_existing=True))
    assert sess.expires_at <= soon


async def test_deactivation_revokes_sessions(make_user, db_urls):
    from app.main import app

    admin, victim = await make_user("admin"), await make_user("viewer")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as vc, \
               httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        await login(vc, victim)
        csrf = await login(ac, admin)
        assert (await ac.post(f"/api/users/{victim.id}/deactivate", headers=csrf)).status_code == 200
        assert (await vc.get("/api/auth/me")).status_code == 401


@pytest.mark.parametrize("role", ["viewer", "developer", "approver"])
async def test_non_admin_cannot_write_users(client, make_user, role):
    u = await make_user(role)
    csrf = await login(client, u)
    r = await client.post("/api/users", headers=csrf, json={"email": "x@y.z", "password": "long-enough-pass", "roles": ["admin"]})
    assert r.status_code == 403
    r = await client.put(f"/api/users/{u.id}/roles", headers=csrf, json={"roles": ["admin"]})
    assert r.status_code == 403


async def test_secret_in_scope_refused_and_reason_redacted(client, make_user, owner_db):
    action = await _policy(owner_db, PolicyTier.approval_required)
    dev = await make_user("developer")
    csrf = await login(client, dev)
    tok = "ghp_" + "Qw7" * 12
    r = await client.post("/api/approvals", headers=csrf, json={"action": action, "scope": {"t": tok}, "reason": "x"})
    assert r.status_code == 422
    r = await client.post("/api/approvals", headers=csrf, json={"action": action, "scope": {}, "reason": f"use {tok}"})
    assert r.status_code == 201 and tok not in r.text
