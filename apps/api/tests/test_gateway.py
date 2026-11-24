"""T-R2, T-R4, T-R9 at the gateway; orchestrator run records and failure handling."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from app.agents.gateway import ApprovalRequired, RunState, ToolDenied, ToolGateway
from app.agents.orchestrator import Orchestrator
from app.agents.registry import Tool, ToolRegistry
from app.agents.spec import AgentSpec, SpecError
from app.core.redaction import Redactor
from app.db.models import AgentRun, AgentRunStatus, AuditLog, Policy, PolicyTier
from app.modules.approvals import service

FAKE = "ghp_" + "Zx9" * 12  # canary, built at runtime


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo: str


class Result(BaseModel):
    text: str


async def echo(ctx, args):
    return Result(text=f"repo={args.repo} leaked={FAKE}")


class FakeLLM:
    def __init__(self):
        self.requests = []

    async def complete(self, request):
        self.requests.append(request)
        return {"content": [], "usage": {"input_tokens": 7, "output_tokens": 3}}


@pytest.fixture
async def env(owner_db):
    suffix = uuid.uuid4().hex[:6]
    names = {"free": f"free_{suffix}", "gated": f"gated_{suffix}", "nopolicy": f"nopolicy_{suffix}"}
    owner_db.add(Policy(action=names["free"], tier=PolicyTier.allowed))
    owner_db.add(Policy(action=names["gated"], tier=PolicyTier.approval_required))
    await owner_db.commit()
    reg = ToolRegistry()
    reg.register(Tool(names["free"], PolicyTier.allowed, "read", Args, Result, echo))
    reg.register(Tool(names["gated"], PolicyTier.approval_required, "read", Args, Result, echo))
    reg.register(Tool(names["nopolicy"], PolicyTier.allowed, "read", Args, Result, echo))
    redactor = Redactor(b"z" * 32)
    llm = FakeLLM()
    gw = ToolGateway(reg, redactor, llm)
    spec = AgentSpec(name="test_agent", purpose="t", input_schema=Args, output_schema=Result,
                     allowed_tools=tuple(names.values()), uses_llm=True, timeout_s=5, max_retries=1,
                     approval_required_for=(names["gated"],))
    return {"names": names, "reg": reg, "gw": gw, "spec": spec, "llm": llm, "redactor": redactor}


def state(env, db):
    return RunState(run_id=uuid.uuid4(), spec=env["spec"], session=db)


async def test_allowed_tool_runs_redacted_and_audited(env, app_db):
    st = state(env, app_db)
    out = await env["gw"].call(st, env["names"]["free"], {"repo": "r1"})
    assert FAKE not in out["text"] and "repo=r1" in out["text"]
    await app_db.commit()
    rows = list(await app_db.scalars(select(AuditLog).where(AuditLog.actor_id == str(st.run_id))))
    assert [r.outcome for r in rows] == ["allowed", "success"]


async def test_denials(env, app_db):
    gw, n = env["gw"], env["names"]
    st = state(env, app_db)
    with pytest.raises(ToolDenied, match="deny by default"):
        await gw.call(st, n["nopolicy"], {"repo": "r"})
    with pytest.raises(ToolDenied, match="not in agent spec"):
        await gw.call(st, "deploy", {"repo": "r"})
    with pytest.raises(ToolDenied, match="invalid arguments"):
        await gw.call(st, n["free"], {"repo": "r", "path": "/etc/passwd"})
    await app_db.commit()
    rows = list(await app_db.scalars(select(AuditLog).where(AuditLog.actor_id == str(st.run_id))))
    assert len(rows) == 3 and all(r.outcome == "denied" for r in rows)


async def test_approval_gated_tool(env, app_db, owner_db, make_user):
    gw, gated = env["gw"], env["names"]["gated"]
    st = state(env, app_db)
    with pytest.raises(ApprovalRequired):
        await gw.call(st, gated, {"repo": "r1"})
    dev, appr = await make_user("developer"), await make_user("approver")
    a = service.create(owner_db, action=gated, scope={"repo": "r1"}, reason="r", risks="", requested_by=dev.id)
    await owner_db.flush()
    await service.decide(owner_db, a.id, appr.id, True)
    await owner_db.commit()
    with pytest.raises(ApprovalRequired):
        await gw.call(st, gated, {"repo": "other"})  # scope mismatch
    assert "repo=r1" in (await gw.call(st, gated, {"repo": "r1"}))["text"]
    with pytest.raises(ApprovalRequired):
        await gw.call(st, gated, {"repo": "r1"})  # one approval, one operation
    await app_db.commit()


async def test_llm_payload_redacted(env, app_db):
    st = state(env, app_db)
    await env["gw"].llm_complete(st, {"model": "m", "messages": [{"role": "user", "content": f"key {FAKE}"}]})
    assert FAKE not in str(env["llm"].requests)
    assert (st.tokens_in, st.tokens_out) == (7, 3)
    await app_db.commit()


async def test_orchestrator_records_runs(env, app_db):
    orch = Orchestrator(env["reg"], env["gw"], env["redactor"], backoff_s=0)
    free = env["names"]["free"]

    async def good(ctx):
        return await ctx.call(free, {"repo": ctx.input.repo})

    run = await orch.run(app_db, env["spec"], good, {"repo": "r9"})
    assert run.status == AgentRunStatus.succeeded and run.tool_calls == 1 and FAKE not in str(run.output)

    async def bad_output(ctx):
        return {"wrong": 1}

    assert (await orch.run(app_db, env["spec"], bad_output, {"repo": "r"})).status == AgentRunStatus.failed

    calls = {"n": 0}

    async def flaky(ctx):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        return {"text": "ok"}

    assert (await orch.run(app_db, env["spec"], flaky, {"repo": "r"})).status == AgentRunStatus.succeeded

    async def slow(ctx):
        await asyncio.sleep(10)

    slow_spec = env["spec"].model_copy(update={"timeout_s": 1})
    assert (await orch.run(app_db, slow_spec, slow, {"repo": "r"})).status == AgentRunStatus.timed_out

    stored = await app_db.scalar(select(AgentRun).where(AgentRun.id == run.id))
    assert stored.input_hash and stored.finished_at is not None


async def test_orchestrator_refuses_bad_spec(env, app_db):
    orch = Orchestrator(env["reg"], env["gw"], env["redactor"])
    bad = env["spec"].model_copy(update={"allowed_tools": ("ghost",), "approval_required_for": ()})
    with pytest.raises(SpecError):
        await orch.run(app_db, bad, lambda ctx: None, {"repo": "r"})
