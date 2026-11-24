"""Tool Gateway: the only path from an agent to a tool or to the LLM (rules R2, R4, R9, R10)."""

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.llm import LLMProvider
from app.agents.registry import ToolContext, ToolRegistry
from app.agents.spec import AgentSpec
from app.core import policy
from app.core.redaction import Redactor
from app.db.models import ActorType, ApprovalStatus, PolicyTier
from app.modules.approvals import service as approvals
from app.modules.audit.service import record


MAX_AUDIT_SCOPE_CHARS = 4000


class GatewayError(Exception):
    pass


class ToolDenied(GatewayError):
    pass


class ApprovalRequired(GatewayError):
    pass


@dataclass
class RunState:
    run_id: uuid.UUID
    spec: AgentSpec
    session: AsyncSession
    tool_calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    llm_denied: bool = False  # set by tools that touched data from a project with llm_allowed = false


class ToolGateway:
    def __init__(self, registry: ToolRegistry, redactor: Redactor, llm: LLMProvider | None = None) -> None:
        self._registry = registry
        self._redactor = redactor
        self._llm = llm

    def _audit(self, st: RunState, action: str, outcome: str, target: str, detail: dict[str, Any]) -> None:
        if "scope" in detail:
            raw = json.dumps(detail["scope"], sort_keys=True, default=str)
            if len(raw) > MAX_AUDIT_SCOPE_CHARS:  # big payloads (inventories) are identified, not copied
                detail = {**detail, "scope": {"sha256": hashlib.sha256(raw.encode()).hexdigest(), "chars": len(raw)}}
        record(st.session, actor_type=ActorType.agent, actor_id=st.run_id, action=action, outcome=outcome,
               target_type="tool", target_id=target, detail={"agent": st.spec.name, **detail})

    async def _deny(self, st: RunState, tool_name: str, reason: str) -> ToolDenied:
        self._audit(st, "gateway.tool_call", "denied", tool_name, {"reason": reason})
        await st.session.commit()
        return ToolDenied(f"{tool_name}: {reason}")

    async def call(self, st: RunState, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Every decision is committed as it happens, so the audit trail survives a crash mid-run (rule R10)."""
        st.tool_calls += 1
        if tool_name not in st.spec.allowed_tools:
            raise await self._deny(st, tool_name, "tool not in agent spec")
        tool = self._registry.get(tool_name)
        if tool is None:
            raise await self._deny(st, tool_name, "unknown tool")
        try:
            parsed = tool.input_model.model_validate(args)
        except ValidationError:
            raise await self._deny(st, tool_name, "invalid arguments") from None
        scope = parsed.model_dump(mode="json")

        decision = await policy.decide(st.session, tool_name)
        if decision.outcome == policy.Outcome.deny:
            raise await self._deny(st, tool_name, decision.reason)
        # The strictest of DB policy, tool tier and agent spec wins.
        approval = None
        if (
            decision.outcome == policy.Outcome.needs_approval
            or tool.tier == PolicyTier.approval_required
            or tool_name in st.spec.approval_required_for
        ):
            approval = await approvals.consume(st.session, tool_name, scope, st.run_id)
            if approval is None:
                self._audit(st, "gateway.tool_call", "needs_approval", tool_name, {"scope": scope})
                await st.session.commit()
                raise ApprovalRequired(f"{tool_name} needs an approval for this exact scope")
            self._audit(st, "gateway.approval_consumed", "success", tool_name, {"approval_id": str(approval.id)})

        self._audit(st, "gateway.tool_call", "allowed", tool_name, {"scope": scope})
        await st.session.commit()  # approval marked executed and lock released before the tool runs
        try:
            async with st.session.begin_nested():  # tool writes roll back on error
                ctx = ToolContext(session=st.session, run_id=st.run_id, deny_llm=lambda: setattr(st, "llm_denied", True))
                result = await tool.fn(ctx, parsed)
                out = tool.output_model.model_validate(result, from_attributes=True).model_dump(mode="json")
        except Exception as e:
            self._audit(st, "gateway.tool_result", "error", tool_name, {"error": type(e).__name__})
            if approval is not None:
                approval.status = ApprovalStatus.failed
                approval.result = {"error": type(e).__name__}
            await st.session.commit()
            raise
        if approval is not None:
            approval.result = {"status": "succeeded"}
        self._audit(st, "gateway.tool_result", "success", tool_name, {})
        await st.session.commit()
        return self._redactor.redact_obj(out)

    async def llm_complete(self, st: RunState, request: dict[str, Any]) -> dict[str, Any]:
        if not st.spec.uses_llm:
            raise await self._deny(st, "llm", "agent spec does not allow LLM use")
        if st.llm_denied:
            raise await self._deny(st, "llm", "run read data from a project with llm_allowed = false")
        if self._llm is None:
            raise await self._deny(st, "llm", "no LLM provider configured")
        safe = self._redactor.redact_obj(request)  # rule R4: nothing leaves unredacted
        self._audit(st, "gateway.llm_call", "allowed", "llm", {"model": safe.get("model")})
        await st.session.commit()
        response = await self._llm.complete(safe)
        usage = response.get("usage") or {}
        st.tokens_in += int(usage.get("input_tokens", 0))
        st.tokens_out += int(usage.get("output_tokens", 0))
        return response
