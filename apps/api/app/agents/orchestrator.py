"""Runs an agent: validates its spec, records agent_runs, enforces timeout and retries, validates output."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.gateway import ApprovalRequired, GatewayError, RunState, ToolGateway
from app.agents.registry import ToolRegistry
from app.agents.spec import AgentSpec, validate_spec
from app.core.metrics import AGENT_RUNS, LLM_TOKENS
from app.core.redaction import Redactor
from app.db.models import ActorType, AgentRun, AgentRunStatus
from app.modules.audit.service import record

ToolCall = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]
LLMCall = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class AgentContext:
    """Everything a handler gets: its input and two gateway calls. No session, registry, path or network.

    ponytail: Python cannot sandbox in-process code; handlers are reviewed platform code, and this keeps the
    gateway the only obvious path. Out-of-process isolation would be the upgrade if handlers ever came from outside.
    """

    input: BaseModel
    call: ToolCall
    llm: LLMCall


Handler = Callable[[AgentContext], Awaitable[BaseModel | dict[str, Any]]]


class Orchestrator:
    def __init__(self, registry: ToolRegistry, gateway: ToolGateway, redactor: Redactor, backoff_s: float = 1.0) -> None:
        self._registry, self._gateway, self._redactor, self._backoff = registry, gateway, redactor, backoff_s

    async def run(self, session: AsyncSession, spec: AgentSpec, handler: Handler, raw_input: dict[str, Any]) -> AgentRun:
        validate_spec(spec, self._registry)  # refuses incomplete or inconsistent specs before anything is recorded
        parsed = spec.input_schema.model_validate(raw_input)
        input_json = parsed.model_dump(mode="json")
        run = AgentRun(
            agent_name=spec.name,
            input_hash=self._redactor.match_hash(json.dumps(input_json, sort_keys=True)),  # salted (rule R4)
            input=self._redactor.redact_obj(input_json),
            status=AgentRunStatus.running,
        )
        session.add(run)
        await session.flush()
        record(session, actor_type=ActorType.agent, actor_id=run.id, action="agent.run", outcome="started",
               target_type="agent", target_id=spec.name)
        await session.commit()  # the run is visible as `running` even if the process dies later
        run_id = run.id

        state = RunState(run_id=run_id, spec=spec, session=session)

        async def call(tool: str, args: dict[str, Any]) -> dict[str, Any]:
            return await self._gateway.call(state, tool, args)

        async def llm(request: dict[str, Any]) -> dict[str, Any]:
            return await self._gateway.llm_complete(state, request)

        ctx = AgentContext(input=parsed, call=call, llm=llm)

        async def attempts() -> dict[str, Any]:
            for attempt in range(spec.max_retries + 1):
                try:
                    result = await handler(ctx)
                    data = result.model_dump(mode="json") if isinstance(result, BaseModel) else result
                    return spec.output_schema.model_validate(data).model_dump(mode="json")
                except (GatewayError, ValidationError):
                    raise  # policy and contract failures are never retried
                except Exception:
                    if attempt == spec.max_retries:
                        raise
                    await asyncio.sleep(self._backoff * 2**attempt)
            raise AssertionError("unreachable")

        status, output, error = AgentRunStatus.failed, None, None
        try:
            output = self._redactor.redact_obj(await asyncio.wait_for(attempts(), spec.timeout_s))
            status = AgentRunStatus.succeeded
        except TimeoutError:
            status, error = AgentRunStatus.timed_out, f"exceeded {spec.timeout_s}s"
        except ApprovalRequired as e:
            error = self._redactor.redact(f"approval required: {e}")
        except Exception as e:
            error = self._redactor.redact(f"{type(e).__name__}: {e}")[:2000]

        if status != AgentRunStatus.succeeded:
            # A cancelled or failed handler can leave the session mid-transaction; discard uncommitted work.
            # Everything the gateway decided is already committed.
            await session.rollback()
        run = await session.get(AgentRun, run_id, populate_existing=True)
        run.status, run.output, run.error = status, output, error
        run.finished_at = datetime.now(UTC)
        run.tool_calls, run.tokens_in, run.tokens_out = state.tool_calls, state.tokens_in, state.tokens_out
        record(session, actor_type=ActorType.agent, actor_id=run_id, action="agent.run", outcome=status.value,
               target_type="agent", target_id=spec.name)
        await session.commit()
        AGENT_RUNS.labels(spec.name, status.value).inc()
        LLM_TOKENS.labels(spec.name, "in").inc(state.tokens_in)
        LLM_TOKENS.labels(spec.name, "out").inc(state.tokens_out)
        return run
