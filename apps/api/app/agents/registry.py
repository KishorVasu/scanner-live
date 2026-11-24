"""Tool registry. Only read and platform-write tools can exist (rule R1)."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.policy import FORBIDDEN_ACTIONS
from app.db.models import PolicyTier

Effect = Literal["read", "platform_write"]
ALLOWED_EFFECTS: frozenset[str] = frozenset({"read", "platform_write"})


class RegistryError(Exception):
    pass


@dataclass(frozen=True)
class ToolContext:
    """What a tool implementation receives. Platform code only; agents never see this."""

    session: AsyncSession
    run_id: object
    # A tool that returns data from a project with llm_allowed = false calls this; the gateway then refuses every
    # later LLM call in the run (OQ-6), whatever the handler does.
    deny_llm: Callable[[], None] = lambda: None


ToolFn = Callable[[ToolContext, BaseModel], Awaitable[BaseModel]]


@dataclass(frozen=True)
class Tool:
    name: str
    tier: PolicyTier
    effect: Effect
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    fn: ToolFn


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in FORBIDDEN_ACTIONS:
            raise RegistryError(f"{tool.name} is a forbidden action")
        if tool.tier == PolicyTier.forbidden:
            raise RegistryError(f"{tool.name}: forbidden tools cannot be registered")
        if tool.effect not in ALLOWED_EFFECTS:
            raise RegistryError(f"{tool.name}: effect {tool.effect!r} not allowed")
        if tool.input_model.model_config.get("extra") != "forbid":
            raise RegistryError(f"{tool.name}: input model must forbid extra fields")
        if tool.name in self._tools:
            raise RegistryError(f"{tool.name} already registered")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)
