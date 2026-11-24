from pydantic import BaseModel, ConfigDict, Field

from app.agents.registry import ToolRegistry
from app.db.models import PolicyTier


# Below Celery's soft limit (840 s) so a run always records its own timeout before the worker kills it.
MAX_TIMEOUT_S = 800


class SpecError(Exception):
    pass


class AgentSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    purpose: str = Field(min_length=1)
    input_schema: type[BaseModel]
    output_schema: type[BaseModel]
    allowed_tools: tuple[str, ...]
    uses_llm: bool
    timeout_s: int = Field(gt=0, le=MAX_TIMEOUT_S)
    max_retries: int = Field(ge=0, le=5)
    approval_required_for: tuple[str, ...]


def validate_spec(spec: AgentSpec, registry: ToolRegistry) -> None:
    """Fail closed before a run starts."""
    unknown = set(spec.allowed_tools) - registry.names()
    if unknown:
        raise SpecError(f"{spec.name}: unknown tools {sorted(unknown)}")
    stray = set(spec.approval_required_for) - set(spec.allowed_tools)
    if stray:
        raise SpecError(f"{spec.name}: approval_required_for names tools not allowed {sorted(stray)}")
    for name in spec.allowed_tools:
        tool = registry.get(name)
        if tool.tier == PolicyTier.approval_required and name not in spec.approval_required_for:
            raise SpecError(f"{spec.name}: {name} requires approval but is not in approval_required_for")
