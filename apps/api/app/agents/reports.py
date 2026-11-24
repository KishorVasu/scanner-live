"""Report Generation agent (AGENT_SPECIFICATIONS 5.8). Deterministic tables; optional LLM narrative; output is a draft.

`save_report_draft` rebuilds the tables from the database itself (nothing the handler or the model passes can change
them), refuses a narrative that claims safety, and never sets `approved`. Approval is a separate API call by a different
user (DB constraint too). A run whose scope includes a project with llm_allowed = false cannot call the LLM.
"""

import json
import uuid

import anthropic
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.agents.discovery import ToolError
from app.agents.gateway import GatewayError, ToolGateway
from app.agents.intel import _json_answer, _request
from app.agents.llm import data_block
from app.agents.orchestrator import AgentContext, Orchestrator
from app.agents.registry import Tool, ToolContext, ToolRegistry
from app.agents.spec import AgentSpec
from app.core.redaction import get_redactor
from app.db.intel import Report, ReportStatus
from app.db.models import PolicyTier
from app.db.registry import Project
from app.reports import content as rc


class ScopeArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: uuid.UUID | None = None


class DataOut(BaseModel):
    content: dict
    llm_allowed: bool


class SaveArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: uuid.UUID | None = None
    created_by: uuid.UUID
    narrative: str | None = Field(default=None, max_length=6000)
    narrative_note: str | None = Field(default=None, max_length=300)


class Saved(BaseModel):
    report_id: str


async def read_report_data(ctx: ToolContext, args: ScopeArgs) -> DataOut:
    try:
        content, pids = await rc.build(ctx.session, args.project_id)
    except LookupError as e:
        raise ToolError(str(e)) from None
    allowed = all((await ctx.session.scalars(select(Project.llm_allowed).where(Project.id.in_(pids)))).all())
    if not allowed:
        ctx.deny_llm()
    return DataOut(content=content, llm_allowed=allowed)


async def save_report_draft(ctx: ToolContext, args: SaveArgs) -> Saved:
    if args.narrative and (claim := rc.unsafe_claim(args.narrative)):
        raise ToolError(f"narrative claims safety ({claim!r})")
    content, _ = await rc.build(ctx.session, args.project_id)
    name = content["projects"][0]["project"] if args.project_id and content["projects"] else "All projects"
    report = Report(kind="project" if args.project_id else "portfolio", project_id=args.project_id,
                    title=f"Security report: {name} ({content['generated_at'][:10]})", status=ReportStatus.draft,
                    content=content, narrative=args.narrative, narrative_note=args.narrative_note,
                    generated_by_run_id=ctx.run_id, created_by=args.created_by)
    ctx.session.add(report)
    await ctx.session.flush()
    return Saved(report_id=str(report.id))


def build_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(Tool("read_report_data", PolicyTier.allowed, "read", ScopeArgs, DataOut, read_report_data))
    reg.register(Tool("save_report_draft", PolicyTier.allowed, "platform_write", SaveArgs, Saved, save_report_draft))
    return reg


class ReportInput(BaseModel):
    project_id: uuid.UUID | None = None
    created_by: uuid.UUID


class ReportOut(BaseModel):
    report_id: str
    narrative: str  # included | not_allowed | unavailable | rejected


SPEC = AgentSpec(name="report_generation", purpose="Draft a project or portfolio security report.",
                 input_schema=ReportInput, output_schema=ReportOut,
                 allowed_tools=("read_report_data", "save_report_draft"), uses_llm=True, timeout_s=600,
                 max_retries=0, approval_required_for=())

NARRATIVE_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["narrative"],
                    "properties": {"narrative": {"type": "string"}}}


async def handler(ctx: AgentContext) -> ReportOut:
    scope = {"project_id": str(ctx.input.project_id) if ctx.input.project_id else None}
    data = await ctx.call("read_report_data", scope)
    save = {**scope, "created_by": str(ctx.input.created_by)}
    if not data["llm_allowed"]:
        status, save["narrative_note"] = "not_allowed", "No AI summary: a project in scope does not allow LLM use."
    else:
        prompt = ("Write a plain-language summary of this security report for engineering managers, at most 250 words, "
                  "in short paragraphs. Start with what needs attention first (known-exploited or affected advisories, "
                  "critical and high findings). Name every repository listed under not_scanned and say it was not "
                  "examined. Never say or imply that a project is secure, safe or free of vulnerabilities: the data "
                  "only shows what scanners found.")
        try:
            answer = _json_answer(await ctx.llm(_request(prompt, data_block("report_data", "report",
                                                                             json.dumps(data["content"])),
                                                         NARRATIVE_SCHEMA)))
        except (GatewayError, anthropic.APIError):
            answer = None
        text = (answer or {}).get("narrative") if answer else None
        if not text:
            status, save["narrative_note"] = "unavailable", "AI summary unavailable; tables only."
        elif rc.unsafe_claim(text):
            status, save["narrative_note"] = "rejected", "AI summary rejected because it claimed safety; tables only."
        else:
            status, save["narrative"] = "included", text[:6000]
    saved = await ctx.call("save_report_draft", save)
    return ReportOut(report_id=saved["report_id"], narrative=status)


async def run(session, project_id: uuid.UUID | None, created_by: uuid.UUID, llm=None):
    from app.agents.anthropic_provider import provider_from_settings

    reg, redactor = build_registry(), get_redactor()
    gateway = ToolGateway(reg, redactor, llm if llm is not None else provider_from_settings())
    payload = {"project_id": str(project_id) if project_id else None, "created_by": str(created_by)}
    return await Orchestrator(reg, gateway, redactor).run(session, SPEC, handler, payload)
