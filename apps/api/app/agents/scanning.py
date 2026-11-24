"""Phase 3 agents: Dependency Analysis, Code Security, Secret Detection, Repository Integrity (deterministic, no LLM).

Scanner tools create a scan job, ask scan-runner to run the pinned image, and feed the report through the finding
lifecycle. If scan-runner is unreachable or refuses (for example, no pinned digest yet), the job is recorded as
failed: never as a clean result.
"""

import asyncio
import uuid
from datetime import UTC, datetime

import httpx
from pydantic import BaseModel, ConfigDict, Field
from sp_inventory import is_secret_path
from sqlalchemy import select

from app.agents.discovery import RepoArgs, ToolError, _session_for
from app.agents.gateway import ToolGateway
from app.agents.orchestrator import AgentContext, Orchestrator
from app.agents.registry import Tool, ToolContext, ToolRegistry
from app.agents.spec import AgentSpec
from app.core.config import get_settings
from app.core.redaction import get_redactor
from app.db.models import PolicyTier
from app.db.registry import Repository, RepositoryEvent, RepoEventKind, Severity, TechnologyProfile
from app.db.scanning import ScanStatus, ScanTrigger, Scanner
from app.integrity.checks import BUILD_CONFIG, Change, Hit, run_checks
from app.scanners import service
from app.scanners.base import ParseResult, RawFinding

_runner_transport: httpx.AsyncBaseTransport | None = None  # tests inject a MockTransport


class ScanArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_id: uuid.UUID
    trigger: ScanTrigger = ScanTrigger.manual
    target: str | None = Field(default=None, max_length=300, pattern=r"^[A-Za-z0-9._/\-]+$")


class ScanOut(BaseModel):
    job_id: str
    scanner: str
    status: str
    error: str | None = None


class Profiles(BaseModel):
    profiles: list[dict]


class IntegrityArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_id: uuid.UUID
    before: str = Field(pattern=r"^[0-9a-f]{40}$")
    after: str = Field(pattern=r"^[0-9a-f]{40}$")
    paths: list[str] = Field(max_length=3000)


async def _call_runner(scanner: str, job_id: uuid.UUID, target: str | None) -> dict:
    body = {"scanner": scanner, "job_id": str(job_id), "mount_ref": f"sp-src-{job_id}"}
    if target:
        body["target"] = target
    async with httpx.AsyncClient(base_url=get_settings().scan_runner_url, timeout=1000,
                                 transport=_runner_transport) as c:
        r = await c.post("/scan", json=body)
    if r.status_code != 200:
        detail = r.json().get("error", "") if r.headers.get("content-type", "").startswith("application/json") else ""
        raise RuntimeError(f"scan-runner refused ({r.status_code}): {detail}")
    return r.json()


def _scanner_tool(scanner: Scanner):
    async def fn(ctx: ToolContext, args: ScanArgs) -> ScanOut:
        repo = await ctx.session.get(Repository, args.repository_id)
        if repo is None:
            raise ToolError("repository not found")
        job, created = await service.create_job(ctx.session, repo, scanner, args.trigger, None)
        if not created or job.status == ScanStatus.skipped_unchanged:
            return ScanOut(job_id=str(job.id), scanner=scanner.value, status=job.status.value)
        job.status, job.started_at = ScanStatus.running, datetime.now(UTC)
        await ctx.session.flush()
        try:
            result = await _call_runner(scanner.value, job.id, args.target)
            report = result.get("report")
            await service.complete_job(ctx.session, job, exit_code=result.get("exit_code"),
                                       report=report.encode() if isinstance(report, str) else None,
                                       error=result.get("error"))
        except (httpx.HTTPError, RuntimeError, ValueError) as e:
            await service.fail_job(ctx.session, job, str(e))
        return ScanOut(job_id=str(job.id), scanner=scanner.value, status=job.status.value, error=job.error)

    return fn


async def repository_profile(ctx: ToolContext, args: RepoArgs) -> Profiles:
    rows = await ctx.session.scalars(select(TechnologyProfile).where(TechnologyProfile.repository_id == args.repository_id))
    return Profiles(profiles=[{"ecosystem": p.ecosystem, "directory": p.directory, "package_manager": p.package_manager,
                               "manifest_path": p.manifest_path, "lockfile_path": p.lockfile_path} for p in rows])


async def _fetch(gh, path: str, ref: str) -> bytes | None:
    """One side of a change. Missing on that side (added or removed file) is None, not an error."""
    try:
        return await gh.file(path, ref)
    except Exception:  # noqa: BLE001
        return None


async def integrity_checks(ctx: ToolContext, args: IntegrityArgs) -> ScanOut:
    """Static checks on the files a push changed. Secret-pattern files are flagged by path, never fetched."""
    repo, gh = await _session_for(ctx, args.repository_id)
    changes, hits = [], []
    for path in args.paths:
        if is_secret_path(path):
            if BUILD_CONFIG.search(path):
                hits.append(Hit("build_config_change", "build-config-changed", "medium", path, "config changed (content not read)"))
            continue
        changes.append(Change(path, await _fetch(gh, path, args.before), await _fetch(gh, path, args.after)))
    hits += run_checks(changes)

    job, _ = await service.create_job(ctx.session, repo, Scanner.integrity, ScanTrigger.webhook)
    job.status, job.started_at = ScanStatus.running, datetime.now(UTC)
    redact = get_redactor().redact
    for h in hits:
        ctx.session.add(RepositoryEvent(repository_id=repo.id, kind=RepoEventKind(h.kind), severity=Severity(h.severity),
                                        ref=None, before_sha=args.before, after_sha=args.after,
                                        detail={"rule": h.rule, "path": h.path, "detail": redact(h.detail)}, source="scan"))
    raws = [RawFinding(rule_id=h.rule, category="integrity", title=redact(h.detail)[:500], severity=h.severity,
                       confidence="high", file_path=h.path, line=h.line, evidence=redact(f"{h.rule} at {h.path}: {h.detail}"))
            for h in hits]
    await service.ingest(ctx.session, job, ParseResult(raws, {"all": False, "paths": list(args.paths)},
                                                       {"findings": len(raws), "changed_paths": len(args.paths)}))
    return ScanOut(job_id=str(job.id), scanner="integrity", status=job.status.value)


SCANNER_TOOLS = {
    "run_osv_scanner": Scanner.osv_scanner, "run_npm_audit": Scanner.npm_audit, "run_pip_audit": Scanner.pip_audit,
    "run_semgrep": Scanner.semgrep, "run_gitleaks": Scanner.gitleaks, "run_trivy": Scanner.trivy,
}


def build_registry() -> ToolRegistry:
    reg = ToolRegistry()
    for name, scanner in SCANNER_TOOLS.items():
        reg.register(Tool(name, PolicyTier.allowed, "platform_write", ScanArgs, ScanOut, _scanner_tool(scanner)))
    reg.register(Tool("read_repository_profile", PolicyTier.allowed, "read", RepoArgs, Profiles, repository_profile))
    reg.register(Tool("run_integrity_checks", PolicyTier.allowed, "platform_write", IntegrityArgs, ScanOut, integrity_checks))
    return reg


class RepoInput(BaseModel):
    repository_id: uuid.UUID
    trigger: ScanTrigger = ScanTrigger.manual


class JobsOut(BaseModel):
    jobs: list[ScanOut]


def _spec(name: str, purpose: str, tools: tuple[str, ...], input_schema=RepoInput, output=JobsOut) -> AgentSpec:
    return AgentSpec(name=name, purpose=purpose, input_schema=input_schema, output_schema=output, allowed_tools=tools,
                     uses_llm=False, timeout_s=800, max_retries=0, approval_required_for=())


DEPENDENCY_SPEC = _spec("dependency_analysis", "Find vulnerable dependencies from lockfiles.",
                        ("read_repository_profile", "run_osv_scanner", "run_npm_audit", "run_pip_audit"))
CODE_SPEC = _spec("code_security", "Static analysis of source code.", ("run_semgrep", "run_trivy"))
SECRET_SPEC = _spec("secret_detection", "Secrets in files and git history.", ("run_gitleaks",))
INTEGRITY_SPEC = _spec("repository_integrity", "Static tampering checks on changed files.", ("run_integrity_checks",),
                       input_schema=IntegrityArgs, output=ScanOut)


async def dependency_handler(ctx: AgentContext) -> dict:
    rid, trig = str(ctx.input.repository_id), ctx.input.trigger.value
    jobs = [await ctx.call("run_osv_scanner", {"repository_id": rid, "trigger": trig})]
    profiles = (await ctx.call("read_repository_profile", {"repository_id": rid}))["profiles"]
    for p in profiles:
        d = "" if p["directory"] == "." else p["directory"]
        if p["ecosystem"] == "npm" and p.get("lockfile_path", "") and p["lockfile_path"].endswith("package-lock.json"):
            jobs.append(await ctx.call("run_npm_audit", {"repository_id": rid, "trigger": trig, "target": d or None}))
        if p["ecosystem"] == "PyPI" and p.get("manifest_path") and "requirements" in p["manifest_path"]:
            jobs.append(await ctx.call("run_pip_audit", {"repository_id": rid, "trigger": trig, "target": p["manifest_path"]}))
    return {"jobs": jobs}


async def code_handler(ctx: AgentContext) -> dict:
    rid, trig = str(ctx.input.repository_id), ctx.input.trigger.value
    return {"jobs": [await ctx.call("run_semgrep", {"repository_id": rid, "trigger": trig}),
                     await ctx.call("run_trivy", {"repository_id": rid, "trigger": trig})]}


async def secret_handler(ctx: AgentContext) -> dict:
    return {"jobs": [await ctx.call("run_gitleaks", {"repository_id": str(ctx.input.repository_id),
                                                     "trigger": ctx.input.trigger.value})]}


async def integrity_handler(ctx: AgentContext) -> dict:
    return await ctx.call("run_integrity_checks", ctx.input.model_dump(mode="json"))


AGENTS = {
    "dependency_analysis": (DEPENDENCY_SPEC, dependency_handler),
    "code_security": (CODE_SPEC, code_handler),
    "secret_detection": (SECRET_SPEC, secret_handler),
    "repository_integrity": (INTEGRITY_SPEC, integrity_handler),
}


async def run_agent(session, name: str, payload: dict):
    spec, handler = AGENTS[name]
    reg = build_registry()
    redactor = get_redactor()
    return await Orchestrator(reg, ToolGateway(reg, redactor), redactor).run(session, spec, handler, payload)


def run_agent_sync(name: str, payload: dict) -> str:
    from app.db.session import get_engine, get_sessionmaker

    async def go() -> str:
        try:
            async with get_sessionmaker()() as session:
                return (await run_agent(session, name, payload)).status.value
        finally:
            await get_engine().dispose()

    return asyncio.run(go())


def enqueue_agent(name: str, payload: dict) -> bool:
    try:
        from app.workers.celery_app import celery

        celery.send_task("scans.agent", args=[name, payload], retry=False)
        return True
    except Exception:  # noqa: BLE001
        return False

