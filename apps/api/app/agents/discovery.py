"""Project Discovery agent (Phase 2, deterministic, no LLM).

Reads one GitHub repository through tokens scoped to that repository (contents:read, metadata:read), detects
technologies and builds the dependency inventory with sp_inventory, and stores it. Every step goes through the
Tool Gateway. Local repositories are inventoried by their local agent instead.
"""

import asyncio
import logging
import uuid

from pydantic import BaseModel, ConfigDict, Field
from sp_inventory import build_inventory, manifest_paths
from sqlalchemy import select

from app.agents.gateway import ToolGateway
from app.agents.orchestrator import AgentContext, Orchestrator
from app.agents.registry import Tool, ToolContext, ToolRegistry
from app.agents.spec import AgentSpec
from app.core.redaction import get_redactor
from app.db.models import AgentRun, PolicyTier
from app.db.registry import GithubInstallation, GithubInstallationRepo, Repository, RepoSource
from app.integrations.github import RepoSession, get_github

log = logging.getLogger(__name__)


class ToolError(Exception):
    pass


class RepoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_id: uuid.UUID


class RefArgs(RepoArgs):
    ref: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._/\-]+$")


class FileArgs(RefArgs):
    path: str = Field(min_length=1, max_length=500)


class Metadata(BaseModel):
    full_name: str
    default_branch: str
    private: bool


class Tree(BaseModel):
    tree_sha: str
    paths: list[str]
    truncated: bool


class ManifestText(BaseModel):
    path: str
    text: str | None


class InventoryOut(BaseModel):
    tree_sha: str
    truncated: bool
    manifest_hash: str
    complete: bool
    profiles: list[dict]
    dependencies: list[dict]
    coverage: list[dict]


class StoreArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_id: uuid.UUID
    default_branch: str = Field(max_length=255)
    inventory: InventoryOut


class Stored(BaseModel):
    dependencies: int
    complete: bool


async def _session_for(ctx: ToolContext, repository_id: uuid.UUID) -> tuple[Repository, RepoSession]:
    """Mint a token for this one repository, only while its installation is read-only and active."""
    repo = await ctx.session.get(Repository, repository_id)
    if repo is None or repo.source != RepoSource.github:
        raise ToolError("not a registered GitHub repository")
    row = (await ctx.session.execute(
        select(GithubInstallationRepo, GithubInstallation)
        .join(GithubInstallation, GithubInstallation.id == GithubInstallationRepo.installation_ref)
        .where(GithubInstallationRepo.github_repo_id == repo.github_repo_id, GithubInstallationRepo.removed_at.is_(None))
    )).first()
    if row is None:
        raise ToolError("repository is no longer accessible to the GitHub App")
    _, inst = row
    if not inst.read_only or inst.suspended_at is not None:
        raise ToolError("installation is not read-only or is suspended")
    return repo, await get_github().repo_session(inst.installation_id, repo.github_repo_id)


async def github_repo_metadata(ctx: ToolContext, args: RepoArgs) -> Metadata:
    _, gh = await _session_for(ctx, args.repository_id)
    m = await gh.metadata()
    return Metadata(full_name=m["full_name"], default_branch=m["default_branch"], private=bool(m.get("private")))


async def list_tree(ctx: ToolContext, args: RefArgs) -> Tree:
    _, gh = await _session_for(ctx, args.repository_id)
    sha, paths, truncated = await gh.tree(args.ref)
    return Tree(tree_sha=sha, paths=paths, truncated=truncated)


async def read_manifest(ctx: ToolContext, args: FileArgs) -> ManifestText:
    if manifest_paths([args.path]) != [args.path]:
        raise ToolError("only manifest and lockfile paths can be read; secret-pattern paths never")
    _, gh = await _session_for(ctx, args.repository_id)
    data = await gh.file(args.path, args.ref)
    return ManifestText(path=args.path, text=data.decode("utf-8", errors="replace") if data is not None else None)


async def hash_inventory(ctx: ToolContext, args: RefArgs) -> InventoryOut:
    _, gh = await _session_for(ctx, args.repository_id)
    sha, tree, truncated = await gh.tree(args.ref)
    contents = {}
    for path in manifest_paths(tree):  # never secret paths, never anything else
        try:
            contents[path] = await gh.file(path, args.ref)
        except Exception:  # noqa: BLE001 - one unreadable file marks coverage, it does not fail the run
            contents[path] = None
    inv = build_inventory(tree, contents).as_dict()
    if truncated:
        inv["complete"] = False  # GitHub truncated the tree: some manifests may be missing
    return InventoryOut(tree_sha=sha, truncated=truncated, **inv)


async def store_inventory_tool(ctx: ToolContext, args: StoreArgs) -> Stored:
    from app.modules.agents.router import store_inventory

    repo = await ctx.session.get(Repository, args.repository_id)
    if repo is None:
        raise ToolError("repository not found")
    inv = args.inventory.model_dump()
    inv["tree_hash"] = inv.pop("tree_sha")
    await store_inventory(ctx.session, repo, inv)
    repo.default_branch = args.default_branch
    return Stored(dependencies=len(inv["dependencies"]), complete=inv["complete"])


def build_registry() -> ToolRegistry:
    reg = ToolRegistry()
    A = PolicyTier.allowed
    reg.register(Tool("github_repo_metadata", A, "read", RepoArgs, Metadata, github_repo_metadata))
    reg.register(Tool("list_tree", A, "read", RefArgs, Tree, list_tree))
    reg.register(Tool("read_manifest", A, "read", FileArgs, ManifestText, read_manifest))
    reg.register(Tool("hash_inventory", A, "read", RefArgs, InventoryOut, hash_inventory))
    reg.register(Tool("store_inventory", A, "platform_write", StoreArgs, Stored, store_inventory_tool))
    return reg


class DiscoveryInput(BaseModel):
    repository_id: uuid.UUID


SPEC = AgentSpec(
    name="project_discovery",
    purpose="Detect technologies and build the dependency inventory of one GitHub repository.",
    input_schema=DiscoveryInput,
    output_schema=Stored,
    allowed_tools=("github_repo_metadata", "list_tree", "read_manifest", "hash_inventory", "store_inventory"),
    uses_llm=False,
    timeout_s=300,
    max_retries=2,
    approval_required_for=(),
)


async def handler(ctx: AgentContext) -> dict:
    rid = str(ctx.input.repository_id)
    meta = await ctx.call("github_repo_metadata", {"repository_id": rid})
    inv = await ctx.call("hash_inventory", {"repository_id": rid, "ref": meta["default_branch"]})
    return await ctx.call("store_inventory", {"repository_id": rid, "default_branch": meta["default_branch"], "inventory": inv})


async def run_discovery(session, repository_id: uuid.UUID) -> AgentRun:
    reg = build_registry()
    redactor = get_redactor()
    orch = Orchestrator(reg, ToolGateway(reg, redactor), redactor)
    return await orch.run(session, SPEC, handler, {"repository_id": str(repository_id)})


def enqueue_discovery(repository_id: uuid.UUID) -> bool:
    """Queue discovery on the worker. Returns False (never raises) if the broker is unavailable."""
    try:
        from app.workers.celery_app import celery

        celery.send_task("discovery.github", args=[str(repository_id)], retry=False)
        return True
    except Exception:  # noqa: BLE001
        log.exception("could not queue discovery")
        return False


def run_discovery_sync(repository_id: str) -> str:
    """Celery entry point."""
    from app.db.session import get_engine, get_sessionmaker

    async def go() -> str:
        try:
            async with get_sessionmaker()() as session:
                run = await run_discovery(session, uuid.UUID(repository_id))
                return run.status.value
        finally:
            await get_engine().dispose()

    return asyncio.run(go())
