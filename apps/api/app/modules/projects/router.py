"""Project → component → repository registry. Writes need projects:manage; reads need dashboard:view."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ActorType, User
from app.db.registry import (
    ComponentKind,
    Criticality,
    DependencyInventory,
    GithubInstallation,
    GithubInstallationRepo,
    LocalAgent,
    Project,
    ProjectComponent,
    ProjectStatus,
    Repository,
    RepoSource,
    ScanPolicy,
    TechnologyProfile,
)
from app.db.session import get_db
from app.modules.audit.service import record
from app.modules.auth.deps import Principal, client_ip, require

router = APIRouter(prefix="/api", tags=["projects"])


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    description: str = Field(default="", max_length=4000)
    owner_user_id: uuid.UUID | None = None
    criticality: Criticality = Criticality.medium
    deployment_environments: list[str] = Field(default_factory=list, max_length=20)
    llm_allowed: bool = True


class ProjectPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    owner_user_id: uuid.UUID | None = None
    criticality: Criticality | None = None
    status: ProjectStatus | None = None
    deployment_environments: list[str] | None = Field(default=None, max_length=20)
    llm_allowed: bool | None = None


class ComponentIn(BaseModel):
    kind: ComponentKind
    name: str = Field(min_length=1, max_length=200)


class RepositoryIn(BaseModel):
    source: RepoSource
    github_repo_id: int | None = None
    local_agent_id: uuid.UUID | None = None
    local_path_alias: str | None = Field(default=None, max_length=64)


class ScanPolicyIn(BaseModel):
    daily_deps: bool = True
    daily_secrets: bool = True
    weekly_full: bool = True
    webhook_targeted: bool = True
    codeql_enabled: bool = False


def _repo_out(r: Repository) -> dict:
    return {
        "id": str(r.id), "source": r.source.value, "github_repo_id": r.github_repo_id, "full_name": r.full_name,
        "local_agent_id": str(r.local_agent_id) if r.local_agent_id else None, "local_path_alias": r.local_path_alias,
        "default_branch": r.default_branch, "manifest_hash": r.manifest_hash, "tree_hash": r.tree_hash,
        # None = never inventoried ("not scanned"), False = partial; never conflated with "no dependencies".
        "inventory_complete": r.inventory_complete,
        "last_inventory_at": r.last_inventory_at.isoformat() if r.last_inventory_at else None,
    }


def _project_out(p: Project) -> dict:
    return {
        "id": str(p.id), "name": p.name, "slug": p.slug, "description": p.description,
        "owner_user_id": str(p.owner_user_id) if p.owner_user_id else None, "criticality": p.criticality.value,
        "status": p.status.value, "deployment_environments": p.deployment_environments, "llm_allowed": p.llm_allowed,
        "scan_policy": None if p.scan_policy is None else {
            k: getattr(p.scan_policy, k) for k in ScanPolicyIn.model_fields
        },
        "components": [
            {"id": str(c.id), "kind": c.kind.value, "name": c.name, "repositories": [_repo_out(r) for r in c.repositories]}
            for c in p.components
        ],
    }


async def _project(db: AsyncSession, project_id: uuid.UUID) -> Project:
    # populate_existing re-runs the eager loads, so no lazy load can happen later in async code.
    p = await db.get(Project, project_id, populate_existing=True)
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return p


def _audit(db, p: Principal, request: Request, action: str, target_type: str, target_id, detail=None) -> None:
    record(db, actor_type=ActorType.user, actor_id=p.id, action=action, outcome="success", target_type=target_type,
           target_id=target_id, ip=client_ip(request), detail=detail)


@router.get("/projects")
async def list_projects(_: Principal = Depends(require("dashboard:view")), db: AsyncSession = Depends(get_db)):
    return [_project_out(p) for p in await db.scalars(select(Project).order_by(Project.name))]


@router.post("/projects", status_code=201)
async def create_project(body: ProjectIn, request: Request, p: Principal = Depends(require("projects:manage")),
                         db: AsyncSession = Depends(get_db)):
    if await db.scalar(select(Project.id).where(Project.slug == body.slug)):
        raise HTTPException(status.HTTP_409_CONFLICT, "slug in use")
    if body.owner_user_id and not await db.get(User, body.owner_user_id):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "owner not found")
    project = Project(**body.model_dump(), status=ProjectStatus.active)
    db.add(project)
    await db.flush()
    db.add(ScanPolicy(project_id=project.id))
    _audit(db, p, request, "projects.create", "project", project.id, {"slug": body.slug})
    await db.commit()
    return _project_out(await _project(db, project.id))


@router.get("/projects/{project_id}")
async def get_project(project_id: uuid.UUID, _: Principal = Depends(require("dashboard:view")),
                      db: AsyncSession = Depends(get_db)):
    return _project_out(await _project(db, project_id))


@router.patch("/projects/{project_id}")
async def patch_project(project_id: uuid.UUID, body: ProjectPatch, request: Request,
                        p: Principal = Depends(require("projects:manage")), db: AsyncSession = Depends(get_db)):
    project = await _project(db, project_id)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(project, k, v)
    _audit(db, p, request, "projects.update", "project", project.id, {"fields": sorted(changes)})
    await db.commit()
    return _project_out(await _project(db, project_id))


@router.put("/projects/{project_id}/scan-policy")
async def set_scan_policy(project_id: uuid.UUID, body: ScanPolicyIn, request: Request,
                          p: Principal = Depends(require("projects:manage")), db: AsyncSession = Depends(get_db)):
    project = await _project(db, project_id)
    for k, v in body.model_dump().items():
        setattr(project.scan_policy, k, v)
    _audit(db, p, request, "projects.scan_policy", "project", project.id, body.model_dump())
    await db.commit()
    return _project_out(project)


@router.post("/projects/{project_id}/components", status_code=201)
async def add_component(project_id: uuid.UUID, body: ComponentIn, request: Request,
                        p: Principal = Depends(require("projects:manage")), db: AsyncSession = Depends(get_db)):
    await _project(db, project_id)
    if await db.scalar(select(ProjectComponent.id).where(ProjectComponent.project_id == project_id,
                                                         ProjectComponent.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "component name in use")
    c = ProjectComponent(project_id=project_id, kind=body.kind, name=body.name)
    db.add(c)
    await db.flush()
    _audit(db, p, request, "projects.add_component", "component", c.id, {"kind": body.kind.value})
    await db.commit()
    return {"id": str(c.id), "kind": c.kind.value, "name": c.name}


@router.post("/components/{component_id}/repositories", status_code=201)
async def add_repository(component_id: uuid.UUID, body: RepositoryIn, request: Request,
                         p: Principal = Depends(require("projects:manage")), db: AsyncSession = Depends(get_db)):
    if not await db.get(ProjectComponent, component_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "component not found")
    if body.source == RepoSource.github:
        if body.github_repo_id is None or body.local_agent_id or body.local_path_alias:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "github repositories need github_repo_id only")
        row = (await db.execute(
            select(GithubInstallationRepo, GithubInstallation)
            .join(GithubInstallation, GithubInstallation.id == GithubInstallationRepo.installation_ref)
            .where(GithubInstallationRepo.github_repo_id == body.github_repo_id,
                   GithubInstallationRepo.removed_at.is_(None))
        )).first()
        if row is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "repository is not accessible to the GitHub App")
        inst_repo, inst = row
        if not inst.read_only or inst.suspended_at is not None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "installation is not read-only or is suspended")
        repo = Repository(component_id=component_id, source=RepoSource.github, github_repo_id=body.github_repo_id,
                          full_name=inst_repo.full_name)
    else:
        if body.local_agent_id is None or not body.local_path_alias or body.github_repo_id is not None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "local repositories need local_agent_id and local_path_alias")
        agent = await db.get(LocalAgent, body.local_agent_id)
        if agent is None or agent.revoked_at is not None or agent.root(body.local_path_alias) is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "alias is not an approved root of an active agent")
        repo = Repository(component_id=component_id, source=RepoSource.local, local_agent_id=agent.id,
                          local_path_alias=body.local_path_alias)
    if await db.scalar(select(Repository.id).where(
        (Repository.github_repo_id == repo.github_repo_id) if repo.github_repo_id is not None else
        ((Repository.local_agent_id == repo.local_agent_id) & (Repository.local_path_alias == repo.local_path_alias))
    )):
        raise HTTPException(status.HTTP_409_CONFLICT, "repository already registered")
    db.add(repo)
    await db.flush()
    _audit(db, p, request, "projects.add_repository", "repository", repo.id, {"source": repo.source.value})
    await db.commit()
    return _repo_out(repo)


@router.post("/repositories/{repository_id}/discover", status_code=202)
async def discover(repository_id: uuid.UUID, request: Request, p: Principal = Depends(require("scans:trigger")),
                   db: AsyncSession = Depends(get_db)):
    from app.agents.discovery import enqueue_discovery

    repo = await db.get(Repository, repository_id)
    if repo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "repository not found")
    if repo.source != RepoSource.github:
        raise HTTPException(status.HTTP_409_CONFLICT, "local repositories are inventoried by their local agent")
    queued = enqueue_discovery(repo.id)
    _audit(db, p, request, "repositories.discover", "repository", repo.id, {"queued": queued})
    await db.commit()
    if not queued:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "job queue unavailable")
    return {"status": "queued"}


@router.get("/repositories/{repository_id}")
async def get_repository(repository_id: uuid.UUID, _: Principal = Depends(require("dashboard:view")),
                         db: AsyncSession = Depends(get_db)):
    repo = await db.get(Repository, repository_id)
    if repo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "repository not found")
    profiles = await db.scalars(select(TechnologyProfile).where(TechnologyProfile.repository_id == repo.id))
    dep_count = await db.scalar(select(func.count()).select_from(DependencyInventory)
                                .where(DependencyInventory.repository_id == repo.id))
    return {
        **_repo_out(repo),
        "inventory_coverage": repo.inventory_coverage,
        "dependency_count": dep_count,
        "profiles": [
            {"ecosystem": t.ecosystem, "directory": t.directory, "framework": t.framework, "version": t.version,
             "package_manager": t.package_manager, "manifest_path": t.manifest_path, "lockfile_path": t.lockfile_path}
            for t in profiles
        ],
    }
