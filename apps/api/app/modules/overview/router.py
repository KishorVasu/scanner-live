"""Read-only dashboard data (Phase 5): overview counts, scan history, integrity events. All need dashboard:view.

Rule 11 everywhere: a repository with no successful scan is reported as "not scanned", never as "no findings".
"""

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.intel import ProjectImpact, SecurityAdvisory
from app.db.registry import Project, ProjectComponent, ProjectStatus, Repository, RepositoryEvent
from app.db.scanning import FindingStatus, ScanJob, ScanStatus, SecurityFinding
from app.db.session import get_db
from app.modules.auth.deps import Principal, require

router = APIRouter(prefix="/api", tags=["dashboard"])

OK = (ScanStatus.succeeded, ScanStatus.partial)


def _repo_names():
    return (select(Repository.id.label("rid"), Project.id.label("pid"), Project.name.label("project"),
                   ProjectComponent.name.label("component"))
            .join(ProjectComponent, ProjectComponent.id == Repository.component_id)
            .join(Project, Project.id == ProjectComponent.project_id)).subquery()


@router.get("/overview")
async def overview(_: Principal = Depends(require("dashboard:view")), db: AsyncSession = Depends(get_db)):
    projects = list(await db.execute(select(Project.id, Project.name, Project.criticality)
                                     .where(Project.status != ProjectStatus.archived).order_by(Project.name)))
    repos = _repo_names()
    total_repos = dict((await db.execute(select(repos.c.pid, func.count()).group_by(repos.c.pid))).all())
    scanned = dict((await db.execute(
        select(repos.c.pid, func.count(func.distinct(ScanJob.repository_id)))
        .join(ScanJob, ScanJob.repository_id == repos.c.rid).where(ScanJob.status.in_(OK))
        .group_by(repos.c.pid))).all())
    open_by_sev: dict = {}
    for pid, sev, n in await db.execute(
            select(SecurityFinding.project_id, SecurityFinding.severity, func.count())
            .where(SecurityFinding.status.in_([FindingStatus.open, FindingStatus.in_progress]))
            .group_by(SecurityFinding.project_id, SecurityFinding.severity)):
        open_by_sev.setdefault(pid, {})[sev.value] = n
    affected = dict((await db.execute(
        select(repos.c.pid, func.count()).join(ProjectImpact, ProjectImpact.repository_id == repos.c.rid)
        .where(ProjectImpact.classification.in_(["confirmed_affected", "potentially_affected"]))
        .group_by(repos.c.pid))).all())
    kev = dict((await db.execute(
        select(repos.c.pid, func.count()).join(ProjectImpact, ProjectImpact.repository_id == repos.c.rid)
        .join(SecurityAdvisory, SecurityAdvisory.id == ProjectImpact.advisory_id)
        .where(SecurityAdvisory.known_exploited.is_(True),
               ProjectImpact.classification.in_(["confirmed_affected", "potentially_affected"]))
        .group_by(repos.c.pid))).all())
    rows = []
    for pid, name, crit in projects:
        n_repos, n_scanned = total_repos.get(pid, 0), scanned.get(pid, 0)
        rows.append({
            "project_id": str(pid), "project": name, "criticality": crit.value,
            "repositories": n_repos, "scanned_repositories": n_scanned,
            # Never "clean": either some repositories were not scanned, or the count shows what scans found.
            "scan_state": "not_scanned" if n_scanned == 0 else ("partial" if n_scanned < n_repos else "scanned"),
            "open_findings": open_by_sev.get(pid, {}), "affected_advisories": affected.get(pid, 0),
            "known_exploited": kev.get(pid, 0),
        })
    return {"projects": rows}


@router.get("/scans")
async def scans(repository_id: uuid.UUID | None = None, project_id: uuid.UUID | None = None,
                offset: int = Query(0, ge=0, le=100_000), limit: int = Query(25, ge=1, le=100),
                _: Principal = Depends(require("dashboard:view")), db: AsyncSession = Depends(get_db)):
    repos = _repo_names()
    q = select(ScanJob, repos.c.pid, repos.c.project, repos.c.component).join(repos, repos.c.rid == ScanJob.repository_id)
    if repository_id:
        q = q.where(ScanJob.repository_id == repository_id)
    if project_id:
        q = q.where(repos.c.pid == project_id)
    total = await db.scalar(select(func.count()).select_from(q.subquery()))
    rows = await db.execute(q.order_by(ScanJob.created_at.desc(), ScanJob.id).offset(offset).limit(limit))
    return {"total": total, "offset": offset, "limit": limit, "items": [
        {"id": str(j.id), "project_id": str(pid), "project": project, "component": comp,
         "repository_id": str(j.repository_id), "scanner": j.scanner.value, "trigger": j.trigger.value,
         "status": j.status.value, "error": j.error, "created_at": j.created_at.isoformat(),
         "started_at": j.started_at.isoformat() if j.started_at else None,
         "finished_at": j.finished_at.isoformat() if j.finished_at else None}
        for j, pid, project, comp in rows]}


@router.get("/integrity/events")
async def integrity_events(project_id: uuid.UUID | None = None,
                           offset: int = Query(0, ge=0, le=100_000), limit: int = Query(25, ge=1, le=100),
                           _: Principal = Depends(require("dashboard:view")), db: AsyncSession = Depends(get_db)):
    repos = _repo_names()
    q = (select(RepositoryEvent, repos.c.pid, repos.c.project, repos.c.component)
         .join(repos, repos.c.rid == RepositoryEvent.repository_id))
    if project_id:
        q = q.where(repos.c.pid == project_id)
    total = await db.scalar(select(func.count()).select_from(q.subquery()))
    rows = await db.execute(q.order_by(RepositoryEvent.created_at.desc(), RepositoryEvent.id).offset(offset).limit(limit))
    return {"total": total, "offset": offset, "limit": limit, "items": [
        {"id": str(e.id), "project_id": str(pid), "project": project, "component": comp,
         "repository_id": str(e.repository_id), "kind": e.kind.value, "severity": e.severity.value, "ref": e.ref,
         "before_sha": e.before_sha, "after_sha": e.after_sha, "detail": e.detail, "source": e.source,
         "created_at": e.created_at.isoformat()}
        for e, pid, project, comp in rows]}
