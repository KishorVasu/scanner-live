"""Impact matrix (Phase 4 API; the dashboard page is Phase 5). Read-only, dashboard:view.

Vendor facts and AI interpretation are separate fields, and the AI field is labelled as such.
"""

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.intel import ImpactClassification, ProjectImpact, SecurityAdvisory
from app.db.registry import Project, ProjectComponent, Repository
from app.db.session import get_db
from app.modules.auth.deps import Principal, require

router = APIRouter(prefix="/api/impacts", tags=["impacts"])


def _base():
    return (select(ProjectImpact, SecurityAdvisory, Project.id, Project.name)
            .join(SecurityAdvisory, SecurityAdvisory.id == ProjectImpact.advisory_id)
            .join(Repository, Repository.id == ProjectImpact.repository_id)
            .join(ProjectComponent, ProjectComponent.id == Repository.component_id)
            .join(Project, Project.id == ProjectComponent.project_id))


@router.get("/matrix")
async def matrix(_: Principal = Depends(require("dashboard:view")), db: AsyncSession = Depends(get_db)):
    """Counts per project and classification: the overview grid."""
    rows = await db.execute(
        select(Project.id, Project.name, ProjectImpact.classification, func.count())
        .join(ProjectComponent, ProjectComponent.project_id == Project.id)
        .join(Repository, Repository.component_id == ProjectComponent.id)
        .join(ProjectImpact, ProjectImpact.repository_id == Repository.id)
        .group_by(Project.id, Project.name, ProjectImpact.classification).order_by(Project.name))
    out: dict[str, dict] = {}
    for pid, name, cls, n in rows:
        out.setdefault(str(pid), {"project_id": str(pid), "project": name, "counts": {}})["counts"][cls.value] = n
    return list(out.values())


@router.get("")
async def list_impacts(
    classification: list[ImpactClassification] = Query(default=[]),
    project_id: uuid.UUID | None = None,
    offset: int = Query(0, ge=0, le=100_000),
    limit: int = Query(25, ge=1, le=100),
    _: Principal = Depends(require("dashboard:view")),
    db: AsyncSession = Depends(get_db),
):
    q = _base()
    if classification:
        q = q.where(ProjectImpact.classification.in_(classification))
    if project_id:
        q = q.where(Project.id == project_id)
    total = await db.scalar(select(func.count()).select_from(q.subquery()))
    rows = await db.execute(q.order_by(SecurityAdvisory.known_exploited.desc(), SecurityAdvisory.severity,
                                       ProjectImpact.decided_at.desc(), ProjectImpact.id).offset(offset).limit(limit))
    return {"total": total, "offset": offset, "limit": limit, "items": [
        {
            "id": str(i.id), "project_id": str(pid), "project": pname, "repository_id": str(i.repository_id),
            "classification": i.classification.value, "reasoning": i.reasoning, "evidence": i.evidence,
            "references": i.references, "decided_by_rule": i.decided_by_rule,
            "decided_by_run_id": str(i.decided_by_run_id) if i.decided_by_run_id else None,
            "decided_at": i.decided_at.isoformat(),
            "advisory": {
                "external_id": a.external_id, "aliases": a.aliases, "title": a.title, "url": a.url,
                "package": a.package, "ecosystem": a.ecosystem, "severity": a.severity.value if a.severity else None,
                "known_exploited": a.known_exploited, "patched_versions": a.patched_versions,
                "vendor_facts": a.vendor_facts,
                "ai_interpretation": a.ai_interpretation,  # LLM-written; the UI must label it as such
                "extra_conditions": a.extra_conditions,
            },
        }
        for i, a, pid, pname in rows
    ]}
