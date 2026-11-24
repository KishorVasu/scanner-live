"""Scheduled scans (docs/SCANNING_STRATEGY.md §10). Projects that are paused, archived or under incident are skipped."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.registry import Project, ProjectComponent, ProjectStatus, Repository

DAILY = (("daily_deps", "dependency_analysis"), ("daily_secrets", "secret_detection"))
WEEKLY = (("weekly_full", "code_security"),)


async def plan(db: AsyncSession, cadence: str, enqueue=None) -> int:
    if enqueue is None:
        from app.agents.scanning import enqueue_agent as enqueue
    pairs = DAILY if cadence == "daily" else WEEKLY if cadence == "weekly" else ()
    rows = await db.execute(
        select(Repository.id, Project)
        .join(ProjectComponent, ProjectComponent.id == Repository.component_id)
        .join(Project, Project.id == ProjectComponent.project_id)
        .where(Project.status == ProjectStatus.active))
    queued = 0
    for repo_id, project in rows:
        policy = project.scan_policy
        for flag, agent in pairs:
            if policy is not None and getattr(policy, flag):
                queued += bool(enqueue(agent, {"repository_id": str(repo_id), "trigger": "schedule"}))
    return queued
