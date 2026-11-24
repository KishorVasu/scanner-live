import asyncio

from celery import Celery, signals
from celery.schedules import crontab

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import get_engine, get_sessionmaker
from app.modules.approvals.service import expire_stale

_redis = get_settings().resolved_redis_url()
celery = Celery("security_platform", broker=_redis, backend=_redis)
celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],  # never pickle
    task_time_limit=900,
    task_soft_time_limit=840,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "expire-approvals": {"task": "approvals.expire", "schedule": 300.0},
        # Offline vulnerability DBs first, so the 02:00 scans read a fresh copy.
        "vulndb-sync": {"task": "vulndb.sync", "schedule": crontab(hour=1, minute=0)},
        # Advisory ingestion and impact analysis (Phase 4), before the daily scans.
        "intel-daily": {"task": "intel.run", "schedule": crontab(hour=0, minute=30)},
        "daily-scans": {"task": "scans.plan", "schedule": crontab(hour=2, minute=0), "args": ["daily"]},
        "weekly-scans": {"task": "scans.plan", "schedule": crontab(hour=3, minute=0, day_of_week="sun"), "args": ["weekly"]},
    },
)


@signals.setup_logging.connect
def _logging(**_: object) -> None:
    """Connecting this signal stops Celery from replacing our redacting log setup."""
    configure_logging(get_settings().log_level)


@celery.task(name="discovery.github", time_limit=600, soft_time_limit=540)
def discovery_github(repository_id: str) -> str:
    from app.agents.discovery import run_discovery_sync

    return run_discovery_sync(repository_id)


@celery.task(name="scans.agent", time_limit=900, soft_time_limit=840)
def scans_agent(name: str, payload: dict) -> str:
    from app.agents.scanning import AGENTS, run_agent_sync

    if name not in AGENTS:  # the broker is internal, but task arguments are still validated
        raise ValueError(f"unknown scan agent {name!r}")
    return run_agent_sync(name, payload)


@celery.task(name="scans.plan")
def scans_plan(cadence: str) -> int:
    """Queue scheduled scans. Unchanged repositories are skipped inside the job service (skipped_unchanged)."""
    from app.scanners.schedule import plan

    async def run() -> int:
        try:
            async with get_sessionmaker()() as db:
                return await plan(db, cadence)
        finally:
            await get_engine().dispose()

    return asyncio.run(run())


@celery.task(name="reports.generate", time_limit=900, soft_time_limit=840)
def reports_generate(project_id: str | None, created_by: str) -> str:
    import uuid

    from app.agents import reports
    from app.db.session import get_engine, get_sessionmaker

    async def run() -> str:
        try:
            async with get_sessionmaker()() as db:
                pid = uuid.UUID(project_id) if project_id else None
                return (await reports.run(db, pid, uuid.UUID(created_by))).status.value
        finally:
            await get_engine().dispose()

    return asyncio.run(run())


@celery.task(name="intel.run", time_limit=3600, soft_time_limit=3540)
def intel_run() -> dict:
    from app.agents.intel import run_pipeline_sync

    return run_pipeline_sync()


@celery.task(name="vulndb.sync", time_limit=1900, soft_time_limit=1840)
def vulndb_sync() -> dict:
    from app.scanners.vulndb import sync_all

    async def run() -> dict:
        try:
            async with get_sessionmaker()() as db:
                return await sync_all(db)
        finally:
            await get_engine().dispose()

    return asyncio.run(run())


@celery.task(name="approvals.expire", autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def expire_approvals() -> int:
    async def run() -> int:
        try:
            async with get_sessionmaker()() as db:
                n = await expire_stale(db)
                await db.commit()
                return n
        finally:
            await get_engine().dispose()  # each asyncio.run gets a new loop; pooled connections cannot cross it

    return asyncio.run(run())
