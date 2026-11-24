"""Migrations run as the schema owner (SP_MIGRATION_DATABASE_URL), never as the app role."""

import asyncio
import os

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

import app.db.registry  # noqa: F401  (registers Phase 2 tables on the metadata)
import app.db.scanning  # noqa: F401  (Phase 3)
from app.db.models import Base

target_metadata = Base.metadata


def _url() -> str:
    url = context.config.attributes.get("url") or os.environ.get("SP_MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("SP_MIGRATION_DATABASE_URL is not set")
    return url


def _run(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, transaction_per_migration=True)
    with context.begin_transaction():
        context.run_migrations()


async def _main() -> None:
    engine = create_async_engine(_url())
    async with engine.connect() as conn:
        await conn.run_sync(_run)
        await conn.commit()
    await engine.dispose()


asyncio.run(_main())
