from fastapi import Depends, FastAPI
from prometheus_client import make_asgi_app
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import get_db
from app.modules.agents.router import router as agents_router
from app.modules.approvals.router import router as approvals_router
from app.modules.audit.router import router as audit_router
from app.modules.auth.router import router as auth_router
from app.modules.github.router import router as github_router
from app.modules.projects.router import router as projects_router
from app.modules.users.router import router as users_router


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    prod = settings.environment == "production"
    app = FastAPI(
        title="Security Platform API",
        docs_url=None if prod else "/api/docs",
        redoc_url=None,
        openapi_url=None if prod else "/api/openapi.json",
    )
    for r in (auth_router, users_router, approvals_router, audit_router, projects_router, github_router, agents_router):
        app.include_router(r)

    @app.get("/api/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.get("/api/health/ready")
    async def ready(db: AsyncSession = Depends(get_db)) -> dict:
        await db.execute(text("SELECT 1"))
        return {"status": "ready"}

    # Internal network only; Caddy does not route /metrics.
    app.mount("/metrics", make_asgi_app())
    return app


app = create_app()
