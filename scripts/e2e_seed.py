"""CI-only: create a throwaway database for the Playwright run and seed synthetic users and data.

Usage: E2E_ADMIN_URL=postgresql+asyncpg://postgres:...@localhost:5432/postgres \
       SP_MASTER_KEY_FILE=... SP_REDACTION_SALT_FILE=... python scripts/e2e_seed.py <creds.json>

Prints the app database URL to stdout for the API process. Every value here is a fixture; nothing is real.
"""

import asyncio
import json
import os
import secrets
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
import pyotp
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "apps" / "api"
sys.path.insert(0, str(API))


async def admin_exec(url: str, sql: str, database: str = "postgres") -> None:
    conn = await asyncpg.connect(make_url(url).set(drivername="postgresql", database=database).render_as_string(False))
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


async def main(creds_path: str) -> None:
    admin = os.environ["E2E_ADMIN_URL"]
    app_pw = secrets.token_urlsafe(16)
    await admin_exec(admin, "DROP DATABASE IF EXISTS sp_e2e WITH (FORCE)")
    await admin_exec(admin, "CREATE DATABASE sp_e2e")
    await admin_exec(admin, "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='platform_app') THEN "
                            f"CREATE ROLE platform_app LOGIN PASSWORD '{app_pw}'; ELSE "
                            f"ALTER ROLE platform_app LOGIN PASSWORD '{app_pw}'; END IF; END $$")
    owner = make_url(admin).set(database="sp_e2e").render_as_string(hide_password=False)
    app_url = make_url(admin).set(database="sp_e2e", username="platform_app", password=app_pw).render_as_string(False)

    from alembic import command
    from alembic.config import Config

    cfg = Config(str(API / "alembic.ini"))
    cfg.set_main_option("script_location", str(API / "app/db/alembic"))
    cfg.attributes["url"] = owner
    await asyncio.to_thread(command.upgrade, cfg, "head")

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.core.security import get_cipher, hash_password
    from app.db.intel import Report, ReportStatus
    from app.db.models import Role, User
    from app.db.registry import ComponentKind, Criticality, Project, ProjectComponent, ProjectStatus, Repository, RepoSource
    from app.db.registry import Severity
    from app.db.scanning import Confidence, FindingStatus, ScanJob, ScanStatus, ScanTrigger, Scanner, SecurityFinding
    from app.reports import content as rc

    engine = create_async_engine(owner)
    creds = {}
    async with async_sessionmaker(engine, expire_on_commit=False)() as s:
        now = datetime.now(UTC)
        users = {}
        for key, roles in {"approver_a": ["approver"], "approver_b": ["approver"], "approver_c": ["approver"],
                          "developer": ["developer"]}.items():
            secret, password = pyotp.random_base32(), secrets.token_urlsafe(16)
            u = User(email=f"e2e-{key}@example.test", password_hash=hash_password(password),
                     roles=list(await s.scalars(select(Role).where(Role.name.in_(roles)))))
            s.add(u)
            await s.flush()
            u.totp_secret_enc = get_cipher().encrypt(secret.encode(), f"users.totp_secret_enc:{u.id}")
            u.totp_confirmed_at = now
            users[key] = u
            creds[key] = {"email": u.email, "password": password, "totp": secret, "id": str(u.id)}

        def project(name):
            p = Project(name=name, slug=name.lower().replace(" ", "-"), criticality=Criticality.high,
                        status=ProjectStatus.active)
            s.add(p)
            return p

        unscanned, scanned = project("E2E Unscanned"), project("E2E Scanned")
        await s.flush()
        repos = {}
        for p in (unscanned, scanned):
            c = ProjectComponent(project_id=p.id, kind=ComponentKind.web, name="web")
            s.add(c)
            await s.flush()
            r = Repository(component_id=c.id, source=RepoSource.github, github_repo_id=uuid.uuid4().int % 10**12,
                           full_name=f"e2e/{p.slug}", manifest_hash="m" * 64, tree_hash="t" * 40)
            s.add(r)
            repos[p.name] = r
        await s.flush()
        s.add(ScanJob(repository_id=repos["E2E Scanned"].id, scanner=Scanner.osv_scanner, trigger=ScanTrigger.manual,
                      inventory_hash="h" * 64, status=ScanStatus.succeeded, finished_at=now))
        s.add(SecurityFinding(fingerprint=uuid.uuid4().hex * 2, project_id=scanned.id, repository_id=repos["E2E Scanned"].id,
                              scanner=Scanner.osv_scanner, rule_id="GHSA-e2e0-0000-aaaa", category="dependency",
                              title="E2E fixture finding", severity=Severity.high, confidence=Confidence.high,
                              status=FindingStatus.open, package="fixture-lib", package_version="1.0.0",
                              first_seen_at=now, last_seen_at=now))
        await s.flush()
        content, _ = await rc.build(s, scanned.id)
        s.add(Report(kind="project", project_id=scanned.id, title="E2E draft report", status=ReportStatus.draft,
                     content=content, narrative=None, narrative_note="tables only (e2e)",
                     created_by=users["approver_a"].id))
        await s.commit()
    await engine.dispose()
    Path(creds_path).write_text(json.dumps(creds))
    print(app_url)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
