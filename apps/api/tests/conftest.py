"""Test setup.

DB-backed tests need a disposable Postgres superuser URL in TEST_PG_ADMIN_URL, e.g.
postgresql+asyncpg://postgres:postgres@localhost:5432/postgres. Without it they are skipped (and reported as skipped,
never as passed). Each session creates a fresh database, runs migrations as the owner, and tests as `platform_app`.
"""

import asyncio
import os
import secrets
import time
import uuid
from pathlib import Path

os.environ["SP_ENVIRONMENT"] = "test"
os.environ["SP_COOKIE_SECURE"] = "false"

import pyotp  # noqa: E402
import pytest  # noqa: E402
from sqlalchemy import select  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

API_DIR = Path(__file__).resolve().parents[1]


def _admin_url() -> str | None:
    """From the environment, or from the gitignored apps/api/.env.test (one line: TEST_PG_ADMIN_URL=...)."""
    if os.environ.get("TEST_PG_ADMIN_URL"):
        return os.environ["TEST_PG_ADMIN_URL"]
    env_file = API_DIR / ".env.test"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "TEST_PG_ADMIN_URL" and value.strip():
                return value.strip()
    return None


ADMIN_URL = _admin_url()
_EMBEDDED = None


def _start_embedded() -> str | None:
    """Fallback: a throwaway embedded Postgres (test-only `pgserver`). No password, no local install touched."""
    global _EMBEDDED
    try:
        import pgserver
    except ImportError:
        return None
    import tempfile

    _EMBEDDED = pgserver.get_server(tempfile.mkdtemp(prefix="sp_pg_"), cleanup_mode="delete")
    return _EMBEDDED.get_uri().replace("postgresql://", "postgresql+asyncpg://", 1)
APP_PASSWORD = secrets.token_urlsafe(16)


async def _exec_admin(sql: str, database: str = "postgres") -> None:
    import asyncpg

    url = make_url(ADMIN_URL).set(drivername="postgresql", database=database)
    conn = await asyncpg.connect(url.render_as_string(hide_password=False))
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


@pytest.fixture(scope="session")
async def db_urls():
    global ADMIN_URL
    if not ADMIN_URL:
        ADMIN_URL = _start_embedded()
    if not ADMIN_URL:
        if os.environ.get("CI"):
            pytest.fail("TEST_PG_ADMIN_URL must be set in CI; DB tests may not be skipped there")
        pytest.skip("No TEST_PG_ADMIN_URL and no embedded Postgres (pip install pgserver): DB tests skipped")
    from alembic import command
    from alembic.config import Config

    name = f"sp_test_{uuid.uuid4().hex[:8]}"
    await _exec_admin(f"CREATE DATABASE {name}")
    await _exec_admin(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='platform_app') THEN "
        f"CREATE ROLE platform_app LOGIN PASSWORD '{APP_PASSWORD}'; ELSE "
        f"ALTER ROLE platform_app LOGIN PASSWORD '{APP_PASSWORD}'; END IF; END $$"
    )
    owner_url = make_url(ADMIN_URL).set(database=name).render_as_string(hide_password=False)
    app_url = (
        make_url(ADMIN_URL).set(database=name, username="platform_app", password=APP_PASSWORD)
        .render_as_string(hide_password=False)
    )
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "app/db/alembic"))
    cfg.attributes["url"] = owner_url
    await asyncio.to_thread(command.upgrade, cfg, "head")

    os.environ["SP_DATABASE_URL"] = app_url
    from app.core.config import get_settings
    from app.db.session import get_engine, get_sessionmaker

    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()
    yield {"owner": owner_url, "app": app_url, "name": name, "cfg": cfg}
    await get_engine().dispose()
    await _exec_admin(f"DROP DATABASE {name} WITH (FORCE)")
    if _EMBEDDED is not None:
        _EMBEDDED.cleanup()


@pytest.fixture(scope="session")
async def owner_session_factory(db_urls):
    engine = create_async_engine(db_urls["owner"])
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
async def owner_db(owner_session_factory):
    async with owner_session_factory() as s:
        yield s


@pytest.fixture
async def app_db(db_urls):
    from app.db.session import get_sessionmaker

    async with get_sessionmaker()() as s:
        yield s


@pytest.fixture
async def client(db_urls):
    import httpx

    from app.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


class TestUser:
    def __init__(self, id, email, password, secret):
        self.id, self.email, self.password, self.secret = id, email, password, secret

    def code(self, offset: int = 0) -> str:
        """TOTP for the current step + offset (each step is usable once per user)."""
        totp = pyotp.TOTP(self.secret)
        return totp.at(time.time() + offset * totp.interval)


@pytest.fixture
def make_user(owner_session_factory):
    async def make(*roles: str, enrolled: bool = True) -> TestUser:
        from datetime import UTC, datetime

        from app.core.security import get_cipher, hash_password
        from app.db.models import Role, User

        email = f"u{uuid.uuid4().hex[:10]}@example.test"
        password = secrets.token_urlsafe(16)
        secret = pyotp.random_base32()
        async with owner_session_factory() as s:
            user = User(email=email, password_hash=hash_password(password),
                        roles=list(await s.scalars(select(Role).where(Role.name.in_(roles)))))
            s.add(user)
            await s.flush()
            if enrolled:
                user.totp_secret_enc = get_cipher().encrypt(secret.encode(), f"users.totp_secret_enc:{user.id}")
                user.totp_confirmed_at = datetime.now(UTC)
            await s.commit()
            return TestUser(user.id, email, password, secret)

    return make


async def login(client, user: TestUser, offset: int = 0):
    r = await client.post("/api/auth/login", json={"email": user.email, "password": user.password,
                                                   "totp_code": user.code(offset)})
    assert r.status_code == 200, r.text
    return {"x-csrf-token": client.cookies["sp_csrf"]}
