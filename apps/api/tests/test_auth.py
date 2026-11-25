import uuid
import pyotp
from sqlalchemy import select

from app.db.models import AuditLog
from tests.conftest import login


async def test_login_requires_password_and_totp(client, make_user):
    u = await make_user("viewer")
    r = await client.post("/api/auth/login", json={"email": u.email, "password": u.password})
    assert r.status_code == 401
    r = await client.post("/api/auth/login", json={"email": u.email, "password": "wrong-password", "totp_code": u.code()})
    assert r.status_code == 401
    await login(client, u)
    me = (await client.get("/api/auth/me")).json()
    assert me["email"] == u.email and me["roles"] == ["viewer"]


async def test_totp_code_cannot_be_replayed(client, make_user):
    u = await make_user("viewer")
    await login(client, u)
    client.cookies.clear()
    r = await client.post("/api/auth/login", json={"email": u.email, "password": u.password, "totp_code": u.code()})
    assert r.status_code == 401


async def test_unknown_user_same_error(client):
    r = await client.post("/api/auth/login", json={"email": "nobody@example.test", "password": "x" * 12, "totp_code": "123456"})
    assert r.status_code == 401 and r.json()["detail"] == "invalid credentials"


async def test_rate_limit(client, make_user):
    u = await make_user("viewer")
    for _ in range(5):
        r = await client.post("/api/auth/login", json={"email": u.email, "password": "wrong-password"})
        assert r.status_code == 401
    r = await client.post("/api/auth/login", json={"email": u.email, "password": u.password, "totp_code": u.code()})
    assert r.status_code == 429


async def test_rate_limit_per_ip_stops_password_spraying(client, make_user, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "login_max_failures_per_ip", 3)
    ip = {"x-forwarded-for": f"198.51.100.{uuid.uuid4().int % 250 + 1}"}
    for _ in range(3):  # one try each on different emails: the per-email limit never triggers
        r = await client.post("/api/auth/login", headers=ip,
                              json={"email": f"spray-{uuid.uuid4().hex[:8]}@example.test", "password": "x" * 12})
        assert r.status_code == 401
    u = await make_user("viewer")
    r = await client.post("/api/auth/login", headers=ip, json={"email": u.email, "password": u.password, "totp_code": u.code()})
    assert r.status_code == 429


async def test_first_login_enrols_totp(client, make_user):
    u = await make_user("viewer", enrolled=False)
    r = await client.post("/api/auth/login", json={"email": u.email, "password": u.password})
    assert r.json() == {"status": "totp_setup_required"}
    # setup session cannot reach normal endpoints
    assert (await client.get("/api/auth/me")).status_code == 401
    csrf = {"x-csrf-token": client.cookies["sp_csrf"]}
    assert (await client.post("/api/auth/totp/setup")).status_code == 403  # CSRF enforced
    uri = (await client.post("/api/auth/totp/setup", headers=csrf)).json()["otpauth_uri"]
    secret = pyotp.parse_uri(uri).secret
    bad = await client.post("/api/auth/totp/confirm", headers=csrf, json={"code": "000000"})
    assert bad.status_code == 401
    ok = await client.post("/api/auth/totp/confirm", headers=csrf, json={"code": pyotp.TOTP(secret).now()})
    assert ok.status_code == 200
    assert (await client.get("/api/auth/me")).status_code == 200


async def test_csrf_and_logout(client, make_user):
    u = await make_user("viewer")
    csrf = await login(client, u)
    assert (await client.post("/api/auth/logout")).status_code == 403
    assert (await client.post("/api/auth/logout", headers={"x-csrf-token": "forged"})).status_code == 403
    assert (await client.post("/api/auth/logout", headers=csrf)).status_code == 200
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_login_audited_without_password(client, make_user, owner_db):
    u = await make_user("viewer")
    await client.post("/api/auth/login", json={"email": u.email, "password": "wrong-password-xyz"})
    rows = list(await owner_db.scalars(select(AuditLog).where(AuditLog.target_id == u.email)))
    assert rows and rows[-1].outcome == "failure"
    assert "wrong-password-xyz" not in str([r.detail for r in rows])
