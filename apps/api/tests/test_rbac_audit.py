"""RBAC matrix and append-only audit log (T-R10)."""

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.db.models import Role
from app.modules.rbac.catalog import ROLE_PERMISSIONS
from tests.conftest import login


async def test_db_seed_matches_catalog(owner_db):
    for role in await owner_db.scalars(select(Role)):
        assert {p.key for p in role.permissions} == ROLE_PERMISSIONS[role.name], role.name


@pytest.mark.parametrize(
    "role,method,path,expected",
    [
        ("viewer", "GET", "/api/audit", 403),
        ("developer", "GET", "/api/audit", 403),
        ("approver", "GET", "/api/audit", 200),
        ("admin", "GET", "/api/audit", 200),
        ("viewer", "GET", "/api/users", 403),
        ("approver", "GET", "/api/users", 403),
        ("admin", "GET", "/api/users", 200),
        ("viewer", "GET", "/api/approvals", 200),
    ],
)
async def test_endpoint_matrix(client, make_user, role, method, path, expected):
    u = await make_user(role)
    await login(client, u)
    assert (await client.request(method, path)).status_code == expected


async def test_admin_creates_user_and_action_is_audited(client, make_user, owner_db):
    admin = await make_user("admin")
    csrf = await login(client, admin)
    r = await client.post("/api/users", headers=csrf,
                          json={"email": "New.Person@Example.test", "password": "long-enough-pass", "roles": ["developer"]})
    assert r.status_code == 201 and r.json()["email"] == "new.person@example.test"
    bad = await client.post("/api/users", headers=csrf, json={"email": "a@b.c", "password": "long-enough-pass", "roles": ["root"]})
    assert bad.status_code == 422
    audit = (await client.get("/api/audit")).json()
    assert any(a["action"] == "users.create" and a["actor_id"] == str(admin.id) for a in audit)
    assert "long-enough-pass" not in str(audit)


@pytest.mark.parametrize("sql", ["UPDATE audit_logs SET outcome='x'", "DELETE FROM audit_logs", "TRUNCATE audit_logs"])
async def test_audit_log_append_only_for_app_role(app_db, sql):
    await app_db.execute(text("INSERT INTO audit_logs (actor_type, action, outcome) VALUES ('system','test','ok')"))
    await app_db.commit()
    with pytest.raises(DBAPIError):
        await app_db.execute(text(sql))
    await app_db.rollback()


async def test_audit_trigger_blocks_owner_too(owner_db):
    await owner_db.execute(text("INSERT INTO audit_logs (actor_type, action, outcome) VALUES ('system','test','ok')"))
    await owner_db.commit()
    with pytest.raises(DBAPIError, match="append-only"):
        await owner_db.execute(text("DELETE FROM audit_logs"))
    await owner_db.rollback()


@pytest.mark.parametrize("sql", [
    "UPDATE policies SET tier='allowed' WHERE action='deploy'",
    "DELETE FROM approvals",
    "DELETE FROM agent_runs",
    "INSERT INTO role_permissions SELECT r.id, p.id FROM roles r, permissions p WHERE r.name='viewer' LIMIT 1",
])
async def test_app_role_least_privilege(app_db, sql):
    with pytest.raises(DBAPIError):
        await app_db.execute(text(sql))
    await app_db.rollback()
