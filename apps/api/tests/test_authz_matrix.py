"""Every API route against every role (Phase 6 permission test).

GUARDS is the reviewed access table. Adding, removing or re-guarding a route fails test_every_route_is_in_the_table
until the table is updated, so a new route can never ship without a deliberate access decision.
"""

import uuid

import pytest
from fastapi.routing import APIRoute

from app.main import app
from app.modules.rbac.catalog import ROLE_PERMISSIONS
from tests.conftest import login

PUBLIC = "public"  # no session; each handler authenticates its own way (signature, enrolment code, challenge) or is health
AGENT = "agent"  # local-agent session token
SETUP = "setup"  # TOTP-setup session scope
SESSION = "session"  # any signed-in user

GUARDS: dict[tuple[str, str], str] = {
    ("POST", "/api/auth/login"): PUBLIC,
    ("POST", "/api/auth/totp/setup"): SETUP,
    ("POST", "/api/auth/totp/confirm"): SETUP,
    ("POST", "/api/auth/logout"): SESSION,
    ("GET", "/api/auth/me"): SESSION,
    ("GET", "/api/users"): "users:manage",
    ("POST", "/api/users"): "users:manage",
    ("PUT", "/api/users/{user_id}/roles"): "users:manage",
    ("POST", "/api/users/{user_id}/deactivate"): "users:manage",
    ("POST", "/api/approvals"): "approvals:request",
    ("GET", "/api/approvals"): "dashboard:view",
    ("POST", "/api/approvals/{approval_id}/decision"): "approvals:decide",
    ("GET", "/api/audit"): "audit:view",
    ("GET", "/api/projects"): "dashboard:view",
    ("POST", "/api/projects"): "projects:manage",
    ("GET", "/api/projects/{project_id}"): "dashboard:view",
    ("PATCH", "/api/projects/{project_id}"): "projects:manage",
    ("PUT", "/api/projects/{project_id}/scan-policy"): "projects:manage",
    ("POST", "/api/projects/{project_id}/components"): "projects:manage",
    ("POST", "/api/components/{component_id}/repositories"): "projects:manage",
    ("POST", "/api/repositories/{repository_id}/discover"): "scans:trigger",
    ("GET", "/api/repositories/{repository_id}"): "dashboard:view",
    ("GET", "/api/github/install"): "github:manage",
    ("POST", "/api/github/installations"): "github:manage",
    ("GET", "/api/github/installations"): "github:manage",
    ("POST", "/api/webhooks/github"): PUBLIC,
    ("GET", "/api/agents"): "agents:manage",
    ("POST", "/api/agents"): "agents:manage",
    ("PUT", "/api/agents/{agent_id}/roots"): "agents:manage",
    ("POST", "/api/agents/{agent_id}/revoke"): "agents:manage",
    ("POST", "/api/agents/register"): PUBLIC,
    ("POST", "/api/agents/challenge"): PUBLIC,
    ("POST", "/api/agents/session"): PUBLIC,
    ("GET", "/api/agents/me/config"): AGENT,
    ("POST", "/api/agents/me/inventory"): AGENT,
    ("POST", "/api/agents/me/log"): AGENT,
    ("GET", "/api/findings"): "dashboard:view",
    ("GET", "/api/findings/{finding_id}"): "dashboard:view",
    ("PATCH", "/api/findings/{finding_id}"): "findings:triage",
    ("GET", "/api/impacts/matrix"): "dashboard:view",
    ("GET", "/api/impacts"): "dashboard:view",
    ("GET", "/api/overview"): "dashboard:view",
    ("GET", "/api/scans"): "dashboard:view",
    ("GET", "/api/integrity/events"): "dashboard:view",
    ("POST", "/api/reports"): "scans:trigger",
    ("GET", "/api/reports"): "dashboard:view",
    ("GET", "/api/reports/{report_id}"): "dashboard:view",
    ("GET", "/api/reports/{report_id}/pdf"): "dashboard:view",
    ("POST", "/api/reports/{report_id}/approve"): "reports:approve",
    ("GET", "/api/health"): PUBLIC,
    ("GET", "/api/health/ready"): PUBLIC,
}


def _routes():
    def flat(rs):
        for r in rs:
            yield from flat(r.original_router.routes) if hasattr(r, "original_router") else [r]

    return [r for r in flat(app.routes) if isinstance(r, APIRoute)]


def _guard(route: APIRoute) -> str:
    found: set[str] = set()

    def walk(d):
        for sub in d.dependencies:
            name = getattr(sub.call, "__qualname__", "")
            if name == "require.<locals>.dep":
                found.add(sub.call.__closure__[0].cell_contents)
            elif name in ("current_principal", "setup_principal", "current_agent"):
                found.add({"current_principal": SESSION, "setup_principal": SETUP, "current_agent": AGENT}[name])
            walk(sub)

    walk(route.dependant)
    perms = found - {SESSION, SETUP, AGENT}
    assert len(perms) <= 1, (route.path, found)
    return perms.pop() if perms else (found.pop() if len(found) == 1 else PUBLIC if not found else str(sorted(found)))


def _url(path: str) -> str:
    return path.format(**{k: uuid.uuid4() for k in ("user_id", "approval_id", "project_id", "component_id",
                                                     "repository_id", "agent_id", "finding_id", "report_id")})


def test_every_route_is_in_the_table():
    actual = {(m, r.path): _guard(r) for r in _routes() for m in r.methods}
    assert actual == GUARDS


def test_catalog_permissions_exist():
    perms = {g for g in GUARDS.values() if ":" in g}
    assert perms <= {p for ps in ROLE_PERMISSIONS.values() for p in ps}


async def test_anonymous_gets_401_on_every_guarded_route(client):
    for (method, path), guard in GUARDS.items():
        if guard != PUBLIC:
            r = await client.request(method, _url(path))
            assert r.status_code == 401, (method, path, r.status_code)


@pytest.mark.parametrize("role", sorted(ROLE_PERMISSIONS))
async def test_role_matrix(client, make_user, role):
    csrf = await login(client, await make_user(role))
    granted = ROLE_PERMISSIONS[role]
    for (method, path), guard in GUARDS.items():
        if ":" not in guard:
            continue
        r = await client.request(method, _url(path), headers=csrf)
        if guard in granted:
            assert r.status_code not in (401, 403), (role, method, path, r.status_code, r.text)
        else:
            assert r.status_code == 403 and r.json()["detail"] == "permission denied", (role, method, path, r.status_code)
