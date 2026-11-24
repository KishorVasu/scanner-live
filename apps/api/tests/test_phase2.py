"""Phase 2: registry, GitHub App (mocked), webhooks, local agents, Project Discovery.

GitHub is never contacted: every call goes to an httpx.MockTransport. No external repository is touched.
"""

import base64
import hashlib
import hmac
import json
import random
import time
import uuid


import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select, text

from app.core.config import get_settings
from app.db.models import AgentRunStatus, AuditLog
from app.db.registry import (
    DependencyInventory,
    GithubInstallation,
    GithubInstallationRepo,
    LocalAgent,
    Project,
    ProjectComponent,
    Repository,
    RepositoryEvent,
    RepoSource,
    ComponentKind,
    Criticality,
    ProjectStatus,
)
from app.integrations import github as gh_mod
from app.integrations.github import GitHubClient, app_jwt
from app.modules.github import router as gh_router
from tests.conftest import login

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PEM = RSA_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
WEBHOOK_SECRET = b"test-webhook-secret-not-real"


def rid() -> int:
    return random.randint(10**8, 10**9)


def b64(s: str | bytes) -> str:
    return base64.b64encode(s.encode() if isinstance(s, str) else s).decode()


# ---------------- fixtures ----------------

class FakeGitHub:
    """Records every request; serves one installation and its repositories."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.permissions = {"contents": "read", "metadata": "read"}
        self.installation_id = rid()
        self.repos: dict[int, dict] = {}

    def add_repo(self, files: dict[str, bytes]) -> int:
        repo_id = rid()
        self.repos[repo_id] = {"full_name": f"fixture-org/repo-{repo_id}", "files": files}
        return repo_id

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        p = req.url.path
        if p == f"/app/installations/{self.installation_id}":
            return httpx.Response(200, json={"id": self.installation_id, "permissions": self.permissions,
                                             "account": {"login": "fixture-org", "type": "Organization"}})
        if p.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "ghs_" + "T" * 36})
        if p == "/installation/repositories":
            return httpx.Response(200, json={"repositories": [
                {"id": i, "full_name": r["full_name"], "private": True} for i, r in self.repos.items()]})
        for repo_id, r in self.repos.items():
            base = f"/repositories/{repo_id}"
            if p == base:
                return httpx.Response(200, json={"full_name": r["full_name"], "default_branch": "main", "private": True})
            if p == f"{base}/git/trees/main":
                return httpx.Response(200, json={"sha": "a" * 40, "truncated": False,
                                                 "tree": [{"path": f, "type": "blob"} for f in r["files"]]})
            if p.startswith(f"{base}/contents/"):
                path = p.removeprefix(f"{base}/contents/")
                content = r["files"].get(path)
                if content is None:
                    return httpx.Response(404, json={})
                return httpx.Response(200, json={"type": "file", "size": len(content), "encoding": "base64",
                                                 "content": base64.b64encode(content).decode()})
        return httpx.Response(404, json={"message": "not mocked"})


@pytest.fixture
def github(tmp_path, monkeypatch):
    s = get_settings()
    key_file, secret_file = tmp_path / "app.pem", tmp_path / "hook.secret"
    key_file.write_bytes(RSA_PEM)
    secret_file.write_bytes(WEBHOOK_SECRET)
    for k, v in {"github_app_id": 4242, "github_app_slug": "fixture-app", "github_private_key_file": key_file,
                 "github_webhook_secret_file": secret_file}.items():
        monkeypatch.setattr(s, k, v)
    fake = FakeGitHub()
    client = GitHubClient(4242, RSA_PEM, httpx.AsyncClient(base_url="https://api.github.test",
                                                           transport=httpx.MockTransport(fake.handler)))
    monkeypatch.setattr(gh_mod, "_client_override", client)
    return fake


@pytest.fixture
async def component(owner_db):
    p = Project(name="Fixture", slug=f"fx-{uuid.uuid4().hex[:8]}", criticality=Criticality.low, status=ProjectStatus.active)
    owner_db.add(p)
    await owner_db.flush()
    c = ProjectComponent(project_id=p.id, kind=ComponentKind.web, name="web")
    owner_db.add(c)
    await owner_db.commit()
    return c


async def _installation(db, fake: FakeGitHub, repo_id: int, read_only=True) -> GithubInstallation:
    inst = GithubInstallation(installation_id=fake.installation_id, account_login="fixture-org",
                              account_type="Organization", permissions=fake.permissions, read_only=read_only)
    db.add(inst)
    await db.flush()
    db.add(GithubInstallationRepo(installation_ref=inst.id, github_repo_id=repo_id,
                                  full_name=fake.repos.get(repo_id, {}).get("full_name", "fixture-org/x")))
    await db.commit()
    return inst


async def _github_repo(db, fake, component, files, read_only=True) -> Repository:
    repo_id = fake.add_repo(files)
    await _installation(db, fake, repo_id, read_only)
    repo = Repository(component_id=component.id, source=RepoSource.github, github_repo_id=repo_id,
                      full_name=fake.repos[repo_id]["full_name"], default_branch="main")
    db.add(repo)
    await db.commit()
    return repo


# ---------------- registry ----------------

async def test_registry_crud_and_rbac(client, make_user):
    admin, viewer = await make_user("admin"), await make_user("viewer")
    csrf = await login(client, admin)
    slug = f"p-{uuid.uuid4().hex[:6]}"
    r = await client.post("/api/projects", headers=csrf, json={"name": "Pilot", "slug": slug, "criticality": "high"})
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    assert r.json()["scan_policy"]["daily_deps"] is True
    assert (await client.post("/api/projects", headers=csrf, json={"name": "x", "slug": slug})).status_code == 409
    assert (await client.post("/api/projects", headers=csrf, json={"name": "x", "slug": "Bad Slug"})).status_code == 422
    r = await client.post(f"/api/projects/{pid}/components", headers=csrf, json={"kind": "api", "name": "backend"})
    assert r.status_code == 201
    detail = (await client.get(f"/api/projects/{pid}")).json()
    assert detail["components"][0]["name"] == "backend" and detail["components"][0]["repositories"] == []

    client.cookies.clear()
    csrf = await login(client, viewer)
    assert (await client.get("/api/projects")).status_code == 200
    assert (await client.post("/api/projects", headers=csrf, json={"name": "x", "slug": "x1"})).status_code == 403
    assert (await client.patch(f"/api/projects/{pid}", headers=csrf, json={"status": "archived"})).status_code == 403


async def test_repository_link_validation(client, make_user, owner_db, component, github):
    admin = await make_user("admin")
    csrf = await login(client, admin)
    url = f"/api/components/{component.id}/repositories"
    unknown = await client.post(url, headers=csrf, json={"source": "github", "github_repo_id": rid()})
    assert unknown.status_code == 422  # not visible to the App

    repo_id = github.add_repo({})
    await _installation(owner_db, github, repo_id, read_only=False)
    assert (await client.post(url, headers=csrf, json={"source": "github", "github_repo_id": repo_id})).status_code == 422
    await owner_db.execute(text("UPDATE github_installations SET read_only = true WHERE installation_id = :i")
                           .bindparams(i=github.installation_id))
    await owner_db.commit()
    ok = await client.post(url, headers=csrf, json={"source": "github", "github_repo_id": repo_id})
    assert ok.status_code == 201 and ok.json()["inventory_complete"] is None  # never inventoried = not scanned
    assert (await client.post(url, headers=csrf, json={"source": "github", "github_repo_id": repo_id})).status_code == 409

    agent = LocalAgent(name="dev-box", approved_roots={"roots": [{"alias": "web", "path": "/srv/web"}]})
    owner_db.add(agent)
    await owner_db.commit()
    bad = await client.post(url, headers=csrf, json={"source": "local", "local_agent_id": str(agent.id), "local_path_alias": "nope"})
    assert bad.status_code == 422
    good = await client.post(url, headers=csrf, json={"source": "local", "local_agent_id": str(agent.id), "local_path_alias": "web"})
    assert good.status_code == 201


# ---------------- GitHub App ----------------

def test_app_jwt_is_valid_rs256():
    token = app_jwt(4242, RSA_PEM, now=1_700_000_000)
    header, payload, sig = token.split(".")
    pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
    RSA_KEY.public_key().verify(pad(sig), f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    claims = json.loads(pad(payload))
    assert claims["iss"] == "4242" and claims["exp"] - claims["iat"] <= 600


def test_install_state_binding():
    user, other = uuid.uuid4(), uuid.uuid4()
    state = gh_router.make_state(user)
    assert gh_router.check_state(state, user)
    assert not gh_router.check_state(state, other)
    assert not gh_router.check_state(state[:-1] + ("0" if state[-1] != "0" else "1"), user)
    assert not gh_router.check_state(gh_router.make_state(user, now=time.time() - 7200), user)
    assert not gh_router.check_state("garbage", user)


async def test_install_refuses_write_permissions(client, make_user, github, owner_db):
    admin = await make_user("admin")
    csrf = await login(client, admin)
    assert (await client.get("/api/github/install")).json()["url"].startswith("https://github.com/apps/fixture-app/")
    github.add_repo({})
    github.permissions = {"contents": "write", "metadata": "read"}
    state = gh_router.make_state(admin.id)
    r = await client.post("/api/github/installations", headers=csrf,
                          json={"installation_id": github.installation_id, "state": state})
    assert r.status_code == 422
    assert not any(q.url.path.endswith("/access_tokens") for q in github.requests)  # no token ever minted

    github.permissions = {"contents": "read", "metadata": "read", "pull_requests": "read"}
    r = await client.post("/api/github/installations", headers=csrf,
                          json={"installation_id": github.installation_id, "state": state})
    assert r.status_code == 201 and r.json()["read_only"] is True
    listed = (await client.get("/api/github/installations")).json()
    assert any(i["installation_id"] == github.installation_id and len(i["repositories"]) == 1 for i in listed)
    bad_state = await client.post("/api/github/installations", headers=csrf,
                                  json={"installation_id": github.installation_id, "state": gh_router.make_state(uuid.uuid4())})
    assert bad_state.status_code == 400


async def test_github_not_configured_returns_503(client, make_user):
    admin = await make_user("admin")
    await login(client, admin)
    assert (await client.get("/api/github/install")).status_code == 503
    assert (await client.post("/api/webhooks/github", content=b"{}")).status_code == 503


# ---------------- webhooks ----------------

async def hook(client, event: str, payload: dict, delivery: str | None = None, secret: bytes = WEBHOOK_SECRET, sign=True):
    body = json.dumps(payload).encode()
    headers = {"x-github-event": event, "x-github-delivery": delivery or uuid.uuid4().hex}
    if sign:
        headers["x-hub-signature-256"] = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return await client.post("/api/webhooks/github", content=body, headers=headers)


async def test_webhook_signature_and_idempotency(client, github):
    assert (await hook(client, "ping", {}, sign=False)).status_code == 401
    assert (await hook(client, "ping", {}, secret=b"wrong")).status_code == 401
    r = await hook(client, "ping", {}, delivery="d-" + uuid.uuid4().hex)
    assert r.status_code == 202 and r.json()["status"] == "ok"
    d = "d-" + uuid.uuid4().hex
    assert (await hook(client, "ping", {}, delivery=d)).json()["status"] == "ok"
    assert (await hook(client, "ping", {}, delivery=d)).json()["status"] == "duplicate"


async def test_webhook_rate_limit_per_repo(client, github, monkeypatch):
    monkeypatch.setattr(get_settings(), "webhook_repo_limit_per_minute", 2)
    payload = {"repository": {"id": rid()}}
    statuses = [(await hook(client, "ping", payload)).json()["status"] for _ in range(4)]
    assert statuses == ["ok", "ok", "rate_limited", "rate_limited"]


async def test_push_events_force_push_rewrite_and_discovery(client, github, owner_db, component, monkeypatch):
    queued = []
    monkeypatch.setattr(gh_router, "enqueue_discovery", lambda repo_id: queued.append(repo_id) or True)
    integrity = []
    monkeypatch.setattr(gh_router, "enqueue_agent", lambda name, args: integrity.append((name, args)) or True)
    repo = await _github_repo(owner_db, github, component, {})
    base = {"repository": {"id": repo.github_repo_id, "default_branch": "main"}, "ref": "refs/heads/main",
            "pusher": {"name": "dev"}}
    c1 = "1" * 40
    await hook(client, "push", {**base, "before": "0" * 40, "after": c1,
                                "commits": [{"message": "SECRET-COMMIT-MESSAGE", "modified": ["README.md"]}]})
    assert queued == []  # no manifest changed
    await hook(client, "push", {**base, "before": "9" * 40, "after": "2" * 40, "commits": [{"modified": ["web/package.json"]}]})
    await hook(client, "push", {**base, "forced": True, "before": "2" * 40, "after": "3" * 40, "commits": []})
    kinds = [e.kind.value for e in await owner_db.scalars(
        select(RepositoryEvent).where(RepositoryEvent.repository_id == repo.id).order_by(RepositoryEvent.created_at))]
    assert kinds == ["history_rewrite", "force_push"]
    assert queued == [repo.id, repo.id]  # manifest change, then forced push
    assert [(n, a["paths"]) for n, a in integrity] == [("repository_integrity", ["web/package.json"])]
    audit = await owner_db.scalars(select(AuditLog.detail).where(AuditLog.action == "webhook.push"))
    events = await owner_db.scalars(select(RepositoryEvent.detail).where(RepositoryEvent.repository_id == repo.id))
    assert "SECRET-COMMIT-MESSAGE" not in json.dumps(list(audit)) + json.dumps(list(events))


async def test_installation_event_rechecks_read_only(client, github, owner_db):
    inst_id = rid()
    r = await hook(client, "installation", {"action": "new_permissions_accepted", "installation": {
        "id": inst_id, "permissions": {"contents": "write"}, "account": {"login": "o", "type": "Organization"}}})
    assert r.json()["status"] == "processed_not_read_only"
    row = await owner_db.scalar(select(GithubInstallation).where(GithubInstallation.installation_id == inst_id))
    assert row.read_only is False


# ---------------- local agents ----------------

async def _agent_with_code(client, make_user, roots=None):
    admin = await make_user("admin")
    csrf = await login(client, admin)
    r = await client.post("/api/agents", headers=csrf, json={
        "name": "dev-box", "approved_roots": roots or [{"alias": "web", "path": "/srv/web"}]})
    assert r.status_code == 201, r.text
    client.cookies.clear()
    return r.json(), admin


async def _register(client, code):
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    r = await client.post("/api/agents/register", json={"code": code, "public_key": b64(raw), "os": "Linux"})
    return key, r


async def _token(client, key, agent_id) -> str:
    nonce = (await client.post("/api/agents/challenge", json={"agent_id": agent_id})).json()["nonce"]
    sig = key.sign(b"sp-agent-session:" + nonce.encode() + b":" + agent_id.encode())
    r = await client.post("/api/agents/session", json={"agent_id": agent_id, "nonce": nonce, "signature": b64(sig)})
    assert r.status_code == 200, r.text
    return r.json()["token"]


async def test_enrolment_code_single_use_and_expiry(client, make_user, owner_db):
    created, _ = await _agent_with_code(client, make_user)
    _, r = await _register(client, created["enrolment_code"])
    assert r.status_code == 200 and r.json()["agent_id"] == created["id"]
    _, again = await _register(client, created["enrolment_code"])
    assert again.status_code == 401

    created2, _ = await _agent_with_code(client, make_user)
    await owner_db.execute(text("UPDATE agent_enrolment_codes SET expires_at = now() - interval '1 minute' "
                                "WHERE local_agent_id = :a").bindparams(a=uuid.UUID(created2["id"])))
    await owner_db.commit()
    _, expired = await _register(client, created2["enrolment_code"])
    assert expired.status_code == 401


async def test_challenge_signature_replay_and_revocation(client, make_user):
    created, admin = await _agent_with_code(client, make_user)
    key, _ = await _register(client, created["enrolment_code"])
    aid = created["id"]

    nonce = (await client.post("/api/agents/challenge", json={"agent_id": aid})).json()["nonce"]
    wrong = Ed25519PrivateKey.generate().sign(b"sp-agent-session:" + nonce.encode() + b":" + aid.encode())
    assert (await client.post("/api/agents/session", json={"agent_id": aid, "nonce": nonce, "signature": b64(wrong)})).status_code == 401
    good = key.sign(b"sp-agent-session:" + nonce.encode() + b":" + aid.encode())
    replay = await client.post("/api/agents/session", json={"agent_id": aid, "nonce": nonce, "signature": b64(good)})
    assert replay.status_code == 401  # the nonce was consumed by the failed attempt

    token = await _token(client, key, aid)
    auth = {"Authorization": f"Bearer {token}"}
    cfg = await client.get("/api/agents/me/config", headers=auth)
    assert cfg.status_code == 200 and cfg.json()["approved_roots"][0]["alias"] == "web"

    csrf = await login(client, admin, offset=1)
    assert (await client.post(f"/api/agents/{aid}/revoke", headers=csrf)).status_code == 200
    client.cookies.clear()
    assert (await client.get("/api/agents/me/config", headers=auth)).status_code == 401  # instant
    assert (await client.post("/api/agents/challenge", json={"agent_id": aid})).status_code == 401


def _inventory(alias="web", deps=1):
    return {"alias": alias, "manifest_hash": "b" * 64, "tree_hash": "c" * 64, "complete": True,
            "profiles": [{"ecosystem": "npm", "directory": ".", "package_manager": "npm", "framework": "nextjs"}],
            "dependencies": [{"ecosystem": "npm", "package": f"pkg{i}", "version": "1.0.0", "direct": True}
                             for i in range(deps)],
            "coverage": [{"path": "package-lock.json", "status": "parsed", "entries": deps}]}


async def test_inventory_upload_rules(client, make_user, owner_db, component):
    created, _ = await _agent_with_code(client, make_user, roots=[{"alias": "web", "path": "/srv/web"},
                                                                  {"alias": "unmapped", "path": "/srv/x"}])
    key, _ = await _register(client, created["enrolment_code"])
    auth = {"Authorization": f"Bearer {await _token(client, key, created['id'])}"}

    assert (await client.post("/api/agents/me/inventory", headers=auth, json=_inventory("secret-dir"))).status_code == 403
    assert (await client.post("/api/agents/me/inventory", headers=auth, json=_inventory("unmapped"))).status_code == 404
    repo = Repository(component_id=component.id, source=RepoSource.local, local_agent_id=uuid.UUID(created["id"]),
                      local_path_alias="web")
    owner_db.add(repo)
    await owner_db.commit()
    assert (await client.post("/api/agents/me/inventory", headers=auth, json=_inventory(deps=3))).status_code == 200
    assert (await client.post("/api/agents/me/inventory", headers=auth, json=_inventory(deps=2))).status_code == 200
    count = await owner_db.scalar(select(func.count()).select_from(DependencyInventory)
                                  .where(DependencyInventory.repository_id == repo.id))
    assert count == 2  # replaced, not appended
    assert (await client.post("/api/agents/me/log", headers=auth, json={"events": [
        {"action": "scan", "outcome": "uploaded", "detail": {"alias": "web"}}]})).json() == {"accepted": 1}
    assert (await client.get("/api/agents/me/config")).status_code == 401  # no token, no access


# ---------------- Project Discovery ----------------

FILES = {
    "web/package.json": json.dumps({"dependencies": {"next": "^15.0.0"}}).encode(),
    "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "": {}, "node_modules/next": {"version": "15.0.3"}}}).encode(),
    ".env": b"DB_PASSWORD=fixture",
    "certs/server.key": b"fixture",
    "src/app.ts": b"export {}",
}


async def test_discovery_end_to_end(github, owner_db, app_db, component):
    from app.agents.discovery import run_discovery

    repo = await _github_repo(owner_db, github, component, dict(FILES))
    run = await run_discovery(app_db, repo.id)
    assert run.status == AgentRunStatus.succeeded, run.error

    token_bodies = [json.loads(q.content) for q in github.requests if q.url.path.endswith("/access_tokens")]
    assert token_bodies and all(b == {"permissions": {"contents": "read", "metadata": "read"},
                                      "repository_ids": [repo.github_repo_id]} for b in token_bodies)
    fetched = [q.url.path for q in github.requests if "/contents/" in q.url.path]
    assert sorted(p.split("/contents/")[1] for p in fetched) == ["web/package-lock.json", "web/package.json"]
    assert all(q.method == "GET" or q.url.path.endswith("/access_tokens") for q in github.requests)  # read only

    stored = await owner_db.scalar(select(Repository).where(Repository.id == repo.id).execution_options(populate_existing=True))
    assert stored.inventory_complete is True and stored.tree_hash == "a" * 40 and stored.last_inventory_at
    deps = list(await owner_db.scalars(select(DependencyInventory).where(DependencyInventory.repository_id == repo.id)))
    assert [(d.package, d.version, d.direct) for d in deps] == [("next", "15.0.3", True)]
    calls = await owner_db.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.actor_id == str(run.id), AuditLog.action == "gateway.tool_call", AuditLog.outcome == "allowed"))
    assert calls == 3


async def test_discovery_refuses_non_read_only_installation(github, owner_db, app_db, component):
    from app.agents.discovery import run_discovery

    repo = await _github_repo(owner_db, github, component, dict(FILES), read_only=False)
    run = await run_discovery(app_db, repo.id)
    assert run.status == AgentRunStatus.failed and "read-only" in run.error
    assert not any(q.url.path.endswith("/access_tokens") for q in github.requests)


async def test_read_manifest_tool_refuses_secret_paths(github, owner_db, app_db, component):
    from app.agents.discovery import FileArgs, ToolError, read_manifest
    from app.agents.registry import ToolContext

    repo = await _github_repo(owner_db, github, component, dict(FILES))
    for path in (".env", "certs/server.key", "src/app.ts"):
        with pytest.raises(ToolError):
            await read_manifest(ToolContext(session=app_db, run_id=None), FileArgs(repository_id=repo.id, ref="main", path=path))
    assert not any("/contents/" in q.url.path for q in github.requests)


async def test_phase2_grants(owner_db):
    def priv(table, p):
        return text("SELECT has_table_privilege('platform_app', :t, :p)").bindparams(t=table, p=p)

    assert not await owner_db.scalar(priv("repository_events", "UPDATE"))
    assert not await owner_db.scalar(priv("repository_events", "DELETE"))
    assert not await owner_db.scalar(priv("projects", "DELETE"))
    assert await owner_db.scalar(priv("dependency_inventory", "DELETE"))
    assert await owner_db.scalar(text("SELECT count(*) FROM policies WHERE action = 'store_inventory' AND tier = 'allowed'")) == 1


