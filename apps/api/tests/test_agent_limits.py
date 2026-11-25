"""Rate limits on the unauthenticated local-agent endpoints (Phase 2 review follow-up)."""

import asyncio
import base64
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.config import get_settings
from tests.conftest import login


def ip_header() -> dict:
    return {"x-forwarded-for": f"10.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}"}


def pubkey() -> str:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


async def _registered_agent(client, make_user):
    admin = await make_user("admin")
    csrf = await login(client, admin)
    created = (await client.post("/api/agents", headers=csrf, json={
        "name": "box", "approved_roots": [{"alias": "web", "path": "/srv/web"}]})).json()
    client.cookies.clear()
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    r = await client.post("/api/agents/register", headers=ip_header(),
                          json={"code": created["enrolment_code"], "public_key": base64.b64encode(raw).decode()})
    assert r.status_code == 200
    return created["id"], key


async def test_register_guessing_is_limited_per_ip(client):
    ip = ip_header()
    limit = get_settings().agent_register_failures_per_ip
    for _ in range(limit):
        r = await client.post("/api/agents/register", headers=ip, json={"code": "x" * 43, "public_key": pubkey()})
        assert r.status_code == 401
    assert (await client.post("/api/agents/register", headers=ip,
                              json={"code": "x" * 43, "public_key": pubkey()})).status_code == 429
    other = await client.post("/api/agents/register", headers=ip_header(), json={"code": "x" * 43, "public_key": pubkey()})
    assert other.status_code == 401  # a different client is not blocked


async def test_concurrent_register_burst_is_capped(client):
    ip = ip_header()
    limit = get_settings().agent_register_failures_per_ip

    async def attempt():
        return (await client.post("/api/agents/register", headers=ip,
                                  json={"code": "y" * 43, "public_key": pubkey()})).status_code

    codes = await asyncio.gather(*[attempt() for _ in range(limit + 5)])
    assert codes.count(401) == limit and codes.count(429) == 5, codes


async def test_challenge_flood_is_limited_per_agent(client, make_user):
    aid, _ = await _registered_agent(client, make_user)
    limit = get_settings().agent_challenges_per_minute
    codes = [(await client.post("/api/agents/challenge", headers=ip_header(), json={"agent_id": aid})).status_code
             for _ in range(limit + 2)]
    assert codes == [200] * limit + [429, 429]


async def test_session_failures_limit_the_attacker_ip_not_the_agent(client, make_user, monkeypatch):
    monkeypatch.setattr(get_settings(), "agent_session_failures_per_ip", 3)
    aid, key = await _registered_agent(client, make_user)
    wrong, attacker = Ed25519PrivateKey.generate(), ip_header()

    async def attempt(signer, headers):
        nonce = (await client.post("/api/agents/challenge", json={"agent_id": aid})).json()["nonce"]
        sig = base64.b64encode(signer.sign(b"sp-agent-session:" + nonce.encode() + b":" + aid.encode())).decode()
        return (await client.post("/api/agents/session", headers=headers,
                                  json={"agent_id": aid, "nonce": nonce, "signature": sig})).status_code

    assert [await attempt(wrong, attacker) for _ in range(4)] == [401, 401, 401, 429]
    assert await attempt(key, ip_header()) == 200  # the real agent, from its own address, is not locked out


@pytest.mark.parametrize("endpoint", ["/api/agents/challenge", "/api/agents/session"])
async def test_unknown_agents_write_nothing(client, endpoint):
    body = {"agent_id": str(uuid.uuid4())}
    if endpoint.endswith("session"):
        body |= {"nonce": "n", "signature": "s"}
    assert (await client.post(endpoint, headers=ip_header(), json=body)).status_code == 401
