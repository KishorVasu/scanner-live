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


async def test_session_signature_guessing_is_limited(client, make_user):
    aid, key = await _registered_agent(client, make_user)
    limit = get_settings().agent_session_failures
    wrong = Ed25519PrivateKey.generate()
    for _ in range(limit):
        nonce = (await client.post("/api/agents/challenge", json={"agent_id": aid})).json()["nonce"]
        sig = base64.b64encode(wrong.sign(b"sp-agent-session:" + nonce.encode() + b":" + aid.encode())).decode()
        r = await client.post("/api/agents/session", headers=ip_header(),
                              json={"agent_id": aid, "nonce": nonce, "signature": sig})
        assert r.status_code == 401
    nonce = (await client.post("/api/agents/challenge", json={"agent_id": aid})).json()["nonce"]
    good = base64.b64encode(key.sign(b"sp-agent-session:" + nonce.encode() + b":" + aid.encode())).decode()
    r = await client.post("/api/agents/session", headers=ip_header(), json={"agent_id": aid, "nonce": nonce, "signature": good})
    assert r.status_code == 429  # even the right key waits out the window once the agent is under attack


@pytest.mark.parametrize("endpoint", ["/api/agents/challenge", "/api/agents/session"])
async def test_unknown_agents_write_nothing(client, endpoint):
    body = {"agent_id": str(uuid.uuid4())}
    if endpoint.endswith("session"):
        body |= {"nonce": "n", "signature": "s"}
    assert (await client.post(endpoint, headers=ip_header(), json=body)).status_code == 401
