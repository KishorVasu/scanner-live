"""T-R9: self-approval, expiry, single use, scope binding, backend enforcement."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.db.models import Approval, ApprovalStatus, Policy, PolicyTier
from app.modules.approvals import service
from tests.conftest import login


@pytest.fixture
async def approvable(owner_db):
    action = f"risky_{uuid.uuid4().hex[:8]}"
    owner_db.add(Policy(action=action, tier=PolicyTier.approval_required, description="test"))
    await owner_db.commit()
    return action


async def test_request_and_decide_via_api(client, make_user, approvable):
    dev, approver = await make_user("developer"), await make_user("approver")
    csrf = await login(client, dev)
    r = await client.post("/api/approvals", headers=csrf,
                          json={"action": approvable, "scope": {"repo": "r1"}, "reason": "need it"})
    assert r.status_code == 201
    approval_id = r.json()["id"]
    # developer lacks approvals:decide
    assert (await client.post(f"/api/approvals/{approval_id}/decision", headers=csrf,
                              json={"totp_code": dev.code(1), "approve": True})).status_code == 403

    client.cookies.clear()
    csrf = await login(client, approver)
    bad = await client.post(f"/api/approvals/{approval_id}/decision", headers=csrf,
                            json={"totp_code": "000000", "approve": True})
    assert bad.status_code == 401  # re-authentication required
    ok = await client.post(f"/api/approvals/{approval_id}/decision", headers=csrf,
                           json={"totp_code": approver.code(1), "approve": True})
    assert ok.status_code == 200 and ok.json()["status"] == "approved"


async def test_self_approval_blocked_api(client, make_user, approvable):
    approver = await make_user("approver")
    csrf = await login(client, approver)
    r = await client.post("/api/approvals", headers=csrf, json={"action": approvable, "scope": {}, "reason": "x"})
    d = await client.post(f"/api/approvals/{r.json()['id']}/decision", headers=csrf,
                          json={"totp_code": approver.code(1), "approve": True})
    assert d.status_code == 409 and "own request" in d.json()["detail"]


async def test_self_approval_blocked_by_db(owner_db, make_user):
    u = await make_user("approver")
    a = service.create(owner_db, action="x", scope={}, reason="r", risks="", requested_by=u.id)
    a.approver_id = u.id
    with pytest.raises(IntegrityError):
        await owner_db.commit()
    await owner_db.rollback()


async def test_forbidden_or_unknown_actions_not_approvable(client, make_user):
    dev = await make_user("developer")
    csrf = await login(client, dev)
    for action in ("deploy", "not_a_policy"):
        r = await client.post("/api/approvals", headers=csrf, json={"action": action, "scope": {}, "reason": "x"})
        assert r.status_code == 422


async def _approved(db, requester, approver, action, scope, expires_in=timedelta(hours=1)) -> Approval:
    a = service.create(db, action=action, scope=scope, reason="r", risks="", requested_by=requester.id)
    await db.flush()
    await service.decide(db, a.id, approver.id, True)
    a.expires_at = datetime.now(UTC) + expires_in
    await db.commit()
    return a


async def test_consume_once_scope_bound_and_expiry(owner_db, make_user):
    dev, appr = await make_user("developer"), await make_user("approver")
    action = f"op_{uuid.uuid4().hex[:6]}"
    await _approved(owner_db, dev, appr, action, {"repo": "a"})
    assert await service.consume(owner_db, action, {"repo": "b"}) is None  # different scope
    assert await service.consume(owner_db, action, {"repo": "a"}) is not None
    assert await service.consume(owner_db, action, {"repo": "a"}) is None  # single use
    await owner_db.commit()

    await _approved(owner_db, dev, appr, action, {"repo": "c"}, expires_in=timedelta(seconds=-1))
    assert await service.consume(owner_db, action, {"repo": "c"}) is None  # expired
    assert await service.expire_stale(owner_db) >= 1
    await owner_db.commit()


async def test_expired_pending_cannot_be_decided(owner_db, make_user):
    dev, appr = await make_user("developer"), await make_user("approver")
    a = service.create(owner_db, action="x", scope={}, reason="r", risks="", requested_by=dev.id)
    a.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await owner_db.commit()
    with pytest.raises(service.ApprovalError, match="expired"):
        await service.decide(owner_db, a.id, appr.id, True)
    await owner_db.commit()
    status = await owner_db.scalar(text("SELECT status FROM approvals WHERE id = :id").bindparams(id=a.id))
    assert status == ApprovalStatus.expired.value
