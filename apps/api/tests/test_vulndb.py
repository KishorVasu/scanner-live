"""Offline vulnerability DB sync: the worker only names a DB, never a URL; every outcome is audited."""

import json

import httpx
from sqlalchemy import select

from app.db.models import AuditLog
from app.scanners import vulndb
from app.workers.celery_app import celery


async def _audit(owner_db):
    rows = await owner_db.scalars(select(AuditLog).where(AuditLog.action == "vulndb.sync")
                                  .order_by(AuditLog.at.desc()).limit(2))
    return {r.target_id: r for r in rows}


async def test_sync_asks_runner_for_each_db_and_audits(app_db, owner_db, monkeypatch):
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sent.append((request.url.path, body))
        if body["db"] == "osv":
            return httpx.Response(200, json={"ok": True, "exit_code": 0})
        return httpx.Response(200, json={"ok": False, "error": "download failed; previous DB kept"})

    monkeypatch.setattr(vulndb, "_transport", httpx.MockTransport(handler))
    assert await vulndb.sync_all(app_db) == {"osv": True, "trivy": False}
    assert sent == [("/sync", {"db": "osv"}), ("/sync", {"db": "trivy"})]
    rows = await _audit(owner_db)
    assert rows["osv"].outcome == "success" and rows["trivy"].outcome == "failure"
    assert rows["trivy"].detail == {"error": "download failed; previous DB kept"}


async def test_unreachable_runner_is_a_failure_not_a_crash(app_db, owner_db, monkeypatch):
    def handler(request):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(vulndb, "_transport", httpx.MockTransport(handler))
    assert await vulndb.sync_all(app_db) == {"osv": False, "trivy": False}
    assert {r.outcome for r in (await _audit(owner_db)).values()} == {"failure"}


def test_beat_runs_sync_before_daily_scans():
    beat = celery.conf.beat_schedule
    assert beat["vulndb-sync"]["task"] == "vulndb.sync"
    assert min(beat["vulndb-sync"]["schedule"].hour) < min(beat["daily-scans"]["schedule"].hour)
