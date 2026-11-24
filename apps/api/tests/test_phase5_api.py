"""Phase 5 API: finding triage rules, finding detail, overview (not scanned vs scanned), scan history, integrity events.

All rows are synthetic fixtures.
"""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.db.models import AuditLog
from app.db.registry import (ComponentKind, Criticality, Project, ProjectComponent, ProjectStatus, Repository,
                             RepositoryEvent, RepoEventKind, RepoSource, Severity)
from app.db.scanning import (Confidence, FindingEvidence, FindingStatus, ScanJob, ScanStatus, ScanTrigger, Scanner,
                             SecurityFinding)
from tests.conftest import login

NOW = datetime.now(UTC)


@pytest.fixture
async def world(owner_db):
    p = Project(name=f"P5 {uuid.uuid4().hex[:6]}", slug=f"p5-{uuid.uuid4().hex[:8]}", criticality=Criticality.high,
                status=ProjectStatus.active)
    owner_db.add(p)
    await owner_db.flush()
    c = ProjectComponent(project_id=p.id, kind=ComponentKind.api, name="api")
    owner_db.add(c)
    await owner_db.flush()
    repos = []
    for _ in range(2):
        r = Repository(component_id=c.id, source=RepoSource.github, github_repo_id=uuid.uuid4().int % 10**12,
                       manifest_hash="m" * 64, tree_hash="t" * 40)
        owner_db.add(r)
        repos.append(r)
    await owner_db.flush()
    job = ScanJob(repository_id=repos[0].id, scanner=Scanner.osv_scanner, trigger=ScanTrigger.manual,
                  inventory_hash="h" * 64, status=ScanStatus.succeeded)
    owner_db.add(job)
    await owner_db.flush()
    findings = {}
    for st in (FindingStatus.open, FindingStatus.resolved):
        f = SecurityFinding(fingerprint=uuid.uuid4().hex * 2, project_id=p.id, repository_id=repos[0].id,
                            scanner=Scanner.osv_scanner, rule_id="GHSA-fixt-5555-aaaa", category="dependency",
                            title="fixture", severity=Severity.high, confidence=Confidence.high, status=st,
                            package="fixture-lib", package_version="1.0.0", first_seen_at=NOW, last_seen_at=NOW)
        owner_db.add(f)
        findings[st] = f
    await owner_db.flush()
    owner_db.add(FindingEvidence(finding_id=findings[FindingStatus.open].id, scan_job_id=job.id,
                                 evidence_redacted="fixture-lib@1.0.0 in package-lock.json", captured_at=NOW))
    owner_db.add(RepositoryEvent(repository_id=repos[1].id, kind=RepoEventKind.force_push, severity=Severity.high,
                                 ref="refs/heads/main", before_sha="a" * 40, after_sha="b" * 40, source="webhook"))
    await owner_db.commit()
    return p, repos, findings


async def as_role(client, make_user, role):
    return await login(client, await make_user(role))


async def test_reads_require_sign_in(client):
    for path in ("/api/overview", "/api/scans", "/api/integrity/events", f"/api/findings/{uuid.uuid4()}"):
        assert (await client.get(path)).status_code == 401, path


async def test_finding_detail_has_evidence_history(client, make_user, world):
    _, _, findings = world
    await as_role(client, make_user, "viewer")
    body = (await client.get(f"/api/findings/{findings[FindingStatus.open].id}")).json()
    assert body["evidence"][0]["evidence"] == "fixture-lib@1.0.0 in package-lock.json"


async def test_triage_rules(client, make_user, owner_db, world):
    _, _, findings = world
    fid = findings[FindingStatus.open].id
    url = f"/api/findings/{fid}"

    h = await as_role(client, make_user, "viewer")
    assert (await client.patch(url, json={"status": "in_progress"}, headers=h)).status_code == 403

    h = await as_role(client, make_user, "developer")
    assert (await client.patch(url, json={"status": "in_progress"}, headers=h)).json()["status"] == "in_progress"
    # Developers cannot accept risk or mark false positives; nobody can resolve by hand.
    assert (await client.patch(url, json={"status": "accepted_risk", "note": "long enough note"}, headers=h)).status_code == 403
    assert (await client.patch(url, json={"status": "resolved"}, headers=h)).status_code == 422

    h = await as_role(client, make_user, "approver")
    assert (await client.patch(url, json={"status": "false_positive", "note": "short"}, headers=h)).status_code == 422
    r = await client.patch(url, json={"status": "false_positive", "note": "test fixture only, not shipped"}, headers=h)
    assert r.json()["status"] == "false_positive"
    resolved = f"/api/findings/{findings[FindingStatus.resolved].id}"
    assert (await client.patch(resolved, json={"status": "open"}, headers=h)).status_code == 409

    audit = await owner_db.scalars(select(AuditLog).where(AuditLog.action == "finding.triage",
                                                          AuditLog.target_id == str(fid)))
    assert [a.detail["to"] for a in audit] == ["in_progress", "false_positive"]


async def test_overview_separates_not_scanned(client, make_user, world):
    p, _, _ = world
    await as_role(client, make_user, "viewer")
    row = next(r for r in (await client.get("/api/overview")).json()["projects"] if r["project_id"] == str(p.id))
    # One of two repositories scanned: "partial", never "clean".
    assert row["repositories"] == 2 and row["scanned_repositories"] == 1 and row["scan_state"] == "partial"
    assert row["open_findings"] == {"high": 1}


async def test_scan_history_and_integrity_events(client, make_user, world):
    p, repos, _ = world
    await as_role(client, make_user, "viewer")
    scans = (await client.get("/api/scans", params={"project_id": str(p.id)})).json()
    assert scans["total"] == 1 and scans["items"][0]["status"] == "succeeded"
    events = (await client.get("/api/integrity/events", params={"project_id": str(p.id)})).json()
    assert events["total"] == 1 and events["items"][0]["kind"] == "force_push"
    assert events["items"][0]["repository_id"] == str(repos[1].id)
