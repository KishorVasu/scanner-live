"""GET /api/findings: RBAC, filters, paging with a total, severity order, and the not-scanned flag (rule 11).

All rows are synthetic fixtures.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.db.registry import ComponentKind, Criticality, Project, ProjectComponent, ProjectStatus, Repository, RepoSource
from app.db.registry import Severity
from app.db.scanning import Confidence, FindingStatus, ScanJob, ScanStatus, ScanTrigger, Scanner, SecurityFinding
from tests.conftest import login


@pytest.fixture
async def seeded(owner_db):
    p = Project(name=f"Fx {uuid.uuid4().hex[:6]}", slug=f"fx-{uuid.uuid4().hex[:8]}", criticality=Criticality.low,
                status=ProjectStatus.active)
    owner_db.add(p)
    await owner_db.flush()
    c = ProjectComponent(project_id=p.id, kind=ComponentKind.web, name="web")
    owner_db.add(c)
    await owner_db.flush()
    r = Repository(component_id=c.id, source=RepoSource.github, github_repo_id=uuid.uuid4().int % 10**12,
                   manifest_hash="m" * 64, tree_hash="t" * 40)
    owner_db.add(r)
    await owner_db.flush()
    now = datetime.now(UTC)
    sev = [Severity.low, Severity.critical, Severity.medium] * 10  # 30 findings, mixed order
    for i, s in enumerate(sev):
        owner_db.add(SecurityFinding(
            fingerprint=uuid.uuid4().hex + uuid.uuid4().hex, project_id=p.id, repository_id=r.id,
            scanner=Scanner.osv_scanner, rule_id=f"GHSA-fixt-{i:04d}", category="dependency", title=f"fixture {i}",
            severity=s, confidence=Confidence.high,
            status=FindingStatus.resolved if i % 10 == 0 else FindingStatus.open,
            package=f"pkg{i}", package_version="1.0.0", first_seen_at=now, last_seen_at=now - timedelta(minutes=i)))
    await owner_db.commit()
    return p, r


async def test_requires_sign_in(client):
    assert (await client.get("/api/findings")).status_code == 401


async def test_viewer_pages_through_findings(client, make_user, seeded):
    p, _ = seeded
    await login(client, await make_user("viewer"))
    r = await client.get("/api/findings", params={"project_id": str(p.id), "limit": 10})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 30 and len(body["items"]) == 10 and body["offset"] == 0
    assert [i["severity"] for i in body["items"]] == ["critical"] * 10  # critical first
    page3 = (await client.get("/api/findings", params={"project_id": str(p.id), "limit": 10, "offset": 20})).json()
    assert [i["severity"] for i in page3["items"]] == ["low"] * 10
    seen = {i["id"] for o in (0, 10, 20) for i in
            (await client.get("/api/findings", params={"project_id": str(p.id), "limit": 10, "offset": o})).json()["items"]}
    assert len(seen) == 30  # stable order: no row repeated or skipped across pages


async def test_filters(client, make_user, seeded):
    p, _ = seeded
    await login(client, await make_user("viewer"))
    q = {"project_id": str(p.id), "status": ["open", "in_progress"], "severity": "critical"}
    body = (await client.get("/api/findings", params=q)).json()
    assert body["total"] == 9 and all(i["status"] == "open" and i["severity"] == "critical" for i in body["items"])
    assert (await client.get("/api/findings", params={"limit": 101})).status_code == 422
    assert (await client.get("/api/findings", params={"status": "deleted"})).status_code == 422


async def test_scanned_flag_separates_not_scanned_from_no_findings(client, make_user, owner_db, seeded):
    p, repo = seeded
    await login(client, await make_user("viewer"))
    owner_db.add(ScanJob(repository_id=repo.id, scanner=Scanner.osv_scanner, trigger=ScanTrigger.manual,
                         inventory_hash="h" * 64, status=ScanStatus.succeeded))
    await owner_db.commit()
    assert (await client.get("/api/findings", params={"project_id": str(p.id)})).json()["scanned"] is True
    # A scan of another project never makes an unscanned project read as "no findings" (rule 11).
    other = (await client.get("/api/findings", params={"project_id": str(uuid.uuid4())})).json()
    assert other["total"] == 0 and other["scanned"] is False
