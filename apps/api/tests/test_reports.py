"""Phase 5 reports: drafts state what was not scanned, never claim safety, respect llm_allowed, cannot be self-approved.

All data and LLM answers are synthetic fixtures.
"""

import json
import uuid

import pytest
from sqlalchemy import text

from app.agents import reports
from app.db.intel import Report, ReportStatus
from app.db.models import AgentRunStatus
from app.db.registry import ComponentKind, Criticality, Project, ProjectComponent, ProjectStatus, Repository, RepoSource
from app.reports import content as rc
from app.reports import render
from tests.conftest import login


@pytest.mark.parametrize("text_, unsafe", [
    ("The API project is secure.", True), ("All repositories are now fully protected.", True),
    ("No known vulnerabilities were found.", True), ("Nothing here is vulnerable; we guarantee it.", True),
    ("Two repositories were not scanned. Three high findings need attention.", False),
    ("Scanners reported 4 open findings in lodash; upgrade to 4.17.21.", False),
])
def test_unsafe_claim_check(text_, unsafe):
    assert bool(rc.unsafe_claim(text_)) is unsafe


class FakeLLM:
    def __init__(self, narrative):
        self.narrative, self.requests = narrative, []

    async def complete(self, request):
        self.requests.append(request)
        return {"stop_reason": "end_turn", "usage": {}, "content": [{"type": "text",
                                                                     "text": json.dumps({"narrative": self.narrative})}]}


@pytest.fixture
async def project(owner_db):
    async def make(llm_allowed=True, name=None):
        p = Project(name=name or f"R5 {uuid.uuid4().hex[:6]}", slug=f"r5-{uuid.uuid4().hex[:8]}",
                    criticality=Criticality.medium, status=ProjectStatus.active, llm_allowed=llm_allowed)
        owner_db.add(p)
        await owner_db.flush()
        c = ProjectComponent(project_id=p.id, kind=ComponentKind.web, name="web")
        owner_db.add(c)
        await owner_db.flush()
        owner_db.add(Repository(component_id=c.id, source=RepoSource.github, github_repo_id=uuid.uuid4().int % 10**12,
                                full_name="acme/fixture-web", manifest_hash="m" * 64, tree_hash="t" * 40))
        await owner_db.commit()
        return p
    return make


async def _report(app_db, report_id) -> Report:
    return await app_db.get(Report, uuid.UUID(report_id), populate_existing=True)


async def test_draft_lists_not_scanned_and_keeps_ai_text_labelled(app_db, make_user, project):
    p = await project()
    user = await make_user("developer")
    llm = FakeLLM("The web repository acme/fixture-web was not scanned, so nothing is known about it yet.")
    run = await reports.run(app_db, p.id, user.id, llm=llm)
    assert run.status == AgentRunStatus.succeeded and run.output["narrative"] == "included"
    r = await _report(app_db, run.output["report_id"])
    assert r.status == ReportStatus.draft and r.created_by == user.id and r.generated_by_run_id == run.id
    assert any("acme/fixture-web" in n for n in r.content["not_scanned"])
    assert "does not show that any project is secure" in r.content["statement"]
    assert '<untrusted_data source="report_data"' in llm.requests[0]["messages"][0]["content"]
    page = render.html(r)
    assert "Not scanned" in page and "AI-written draft" in page


async def test_safety_claim_drops_the_narrative(app_db, make_user, project):
    p = await project()
    run = await reports.run(app_db, p.id, (await make_user("developer")).id,
                            llm=FakeLLM("Good news: the project is secure and has no vulnerabilities."))
    assert run.output["narrative"] == "rejected"
    r = await _report(app_db, run.output["report_id"])
    assert r.narrative is None and "claimed safety" in r.narrative_note


async def test_save_tool_itself_refuses_a_safety_claim(app_db, make_user, project):
    """Enforcement is in the tool, not only in the handler."""
    from app.agents.discovery import ToolError
    from app.agents.registry import ToolContext

    p = await project()
    ctx = ToolContext(session=app_db, run_id=None)
    with pytest.raises(ToolError):
        await reports.save_report_draft(ctx, reports.SaveArgs(project_id=p.id, created_by=(await make_user("developer")).id,
                                                              narrative="Everything is safe."))


async def test_llm_not_allowed_project_gets_tables_only(app_db, make_user, project):
    p = await project(llm_allowed=False)
    llm = FakeLLM("should never be asked")
    run = await reports.run(app_db, p.id, (await make_user("developer")).id, llm=llm)
    assert run.output["narrative"] == "not_allowed" and llm.requests == []


async def test_approval_rules(client, make_user, app_db, owner_db, project):
    p = await project()
    requester, approver, dev = await make_user("approver"), await make_user("approver"), await make_user("developer")
    run = await reports.run(app_db, p.id, requester.id, llm=FakeLLM("Two findings need attention."))
    url = f"/api/reports/{run.output['report_id']}/approve"

    h = await login(client, dev)
    assert (await client.post(url, json={"totp_code": dev.code(1)}, headers=h)).status_code == 403

    h = await login(client, requester)
    r = await client.post(url, json={"totp_code": requester.code(1)}, headers=h)
    assert r.status_code == 409 and "own report" in r.json()["detail"]

    h = await login(client, approver)
    assert (await client.post(url, json={"totp_code": "000000"}, headers=h)).status_code == 401
    r = await client.post(url, json={"totp_code": approver.code(1)}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "approved" and r.json()["approved_by"] == str(approver.id)
    other = await make_user("approver")
    h = await login(client, other)
    r = await client.post(url, json={"totp_code": other.code(1)}, headers=h)
    assert r.status_code == 409 and "already approved" in r.json()["detail"]

    listed = (await client.get("/api/reports")).json()
    assert any(i["id"] == run.output["report_id"] and i["status"] == "approved" for i in listed["items"])
    detail = (await client.get(f"/api/reports/{run.output['report_id']}")).json()
    assert detail["narrative"] == "Two findings need attention." and detail["content"]["not_scanned"]


async def test_database_forbids_self_approval(owner_db, app_db, make_user, project):
    p = await project()
    user = await make_user("approver")
    run = await reports.run(app_db, p.id, user.id, llm=FakeLLM("x"))
    with pytest.raises(Exception, match="ck_reports_not_self_approved"):
        await owner_db.execute(text("UPDATE reports SET status = 'approved', approved_by = created_by, "
                                    "approved_at = now() WHERE id = :id"), {"id": run.output["report_id"]})
    await owner_db.rollback()


async def test_generate_endpoint(client, make_user, monkeypatch):
    from app.workers.celery_app import celery

    sent = []
    monkeypatch.setattr(celery, "send_task", lambda name, args, retry: sent.append((name, args)))
    viewer, dev = await make_user("viewer"), await make_user("developer")
    h = await login(client, viewer)
    assert (await client.post("/api/reports", json={}, headers=h)).status_code == 403
    h = await login(client, dev)
    assert (await client.post("/api/reports", json={}, headers=h)).json() == {"queued": True}
    assert sent == [("reports.generate", [None, str(dev.id)])]

    def down(*a, **k):
        raise ConnectionError("broker down")

    monkeypatch.setattr(celery, "send_task", down)
    assert (await client.post("/api/reports", json={}, headers=h)).status_code == 503


def test_html_escapes_everything():
    r = Report(kind="project", title="<script>alert(1)</script>", status=ReportStatus.draft,
               narrative="<img src=x onerror=alert(1)>", content={
                   "generated_at": "2026-11-24T00:00:00+00:00", "scope": "project", "statement": rc.STATEMENT,
                   "not_scanned": ["<b>x</b>"], "projects": []})
    page = render.html(r)
    assert "<script>" not in page and "<img" not in page and "<b>x</b>" not in page and "&lt;script&gt;" in page


def test_pdf_renders_and_fetches_nothing():
    pytest.importorskip("weasyprint", exc_type=OSError, reason="WeasyPrint needs Pango (present in CI and the image)")
    r = Report(kind="project", title="Fixture report", status=ReportStatus.draft, narrative=None,
               narrative_note="tables only", content={
                   "generated_at": "2026-11-24T00:00:00+00:00", "scope": "project", "statement": rc.STATEMENT,
                   "not_scanned": [], "projects": []})
    assert render.pdf(r).startswith(b"%PDF")
    with pytest.raises(ValueError):
        render._no_fetch("https://example.com/x.png")
