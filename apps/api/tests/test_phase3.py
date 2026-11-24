"""Phase 3: scanner adapters, integrity checks, finding lifecycle, scan jobs, scanner tools (scan-runner mocked).

All scanner reports and repository contents here are synthetic. No container runs and no external repository is read.
"""

import base64
import json
import uuid

import httpx
import pytest
from sqlalchemy import func, select, text

from app.agents import scanning
from app.db.registry import ComponentKind, Criticality, Project, ProjectComponent, ProjectStatus, Repository, RepoSource, ScanPolicy
from app.db.scanning import FindingEvidence, FindingStatus, ScanJob, ScanStatus, ScanTrigger, Scanner, SecurityFinding
from app.integrity.checks import Change, check_ignored_committed, run_checks
from app.scanners import service
from app.scanners.adapters import ADAPTERS, parse_gitleaks, parse_npm_audit, parse_osv, parse_pip_audit, parse_semgrep, parse_trivy
from app.scanners.base import RawFinding, ReportError, fingerprint, severity_from_word


def j(o) -> bytes:
    return json.dumps(o).encode()


def osv_report(*vulns: tuple[str, str, str], source="/src/web/package-lock.json") -> bytes:
    """vulns: (package, version, id)"""
    return j({"results": [{"source": {"path": source, "type": "lockfile"}, "packages": [
        {"package": {"name": p, "version": v, "ecosystem": "npm"},
         "vulnerabilities": [{"id": i, "aliases": [f"CVE-FIXTURE-{i[-4:]}"], "summary": f"fixture {i}"}],
         "groups": [{"ids": [i], "max_severity": "7.5"}]} for p, v, i in vulns]}]})


# ---------------- adapters ----------------

def test_osv_adapter():
    r = parse_osv(osv_report(("next", "15.0.3", "GHSA-fixt-0001-aaaa")))
    f = r.findings[0]
    assert (f.package, f.package_version, f.severity, f.file_path) == ("next", "15.0.3", "high", "web/package-lock.json")
    assert f.advisory_ids[0] == "GHSA-fixt-0001-aaaa" and r.coverage == {"all": False, "paths": ["web/package-lock.json"]}


def test_npm_pip_trivy_semgrep_adapters():
    npm = parse_npm_audit(j({"auditReportVersion": 2, "vulnerabilities": {"lodash": {
        "name": "lodash", "severity": "high", "isDirect": True,
        "via": [{"source": 1, "name": "lodash", "title": "fixture", "url": "https://github.com/advisories/GHSA-fixt-0002-bbbb",
                 "severity": "high", "range": "<4.17.21"}]}, "express": {"via": ["lodash"], "severity": "high"}}}))
    assert [(f.package, f.rule_id) for f in npm.findings] == [("lodash", "GHSA-fixt-0002-bbbb")]

    pip = parse_pip_audit(j({"dependencies": [
        {"name": "django", "version": "4.2.0", "vulns": [{"id": "PYSEC-FIXTURE-1", "fix_versions": ["4.2.1"], "aliases": []}]},
        {"name": "private-lib", "skip_reason": "not on PyPI"}]}))
    assert pip.findings[0].confidence == "needs_verification" and pip.summary["partial"] is True

    trivy = parse_trivy(j({"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Class": "config", "Misconfigurations": [
        {"ID": "DS002", "Title": "root user", "Severity": "HIGH", "Status": "FAIL", "CauseMetadata": {"StartLine": 1}},
        {"ID": "DS001", "Title": "ok", "Severity": "LOW", "Status": "PASS"}]}]}))
    assert [(f.rule_id, f.category) for f in trivy.findings] == [("DS002", "misconfiguration")]

    sg = parse_semgrep(j({"results": [{"check_id": "js.xss", "path": "/src/app.js", "start": {"line": 3},
                                       "extra": {"message": "xss", "severity": "ERROR", "lines": "el.innerHTML = x",
                                                 "metadata": {"confidence": "HIGH"}}}],
                          "errors": [{"message": "timeout"}], "paths": {"scanned": ["/src/app.js"]}}))
    assert sg.findings[0].severity == "high" and sg.summary["partial"] is True and sg.coverage["paths"] == ["app.js"]


def test_gitleaks_never_keeps_the_secret():
    secret = "ghp_" + "Fx9" * 12
    r = parse_gitleaks(j([{"RuleID": "github-pat", "Description": "GitHub token", "File": "/src/config.js",
                           "StartLine": 4, "Commit": "c" * 40, "Secret": secret, "Match": f"token = '{secret}'"}]))
    f = r.findings[0]
    assert secret not in json.dumps(f.__dict__) and f.match_hash and len(f.match_hash) == 64
    assert r.coverage["all"] is True


@pytest.mark.parametrize("report", [b"", b"   ", b"{not json", j({"auditReportVersion": 1})])
def test_bad_reports_rejected(report):
    with pytest.raises(ReportError):
        parse_npm_audit(report)
    with pytest.raises(ReportError):
        parse_trivy(j({"SchemaVersion": 1}))


def test_unknown_severity_is_never_downgraded():
    assert severity_from_word("weird") == ("medium", False)
    assert ADAPTERS["trivy"].ok_exit_codes == frozenset({0})


def test_fingerprints():
    code = RawFinding("r", "code", "t", "high", "high", "e", file_path="a.js", line=3, snippet="x  =  eval(y)")
    moved = RawFinding("r", "code", "t", "high", "high", "e", file_path="a.js", line=40, snippet="x = eval(y)")
    assert fingerprint("repo", "semgrep", code) == fingerprint("repo", "semgrep", moved)  # line shift stable
    assert fingerprint("repo", "semgrep", code) != fingerprint("repo", "codeql", code)
    dep = RawFinding("GHSA-1", "dependency", "t", "high", "high", "e", package="next", advisory_ids=["GHSA-1"], file_path="l")
    bumped = RawFinding("GHSA-1", "dependency", "t", "high", "high", "e", package="next", package_version="15.0.4",
                        advisory_ids=["GHSA-1"], file_path="l")
    assert fingerprint("repo", "osv_scanner", dep) == fingerprint("repo", "osv_scanner", bumped)


# ---------------- integrity checks (synthetic, harmless fixtures) ----------------

def rules(changes, **kw):
    return {(h.rule, h.severity) for h in run_checks(changes, **kw)}


def test_lifecycle_scripts():
    before = j({"scripts": {"build": "x", "prepare": "echo a"}})
    after = j({"scripts": {"build": "x", "prepare": "echo b", "postinstall": "echo fixture"}})
    assert rules([Change("package.json", before, after)]) == {("npm-postinstall-added", "high"), ("npm-prepare-changed", "medium")}
    assert ("python-setup-py", "high") in rules([Change("setup.py", None, b"print('fixture')")])


def test_editor_and_build_config():
    tasks = b'{\n // comment\n "tasks": [{"label": "fixture", "runOptions": {"runOn": "folderOpen"},},]\n}'
    assert rules([Change(".vscode/tasks.json", None, tasks)]) == {("vscode-folder-open-task", "high")}
    assert ("vscode-terminal-settings", "medium") in rules(
        [Change(".vscode/settings.json", b"{}", b'{"terminal.integrated.shell.linux": "/bin/fixture"}')])
    assert ("build-config-changed", "medium") in rules([Change("web/next.config.mjs", b"a", b"b")])


def test_workflow_checks():
    wf = b"on: pull_request_target\npermissions: write-all\njobs:\n x:\n  steps:\n   - uses: actions/checkout@v4\n   - uses: ./local\n"
    got = rules([Change(".github/workflows/ci.yml", b"on: push\n", wf)])
    assert {("workflow-pull-request-target", "high"), ("workflow-permissions-broadened", "medium"),
            ("workflow-unpinned-action", "medium")} <= got
    pinned = b"on: push\njobs:\n x:\n  steps:\n   - uses: actions/checkout@" + b"a" * 40 + b"\n"
    assert rules([Change(".github/workflows/ci.yml", b"on: push\n", pinned)]) == {("workflow-changed", "low")}


def test_binary_and_obfuscation():
    assert ("binary-magic-mismatch", "high") in rules([Change("assets/logo.png", None, b"<script>fixture</script>")])
    png_with_js = b"\x89PNG\r\n\x1a\n" + b"\x00" * 10 + b"require('child_process')"
    assert ("binary-script-markers", "high") in rules([Change("assets/logo.png", None, png_with_js)])
    assert rules([Change("assets/ok.png", None, b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)]) == set()
    js = b"const s = atob('ZmF4dHVyZQ=='); eval(s);"  # harmless: decodes to a fixture word, never executed
    assert ("js-eval-decoded", "high") in rules([Change("src/a.js", None, js)])
    assert ("js-large-base64", "medium") in rules([Change("src/b.js", None, b"const x='" + b"A" * 1200 + b"';")])
    assert rules([Change("src/c.js", None, b"var a=1;" * 800)]) == {("js-very-long-line", "low")}
    assert rules([Change("dist/app.min.js", None, b"x" * 6000 + b"eval(atob('a'))")]) == set()


def test_ignored_files_committed():
    hits = check_ignored_committed([".env", "node_modules/a/index.js", "src/app.js", "logs/debug.log"],
                                   b"# fixture\n.env\nnode_modules/\n*.log\n")
    assert {(h.path, h.severity) for h in hits} == {(".env", "high"), ("node_modules/a/index.js", "low"),
                                                   ("logs/debug.log", "low")}


# ---------------- DB: lifecycle, jobs, tools ----------------

@pytest.fixture
async def repo(owner_db):
    p = Project(name="Fx", slug=f"fx-{uuid.uuid4().hex[:8]}", criticality=Criticality.low, status=ProjectStatus.active)
    owner_db.add(p)
    await owner_db.flush()
    owner_db.add(ScanPolicy(project_id=p.id))
    c = ProjectComponent(project_id=p.id, kind=ComponentKind.web, name="web")
    owner_db.add(c)
    await owner_db.flush()
    r = Repository(component_id=c.id, source=RepoSource.github, github_repo_id=uuid.uuid4().int % 10**12,
                   manifest_hash="m" * 64, tree_hash="t" * 40)
    owner_db.add(r)
    await owner_db.commit()
    return r


async def _run(db, repo, report: bytes | None, *, scanner=Scanner.osv_scanner, exit_code=1, error=None) -> ScanJob:
    job, created = await service.create_job(db, repo, scanner, ScanTrigger.manual)
    assert created
    await service.complete_job(db, job, exit_code=exit_code, report=report, error=error)
    await db.commit()
    return job


async def _findings(db, repo):
    rows = await db.scalars(select(SecurityFinding).where(SecurityFinding.repository_id == repo.id)
                            .execution_options(populate_existing=True))
    return {f.package: f for f in rows}


async def test_finding_lifecycle(app_db, repo):
    a, b = ("next", "15.0.3", "GHSA-fixt-000a-aaaa"), ("react", "19.0.0", "GHSA-fixt-000b-bbbb")
    j1 = await _run(app_db, repo, osv_report(a, b))
    assert j1.status == ScanStatus.succeeded
    f = await _findings(app_db, repo)
    assert {k: v.status for k, v in f.items()} == {"next": FindingStatus.open, "react": FindingStatus.open}

    await _run(app_db, repo, osv_report(a, b, ("lodash", "4.0.0", "GHSA-fixt-000c-cccc")))
    ev = await app_db.scalar(select(func.count()).select_from(FindingEvidence).where(FindingEvidence.finding_id == f["next"].id))
    assert ev == 2  # repeat detection adds evidence, same finding

    failed = await _run(app_db, repo, None, exit_code=2)
    crashed = await _run(app_db, repo, b"{truncated", exit_code=1)
    runner_down = await _run(app_db, repo, None, error="scan-runner unreachable")
    assert {failed.status, crashed.status, runner_down.status} == {ScanStatus.failed}
    assert all(x.status == FindingStatus.open for x in (await _findings(app_db, repo)).values())  # R11

    other_lockfile = await _run(app_db, repo, osv_report(source="/src/api/package-lock.json"))
    assert other_lockfile.status == ScanStatus.succeeded
    assert all(x.status == FindingStatus.open for x in (await _findings(app_db, repo)).values())  # not covered

    await _run(app_db, repo, osv_report(b))  # covers web/package-lock.json and no longer reports next or lodash
    f = await _findings(app_db, repo)
    assert f["next"].status == FindingStatus.resolved and f["next"].resolved_by_scan_job_id is not None
    assert f["react"].status == FindingStatus.open

    await _run(app_db, repo, osv_report(a, b))  # next is back
    assert (await _findings(app_db, repo))["next"].status == FindingStatus.open


async def test_partial_scan_never_resolves(app_db, repo):
    vuln = j({"dependencies": [{"name": "django", "version": "4.2.0", "vulns": [{"id": "PYSEC-FIXTURE-9"}]}]})
    await _run(app_db, repo, vuln, scanner=Scanner.pip_audit)
    partial = j({"dependencies": [{"name": "x", "skip_reason": "fixture"}]})
    job = await _run(app_db, repo, partial, scanner=Scanner.pip_audit)
    assert job.status == ScanStatus.partial
    assert (await _findings(app_db, repo))["django"].status == FindingStatus.open


async def test_job_dedup_and_skip_unchanged(app_db, repo):
    j1, c1 = await service.create_job(app_db, repo, Scanner.gitleaks, ScanTrigger.webhook)
    j2, c2 = await service.create_job(app_db, repo, Scanner.gitleaks, ScanTrigger.webhook)
    assert c1 and not c2 and j1.id == j2.id  # ten pushes, one scan
    await service.complete_job(app_db, j1, exit_code=0, report=b"[]")
    await app_db.commit()
    skipped, created = await service.create_job(app_db, repo, Scanner.gitleaks, ScanTrigger.schedule)
    assert created and skipped.status == ScanStatus.skipped_unchanged
    await app_db.commit()


async def test_scanner_tool_failure_is_never_clean(app_db, repo, monkeypatch):
    def runner(req: httpx.Request) -> httpx.Response:
        return httpx.Response(501, json={"error": "execution disabled"})

    monkeypatch.setattr(scanning, "_runner_transport", httpx.MockTransport(runner))
    run = await scanning.run_agent(app_db, "secret_detection", {"repository_id": str(repo.id)})
    out = run.output["jobs"][0]
    assert out["status"] == "failed" and "execution disabled" in out["error"]


async def test_scanner_tool_ingests_report(app_db, repo, monkeypatch):
    seen = []

    def runner(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen.append(body)
        return httpx.Response(200, json={"exit_code": 1, "report": osv_report(("next", "15.0.3", "GHSA-fixt-00dd-dddd")).decode()})

    monkeypatch.setattr(scanning, "_runner_transport", httpx.MockTransport(runner))
    run = await scanning.run_agent(app_db, "dependency_analysis", {"repository_id": str(repo.id)})
    assert run.status.value == "succeeded", run.error
    assert seen[0] == {"scanner": "osv_scanner", "job_id": run.output["jobs"][0]["job_id"],
                       "mount_ref": f"sp-src-{run.output['jobs'][0]['job_id']}"}
    assert "next" in await _findings(app_db, repo)


async def test_integrity_tool_end_to_end(app_db, owner_db, repo, monkeypatch):
    from app.db.registry import GithubInstallation, GithubInstallationRepo, RepositoryEvent
    from app.integrations import github as gh_mod
    from app.integrations.github import GitHubClient
    from tests.test_phase2 import RSA_PEM

    before, after = "1" * 40, "2" * 40
    files = {before: {"package.json": j({"scripts": {}})},
             after: {"package.json": j({"scripts": {"postinstall": "echo fixture"}}), "setup.py": b"print('fixture')"}}
    requested = []

    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "ghs_" + "T" * 36})
        if "/contents/" in p:
            path, ref = p.split("/contents/")[1], req.url.params["ref"]
            requested.append(path)
            content = files[ref].get(path)
            if content is None:
                return httpx.Response(404, json={})
            return httpx.Response(200, json={"type": "file", "size": len(content), "encoding": "base64",
                                             "content": base64.b64encode(content).decode()})
        return httpx.Response(404, json={})

    inst = GithubInstallation(installation_id=uuid.uuid4().int % 10**9, account_login="fx", account_type="Organization",
                              permissions={"contents": "read"}, read_only=True)
    owner_db.add(inst)
    await owner_db.flush()
    owner_db.add(GithubInstallationRepo(installation_ref=inst.id, github_repo_id=repo.github_repo_id, full_name="fx/r"))
    await owner_db.commit()
    monkeypatch.setattr(gh_mod, "_client_override", GitHubClient(1, RSA_PEM, httpx.AsyncClient(
        base_url="https://api.github.test", transport=httpx.MockTransport(handler))))

    run = await scanning.run_agent(app_db, "repository_integrity", {
        "repository_id": str(repo.id), "before": before, "after": after, "paths": ["package.json", "setup.py", ".npmrc", ".env"]})
    assert run.status.value == "succeeded", run.error
    assert ".env" not in requested and ".npmrc" not in requested  # secret-pattern files are never fetched
    kinds = {(e.kind.value, e.severity.value) for e in await owner_db.scalars(
        select(RepositoryEvent).where(RepositoryEvent.repository_id == repo.id, RepositoryEvent.source == "scan"))}
    assert kinds == {("lifecycle_script_change", "high"), ("build_config_change", "medium")}
    rules_found = {f.rule_id for f in await owner_db.scalars(
        select(SecurityFinding).where(SecurityFinding.repository_id == repo.id, SecurityFinding.scanner == Scanner.integrity))}
    assert rules_found == {"npm-postinstall-added", "python-setup-py", "build-config-changed"}  # added file checked too


async def test_schedule_skips_inactive_projects(app_db, owner_db, repo):
    from app.scanners.schedule import plan

    queued = []
    await plan(app_db, "daily", enqueue=lambda name, payload: queued.append((name, payload["repository_id"])) or True)
    assert ("dependency_analysis", str(repo.id)) in queued and ("secret_detection", str(repo.id)) in queued
    comp = await owner_db.get(ProjectComponent, repo.component_id)
    await owner_db.execute(text("UPDATE projects SET status='incident' WHERE id=:p").bindparams(p=comp.project_id))
    await owner_db.commit()
    queued.clear()
    await plan(app_db, "daily", enqueue=lambda name, payload: queued.append(payload["repository_id"]) or True)
    assert str(repo.id) not in queued  # incident projects pause automated jobs


async def test_phase3_grants(owner_db):
    def priv(t, p):
        return text("SELECT has_table_privilege('platform_app', :t, :p)").bindparams(t=t, p=p)

    for table, p in (("finding_evidence", "UPDATE"), ("finding_evidence", "DELETE"), ("security_findings", "DELETE"),
                     ("scan_jobs", "DELETE"), ("scan_results", "UPDATE")):
        assert not await owner_db.scalar(priv(table, p)), (table, p)
    tier = await owner_db.scalar(text("SELECT tier FROM policies WHERE action='run_codeql'"))
    assert tier == "approval_required"
