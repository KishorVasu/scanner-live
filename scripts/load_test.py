"""Phase 6 load test: 20 synthetic projects, concurrent dashboard reads, latency budget. CI and the server only.

  python scripts/load_test.py --owner-url postgresql+asyncpg://...@host/sp_e2e --creds apps/web/e2e/.creds.json \
      --base http://127.0.0.1:8000 [--users 10 --seconds 60 --p95-ms 1000]

Seeds a database already prepared by scripts/e2e_seed.py (never a live one: it refuses a database named `platform`),
signs in once as the seeded developer, then N concurrent clients read the dashboard endpoints for the given time.
Exits 1 on any non-2xx/404 response or when an endpoint's p95 exceeds the budget. Every row is a labelled fixture.

ponytail: measures the API and Postgres only. Worker and scan throughput depend on scanner runtime and are measured on
the server (docs/SELF_HOSTED_DEPLOYMENT.md §12), not here.
"""

import argparse
import asyncio
import json
import random
import statistics
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pyotp
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

PROJECTS, REPOS_PER_PROJECT, FINDINGS_PER_REPO = 20, 3, 100


async def seed(owner_url: str) -> tuple[list[str], list[str]]:
    if make_url(owner_url).database == "platform":
        raise SystemExit("refusing to seed the live database")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db.registry import ComponentKind, Criticality, Project, ProjectComponent, ProjectStatus, Repository
    from app.db.registry import RepoSource, Severity
    from app.db.scanning import (Confidence, FindingEvidence, FindingStatus, ScanJob, ScanStatus, ScanTrigger,
                                 Scanner, SecurityFinding)

    engine = create_async_engine(owner_url)
    now = datetime.now(UTC)
    sevs, statuses = list(Severity), [FindingStatus.open, FindingStatus.in_progress, FindingStatus.resolved]
    scanners = [Scanner.osv_scanner, Scanner.gitleaks, Scanner.semgrep]
    project_ids, finding_ids = [], []
    async with async_sessionmaker(engine, expire_on_commit=False)() as s:
        for i in range(PROJECTS):
            p = Project(name=f"Load fixture {i:02d}", slug=f"load-fixture-{i:02d}", criticality=list(Criticality)[i % 4],
                        status=ProjectStatus.active)
            s.add(p)
            await s.flush()
            project_ids.append(str(p.id))
            for kind in list(ComponentKind)[:REPOS_PER_PROJECT]:
                c = ProjectComponent(project_id=p.id, kind=kind, name=kind.value)
                s.add(c)
                await s.flush()
                r = Repository(component_id=c.id, source=RepoSource.github, github_repo_id=uuid.uuid4().int % 10**12,
                               full_name=f"load-fixture/{p.slug}-{kind.value}", manifest_hash="m" * 64, tree_hash="t" * 40)
                s.add(r)
                await s.flush()
                jobs = []
                for sc in scanners:
                    j = ScanJob(repository_id=r.id, scanner=sc, trigger=ScanTrigger.schedule, inventory_hash=uuid.uuid4().hex * 2,
                                status=ScanStatus.succeeded, finished_at=now)
                    s.add(j)
                    jobs.append(j)
                await s.flush()
                for n in range(FINDINGS_PER_REPO):
                    f = SecurityFinding(
                        fingerprint=uuid.uuid4().hex * 2, project_id=p.id, repository_id=r.id, scanner=scanners[n % 3],
                        rule_id=f"LOAD-FIXTURE-{n:03d}", category="dependency", title=f"Load fixture finding {n}",
                        severity=sevs[n % len(sevs)], confidence=Confidence.high, status=statuses[n % 3],
                        package=f"fixture-lib-{n % 17}", package_version="1.0.0", first_seen_at=now, last_seen_at=now)
                    s.add(f)
                    await s.flush()
                    finding_ids.append(str(f.id))
                    s.add(FindingEvidence(finding_id=f.id, scan_job_id=jobs[n % 3].id, captured_at=now,
                                          evidence_redacted=f"fixture-lib-{n % 17}@1.0.0 in package-lock.json"))
            await s.commit()
    await engine.dispose()
    return project_ids, finding_ids


async def run(base: str, creds: dict, users: int, seconds: int, project_ids: list[str], finding_ids: list[str]) -> dict:
    dev = creds["developer"]
    async with httpx.AsyncClient(base_url=base, timeout=30) as c:
        r = await c.post("/api/auth/login", json={"email": dev["email"], "password": dev["password"],
                                                  "totp_code": pyotp.TOTP(dev["totp"]).now()})
        r.raise_for_status()
        endpoints = [
            ("/api/overview", lambda: "/api/overview"),
            ("/api/projects", lambda: "/api/projects"),
            ("/api/projects/{id}", lambda: f"/api/projects/{random.choice(project_ids)}"),
            ("/api/findings", lambda: "/api/findings?limit=25"),
            ("/api/findings?project_id&severity", lambda: f"/api/findings?project_id={random.choice(project_ids)}&severity=critical"),
            ("/api/findings/{id}", lambda: f"/api/findings/{random.choice(finding_ids)}"),
            ("/api/scans", lambda: "/api/scans"),
            ("/api/impacts/matrix", lambda: "/api/impacts/matrix"),
            ("/api/integrity/events", lambda: "/api/integrity/events"),
        ]
        times: dict[str, list[float]] = {name: [] for name, _ in endpoints}
        errors: list[str] = []
        deadline = time.monotonic() + seconds

        async def user() -> None:
            while time.monotonic() < deadline:
                name, url = random.choice(endpoints)
                t = time.perf_counter()
                resp = await c.get(url())
                times[name].append(time.perf_counter() - t)
                if resp.status_code >= 400:
                    errors.append(f"{name}: {resp.status_code}")

        await asyncio.gather(*(user() for _ in range(users)))
    q = lambda xs, p: sorted(xs)[min(len(xs) - 1, int(len(xs) * p))] * 1000  # noqa: E731
    return {
        "users": users, "seconds": seconds, "requests": sum(map(len, times.values())), "errors": errors[:20],
        "error_count": len(errors),
        "endpoints": {n: {"n": len(xs), "p50_ms": round(statistics.median(xs) * 1000, 1), "p95_ms": round(q(xs, 0.95), 1),
                          "max_ms": round(max(xs) * 1000, 1)} for n, xs in times.items() if xs},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner-url", required=True)
    ap.add_argument("--creds", required=True)
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--users", type=int, default=10)
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--p95-ms", type=float, default=1000)
    ap.add_argument("--out", default="load-test-report.json")
    a = ap.parse_args()
    projects, findings = asyncio.run(seed(a.owner_url))
    report = asyncio.run(run(a.base, json.loads(Path(a.creds).read_text()), a.users, a.seconds, projects, findings))
    report["budget_p95_ms"] = a.p95_ms
    report["dataset"] = {"projects": PROJECTS, "repositories": PROJECTS * REPOS_PER_PROJECT,
                         "findings": len(findings)}
    over = [n for n, e in report["endpoints"].items() if e["p95_ms"] > a.p95_ms]
    report["over_budget"] = over
    Path(a.out).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 1 if over or report["error_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
