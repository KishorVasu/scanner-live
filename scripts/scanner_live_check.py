"""CI-only: run each pinned scanner through scan-runner's real `docker run` command against a synthetic fixture repo,
then parse the real output with the API's adapters. Linux + Docker required (GitHub Actions ubuntu runners).

Evidence for the reviewer who sets `reviewed_by` in scanners/images/images.lock: writes scanner-live-report.json.
The fixture is harmless: old package versions with public advisories, a Dockerfile running as root, and a fake
token generated at run time (never committed). Nothing in the fixture is executed.
"""

import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scan-runner"))
sys.path.insert(0, str(ROOT / "apps" / "api"))
os.environ.setdefault("SP_ENVIRONMENT", "test")

import runner  # noqa: E402
from app.scanners.adapters import ADAPTERS  # noqa: E402
from app.scanners.base import ReportError  # noqa: E402

HELPER = "node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a"

# scanner -> (target, expectation). "findings" means the adapter must parse real output and find `expect`.
PLAN = {
    "osv_scanner": (None, {"expect": "lodash"}),
    "npm_audit": (None, {"expect": "lodash"}),
    "pip_audit": ("requirements.txt", {"expect": "django", "image_ref": "sp-pip-audit:ci"}),
    "gitleaks": (None, {"expect": "github-pat"}),
    # Expected to fail until OQ-9 is decided: offline Trivy needs a vulnerability DB mirror; Semgrep needs baked rules.
    "trivy": (None, {"expect_failure": "no vulnerability DB mirror yet (OQ-9)"}),
    "semgrep": (None, {"expect_failure": "no rule packs baked into the image yet"}),
}


def sh(*argv: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, check=check, **kw)


def fixture() -> tuple[Path, str]:
    d = Path(tempfile.mkdtemp(prefix="sp-fixture-"))
    (d / "package.json").write_text(json.dumps({"name": "fixture", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}}))
    (d / "package-lock.json").write_text(json.dumps({
        "name": "fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
        "packages": {"": {"name": "fixture", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
                     "node_modules/lodash": {"version": "4.17.20",
                                             "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}))
    (d / "requirements.txt").write_text("django==3.2.0\n")
    (d / "Dockerfile").write_text("FROM alpine:3.10\nUSER root\nCMD [\"true\"]\n")
    fake = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    (d / "config.js").write_text(f"const token = '{fake}';\n")
    sh("git", "init", "-q", str(d))
    sh("git", "-C", str(d), "-c", "user.email=ci@example.test", "-c", "user.name=ci", "add", ".")
    sh("git", "-C", str(d), "-c", "user.email=ci@example.test", "-c", "user.name=ci", "commit", "-qm", "fixture")
    return d, fake


def run_one(scanner: str, src: Path, images: dict, target, opts: dict, fake: str) -> dict:
    job = str(uuid.uuid4())
    vol_src = f"sp-src-{job}"
    # Stand-in for the source fetch (not built yet): copy the fixture into the job's source volume as uid 10001.
    # Everything after this is scan-runner's real code path: prepare, sandboxed scan, readback, cleanup.
    sh("docker", "volume", "create", vol_src)
    sh("docker", "run", "--rm", "-v", f"{vol_src}:/src", "-v", f"{src}:/in:ro", HELPER,
       "sh", "-c", "cp -a /in/. /src/ && chown -R 10001:10001 /src")
    req = runner.validate({"scanner": scanner, "job_id": job, "mount_ref": vol_src,
                           **({"target": target} if target else {})}, images)
    out = runner.run(req, images, None, image_ref=opts.get("image_ref"))
    report = (out.get("report") or "").encode()
    adapter = ADAPTERS[scanner]
    result = {"scanner": scanner, "exit_code": out.get("exit_code"), "report_bytes": len(report),
              "stderr_tail": out.get("stderr_tail", ""), "runner_error": out.get("error")}
    result["secret_leaked_into_report"] = fake.encode() in report
    if fake in result["stderr_tail"]:  # the evidence file is uploaded; never let the fake token ride along
        result["stderr_tail"] = "<withheld: contained the fixture token>"
        result["secret_leaked_into_report"] = True
    leftover = sh("docker", "volume", "ls", "-q", "--filter", f"name={job}").stdout.strip()
    result["volumes_left_behind"] = leftover.decode().split() if leftover else []
    if out.get("error") or out.get("exit_code") not in adapter.ok_exit_codes:
        result["outcome"] = "failed"
        return result
    try:
        parsed = adapter.parse(report)
    except ReportError as e:
        result["outcome"] = f"report_error: {e}"
    else:
        result |= {"outcome": "parsed", "findings": len(parsed.findings),
                   "rules": sorted({f.rule_id for f in parsed.findings})[:20],
                   "packages": sorted({f.package for f in parsed.findings if f.package})[:20]}
    return result


def missing_source_is_an_error(images: dict) -> bool:
    """Rule 11: without a source volume, runner.run must refuse instead of scanning an auto-created empty volume."""
    job = str(uuid.uuid4())
    req = runner.validate({"scanner": "gitleaks", "job_id": job, "mount_ref": f"sp-src-{job}"}, images)
    out = runner.run(req, images, None)
    return "report" not in out and "source volume missing" in (out.get("error") or "")


def main() -> int:
    images, _ = runner.load_lock()
    # CI is the evidence step *before* human review, so the review gate is satisfied in memory only, never on disk.
    images = {k: {**v, "reviewed_by": "ci-scanner-live", "digest": v["digest"] or "sha256:" + "0" * 64}
              for k, v in images.items()}
    sh("docker", "network", "create", runner.NETWORKS["egress"], check=False)
    src, fake = fixture()
    results, failures = [], []
    for scanner, (target, opts) in PLAN.items():
        try:
            r = run_one(scanner, src, images, target, opts, fake)
        except Exception as e:  # keep going: one broken scanner must not hide the others' evidence
            r = {"scanner": scanner, "outcome": f"error: {type(e).__name__}: {e}"[:600],
                 "secret_leaked_into_report": False}
        r["digest"] = images[scanner]["digest"]
        results.append(r)
        if r.get("volumes_left_behind"):
            failures.append(f"{scanner}: volumes not removed: {r['volumes_left_behind']}")
        if r["secret_leaked_into_report"]:
            failures.append(f"{scanner}: fake secret appears in the report")
        if "expect" in opts:
            hit = opts["expect"] in r.get("rules", []) + r.get("packages", [])
            if r.get("outcome") != "parsed" or not hit:
                failures.append(f"{scanner}: expected {opts['expect']!r}, got {r.get('outcome')} {r.get('rules')}")
        elif r.get("outcome") == "parsed":
            failures.append(f"{scanner}: expected to fail ({opts['expect_failure']}) but parsed; update the plan")
    if not missing_source_is_an_error(images):
        failures.append("runner.run scanned without a source volume")
    Path("scanner-live-report.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    for f in failures:
        print("FAIL:", f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
