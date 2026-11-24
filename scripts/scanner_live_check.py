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
    vol_src, vol_rep = f"sp-src-{job}", f"sp-report-{job}"
    try:
        sh("docker", "volume", "create", vol_src)
        sh("docker", "volume", "create", vol_rep)
        sh("docker", "run", "--rm", "-v", f"{vol_src}:/src", "-v", f"{src}:/in:ro", HELPER,
           "sh", "-c", "cp -a /in/. /src/ && chown -R 10001:10001 /src")
        sh("docker", "run", "--rm", "-v", f"{vol_rep}:/report", HELPER, "chown", "10001:10001", "/report")
        req = runner.validate({"scanner": scanner, "job_id": job, "mount_ref": vol_src,
                               **({"target": target} if target else {})}, images)
        proc = sh(*runner.docker_argv(req, images, None, image_ref=opts.get("image_ref")), check=False, timeout=900)
        if runner.TEMPLATES[scanner]["report"] == "stdout":
            report = proc.stdout
        else:
            report = sh("docker", "run", "--rm", "-v", f"{vol_rep}:/report:ro", HELPER, "cat", "/report/report.json",
                        check=False).stdout
        adapter = ADAPTERS[scanner]
        result = {"scanner": scanner, "exit_code": proc.returncode, "report_bytes": len(report),
                  "stderr_tail": proc.stderr.decode("utf-8", "replace")[-400:]}
        if proc.returncode not in adapter.ok_exit_codes:
            result["outcome"] = "failed"
        else:
            parsed = adapter.parse(report)
            result |= {"outcome": "parsed", "findings": len(parsed.findings),
                       "rules": sorted({f.rule_id for f in parsed.findings})[:20],
                       "packages": sorted({f.package for f in parsed.findings if f.package})[:20]}
        result["secret_leaked_into_report"] = fake.encode() in report
        return result
    finally:
        sh("docker", "volume", "rm", "-f", vol_src, vol_rep, check=False)


def main() -> int:
    images, _ = runner.load_lock()
    # CI is the evidence step *before* human review, so the review gate is satisfied in memory only, never on disk.
    images = {k: {**v, "reviewed_by": "ci-scanner-live", "digest": v["digest"] or "sha256:" + "0" * 64}
              for k, v in images.items()}
    sh("docker", "network", "create", runner.NETWORKS["egress"], check=False)
    src, fake = fixture()
    results, failures = [], []
    for scanner, (target, opts) in PLAN.items():
        r = run_one(scanner, src, images, target, opts, fake)
        r["digest"] = images[scanner]["digest"]
        results.append(r)
        if r["secret_leaked_into_report"]:
            failures.append(f"{scanner}: fake secret appears in the report")
        if "expect" in opts:
            hit = opts["expect"] in r.get("rules", []) + r.get("packages", [])
            if r.get("outcome") != "parsed" or not hit:
                failures.append(f"{scanner}: expected {opts['expect']!r}, got {r.get('outcome')} {r.get('rules')}")
        elif r.get("outcome") == "parsed":
            failures.append(f"{scanner}: expected to fail ({opts['expect_failure']}) but parsed; update the plan")
    Path("scanner-live-report.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    for f in failures:
        print("FAIL:", f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
