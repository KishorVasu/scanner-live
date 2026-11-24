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
import time
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
    "trivy": (None, {"expect": "lodash"}),
    "semgrep": (None, {"expect": "subprocess-shell-true", "image_ref": "sp-semgrep:ci"}),
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
    # Pattern for Semgrep to flag; never imported or run.
    (d / "tool.py").write_text("import subprocess\n\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n")
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


SQUID = "ubuntu/squid:6.6-24.04_edge@sha256:d9c34c5ab74c6dd41cf1070d9b4221aac072e67e983527ca2d41512958f77506"


def start_proxy() -> None:
    """The same network layout and Squid flags as deploy/docker-compose.yml: `sp-scan` is internal, the proxy alone
    also sits on `sp-scan-egress`."""
    sh("docker", "network", "create", "--internal", runner.NETWORKS["egress"])
    sh("docker", "network", "create", "sp-scan-egress")
    sh("docker", "run", "-d", "--name", "scan-proxy", "--network", "sp-scan-egress", "--user", "13:13",
       "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
       *[x for d in ("/tmp", "/var/spool/squid", "/var/log/squid", "/run") for x in ("--tmpfs", d)],
       "-v", f"{ROOT / 'deploy' / 'scan-proxy' / 'squid.conf'}:/etc/squid/squid.conf:ro",
       "--entrypoint", "squid", SQUID, "-N", "-f", "/etc/squid/squid.conf")
    sh("docker", "network", "connect", runner.NETWORKS["egress"], "scan-proxy")


def egress_checks(images: dict) -> dict:
    """From the scan network: allowlisted host via the proxy works; any other host, plain HTTP, or going direct
    does not. Exit codes are recorded as evidence."""
    curl = f"{images['curl']['image']}@{images['curl']['digest']}"

    def probe(*args: str) -> int:
        return sh("docker", "run", "--rm", "--network", runner.NETWORKS["egress"], "--read-only", "--cap-drop", "ALL",
                  curl, "--silent", "--output", "/dev/null", "--max-time", "20", *args, check=False).returncode

    for _ in range(30):  # wait for Squid
        if (allowed := probe("--fail", "--proxy", runner.PROXY, "https://pypi.org/simple/")) == 0:
            break
        time.sleep(2)
    return {
        "allowlisted_via_proxy": allowed,
        "other_host_via_proxy": probe("--fail", "--proxy", runner.PROXY, "https://example.com/"),
        "plain_http_via_proxy": probe("--fail", "--proxy", runner.PROXY, "http://pypi.org/simple/"),
        "direct_without_proxy": probe("--fail", "--noproxy", "*", "https://pypi.org/simple/"),
    }


def main() -> int:
    images, _ = runner.load_lock()
    # CI is the evidence step *before* human review, so the review gate is satisfied in memory only, never on disk.
    images = {k: {**v, "reviewed_by": "ci-scanner-live", "digest": v["digest"] or "sha256:" + "0" * 64}
              for k, v in images.items()}
    results, failures = [], []
    start_proxy()
    egress = egress_checks(images)
    results.append({"check": "egress", **egress})
    if egress["allowlisted_via_proxy"] != 0:
        failures.append(f"proxy: allowlisted host not reachable ({egress})")
    if any(egress[k] == 0 for k in ("other_host_via_proxy", "plain_http_via_proxy", "direct_without_proxy")):
        failures.append(f"proxy: traffic that must be refused got through ({egress})")
    for db in runner.SYNC:
        out = runner.sync(db, images, None)
        results.append({"check": f"{db}_db_sync", **out})
        if not out.get("ok"):
            failures.append(f"{db} DB sync failed: {out.get('error')}")
    src, fake = fixture()
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
            # Semgrep rule IDs are long dotted paths, so match on a substring.
            hit = any(opts["expect"] in x for x in r.get("rules", []) + r.get("packages", []))
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
