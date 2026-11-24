"""scan-runner core (stdlib only). The only component allowed to start containers (rule R8).

It accepts a request naming a scanner, a job, a source volume and at most one relative target path. Everything else
(image, digest, arguments, limits, network) comes from this file and scanners/images/images.lock. A scanner whose digest
is not pinned cannot run.
"""

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

LOCK_PATH = Path(__file__).resolve().parent.parent / "scanners" / "images" / "images.lock"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
REQUEST_KEYS = {"scanner", "job_id", "mount_ref", "target"}
NETWORKS = {"none": "none", "egress": "sp-scan-egress"}

# Fixed argument templates. `{target}` is the only substitution, and only where listed.
TEMPLATES: dict[str, dict] = {
    "osv_scanner": {"argv": ["scan", "source", "--recursive", "--format", "json", "--output", "/report/report.json", "/src"],
                    "report": "file"},
    "npm_audit": {"argv": ["npm", "audit", "--package-lock-only", "--json", "--ignore-scripts"],
                  "report": "stdout", "workdir_target": True,
                  "env": {"HOME": "/tmp", "npm_config_cache": "/tmp/.npm", "npm_config_update_notifier": "false"}},
    "pip_audit": {"argv": ["pip-audit", "--requirement", "/src/{target}", "--no-deps", "--disable-pip", "--format", "json",
                           "--output", "/report/report.json"], "report": "file", "target_required": True,
                  # Root fs is read-only and uid 10001 has no home; pip-audit's cache must live on the /tmp tmpfs.
                  "env": {"HOME": "/tmp", "XDG_CACHE_HOME": "/tmp/.cache"}},
    "gitleaks": {"argv": ["git", "--redact", "--report-format", "json", "--report-path", "/report/report.json",
                          "--exit-code", "1", "/src"], "report": "file",
                 # The source volume is owned by another uid; let git read it (read-only mount, nothing executes).
                 "env": {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "/src"}},
    "semgrep": {"argv": ["semgrep", "scan", "--config", "/rules", "--json", "--output", "/report/report.json",
                         "--metrics", "off", "--disable-version-check", "/src"], "report": "file"},
    "trivy": {"argv": ["fs", "--format", "json", "--output", "/report/report.json", "--scanners", "vuln,misconfig",
                       "--skip-db-update", "--offline-scan", "/src"], "report": "file"},
}
LIMITS = {"memory": "2g", "cpus": "1", "pids": "256", "timeout_s": 900}
MAX_REPORT_BYTES = 64 * 1024 * 1024  # same cap as the API's adapters (apps/api/app/scanners/base.py)
HELPER = "npm_audit"  # images.lock entry whose image runs the prepare/readback helper containers


class RequestError(Exception):
    pass


@dataclass(frozen=True)
class ScanRequest:
    scanner: str
    job_id: str
    mount_ref: str
    target: str | None


def load_lock(path: Path = LOCK_PATH) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["images"], data.get("registry")


def _safe_target(target: str) -> str:
    norm = target.replace("\\", "/")
    parts = PurePosixPath(norm).parts
    if (not norm or norm.startswith("/") or ".." in parts or "\0" in norm or (len(norm) > 1 and norm[1] == ":")
            or not re.fullmatch(r"[A-Za-z0-9._/\-]{1,300}", norm)):
        raise RequestError("target must be a plain relative path inside the repository")
    return norm


def validate(raw: dict, images: dict) -> ScanRequest:
    if not isinstance(raw, dict) or set(raw) - REQUEST_KEYS:
        raise RequestError("unknown request fields")
    scanner = raw.get("scanner")
    if scanner not in TEMPLATES or scanner not in images:
        raise RequestError("scanner not allowlisted")
    digest = images[scanner].get("digest")
    if not digest or not DIGEST.fullmatch(str(digest)):
        raise RequestError(f"{scanner} image is not pinned by digest; refusing to run")
    if not images[scanner].get("reviewed_by"):
        raise RequestError(f"{scanner} image digest has not been reviewed; refusing to run")
    job_id = str(raw.get("job_id", ""))
    if not UUID.fullmatch(job_id):
        raise RequestError("job_id must be a UUID")
    mount_ref = str(raw.get("mount_ref", ""))
    if mount_ref != f"sp-src-{job_id}":
        raise RequestError("mount_ref must be the job's own source volume")
    tpl = TEMPLATES[scanner]
    target = raw.get("target")
    if target is not None:
        if not (tpl.get("target_required") or tpl.get("workdir_target")):
            raise RequestError("this scanner takes no target")
        target = _safe_target(str(target))
    elif tpl.get("target_required"):
        raise RequestError("target required")
    return ScanRequest(scanner, job_id, mount_ref, target)


def docker_argv(req: ScanRequest, images: dict, registry: str | None, image_ref: str | None = None) -> list[str]:
    """The complete `docker run` command. No shell is involved; every element is a separate argument.

    `image_ref` exists only for the CI scanner-live check of locally built images; the HTTP service never passes it.
    """
    img = images[req.scanner]
    repo = f"{registry.rstrip('/')}/{req.scanner}" if registry else img["image"].split(" ")[0]
    tpl = TEMPLATES[req.scanner]
    argv = [a.replace("{target}", req.target or "") for a in tpl["argv"]]
    workdir = f"/src/{req.target}" if tpl.get("workdir_target") and req.target else "/src"
    return [
        "docker", "run", "--rm",
        "--name", f"sp-scan-{req.job_id}",
        "--label", f"sp.job={req.job_id}",
        "--user", "10001:10001",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", LIMITS["pids"],
        "--memory", LIMITS["memory"],
        "--cpus", LIMITS["cpus"],
        "--network", NETWORKS[img.get("network", "none")],
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
        "--mount", f"type=volume,src={req.mount_ref},dst=/src,readonly",
        "--mount", f"type=volume,src=sp-report-{req.job_id},dst=/report",
        "--workdir", workdir,
        *[x for k, v in tpl.get("env", {}).items() for x in ("--env", f"{k}={v}")],
        image_ref or f"{repo}@{img['digest']}",
        *argv,
    ]


def helper_argv(req: ScanRequest, images: dict, registry: str | None, step: str) -> list[str]:
    """Tiny housekeeping containers around a scan: `prepare` hands the empty report volume to uid 10001 (scanner
    images run as 10001 and a fresh volume is root-owned); `readback` prints the report, read-only, capped in size.

    ponytail: the helper is the npm_audit image (node:22-alpine, has busybox), so it is pinned and review-gated by the
    same images.lock entry; give it its own entry if npm_audit ever moves to an image without a shell.
    """
    if not images[HELPER].get("reviewed_by") or not DIGEST.fullmatch(str(images[HELPER].get("digest"))):
        raise RequestError("helper image is not pinned and reviewed; refusing to run")
    repo = f"{registry.rstrip('/')}/{HELPER}" if registry else images[HELPER]["image"].split(" ")[0]
    common = ["docker", "run", "--rm", "--network", "none", "--read-only", "--security-opt", "no-new-privileges:true",
              "--pids-limit", "32", "--memory", "128m", "--label", f"sp.job={req.job_id}"]
    vol = f"type=volume,src=sp-report-{req.job_id},dst=/report"
    if step == "prepare":  # root with only CAP_CHOWN, for one chown of the empty mount point
        return [*common, "--cap-drop", "ALL", "--cap-add", "CHOWN", "--mount", vol,
                f"{repo}@{images[HELPER]['digest']}", "chown", "10001:10001", "/report"]
    return [*common, "--cap-drop", "ALL", "--user", "10001:10001", "--mount", vol + ",readonly",
            f"{repo}@{images[HELPER]['digest']}", "head", "-c", str(MAX_REPORT_BYTES + 1), "/report/report.json"]


def _docker(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, timeout=timeout, check=False)


def run(req: ScanRequest, images: dict, registry: str | None, image_ref: str | None = None) -> dict:
    """Run one scan, read its report back, and always remove the container's volumes.

    Returns {"exit_code", "report"} or {"exit_code", "error"}, plus "stderr_tail" for diagnostics, which main.py
    strips before answering (scanner stderr is untrusted and could echo a secret). A missing source volume, a
    missing or oversized report, or a timeout is an error, never an empty (clean-looking) report: rule 11.
    """
    try:
        # `docker run --mount` silently creates a missing volume, and an empty /src scans as "no findings".
        if _docker(["docker", "volume", "inspect", req.mount_ref]).returncode != 0:
            return {"exit_code": None, "error": "source volume missing; nothing was scanned"}
        if _docker(helper_argv(req, images, registry, "prepare")).returncode != 0:
            return {"exit_code": None, "error": "could not prepare the report volume"}
        proc = _docker(docker_argv(req, images, registry, image_ref), timeout=LIMITS["timeout_s"])
        tail = {"stderr_tail": proc.stderr.decode("utf-8", "replace")[-1500:]}
        if TEMPLATES[req.scanner]["report"] == "stdout":
            report = proc.stdout
        else:
            back = _docker(helper_argv(req, images, registry, "readback"))
            if back.returncode != 0:
                return {"exit_code": proc.returncode, "error": "scanner wrote no report", **tail}
            report = back.stdout
        if len(report) > MAX_REPORT_BYTES:
            return {"exit_code": proc.returncode, "error": "report too large", **tail}
        return {"exit_code": proc.returncode, "report": report.decode("utf-8", "replace"), **tail}
    except subprocess.TimeoutExpired:
        _docker(["docker", "rm", "-f", f"sp-scan-{req.job_id}"])
        return {"exit_code": None, "error": "timeout"}
    except RequestError as e:
        return {"exit_code": None, "error": str(e)}
    finally:
        for vol in (req.mount_ref, f"sp-report-{req.job_id}"):
            subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True, check=False)
