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


def run(req: ScanRequest, images: dict, registry: str | None) -> dict:  # pragma: no cover - needs a container runtime
    """Run one scan and always remove its volumes. Phase 3 follow-up: fetch source into sp-src-<job> and read the
    report out of sp-report-<job>; this needs Docker on the host and is not exercised in tests."""
    try:
        proc = subprocess.run(docker_argv(req, images, registry), capture_output=True, timeout=LIMITS["timeout_s"],
                              check=False)
        return {"exit_code": proc.returncode, "stdout": proc.stdout.decode("utf-8", "replace")
                if TEMPLATES[req.scanner]["report"] == "stdout" else None}
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", f"sp-scan-{req.job_id}"], capture_output=True, check=False)
        return {"exit_code": None, "error": "timeout"}
    finally:
        for vol in (req.mount_ref, f"sp-report-{req.job_id}"):
            subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True, check=False)
