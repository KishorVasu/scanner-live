"""scan-runner core (stdlib only). The only component allowed to start containers (rule R8).

It accepts a request naming a scanner, a job, a source volume and at most one relative target path. Everything else
(image, digest, arguments, limits, network) comes from this file and scanners/images/images.lock. A scanner whose digest
is not pinned cannot run.
"""

import json
import re
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

LOCK_PATH = Path(__file__).resolve().parent.parent / "scanners" / "images" / "images.lock"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
REQUEST_KEYS = {"scanner", "job_id", "mount_ref", "target"}
# "egress" is the internal `sp-scan` network: its only way out is the allowlisting Squid proxy (SCANNING_STRATEGY §4).
NETWORKS = {"none": "none", "egress": "sp-scan"}
PROXY = "http://scan-proxy:3128"
PROXY_ENV = {"HTTPS_PROXY": PROXY, "https_proxy": PROXY, "HTTP_PROXY": PROXY, "http_proxy": PROXY,
             "npm_config_https_proxy": PROXY, "npm_config_proxy": PROXY, "NO_PROXY": "", "no_proxy": ""}
DB_VOLUMES = {"osv": "sp-vulndb-osv", "trivy": "sp-vulndb-trivy"}
DB_MAX_AGE_S = 48 * 3600
# OSV ecosystems mirrored for the company's stacks (npm/Node, Python, PHP, Android/Kotlin, Flutter, iOS, Go, Ruby,
# .NET/Unity, Rust). A lockfile from any other ecosystem fails the offline scan instead of passing silently.
OSV_ECOSYSTEMS = ["npm", "PyPI", "Packagist", "Maven", "Pub", "SwiftURL", "Go", "RubyGems", "NuGet", "crates.io"]
OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"

# Fixed argument templates. `{target}` is the only substitution, and only where listed.
TEMPLATES: dict[str, dict] = {
    "osv_scanner": {"argv": ["scan", "source", "--recursive", "--offline", "--format", "json",
                             "--output-file", "/report/report.json", "/src"], "report": "file", "db": "osv",
                    "env": {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/db"}},
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
                         "--metrics", "off", "--disable-version-check", "/src"], "report": "file",
                # Rules are baked into the image (scanners/images/semgrep); semgrep's settings/logs go to the tmpfs.
                "env": {"HOME": "/tmp", "XDG_CONFIG_HOME": "/tmp/.config", "XDG_CACHE_HOME": "/tmp/.cache"}},
    "trivy": {"argv": ["fs", "--format", "json", "--output", "/report/report.json", "--scanners", "vuln,misconfig",
                       "--cache-dir", "/db", "--cache-backend", "memory", "--skip-db-update", "--skip-check-update",
                       "--offline-scan", "/src"], "report": "file", "db": "trivy"},
}

# Offline DB refresh jobs: pinned images, fixed argv, egress only through the proxy, writing into /db/incoming.
# `image` names the images.lock entry. After a successful download, the helper swaps it into place (commit step).
SYNC: dict[str, dict] = {
    "osv": {"image": "curl",
            "argv": ["curl", "--fail", "--silent", "--show-error", "--proto", "=https", "--proto-redir", "=https",
                     "--retry", "3", "--create-dirs",
                     *[x for e in OSV_ECOSYSTEMS
                       for x in ("-o", f"/db/incoming/osv-scalibr/{e}/all.zip", f"{OSV_BUCKET}/{e}/all.zip")]],
            # osv-scanner v2 reads <OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY>/osv-scalibr/<ecosystem>/all.zip (CI run 7).
            "commit": "osv-scalibr"},
    "trivy": {"image": "trivy",
              "argv": ["image", "--download-db-only", "--cache-dir", "/db/incoming",
                       "--db-repository", "ghcr.io/aquasecurity/trivy-db:2"],
              # The DB unpacks to ~700 MB: far past the 256 MB /tmp tmpfs, so Trivy's temp files go on the volume.
              "env": {"HOME": "/tmp", "TMPDIR": "/db/incoming/tmp"}, "commit": "db"},
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


def _env(env: dict) -> list[str]:
    return [x for k, v in env.items() for x in ("--env", f"{k}={v}")]


def _sandbox(name: str, label: str, network: str) -> list[str]:
    """Flags shared by every scanner and sync container."""
    return ["docker", "run", "--rm", "--name", name, "--label", f"sp.job={label}", "--user", "10001:10001",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", LIMITS["pids"], "--memory", LIMITS["memory"], "--cpus", LIMITS["cpus"],
            "--network", network, "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m"]


def _image_ref(name: str, images: dict, registry: str | None) -> str:
    img = images.get(name) or {}
    if not img.get("reviewed_by") or not DIGEST.fullmatch(str(img.get("digest"))):
        raise RequestError(f"{name} image is not pinned and reviewed; refusing to run")
    repo = f"{registry.rstrip('/')}/{name}" if registry else img["image"].split(" ")[0]
    return f"{repo}@{img['digest']}"


def docker_argv(req: ScanRequest, images: dict, registry: str | None, image_ref: str | None = None) -> list[str]:
    """The complete `docker run` command. No shell is involved; every element is a separate argument.

    `image_ref` exists only for the CI scanner-live check of locally built images; the HTTP service never passes it.
    """
    img = images[req.scanner]
    repo = f"{registry.rstrip('/')}/{req.scanner}" if registry else img["image"].split(" ")[0]
    tpl = TEMPLATES[req.scanner]
    argv = [a.replace("{target}", req.target or "") for a in tpl["argv"]]
    workdir = f"/src/{req.target}" if tpl.get("workdir_target") and req.target else "/src"
    network = img.get("network", "none")
    return [
        *_sandbox(f"sp-scan-{req.job_id}", req.job_id, NETWORKS[network]),
        "--mount", f"type=volume,src={req.mount_ref},dst=/src,readonly",
        "--mount", f"type=volume,src=sp-report-{req.job_id},dst=/report",
        *(["--mount", f"type=volume,src={DB_VOLUMES[tpl['db']]},dst=/db,readonly"] if tpl.get("db") else []),
        "--workdir", workdir,
        *_env({**(PROXY_ENV if network == "egress" else {}), **tpl.get("env", {})}),
        image_ref or f"{repo}@{img['digest']}",
        *argv,
    ]


def _helper(images: dict, registry: str | None, label: str, mount: str, cmd: list[str], chown: bool = False) -> list[str]:
    """Tiny housekeeping container (no network, read-only root, 32 pids). Runs as uid 10001, or as root holding only
    CAP_CHOWN when it must hand a fresh root-owned volume to 10001.

    ponytail: the helper is the npm_audit image (node:22-alpine, has busybox), so it is pinned and review-gated by the
    same images.lock entry; give it its own entry if npm_audit ever moves to an image without a shell.
    """
    try:
        ref = _image_ref(HELPER, images, registry)
    except RequestError:
        raise RequestError("helper image is not pinned and reviewed; refusing to run") from None
    who = ["--cap-add", "CHOWN"] if chown else ["--user", "10001:10001"]
    return ["docker", "run", "--rm", "--network", "none", "--read-only", "--security-opt", "no-new-privileges:true",
            "--pids-limit", "32", "--memory", "128m", "--label", f"sp.job={label}", "--cap-drop", "ALL", *who,
            "--mount", mount, ref, *cmd]


def helper_argv(req: ScanRequest, images: dict, registry: str | None, step: str) -> list[str]:
    """`prepare` hands the job's empty report volume to uid 10001; `readback` prints the report, capped in size."""
    vol = f"type=volume,src=sp-report-{req.job_id},dst=/report"
    if step == "prepare":
        return _helper(images, registry, req.job_id, vol, ["chown", "10001:10001", "/report"], chown=True)
    return _helper(images, registry, req.job_id, vol + ",readonly",
                   ["head", "-c", str(MAX_REPORT_BYTES + 1), "/report/report.json"])


def _docker(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, timeout=timeout, check=False)


def db_age_s(db: str, images: dict, registry: str | None, label: str) -> int | None:
    """Seconds since the offline DB was last committed, or None when it is missing or unreadable."""
    proc = _docker(_helper(images, registry, label, f"type=volume,src={DB_VOLUMES[db]},dst=/db,readonly",
                           ["cat", "/db/synced_at"]))
    try:
        return max(0, int(time.time()) - int(proc.stdout.strip())) if proc.returncode == 0 else None
    except ValueError:
        return None


def run(req: ScanRequest, images: dict, registry: str | None, image_ref: str | None = None) -> dict:
    """Run one scan, read its report back, and always remove the container's volumes.

    Returns {"exit_code", "report"} or {"exit_code", "error"}, plus "stderr_tail" for diagnostics, which main.py
    strips before answering (scanner stderr is untrusted and could echo a secret). A missing source volume, a
    missing or stale offline DB, a missing or oversized report, or a timeout is an error, never an empty
    (clean-looking) report: rule 11.
    """
    try:
        # `docker run --mount` silently creates a missing volume, and an empty /src scans as "no findings".
        if _docker(["docker", "volume", "inspect", req.mount_ref]).returncode != 0:
            return {"exit_code": None, "error": "source volume missing; nothing was scanned"}
        db = TEMPLATES[req.scanner].get("db")
        if db:
            age = db_age_s(db, images, registry, req.job_id)
            if age is None:
                return {"exit_code": None, "error": f"offline {db} vulnerability DB missing; run the DB sync"}
            if age > DB_MAX_AGE_S:
                return {"exit_code": None, "error": f"offline {db} vulnerability DB is stale ({age // 3600} h old)"}
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


def sync_argv(db: str, images: dict, registry: str | None, job: str, image_ref: str | None = None) -> list[str]:
    s = SYNC[db]
    return [*_sandbox(f"sp-sync-{job}", job, NETWORKS["egress"]),
            "--mount", f"type=volume,src={DB_VOLUMES[db]},dst=/db",
            *_env({**PROXY_ENV, **s.get("env", {})}),
            image_ref or _image_ref(s["image"], images, registry), *s["argv"]]


def sync(db: str, images: dict, registry: str | None, image_ref: str | None = None) -> dict:
    """Refresh one offline vulnerability DB through the proxy, then swap it into place and stamp `synced_at`.

    A failed download leaves the previous DB untouched; scans keep using it until it is 48 h old, then fail.
    ponytail: the swap is two renames, not atomic; a scan that reads mid-swap fails (fail closed), and beat runs the
    sync an hour before the scans.
    """
    if db not in SYNC:
        return {"ok": False, "error": "unknown DB"}
    job = str(uuid.uuid4())
    vol = f"type=volume,src={DB_VOLUMES[db]},dst=/db"
    final = SYNC[db]["commit"]
    try:
        if _docker(_helper(images, registry, job, vol, ["chown", "10001:10001", "/db"], chown=True)).returncode != 0:
            return {"ok": False, "error": "could not prepare the DB volume"}
        _docker(_helper(images, registry, job, vol, ["rm", "-rf", "/db/incoming"]))
        _docker(_helper(images, registry, job, vol, ["mkdir", "-p", "/db/incoming/tmp"]))
        proc = _docker(sync_argv(db, images, registry, job, image_ref), timeout=LIMITS["timeout_s"])
        tail = {"exit_code": proc.returncode, "stderr_tail": proc.stderr.decode("utf-8", "replace")[-1500:]}
        if proc.returncode != 0:
            _docker(_helper(images, registry, job, vol, ["rm", "-rf", "/db/incoming"]))
            return {"ok": False, "error": "download failed; previous DB kept", **tail}
        commit = (f"rm -rf /db/{final} && mv /db/incoming/{final} /db/{final} && rm -rf /db/incoming"
                  " && date +%s > /db/synced_at")
        if _docker(_helper(images, registry, job, vol, ["sh", "-c", commit])).returncode != 0:
            return {"ok": False, "error": "could not commit the downloaded DB", **tail}
        return {"ok": True, **tail}
    except subprocess.TimeoutExpired:
        _docker(["docker", "rm", "-f", f"sp-sync-{job}"])
        return {"ok": False, "error": "timeout"}
    except RequestError as e:
        return {"ok": False, "error": str(e)}
