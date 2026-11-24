"""scan-runner request validation and sandbox command (T-R5, T-R6, T-R7). No container is started."""

import json
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runner  # noqa: E402

PINNED = "sha256:" + "ab" * 32


def images(digest=PINNED, reviewed_by="reviewer@example.test"):
    imgs, _ = runner.load_lock()
    return {k: {**v, "digest": digest, "reviewed_by": reviewed_by} for k, v in imgs.items()}


def req(**kw):
    job = kw.pop("job_id", str(uuid.uuid4()))
    return {"scanner": "osv_scanner", "job_id": job, "mount_ref": f"sp-src-{job}", **kw}


def test_committed_lock_is_well_formed_and_unreviewed():
    imgs, _ = runner.load_lock()
    assert set(imgs) == set(runner.TEMPLATES)
    for name, img in imgs.items():
        assert img["digest"] is None or runner.DIGEST.fullmatch(img["digest"]), name
    for name in imgs:
        with pytest.raises(runner.RequestError, match="not pinned|not been reviewed"):
            runner.validate(req(scanner=name, **({"target": "requirements.txt"} if name == "pip_audit" else {})), imgs)


def test_pinned_but_unreviewed_digest_is_refused():
    with pytest.raises(runner.RequestError, match="not been reviewed"):
        runner.validate(req(), images(reviewed_by=None))
    runner.validate(req(), images())  # reviewed: accepted


@pytest.mark.parametrize("bad", [
    {"scanner": "bash"},
    {"scanner": "osv_scanner", "extra": "--privileged"},
    {"job_id": "../../etc"},
])
def test_rejects_unknown_scanners_fields_and_ids(bad):
    with pytest.raises(runner.RequestError):
        runner.validate({**req(), **bad}, images())


def test_rejects_tag_or_malformed_digest():
    for d in ("latest", "sha256:abc", "v0.69.4"):
        with pytest.raises(runner.RequestError):
            runner.validate(req(), images(d))


def test_mount_must_be_the_jobs_own_volume():
    r = req()
    r["mount_ref"] = "sp-src-" + str(uuid.uuid4())
    with pytest.raises(runner.RequestError):
        runner.validate(r, images())
    r["mount_ref"] = "/var/run/docker.sock"
    with pytest.raises(runner.RequestError):
        runner.validate(r, images())


@pytest.mark.parametrize("target", ["../x", "/etc/passwd", "a/../../b", "C:/x", "a b", "x;rm -rf /", "$(id)"])
def test_target_paths_are_plain_and_relative(target):
    with pytest.raises(runner.RequestError):
        runner.validate(req(scanner="pip_audit", target=target), images())


def test_target_only_where_template_allows():
    with pytest.raises(runner.RequestError):
        runner.validate(req(scanner="gitleaks", target="src"), images())
    with pytest.raises(runner.RequestError):
        runner.validate(req(scanner="pip_audit"), images())  # requirements file required


def test_sandbox_command():
    r = runner.validate(req(scanner="pip_audit", target="api/requirements.txt"), images())
    argv = runner.docker_argv(r, images(), "registry.internal/mirror")
    joined = " ".join(argv)
    for flag in ("--read-only", "--cap-drop ALL", "--security-opt no-new-privileges:true", "--user 10001:10001",
                 "--memory 2g", "--pids-limit 256", "--rm"):
        assert flag in joined
    assert f"type=volume,src=sp-src-{r.job_id},dst=/src,readonly" in argv
    assert f"registry.internal/mirror/pip_audit@{PINNED}" in argv
    assert "--network" in argv and argv[argv.index("--network") + 1] == "sp-scan-egress"
    assert "/src/api/requirements.txt" in argv
    assert not any("docker.sock" in a or a == "--privileged" for a in argv)


def test_offline_scanners_get_no_network_and_npm_never_runs_scripts():
    g = runner.docker_argv(runner.validate(req(scanner="gitleaks"), images()), images(), None)
    assert g[g.index("--network") + 1] == "none" and "--redact" in g
    n = runner.docker_argv(runner.validate(req(scanner="npm_audit", target="web"), images()), images(), None)
    assert "--package-lock-only" in n and "--ignore-scripts" in n and n[n.index("--workdir") + 1] == "/src/web"
    assert "HOME=/tmp" in n  # npm needs a writable home on a read-only root filesystem
    scanner_args = n[next(i for i, a in enumerate(n) if "@sha256:" in a) + 1:]  # what runs inside the container
    assert scanner_args[:2] == ["npm", "audit"]
    assert not any(a in ("install", "ci", "run", "run-script", "exec") for a in scanner_args)
