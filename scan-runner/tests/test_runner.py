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


# ---------- run(): prepare, scan, readback, cleanup (fake docker; no container runtime needed) ----------

class FakeDocker:
    """Records every docker argv; answers by the step it recognises."""

    def __init__(self, *, src_exists=True, scan_rc=1, stdout=b"", report=b'{"results": []}', readback_rc=0):
        self.calls, self.src_exists, self.scan_rc, self.stdout = [], src_exists, scan_rc, stdout
        self.report, self.readback_rc = report, readback_rc

    def __call__(self, argv, **kw):
        import subprocess
        self.calls.append(argv)
        rc, out = 0, b""
        if argv[1:3] == ["volume", "inspect"]:
            rc = 0 if self.src_exists else 1
        elif "head" in argv:
            rc, out = self.readback_rc, self.report
        elif any("@sha256:" in a for a in argv) and "chown" not in argv:
            rc, out = self.scan_rc, self.stdout
        return subprocess.CompletedProcess(argv, rc, out, b"scanner stderr")


def _run(monkeypatch, fake, scanner="osv_scanner", **kw):
    monkeypatch.setattr(runner.subprocess, "run", fake)
    return runner.run(runner.validate(req(scanner=scanner, **kw), images()), images(), None)


def _removed(fake):
    return {c[-1] for c in fake.calls if c[1:3] == ["volume", "rm"]}


def test_file_report_is_read_back_and_volumes_removed(monkeypatch):
    fake = FakeDocker()
    out = _run(monkeypatch, fake)
    assert out["exit_code"] == 1 and out["report"] == '{"results": []}'
    prepare = next(c for c in fake.calls if "chown" in c)
    assert prepare[prepare.index("--cap-add") + 1] == "CHOWN" and "--network" in prepare
    readback = next(c for c in fake.calls if "head" in c)
    assert readback[readback.index("--user") + 1] == "10001:10001"
    assert any(a.endswith(",readonly") and "sp-report-" in a for a in readback)
    assert str(runner.MAX_REPORT_BYTES + 1) in readback
    job = fake.calls[0][-1].removeprefix("sp-src-")
    assert _removed(fake) == {f"sp-src-{job}", f"sp-report-{job}"}


def test_stdout_report_needs_no_readback(monkeypatch):
    fake = FakeDocker(stdout=b'{"auditReportVersion": 2}')
    out = _run(monkeypatch, fake, scanner="npm_audit", target="web")
    assert out["report"] == '{"auditReportVersion": 2}'
    assert not any("head" in c for c in fake.calls)


def test_missing_source_volume_is_an_error_not_an_empty_scan(monkeypatch):
    fake = FakeDocker(src_exists=False)
    out = _run(monkeypatch, fake)
    assert "report" not in out and "source volume missing" in out["error"]
    assert not any(any("@sha256:" in a for a in c) for c in fake.calls)  # no container started
    assert len(_removed(fake)) == 2


def test_missing_or_oversized_report_is_an_error(monkeypatch):
    assert "no report" in _run(monkeypatch, FakeDocker(readback_rc=1))["error"]
    big = FakeDocker(report=b"x" * (runner.MAX_REPORT_BYTES + 1))
    assert _run(monkeypatch, big)["error"] == "report too large"


def test_timeout_is_an_error_and_cleans_up(monkeypatch):
    import subprocess

    def slow(argv, **kw):
        if any("@sha256:" in a for a in argv) and "chown" not in argv and "head" not in argv:
            raise subprocess.TimeoutExpired(argv, 900)
        return subprocess.CompletedProcess(argv, 0, b"", b"")
    calls = []
    monkeypatch.setattr(runner.subprocess, "run", lambda argv, **kw: (calls.append(argv), slow(argv, **kw))[1])
    out = runner.run(runner.validate(req(), images()), images(), None)
    assert out == {"exit_code": None, "error": "timeout"}
    assert any(c[1:3] == ["rm", "-f"] for c in calls) and sum(c[1:3] == ["volume", "rm"] for c in calls) == 2


def test_unreviewed_helper_image_refuses_before_any_container(monkeypatch):
    imgs = images()
    imgs[runner.HELPER] = {**imgs[runner.HELPER], "reviewed_by": None}
    fake = FakeDocker()
    monkeypatch.setattr(runner.subprocess, "run", fake)
    out = runner.run(runner.validate(req(), imgs), imgs, None)
    assert "helper image" in out["error"]
    assert not any(any("@sha256:" in a for a in c) for c in fake.calls)
