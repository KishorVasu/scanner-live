"""scan-runner HTTP service: execution switch (SP_RUNNER_EXECUTE) and response hygiene. No container is started."""

import json
import sys
import threading
import urllib.error
import urllib.request
import uuid
from http.server import HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main  # noqa: E402
import runner  # noqa: E402

LOCK = {"registry": None, "images": {"gitleaks": {"image": "ghcr.io/gitleaks/gitleaks", "version": "v8.30.1",
                                                  "digest": "sha256:" + "ab" * 32, "network": "none",
                                                  "reviewed_by": "reviewer@example.test"}}}


@pytest.fixture
def server(tmp_path, monkeypatch):
    lock = tmp_path / "images.lock"
    lock.write_text(json.dumps(LOCK))
    monkeypatch.setenv("SP_IMAGES_LOCK", str(lock))
    srv = HTTPServer(("127.0.0.1", 0), main.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def post(url, body):
    r = urllib.request.Request(url + "/scan", json.dumps(body).encode(), {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def body():
    job = str(uuid.uuid4())
    return {"scanner": "gitleaks", "job_id": job, "mount_ref": f"sp-src-{job}"}


@pytest.mark.parametrize("value", [None, "0", "true", "yes"])
def test_execution_is_off_unless_exactly_1(server, monkeypatch, value):
    if value is None:
        monkeypatch.delenv("SP_RUNNER_EXECUTE", raising=False)
    else:
        monkeypatch.setenv("SP_RUNNER_EXECUTE", value)
    monkeypatch.setattr(runner, "run", lambda *a, **k: pytest.fail("must not run"))
    code, out = post(server, body())
    assert code == 501 and out["error"] == "execution disabled"


def test_execution_on_runs_and_strips_stderr(server, monkeypatch):
    monkeypatch.setenv("SP_RUNNER_EXECUTE", "1")
    monkeypatch.setattr(runner, "run", lambda *a, **k: {"exit_code": 1, "report": "{}", "stderr_tail": "ghp_x"})
    code, out = post(server, body())
    assert code == 200 and out == {"exit_code": 1, "report": "{}"}


def test_invalid_request_is_refused_even_when_enabled(server, monkeypatch):
    monkeypatch.setenv("SP_RUNNER_EXECUTE", "1")
    monkeypatch.setattr(runner, "run", lambda *a, **k: pytest.fail("must not run"))
    code, _ = post(server, {**body(), "scanner": "bash"})
    assert code == 400


def post_sync(url, body):
    r = urllib.request.Request(url + "/sync", json.dumps(body).encode(), {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.mark.parametrize("bad", [{}, {"db": "../x"}, {"db": "osv", "url": "https://evil.example"}, ["osv"]])
def test_sync_accepts_only_a_known_db_name(server, monkeypatch, bad):
    monkeypatch.setenv("SP_RUNNER_EXECUTE", "1")
    monkeypatch.setattr(runner, "sync", lambda *a, **k: pytest.fail("must not run"))
    assert post_sync(server, bad)[0] == 400


def test_sync_respects_the_switch_and_strips_stderr(server, monkeypatch):
    monkeypatch.delenv("SP_RUNNER_EXECUTE", raising=False)
    monkeypatch.setattr(runner, "sync", lambda *a, **k: pytest.fail("must not run"))
    assert post_sync(server, {"db": "osv"})[0] == 501
    monkeypatch.setenv("SP_RUNNER_EXECUTE", "1")
    monkeypatch.setattr(runner, "sync", lambda *a, **k: {"ok": True, "exit_code": 0, "stderr_tail": "x"})
    assert post_sync(server, {"db": "trivy"}) == (200, {"ok": True, "exit_code": 0})
