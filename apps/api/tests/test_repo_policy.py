"""T-R7 and T-R8 on this repository's own config."""

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = (ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
SOCKETS = ("docker.sock", "podman.sock", "containerd.sock", "/var/run/docker")


def _load_pin_checker():
    spec = importlib.util.spec_from_file_location("pins", ROOT / "scripts" / "check_action_pins.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _services() -> dict[str, str]:
    """Split the `services:` section into blocks by two-space-indented keys.

    ponytail: text parsing instead of a YAML dependency; fine while compose stays one hand-written file.
    """
    body = COMPOSE.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    parts = re.split(r"^  ([a-z][a-z0-9-]*):\s*$", body, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2]))


def test_compose_has_all_services():
    assert set(_services()) >= {"caddy", "web", "api", "worker", "beat", "scan-runner", "postgres", "redis"}


def test_no_container_socket_outside_scan_runner():
    for name, block in _services().items():
        if name != "scan-runner":
            assert not any(s in block for s in SOCKETS), f"{name} mounts a container runtime socket"


def test_images_pinned_by_digest():
    for ref in re.findall(r"^\s*image:\s*(\S+)", COMPOSE, re.MULTILINE):
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), ref
    for dockerfile in ROOT.glob("**/Dockerfile"):
        if "node_modules" in dockerfile.parts:
            continue
        for ref in re.findall(r"^FROM\s+(\S+)", dockerfile.read_text(), re.MULTILINE):
            assert "@sha256:" in ref, f"{dockerfile}: {ref}"


def test_every_long_running_service_has_limits_and_healthcheck():
    for name, block in _services().items():
        if name == "migrate":
            continue
        # Tempo's image is distroless (nothing to run a check with); Prometheus' up{job="tempo"} covers it.
        assert "healthcheck:" in block or name == "tempo", name
        assert "limits:" in block, name


def test_data_networks_are_internal():
    for net in ("data", "scan-control", "app", "scan", "monitoring"):
        assert re.search(rf"^  {net}: \{{ internal: true[ ,]", COMPOSE, re.MULTILINE), net
    assert "ports:" not in _services()["postgres"] and "ports:" not in _services()["redis"]


def test_only_caddy_publishes_beyond_loopback():
    for name, block in _services().items():
        line = re.search(r"^\s*ports: \[(.*)\]$", block, re.MULTILINE)
        for port in re.findall(r'"([^"]+)"', line.group(1)) if line else []:
            assert name == "caddy" or port.startswith("127.0.0.1:"), f"{name} publishes {port}"
    assert '"127.0.0.1:3001:3000"' in _services()["grafana"]


def test_traces_go_to_tempo_directly_not_through_the_fetch_proxy():
    assert re.search(r"NO_PROXY: [^\n]*\btempo\b", COMPOSE)


def test_workflow_actions_pinned():
    checker = _load_pin_checker()
    assert checker.main(ROOT) == 0
    assert checker.violations("    - uses: actions/checkout@v4") == ["actions/checkout@v4"]
    assert checker.violations("  uses: actions/checkout@" + "a" * 40) == []
    assert checker.violations("  uses: docker://alpine:3") == ["docker://alpine:3"]


def test_services_using_redis_get_its_secret():
    for name, block in _services().items():
        if "*api-env" in block:
            assert "redis_password" in block, name


def test_caddy_blocks_metrics_with_handle():
    caddy = (ROOT / "deploy" / "Caddyfile").read_text()
    assert re.search(r"handle @internal \{\s*respond 404", caddy)


def test_no_secret_files_tracked_by_ignore_rules():
    ignore = (ROOT / ".gitignore").read_text()
    for pattern in (".env", "deploy/secrets/*", "*.pem", "*.key"):
        assert pattern in ignore


def test_app_services_run_as_non_root_users():
    for name in ("web", "api", "migrate", "worker", "beat", "scan-runner"):
        user = re.search(r'^\s*user: "(\d+):', _services()[name], re.MULTILINE)
        assert user and user.group(1) != "0", name


def test_socket_override_touches_scan_runner_only():
    text = (ROOT / "deploy" / "docker-compose.scan-exec.yml").read_text(encoding="utf-8")
    body = text.split("\nservices:\n", 1)[1]
    assert re.findall(r"^  ([a-z][a-z0-9-]*):\s*$", body, re.MULTILINE) == ["scan-runner"]
    assert "docker.sock" in body


def test_deploy_shell_scripts_parse():
    import shutil
    import subprocess

    import pytest

    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("no POSIX sh here; runs in CI")
    for script in [*(ROOT / "deploy" / "backup").glob("*.sh"), *(ROOT / "deploy" / "server").glob("*.sh")]:
        r = subprocess.run([sh, "-n", str(script)], capture_output=True, text=True)
        assert r.returncode == 0, (script.name, r.stderr)


def test_load_test_stack_is_isolated_from_the_live_database():
    text = (ROOT / "deploy" / "server" / "loadtest.compose.yml").read_text(encoding="utf-8")
    assert "ports:" not in text and re.search(r"^  lt: \{ internal: true \}", text, re.MULTILINE)
    assert "postgres:5432/platform" not in text and "pg_data" not in text and "/run/secrets" not in text
    driver = (ROOT / "deploy" / "server" / "load_test.sh").read_text(encoding="utf-8")
    assert "-p sp-loadtest" in driver and "@lt-postgres:5432/sp_e2e" in driver
