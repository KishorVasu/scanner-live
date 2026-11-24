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
        assert "healthcheck:" in block, name
        assert "limits:" in block, name


def test_data_networks_are_internal():
    for net in ("data", "scan-control", "app", "scan"):
        assert re.search(rf"^  {net}: \{{ internal: true[ ,]", COMPOSE, re.MULTILINE), net
    assert "ports:" not in _services()["postgres"] and "ports:" not in _services()["redis"]


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
