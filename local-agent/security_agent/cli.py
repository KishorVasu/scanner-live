"""security-agent CLI. Outbound HTTPS only; the private key lives in the OS keychain."""

import base64
import json
import os
import platform
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import keyring
import typer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security_agent import __version__
from security_agent.paths import PathError, locally_allowed, resolve_root
from security_agent.scan import scan_root

app = typer.Typer(no_args_is_help=True, add_completion=False)
KEYRING_SERVICE = "security-platform-agent"
SESSION_CONTEXT = b"sp-agent-session:"


def config_dir() -> Path:
    d = Path(os.environ.get("SECURITY_AGENT_HOME", Path.home() / ".security-agent"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _config() -> dict:
    path = config_dir() / "config.json"
    if not path.exists():
        raise typer.BadParameter("not registered; run `security-agent register` first")
    return json.loads(path.read_text())


def log_local(action: str, outcome: str, detail: dict | None = None) -> dict:
    event = {"at": datetime.now(UTC).isoformat(), "action": action, "outcome": outcome, "detail": detail or {}}
    with (config_dir() / "agent.log.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")
    return event


def _client(server: str) -> httpx.Client:
    if not server.startswith("https://") and not server.startswith("http://127.0.0.1"):
        raise typer.BadParameter("server must use https:// (http only for 127.0.0.1 testing)")
    return httpx.Client(base_url=server.rstrip("/"), timeout=60, follow_redirects=False)


@app.command()
def register(server: str = typer.Option(..., help="https://security.example.internal"),
             allow: list[str] = typer.Option(..., help="local folder this machine allows the server to inventory "
                                                       "(repeatable); server roots outside these are refused"),
             code: str = typer.Option(..., prompt=True, hide_input=True, help="one-time enrolment code")) -> None:
    """Generate an Ed25519 key in the OS keychain and enrol with a one-time code."""
    local_allow = [str(resolve_root(a)) for a in allow]
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with _client(server) as c:
        r = c.post("/api/agents/register", json={
            "code": code, "public_key": base64.b64encode(public).decode(),
            "host_fingerprint": uuid.UUID(int=uuid.getnode()).hex, "os": platform.system(), "agent_version": __version__})
    if r.status_code != 200:
        log_local("register", "failure", {"status": r.status_code})
        typer.echo(f"registration failed: {r.status_code}", err=True)
        raise typer.Exit(1)
    agent_id = r.json()["agent_id"]
    private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    keyring.set_password(KEYRING_SERVICE, agent_id, base64.b64encode(private).decode())
    (config_dir() / "config.json").write_text(json.dumps({"server": server, "agent_id": agent_id,
                                                          "local_allow": local_allow}))
    log_local("register", "success", {"agent_id": agent_id})
    typer.echo(f"registered agent {agent_id}")


def _session(c: httpx.Client, agent_id: str) -> str:
    secret = keyring.get_password(KEYRING_SERVICE, agent_id)
    if not secret:
        typer.echo("private key missing from the OS keychain; re-register", err=True)
        raise typer.Exit(1)
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(secret))
    nonce = c.post("/api/agents/challenge", json={"agent_id": agent_id}).raise_for_status().json()["nonce"]
    sig = key.sign(SESSION_CONTEXT + nonce.encode() + b":" + agent_id.encode())
    r = c.post("/api/agents/session", json={"agent_id": agent_id, "nonce": nonce,
                                           "signature": base64.b64encode(sig).decode()})
    r.raise_for_status()
    return r.json()["token"]


@app.command()
def scan(alias: list[str] = typer.Option(None, help="limit to these approved aliases")) -> None:
    """Inventory every approved root (roots come from the server, never from the command line)."""
    cfg = _config()
    events = []
    with _client(cfg["server"]) as c:
        c.headers["Authorization"] = f"Bearer {_session(c, cfg['agent_id'])}"
        roots = c.get("/api/agents/me/config").raise_for_status().json()["approved_roots"]
        for root in roots:
            if alias and root["alias"] not in alias:
                continue
            if not locally_allowed(root["path"], cfg.get("local_allow", [])):
                # Defence in depth: a compromised server cannot point the agent at folders the owner did not allow.
                events.append(log_local("scan", "refused_not_locally_allowed", {"alias": root["alias"]}))
                typer.echo(f"{root['alias']}: refused (not in this machine's --allow list)", err=True)
                continue
            try:
                payload, stats = scan_root(root["alias"], root["path"])
            except (PathError, OSError) as e:
                events.append(log_local("scan", "error", {"alias": root["alias"], "error": type(e).__name__}))
                continue
            r = c.post("/api/agents/me/inventory", json=payload)
            outcome = "uploaded" if r.status_code == 200 else f"rejected_{r.status_code}"
            events.append(log_local("scan", outcome, {"alias": root["alias"], **stats,
                                                      "dependencies": len(payload["dependencies"])}))
            typer.echo(f"{root['alias']}: {outcome} ({len(payload['dependencies'])} dependencies)")
        c.post("/api/agents/me/log", json={"events": [{k: e[k] for k in ("action", "outcome", "detail")} for e in events]})


if __name__ == "__main__":
    app()
