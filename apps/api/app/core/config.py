"""Settings. Secret values come from files (Docker secrets), never from the repo."""

import base64
import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SP_", extra="ignore")

    environment: str = "development"  # development | test | production
    log_level: str = "INFO"

    database_url: str = "postgresql+asyncpg://platform_app@localhost:5432/platform"
    database_password_file: Path | None = None
    redis_url: str = "redis://localhost:6379/0"
    redis_password_file: Path | None = None

    master_key_file: Path | None = None  # base64 of 32 random bytes
    redaction_salt_file: Path | None = None  # any random bytes, >= 32

    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    totp_setup_minutes: int = 10
    cookie_secure: bool = True

    # GitHub App (read-only). Unset until the org decision (OQ-2); endpoints return 503 meanwhile.
    github_app_id: int | None = None
    github_app_slug: str | None = None
    github_private_key_file: Path | None = None
    github_webhook_secret_file: Path | None = None
    github_api_url: str = "https://api.github.com"
    webhook_repo_limit_per_minute: int = 30

    # Scanning
    report_dir: Path | None = None  # redacted raw reports; None keeps only the parsed result
    scan_runner_url: str = "http://scan-runner:8080"

    # Intelligence (Phase 4). The key file is mounted on the server; without it LLM steps are refused and the
    # deterministic rules decide alone.
    anthropic_api_key_file: Path | None = None
    llm_model: str = "claude-opus-5-5"
    llm_effort: str = "medium"

    # Local agents
    agent_enrolment_hours: int = 24
    agent_session_minutes: int = 15
    agent_challenge_seconds: int = 120
    agent_register_failures_per_ip: int = 10  # per login_window_minutes
    agent_challenges_per_minute: int = 10
    agent_session_failures_per_ip: int = 20

    approval_ttl_hours: int = 24
    login_max_failures: int = 5
    webhook_bad_signature_audits_per_minute: int = 10  # per IP; the 401 is always sent (review finding 7)
    login_max_failures_per_ip: int = 30  # password spraying across many emails (review finding 6)
    login_window_minutes: int = 15

    def resolved_database_url(self) -> str:
        url = make_url(self.database_url)
        if self.database_password_file:
            url = url.set(password=self.database_password_file.read_text().strip())
        return url.render_as_string(hide_password=False)

    def resolved_redis_url(self) -> str:
        if not self.redis_password_file:
            return self.redis_url
        scheme, rest = self.redis_url.split("://", 1)
        password = quote(self.redis_password_file.read_text().strip(), safe="")
        return f"{scheme}://:{password}@{rest.split('@')[-1]}"


def _read_secret(path: Path | None, name: str, environment: str, size: int) -> bytes:
    if path is not None:
        return path.read_bytes().strip()
    if environment == "test":
        # ponytail: ephemeral secrets are only acceptable in tests; anything else must mount a file.
        return base64.b64encode(os.urandom(size))
    raise RuntimeError(f"{name} file is not configured (set SP_{name.upper()}_FILE)")


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def master_key() -> bytes:
    s = get_settings()
    key = base64.b64decode(_read_secret(s.master_key_file, "master_key", s.environment, 32))
    if len(key) != 32:
        raise RuntimeError("master key must decode to exactly 32 bytes")
    return key


@lru_cache
def redaction_salt() -> bytes:
    s = get_settings()
    salt = _read_secret(s.redaction_salt_file, "redaction_salt", s.environment, 32)
    if len(salt) < 32:
        raise RuntimeError("redaction salt must be at least 32 bytes")
    return salt
