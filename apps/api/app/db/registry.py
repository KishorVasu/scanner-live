"""Phase 2 tables: project registry, GitHub App, local agents, inventory, repository events."""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, CheckConstraint, ForeignKey, Index, LargeBinary, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models import Base, Timestamps, pg_enum


class ProjectStatus(enum.StrEnum):
    active = "active"
    paused = "paused"
    incident = "incident"
    archived = "archived"


class Criticality(enum.StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class ComponentKind(enum.StrEnum):
    web = "web"
    api = "api"
    mobile_ios = "mobile_ios"
    mobile_android = "mobile_android"
    flutter = "flutter"
    game = "game"
    infra = "infra"
    other = "other"


class RepoSource(enum.StrEnum):
    github = "github"
    local = "local"


class RepoEventKind(enum.StrEnum):
    force_push = "force_push"
    history_rewrite = "history_rewrite"
    lifecycle_script_change = "lifecycle_script_change"
    workflow_change = "workflow_change"
    vscode_task = "vscode_task"
    ide_config_change = "ide_config_change"
    build_config_change = "build_config_change"
    suspicious_file = "suspicious_file"
    ignored_file_committed = "ignored_file_committed"


class Severity(enum.StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class Project(Timestamps, Base):
    __tablename__ = "projects"
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(Text, server_default="")
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    criticality: Mapped[Criticality] = mapped_column(pg_enum(Criticality, "criticality"))
    status: Mapped[ProjectStatus] = mapped_column(pg_enum(ProjectStatus, "project_status"))
    deployment_environments: Mapped[list[str]] = mapped_column(ARRAY(String(64)), server_default="{}")
    llm_allowed: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    components: Mapped[list["ProjectComponent"]] = relationship(lazy="selectin", order_by="ProjectComponent.name")
    scan_policy: Mapped["ScanPolicy | None"] = relationship(lazy="selectin", uselist=False)


class ProjectComponent(Timestamps, Base):
    __tablename__ = "project_components"
    __table_args__ = (UniqueConstraint("project_id", "name"),)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"))
    kind: Mapped[ComponentKind] = mapped_column(pg_enum(ComponentKind, "component_kind"))
    name: Mapped[str] = mapped_column(String(200))
    repositories: Mapped[list["Repository"]] = relationship(lazy="selectin")


class ScanPolicy(Timestamps, Base):
    __tablename__ = "scan_policies"
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), unique=True)
    daily_deps: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    daily_secrets: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    weekly_full: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    webhook_targeted: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    codeql_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))


class GithubInstallation(Timestamps, Base):
    __tablename__ = "github_installations"
    installation_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    account_login: Mapped[str] = mapped_column(String(200))
    account_type: Mapped[str] = mapped_column(String(32))
    permissions: Mapped[dict[str, Any]]
    read_only: Mapped[bool] = mapped_column(Boolean)
    suspended_at: Mapped[datetime | None]


class GithubInstallationRepo(Timestamps, Base):
    __tablename__ = "github_installation_repos"
    installation_ref: Mapped[uuid.UUID] = mapped_column(ForeignKey("github_installations.id", ondelete="RESTRICT"))
    github_repo_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    full_name: Mapped[str] = mapped_column(String(300))
    private: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    removed_at: Mapped[datetime | None]


class LocalAgent(Timestamps, Base):
    __tablename__ = "local_agents"
    name: Mapped[str] = mapped_column(String(200))
    host_fingerprint: Mapped[str | None] = mapped_column(String(128))
    public_key: Mapped[bytes | None] = mapped_column(LargeBinary)  # raw 32-byte Ed25519 key
    approved_roots: Mapped[dict[str, Any]]  # {"roots": [{"alias": ..., "path": ...}]}
    os: Mapped[str | None] = mapped_column(String(64))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    registered_at: Mapped[datetime | None]
    last_seen_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]

    def root(self, alias: str) -> dict | None:
        return next((r for r in self.approved_roots.get("roots", []) if r["alias"] == alias), None)


class AgentEnrolmentCode(Timestamps, Base):
    __tablename__ = "agent_enrolment_codes"
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    local_agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("local_agents.id", ondelete="RESTRICT"))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]


class LocalAgentChallenge(Timestamps, Base):
    __tablename__ = "local_agent_challenges"
    local_agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("local_agents.id", ondelete="RESTRICT"), index=True)
    nonce_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]


class LocalAgentSession(Timestamps, Base):
    __tablename__ = "local_agent_sessions"
    local_agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("local_agents.id", ondelete="RESTRICT"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]


class Repository(Timestamps, Base):
    __tablename__ = "repositories"
    __table_args__ = (
        CheckConstraint(
            "(source = 'github' AND github_repo_id IS NOT NULL AND local_agent_id IS NULL) OR "
            "(source = 'local' AND local_agent_id IS NOT NULL AND local_path_alias IS NOT NULL AND github_repo_id IS NULL)",
            name="ck_repositories_source_identity",
        ),
        Index("uq_repositories_github", "github_repo_id", unique=True, postgresql_where=text("github_repo_id IS NOT NULL")),
        Index("uq_repositories_local", "local_agent_id", "local_path_alias", unique=True,
              postgresql_where=text("local_agent_id IS NOT NULL")),
    )
    component_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("project_components.id", ondelete="RESTRICT"))
    source: Mapped[RepoSource] = mapped_column(pg_enum(RepoSource, "repo_source"))
    github_repo_id: Mapped[int | None] = mapped_column(BigInteger)
    full_name: Mapped[str | None] = mapped_column(String(300))
    local_agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("local_agents.id", ondelete="RESTRICT"))
    local_path_alias: Mapped[str | None] = mapped_column(String(64))
    default_branch: Mapped[str | None] = mapped_column(String(255))
    manifest_hash: Mapped[str | None] = mapped_column(String(64))
    tree_hash: Mapped[str | None] = mapped_column(String(64))
    inventory_complete: Mapped[bool | None]
    inventory_coverage: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    last_inventory_at: Mapped[datetime | None]


class RepositoryBranchHead(Timestamps, Base):
    __tablename__ = "repository_branch_heads"
    __table_args__ = (UniqueConstraint("repository_id", "branch"),)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="RESTRICT"))
    branch: Mapped[str] = mapped_column(String(255))
    head_sha: Mapped[str] = mapped_column(String(64))
    observed_at: Mapped[datetime]


class TechnologyProfile(Timestamps, Base):
    __tablename__ = "technology_profiles"
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="RESTRICT"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(32))
    directory: Mapped[str] = mapped_column(String(500))
    framework: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[str | None] = mapped_column(String(128))
    package_manager: Mapped[str] = mapped_column(String(32))
    manifest_path: Mapped[str | None] = mapped_column(String(500))
    lockfile_path: Mapped[str | None] = mapped_column(String(500))
    detected_at: Mapped[datetime]


class DependencyInventory(Timestamps, Base):
    __tablename__ = "dependency_inventory"
    __table_args__ = (Index("ix_dependency_inventory_pkg", "ecosystem", "package"),)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="RESTRICT"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(32))
    package: Mapped[str] = mapped_column(String(500))
    version: Mapped[str | None] = mapped_column(String(128))
    version_spec: Mapped[str | None] = mapped_column(String(255))
    direct: Mapped[bool]
    manifest_path: Mapped[str | None] = mapped_column(String(500))
    manifest_hash: Mapped[str] = mapped_column(String(64))


class RepositoryEvent(Timestamps, Base):
    __tablename__ = "repository_events"
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="RESTRICT"), index=True)
    kind: Mapped[RepoEventKind] = mapped_column(pg_enum(RepoEventKind, "repo_event_kind"))
    severity: Mapped[Severity] = mapped_column(pg_enum(Severity, "severity"))
    ref: Mapped[str | None] = mapped_column(String(255))
    before_sha: Mapped[str | None] = mapped_column(String(64))
    after_sha: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    source: Mapped[str] = mapped_column(String(16))
    delivery_id: Mapped[str | None] = mapped_column(String(64))


class WebhookDelivery(Timestamps, Base):
    __tablename__ = "webhook_deliveries"
    delivery_id: Mapped[str] = mapped_column(String(64), unique=True)
    event: Mapped[str] = mapped_column(String(64))
    github_repo_id: Mapped[int | None] = mapped_column(BigInteger, index=True)
    status: Mapped[str] = mapped_column(String(32))
    processed_at: Mapped[datetime | None]
