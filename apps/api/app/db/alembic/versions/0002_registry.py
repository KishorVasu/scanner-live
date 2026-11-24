"""Registry, GitHub App, local agents, inventory, repository events; grants; discovery tool policies.

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

APP_ROLE = "platform_app"
UUID = pg.UUID(as_uuid=True)
TZ = sa.DateTime(timezone=True)

ENUMS = {
    "project_status": ("active", "paused", "incident", "archived"),
    "criticality": ("critical", "high", "medium", "low"),
    "component_kind": ("web", "api", "mobile_ios", "mobile_android", "flutter", "game", "infra", "other"),
    "repo_source": ("github", "local"),
    "repo_event_kind": ("force_push", "history_rewrite", "lifecycle_script_change", "workflow_change", "vscode_task",
                        "ide_config_change", "build_config_change", "suspicious_file", "ignored_file_committed"),
    "severity": ("critical", "high", "medium", "low", "informational"),
}

# Read-only discovery tools (Project Discovery agent) and the platform write that stores its result.
DISCOVERY_POLICIES = ["github_repo_metadata", "list_tree", "read_manifest", "hash_inventory", "store_inventory"]

# table -> privileges for the app role. History tables get no DELETE.
GRANTS = {
    "projects": "SELECT, INSERT, UPDATE",
    "project_components": "SELECT, INSERT, UPDATE",
    "scan_policies": "SELECT, INSERT, UPDATE",
    "github_installations": "SELECT, INSERT, UPDATE",
    "github_installation_repos": "SELECT, INSERT, UPDATE",
    "local_agents": "SELECT, INSERT, UPDATE",
    "agent_enrolment_codes": "SELECT, INSERT, UPDATE",
    "local_agent_challenges": "SELECT, INSERT, UPDATE",
    "local_agent_sessions": "SELECT, INSERT, UPDATE",
    "repositories": "SELECT, INSERT, UPDATE",
    "repository_branch_heads": "SELECT, INSERT, UPDATE",
    "technology_profiles": "SELECT, INSERT, DELETE",  # rebuilt per inventory
    "dependency_inventory": "SELECT, INSERT, DELETE",  # rebuilt per inventory
    "repository_events": "SELECT, INSERT",  # evidence: append only
    "webhook_deliveries": "SELECT, INSERT, UPDATE",
}


def _ts() -> list[sa.Column]:
    return [
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", TZ, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TZ, nullable=False, server_default=sa.func.now()),
    ]


def _e(name: str) -> pg.ENUM:
    return pg.ENUM(*ENUMS[name], name=name, create_type=False)


def _fk(target: str, nullable: bool = False, **kw) -> sa.Column:
    name = kw.pop("name")
    return sa.Column(name, UUID, sa.ForeignKey(f"{target}.id", ondelete="RESTRICT"), nullable=nullable, **kw)


def upgrade() -> None:
    for name, values in ENUMS.items():
        pg.ENUM(*values, name=name).create(op.get_bind())

    op.create_table(
        "projects", *_ts(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        _fk("users", nullable=True, name="owner_user_id"),
        sa.Column("criticality", _e("criticality"), nullable=False),
        sa.Column("status", _e("project_status"), nullable=False),
        sa.Column("deployment_environments", pg.ARRAY(sa.String(64)), nullable=False, server_default="{}"),
        sa.Column("llm_allowed", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{0,63}$'", name="ck_projects_slug"),
    )
    op.create_table(
        "project_components", *_ts(),
        _fk("projects", name="project_id"),
        sa.Column("kind", _e("component_kind"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.UniqueConstraint("project_id", "name"),
    )
    op.create_table(
        "scan_policies", *_ts(),
        _fk("projects", name="project_id", unique=True),
        *[sa.Column(c, sa.Boolean, nullable=False, server_default=sa.text(d)) for c, d in
          [("daily_deps", "true"), ("daily_secrets", "true"), ("weekly_full", "true"), ("webhook_targeted", "true"),
           ("codeql_enabled", "false")]],
    )
    op.create_table(
        "github_installations", *_ts(),
        sa.Column("installation_id", sa.BigInteger, nullable=False, unique=True),
        sa.Column("account_login", sa.String(200), nullable=False),
        sa.Column("account_type", sa.String(32), nullable=False),
        sa.Column("permissions", pg.JSONB, nullable=False),
        sa.Column("read_only", sa.Boolean, nullable=False),
        sa.Column("suspended_at", TZ),
    )
    op.create_table(
        "github_installation_repos", *_ts(),
        _fk("github_installations", name="installation_ref"),
        sa.Column("github_repo_id", sa.BigInteger, nullable=False, unique=True),
        sa.Column("full_name", sa.String(300), nullable=False),
        sa.Column("private", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("removed_at", TZ),
    )
    op.create_table(
        "local_agents", *_ts(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("host_fingerprint", sa.String(128)),
        sa.Column("public_key", sa.LargeBinary),
        sa.Column("approved_roots", pg.JSONB, nullable=False),
        sa.Column("os", sa.String(64)),
        sa.Column("agent_version", sa.String(32)),
        sa.Column("registered_at", TZ),
        sa.Column("last_seen_at", TZ),
        sa.Column("revoked_at", TZ),
        sa.CheckConstraint("public_key IS NULL OR length(public_key) = 32", name="ck_local_agents_ed25519"),
    )
    op.create_table(
        "agent_enrolment_codes", *_ts(),
        sa.Column("code_hash", sa.String(64), nullable=False, unique=True),
        _fk("local_agents", name="local_agent_id"),
        _fk("users", name="created_by"),
        sa.Column("expires_at", TZ, nullable=False),
        sa.Column("used_at", TZ),
    )
    for table, col in (("local_agent_challenges", "nonce_hash"), ("local_agent_sessions", "token_hash")):
        cols = [_fk("local_agents", name="local_agent_id", index=True),
                sa.Column(col, sa.String(64), nullable=False, unique=True),
                sa.Column("expires_at", TZ, nullable=False)]
        cols.append(sa.Column("used_at" if table == "local_agent_challenges" else "revoked_at", TZ))
        op.create_table(table, *_ts(), *cols)

    op.create_table(
        "repositories", *_ts(),
        _fk("project_components", name="component_id"),
        sa.Column("source", _e("repo_source"), nullable=False),
        sa.Column("github_repo_id", sa.BigInteger),
        sa.Column("full_name", sa.String(300)),
        _fk("local_agents", nullable=True, name="local_agent_id"),
        sa.Column("local_path_alias", sa.String(64)),
        sa.Column("default_branch", sa.String(255)),
        sa.Column("manifest_hash", sa.String(64)),
        sa.Column("tree_hash", sa.String(64)),
        sa.Column("inventory_complete", sa.Boolean),
        sa.Column("inventory_coverage", pg.JSONB),
        sa.Column("last_inventory_at", TZ),
        sa.CheckConstraint(
            "(source = 'github' AND github_repo_id IS NOT NULL AND local_agent_id IS NULL) OR "
            "(source = 'local' AND local_agent_id IS NOT NULL AND local_path_alias IS NOT NULL AND github_repo_id IS NULL)",
            name="ck_repositories_source_identity",
        ),
    )
    op.create_index("uq_repositories_github", "repositories", ["github_repo_id"], unique=True,
                    postgresql_where=sa.text("github_repo_id IS NOT NULL"))
    op.create_index("uq_repositories_local", "repositories", ["local_agent_id", "local_path_alias"], unique=True,
                    postgresql_where=sa.text("local_agent_id IS NOT NULL"))
    op.create_table(
        "repository_branch_heads", *_ts(),
        _fk("repositories", name="repository_id"),
        sa.Column("branch", sa.String(255), nullable=False),
        sa.Column("head_sha", sa.String(64), nullable=False),
        sa.Column("observed_at", TZ, nullable=False),
        sa.UniqueConstraint("repository_id", "branch"),
    )
    op.create_table(
        "technology_profiles", *_ts(),
        _fk("repositories", name="repository_id", index=True),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("directory", sa.String(500), nullable=False),
        sa.Column("framework", sa.String(64)),
        sa.Column("version", sa.String(128)),
        sa.Column("package_manager", sa.String(32), nullable=False),
        sa.Column("manifest_path", sa.String(500)),
        sa.Column("lockfile_path", sa.String(500)),
        sa.Column("detected_at", TZ, nullable=False),
    )
    op.create_table(
        "dependency_inventory", *_ts(),
        _fk("repositories", name="repository_id", index=True),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("package", sa.String(500), nullable=False),
        sa.Column("version", sa.String(128)),
        sa.Column("version_spec", sa.String(255)),
        sa.Column("direct", sa.Boolean, nullable=False),
        sa.Column("manifest_path", sa.String(500)),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
    )
    op.create_index("ix_dependency_inventory_pkg", "dependency_inventory", ["ecosystem", "package"])
    op.create_table(
        "repository_events", *_ts(),
        _fk("repositories", name="repository_id", index=True),
        sa.Column("kind", _e("repo_event_kind"), nullable=False),
        sa.Column("severity", _e("severity"), nullable=False),
        sa.Column("ref", sa.String(255)),
        sa.Column("before_sha", sa.String(64)),
        sa.Column("after_sha", sa.String(64)),
        sa.Column("detail", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("delivery_id", sa.String(64)),
    )
    op.create_table(
        "webhook_deliveries", *_ts(),
        sa.Column("delivery_id", sa.String(64), nullable=False, unique=True),
        sa.Column("event", sa.String(64), nullable=False),
        sa.Column("github_repo_id", sa.BigInteger, index=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("processed_at", TZ),
    )

    for table in GRANTS:
        op.execute(f"CREATE TRIGGER trg_{table}_updated_at BEFORE UPDATE ON {table} FOR EACH ROW "
                   "EXECUTE FUNCTION set_updated_at()")
    grants = "\n".join(f"GRANT {privs} ON {t} TO {APP_ROLE};" for t, privs in GRANTS.items())
    op.execute(f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN {grants} END IF; END $$")
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'platform_readonly') THEN "
               "GRANT SELECT ON ALL TABLES IN SCHEMA public TO platform_readonly; END IF; END $$")

    policies = sa.table("policies", sa.column("action", sa.String),
                        sa.column("tier", pg.ENUM(name="policy_tier", create_type=False)), sa.column("description", sa.Text))
    op.bulk_insert(policies, [{"action": a, "tier": "allowed", "description": "Project Discovery (Phase 2)"}
                              for a in DISCOVERY_POLICIES])


def downgrade() -> None:
    op.execute("DELETE FROM policies WHERE action IN (" + ",".join(f"'{a}'" for a in DISCOVERY_POLICIES) + ")")
    for table in reversed(list(GRANTS)):
        op.drop_table(table)
    for name in reversed(list(ENUMS)):
        op.execute(f"DROP TYPE IF EXISTS {name}")
