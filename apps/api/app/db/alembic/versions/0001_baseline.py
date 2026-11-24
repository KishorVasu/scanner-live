"""Baseline: access, control and audit tables, grants, append-only audit, seed roles/permissions/policies.

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

APP_ROLE = "platform_app"
READONLY_ROLE = "platform_readonly"

# Frozen copies. tests/test_rbac.py and tests/test_policy_gateway.py compare them with the live catalogs.
ROLE_PERMISSIONS = {
    "admin": [
        "dashboard:view", "projects:manage", "scans:trigger", "findings:triage", "findings:accept_risk",
        "approvals:request", "agents:manage", "github:manage", "users:manage", "policies:manage", "audit:view",
    ],
    "approver": [
        "dashboard:view", "scans:trigger", "findings:triage", "findings:accept_risk",
        "approvals:request", "approvals:decide", "reports:approve", "audit:view",
    ],
    "developer": ["dashboard:view", "scans:trigger", "findings:triage", "approvals:request"],
    "viewer": ["dashboard:view"],
}
FORBIDDEN_ACTIONS = [
    "edit_file", "write_file", "delete_file", "delete_branch", "git_push", "force_push", "upgrade_dependency",
    "deploy", "rotate_credential", "change_permission", "share_learning_note", "exec_shell", "run_project_script",
]

TIMESTAMPED = ["users", "roles", "permissions", "user_sessions", "policies", "approvals", "agent_runs"]


def _ts() -> list[sa.Column]:
    return [
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def _enum(name: str, *values: str) -> pg.ENUM:
    return pg.ENUM(*values, name=name, create_type=False)


def upgrade() -> None:
    for name, values in {
        "policy_tier": ("allowed", "approval_required", "forbidden"),
        "approval_status": ("pending", "approved", "rejected", "expired", "executed", "failed"),
        "agent_run_status": ("running", "succeeded", "failed", "timed_out"),
        "actor_type": ("user", "agent", "system"),
        "session_scope": ("full", "totp_setup"),
    }.items():
        pg.ENUM(*values, name=name).create(op.get_bind())

    op.create_table(
        "users",
        *_ts(),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("totp_secret_enc", sa.LargeBinary),
        sa.Column("totp_confirmed_at", sa.DateTime(timezone=True)),
        sa.Column("totp_last_step", sa.BigInteger),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("email = lower(email)", name="ck_users_email_lower"),
    )
    op.create_table("roles", *_ts(), sa.Column("name", sa.String(32), nullable=False, unique=True))
    op.create_table(
        "permissions",
        *_ts(),
        sa.Column("resource", sa.String(64), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.UniqueConstraint("resource", "action"),
    )
    op.create_table(
        "user_roles",
        sa.Column("user_id", pg.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("role_id", pg.UUID(as_uuid=True), sa.ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True),
    )
    op.create_table(
        "role_permissions",
        sa.Column("role_id", pg.UUID(as_uuid=True), sa.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
        sa.Column(
            "permission_id", pg.UUID(as_uuid=True), sa.ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
        ),
    )
    op.create_table(
        "user_sessions",
        *_ts(),
        sa.Column("user_id", pg.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("scope", _enum("session_scope"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("ip", sa.String(64)),
        sa.Column("user_agent", sa.String(512)),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    op.create_table(
        "policies",
        *_ts(),
        sa.Column("action", sa.String(128), nullable=False, unique=True),
        sa.Column("tier", _enum("policy_tier"), nullable=False),
        sa.Column("conditions", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.text("true")),
    )
    op.create_table(
        "agent_runs",
        *_ts(),
        sa.Column("agent_name", sa.String(64), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("input", pg.JSONB, nullable=False),
        sa.Column("output", pg.JSONB),
        sa.Column("model", sa.String(64)),
        sa.Column("tokens_in", sa.Integer, nullable=False, server_default="0"),
        sa.Column("tokens_out", sa.Integer, nullable=False, server_default="0"),
        sa.Column("tool_calls", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", _enum("agent_run_status"), nullable=False),
        sa.Column("error", sa.Text),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_agent_runs_agent_name", "agent_runs", ["agent_name"])
    op.create_table(
        "approvals",
        *_ts(),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("scope", pg.JSONB, nullable=False),
        sa.Column("scope_hash", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("risks", sa.Text, nullable=False, server_default=""),
        sa.Column("requested_by", pg.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("requested_by_run_id", pg.UUID(as_uuid=True), sa.ForeignKey("agent_runs.id", ondelete="RESTRICT")),
        sa.Column("status", _enum("approval_status"), nullable=False),
        sa.Column("approver_id", pg.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True)),
        sa.Column("result", pg.JSONB),
        sa.CheckConstraint("approver_id IS NULL OR approver_id <> requested_by", name="ck_approvals_no_self_approval"),
    )
    op.create_index("ix_approvals_scope_hash", "approvals", ["scope_hash"])
    op.create_index("ix_approvals_status_expires", "approvals", ["status", "expires_at"])
    op.create_table(
        "audit_logs",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("actor_type", _enum("actor_type"), nullable=False),
        sa.Column("actor_id", sa.String(64)),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("target_type", sa.String(64)),
        sa.Column("target_id", sa.String(320)),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("ip", sa.String(64)),
        sa.Column("detail", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_audit_logs_at", "audit_logs", ["at"])
    op.create_index("ix_audit_logs_actor", "audit_logs", ["actor_type", "actor_id"])
    op.create_index("ix_audit_logs_target", "audit_logs", ["target_type", "target_id"])
    op.create_index("ix_audit_logs_action_at", "audit_logs", ["action", "at"])

    # updated_at trigger
    op.execute(
        "CREATE FUNCTION set_updated_at() RETURNS trigger LANGUAGE plpgsql AS "
        "$$ BEGIN NEW.updated_at = now(); RETURN NEW; END $$"
    )
    for table in TIMESTAMPED:
        op.execute(f"CREATE TRIGGER trg_{table}_updated_at BEFORE UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION set_updated_at()")

    # Append-only audit log (rule R10): applies to every role, the owner included.
    op.execute(
        "CREATE FUNCTION audit_logs_append_only() RETURNS trigger LANGUAGE plpgsql AS "
        "$$ BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END $$"
    )
    op.execute(
        "CREATE TRIGGER trg_audit_logs_no_update_delete BEFORE UPDATE OR DELETE ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only()"
    )
    op.execute(
        "CREATE TRIGGER trg_audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only()"
    )

    # Grants. Roles are created by deploy/postgres/init; skip silently where they do not exist.
    op.execute(f"""
    DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
        GRANT USAGE ON SCHEMA public TO {APP_ROLE};
        -- History tables (approvals, agent_runs, sessions) are never deleted by the app.
        GRANT SELECT, INSERT, UPDATE ON users, user_sessions, approvals, agent_runs TO {APP_ROLE};
        GRANT SELECT ON roles, permissions, role_permissions TO {APP_ROLE};
        GRANT SELECT, INSERT, DELETE ON user_roles TO {APP_ROLE};
        GRANT SELECT ON policies TO {APP_ROLE};
        GRANT SELECT, INSERT ON audit_logs TO {APP_ROLE};
        REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM {APP_ROLE};
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{READONLY_ROLE}') THEN
        GRANT USAGE ON SCHEMA public TO {READONLY_ROLE};
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO {READONLY_ROLE};
      END IF;
    END $$
    """)

    # Seed
    roles = sa.table("roles", sa.column("name", sa.String))
    perms = sa.table("permissions", sa.column("resource", sa.String), sa.column("action", sa.String))
    op.bulk_insert(roles, [{"name": r} for r in ROLE_PERMISSIONS])
    keys = sorted({p for ps in ROLE_PERMISSIONS.values() for p in ps})
    op.bulk_insert(perms, [{"resource": k.split(":")[0], "action": k.split(":")[1]} for k in keys])
    for role, ps in ROLE_PERMISSIONS.items():
        for key in ps:
            resource, action = key.split(":")
            op.execute(
                sa.text(
                    "INSERT INTO role_permissions (role_id, permission_id) "
                    "SELECT r.id, p.id FROM roles r, permissions p "
                    "WHERE r.name = :role AND p.resource = :resource AND p.action = :action"
                ).bindparams(role=role, resource=resource, action=action)
            )
    policies = sa.table(
        "policies", sa.column("action", sa.String), sa.column("tier", _enum("policy_tier")), sa.column("description", sa.Text)
    )
    op.bulk_insert(
        policies, [{"action": a, "tier": "forbidden", "description": "Forbidden in v1 (rule R1)"} for a in FORBIDDEN_ACTIONS]
    )


def downgrade() -> None:
    for table in ["audit_logs", "approvals", "agent_runs", "policies", "user_sessions", "role_permissions",
                  "user_roles", "permissions", "roles", "users"]:
        op.drop_table(table)
    op.execute("DROP FUNCTION IF EXISTS audit_logs_append_only()")
    op.execute("DROP FUNCTION IF EXISTS set_updated_at()")
    for name in ["session_scope", "actor_type", "agent_run_status", "approval_status", "policy_tier"]:
        op.execute(f"DROP TYPE IF EXISTS {name}")
