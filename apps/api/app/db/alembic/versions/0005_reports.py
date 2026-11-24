"""Reports (draft -> approved), report tool policies.

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

APP_ROLE = "platform_app"
UUID = pg.UUID(as_uuid=True)
TZ = sa.DateTime(timezone=True)
POLICIES = {"read_report_data": "allowed", "save_report_draft": "allowed"}


def upgrade() -> None:
    pg.ENUM("draft", "approved", name="report_status").create(op.get_bind())
    op.create_table(
        "reports",
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", TZ, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TZ, nullable=False, server_default=sa.func.now()),
        sa.Column("kind", sa.String(16), nullable=False),  # project | portfolio
        sa.Column("project_id", UUID, sa.ForeignKey("projects.id", ondelete="RESTRICT"), index=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("status", pg.ENUM(name="report_status", create_type=False), nullable=False),
        sa.Column("content", pg.JSONB, nullable=False),  # deterministic tables, frozen at generation time
        sa.Column("narrative", sa.Text),  # LLM-written, labelled as such; NULL when not allowed or rejected
        sa.Column("narrative_note", sa.String(300)),
        sa.Column("generated_by_run_id", UUID, sa.ForeignKey("agent_runs.id", ondelete="RESTRICT")),
        sa.Column("created_by", UUID, sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("approved_by", UUID, sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("approved_at", TZ),
        sa.CheckConstraint("approved_by IS NULL OR approved_by <> created_by", name="ck_reports_not_self_approved"),
        sa.CheckConstraint("(status = 'approved') = (approved_by IS NOT NULL)", name="ck_reports_approval_consistent"),
    )
    op.execute("CREATE TRIGGER trg_reports_updated_at BEFORE UPDATE ON reports FOR EACH ROW "
               "EXECUTE FUNCTION set_updated_at()")
    op.execute(f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN "
               f"GRANT SELECT, INSERT, UPDATE ON reports TO {APP_ROLE}; END IF; END $$")
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'platform_readonly') THEN "
               "GRANT SELECT ON reports TO platform_readonly; END IF; END $$")
    policies = sa.table("policies", sa.column("action", sa.String),
                        sa.column("tier", pg.ENUM(name="policy_tier", create_type=False)), sa.column("description", sa.Text))
    op.bulk_insert(policies, [{"action": a, "tier": t, "description": "Reports (Phase 5)"} for a, t in POLICIES.items()])


def downgrade() -> None:
    op.execute("DELETE FROM policies WHERE action IN (" + ",".join(f"'{a}'" for a in POLICIES) + ")")
    op.drop_table("reports")
    op.execute("DROP TYPE IF EXISTS report_status")
