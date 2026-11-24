"""Advisory sources, advisories, project impacts; grants; intelligence tool policies.

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

APP_ROLE = "platform_app"
UUID = pg.UUID(as_uuid=True)
TZ = sa.DateTime(timezone=True)

ENUMS = {
    "source_trust": ("vendor", "ghsa", "osv", "nvd", "cisa_kev", "ecosystem"),
    "impact_classification": ("confirmed_affected", "potentially_affected", "not_affected_on_evidence",
                              "needs_verification", "not_scanned"),
}

# All read-only or platform writes (rule R1). Targeted rescans are static scans, so allowed (rule R5).
POLICIES = {
    "read_advisory": "allowed", "record_interpretation": "allowed",
    "query_inventory": "allowed", "read_finding": "allowed", "record_impact": "allowed",
    "request_targeted_scan": "allowed",
}

GRANTS = {
    "advisory_sources": "SELECT, UPDATE",
    "security_advisories": "SELECT, INSERT, UPDATE",
    "project_impacts": "SELECT, INSERT, UPDATE",
}

# Allowlisted feeds (SCANNING_STRATEGY / Phase 4 plan). Fetch code also enforces the host allowlist.
SOURCES = [
    {"name": "osv", "url": "https://api.osv.dev/v1", "kind": "api", "trust_level": "osv"},
    {"name": "cisa_kev", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "kind": "feed", "trust_level": "cisa_kev"},
    {"name": "nvd", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "kind": "api", "trust_level": "nvd"},
]


def _ts() -> list[sa.Column]:
    return [
        sa.Column("id", UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", TZ, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TZ, nullable=False, server_default=sa.func.now()),
    ]


def _e(name: str) -> pg.ENUM:
    return pg.ENUM(*ENUMS.get(name, ()), name=name, create_type=False)


def _fk(target: str, name: str, nullable: bool = False, **kw) -> sa.Column:
    return sa.Column(name, UUID, sa.ForeignKey(f"{target}.id", ondelete="RESTRICT"), nullable=nullable, **kw)


def upgrade() -> None:
    for name, values in ENUMS.items():
        pg.ENUM(*values, name=name).create(op.get_bind())

    sources = op.create_table(
        "advisory_sources", *_ts(),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("trust_level", _e("source_trust"), nullable=False),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_polled_at", TZ),
        sa.Column("cursor", sa.String(255)),
    )
    op.create_table(
        "security_advisories", *_ts(),
        _fk("advisory_sources", "source_id"),
        sa.Column("external_id", sa.String(128), nullable=False),
        sa.Column("aliases", pg.ARRAY(sa.String(128)), nullable=False, server_default="{}"),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("url", sa.String(500)),
        sa.Column("ecosystem", sa.String(32)),
        sa.Column("package", sa.String(500)),
        sa.Column("affected_ranges", pg.JSONB, nullable=False),
        sa.Column("patched_versions", pg.JSONB, nullable=False),
        sa.Column("severity", pg.ENUM(name="severity", create_type=False)),
        sa.Column("cvss_vector", sa.String(255)),
        sa.Column("known_exploited", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("vendor_facts", sa.Text, nullable=False),
        sa.Column("ai_interpretation", sa.Text),
        sa.Column("extra_conditions", pg.JSONB),
        sa.Column("published_at", TZ),
        sa.Column("modified_at", TZ),
        sa.Column("retrieved_at", TZ, nullable=False),
        sa.UniqueConstraint("source_id", "external_id"),
    )
    op.create_index("ix_advisories_pkg", "security_advisories", ["ecosystem", "package"])
    op.create_table(
        "project_impacts", *_ts(),
        _fk("security_advisories", "advisory_id", index=True),
        _fk("repositories", "repository_id", index=True),
        sa.Column("classification", _e("impact_classification"), nullable=False),
        sa.Column("reasoning", sa.Text, nullable=False),
        sa.Column("evidence", pg.JSONB, nullable=False),
        sa.Column("references", pg.JSONB, nullable=False),
        sa.Column("decided_by_rule", sa.String(64)),
        _fk("agent_runs", "decided_by_run_id", nullable=True),
        sa.Column("decided_at", TZ, nullable=False),
        sa.UniqueConstraint("advisory_id", "repository_id"),
    )

    for table in GRANTS:
        op.execute(f"CREATE TRIGGER trg_{table}_updated_at BEFORE UPDATE ON {table} FOR EACH ROW "
                   "EXECUTE FUNCTION set_updated_at()")
    grants = "\n".join(f"GRANT {p} ON {t} TO {APP_ROLE};" for t, p in GRANTS.items())
    op.execute(f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN {grants} END IF; END $$")
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'platform_readonly') THEN "
               "GRANT SELECT ON ALL TABLES IN SCHEMA public TO platform_readonly; END IF; END $$")

    op.bulk_insert(sources, [{**s, "active": True} for s in SOURCES])
    policies = sa.table("policies", sa.column("action", sa.String),
                        sa.column("tier", pg.ENUM(name="policy_tier", create_type=False)), sa.column("description", sa.Text))
    op.bulk_insert(policies, [{"action": a, "tier": t, "description": "Intelligence (Phase 4)"} for a, t in POLICIES.items()])


def downgrade() -> None:
    op.execute("DELETE FROM policies WHERE action IN (" + ",".join(f"'{a}'" for a in POLICIES) + ")")
    for table in reversed(list(GRANTS)):
        op.drop_table(table)
    for name in reversed(list(ENUMS)):
        op.execute(f"DROP TYPE IF EXISTS {name}")
