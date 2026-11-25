"""Webhook replay protection: a signed body is accepted once, whatever X-GitHub-Delivery says (review finding 3).

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("webhook_deliveries", sa.Column("body_sha256", sa.String(64), nullable=True))
    op.create_unique_constraint("uq_webhook_deliveries_body_sha256", "webhook_deliveries", ["body_sha256"])


def downgrade() -> None:
    op.drop_constraint("uq_webhook_deliveries_body_sha256", "webhook_deliveries")
    op.drop_column("webhook_deliveries", "body_sha256")
