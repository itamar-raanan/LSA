"""snapshot declarative remediation actions

Revision ID: 0014
Revises: 0013
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("remediation_plans")}
    if "action_id" not in columns:
        op.add_column("remediation_plans", sa.Column("action_id", sa.String(200), nullable=True))
        op.add_column("remediation_plans", sa.Column("action_version", sa.Integer(), nullable=True))
        op.add_column("remediation_plans", sa.Column("action_digest", sa.String(64), nullable=True))
        op.add_column("remediation_plans", sa.Column("action_snapshot", sa.JSON(), nullable=True))
        op.add_column(
            "remediation_plans",
            sa.Column(
                "action_catalog_status",
                sa.String(30),
                nullable=False,
                server_default="not_cataloged",
            ),
        )
        op.create_index("ix_remediation_plans_action_id", "remediation_plans", ["action_id"])


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("remediation_plans")}
    if "action_id" in columns:
        op.drop_index("ix_remediation_plans_action_id", table_name="remediation_plans")
        op.drop_column("remediation_plans", "action_snapshot")
        op.drop_column("remediation_plans", "action_digest")
        op.drop_column("remediation_plans", "action_version")
        op.drop_column("remediation_plans", "action_id")
        op.drop_column("remediation_plans", "action_catalog_status")
