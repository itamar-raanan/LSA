"""record authenticated agent communication separately from enrollment

Revision ID: 0023
Revises: 0022
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("linux_agents")}
    if "first_communication_at" in columns:
        return
    op.add_column(
        "linux_agents",
        sa.Column("first_communication_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("linux_agents")}
    if "first_communication_at" in columns:
        op.drop_column("linux_agents", "first_communication_at")
