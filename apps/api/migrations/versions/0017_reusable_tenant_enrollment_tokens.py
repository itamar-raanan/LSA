"""add reusable tenant enrollment tokens

Revision ID: 0017
Revises: 0016
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("agent_enrollment_tokens")}
    additions = (
        ("token_type", sa.Column("token_type", sa.String(20), nullable=False, server_default="one_time")),
        ("max_uses", sa.Column("max_uses", sa.Integer(), nullable=True)),
        ("use_count", sa.Column("use_count", sa.Integer(), nullable=False, server_default="0")),
        ("last_used_at", sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True)),
    )
    with op.batch_alter_table("agent_enrollment_tokens") as batch:
        for name, column in additions:
            if name not in columns:
                batch.add_column(column)

    indexes = {
        index["name"] for index in sa.inspect(op.get_bind()).get_indexes("agent_enrollment_tokens")
    }
    if "ix_agent_enrollment_tokens_token_type" not in indexes:
        op.create_index(
            "ix_agent_enrollment_tokens_token_type",
            "agent_enrollment_tokens",
            ["token_type"],
        )


def downgrade() -> None:
    indexes = {
        index["name"] for index in sa.inspect(op.get_bind()).get_indexes("agent_enrollment_tokens")
    }
    if "ix_agent_enrollment_tokens_token_type" in indexes:
        op.drop_index(
            "ix_agent_enrollment_tokens_token_type",
            table_name="agent_enrollment_tokens",
        )
    columns = {
        column["name"]
        for column in sa.inspect(op.get_bind()).get_columns("agent_enrollment_tokens")
    }
    with op.batch_alter_table("agent_enrollment_tokens") as batch:
        for name in ("last_used_at", "use_count", "max_uses", "token_type"):
            if name in columns:
                batch.drop_column(name)
