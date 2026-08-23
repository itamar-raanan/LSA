"""add two phase platform command key rotation

Revision ID: 0018
Revises: 0017
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    key_columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("platform_command_signing_keys")}
    with op.batch_alter_table("platform_command_signing_keys") as batch:
        if "status" not in key_columns:
            batch.add_column(sa.Column("status", sa.String(20), nullable=False, server_default="active"))
        if "activated_at" not in key_columns:
            batch.add_column(sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True))
        if "retired_at" not in key_columns:
            batch.add_column(sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True))
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("platform_command_signing_keys")}
    if "ix_platform_command_signing_keys_status" not in indexes:
        op.create_index("ix_platform_command_signing_keys_status", "platform_command_signing_keys", ["status"])

    agent_columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("linux_agents")}
    with op.batch_alter_table("linux_agents") as batch:
        if "pending_platform_command_key_id" not in agent_columns:
            batch.add_column(sa.Column("pending_platform_command_key_id", sa.String(36), nullable=True))
        if "pending_platform_command_key_fingerprint" not in agent_columns:
            batch.add_column(sa.Column("pending_platform_command_key_fingerprint", sa.String(64), nullable=True))
        if "platform_command_key_acknowledged_at" not in agent_columns:
            batch.add_column(sa.Column("platform_command_key_acknowledged_at", sa.DateTime(timezone=True), nullable=True))
    foreign_keys = sa.inspect(op.get_bind()).get_foreign_keys("linux_agents")
    if not any(key.get("constrained_columns") == ["pending_platform_command_key_id"] for key in foreign_keys):
        with op.batch_alter_table("linux_agents") as batch:
            batch.create_foreign_key(
                "fk_linux_agents_pending_platform_command_key_id",
                "platform_command_signing_keys",
                ["pending_platform_command_key_id"],
                ["id"],
            )
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("linux_agents")}
    if "ix_linux_agents_pending_platform_command_key_id" not in indexes:
        op.create_index("ix_linux_agents_pending_platform_command_key_id", "linux_agents", ["pending_platform_command_key_id"])


def downgrade() -> None:
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("linux_agents")}
    if "ix_linux_agents_pending_platform_command_key_id" in indexes:
        op.drop_index("ix_linux_agents_pending_platform_command_key_id", table_name="linux_agents")
    with op.batch_alter_table("linux_agents") as batch:
        for foreign_key in sa.inspect(op.get_bind()).get_foreign_keys("linux_agents"):
            if foreign_key.get("constrained_columns") == ["pending_platform_command_key_id"] and foreign_key.get("name"):
                batch.drop_constraint(foreign_key["name"], type_="foreignkey")
        for name in (
            "platform_command_key_acknowledged_at",
            "pending_platform_command_key_fingerprint",
            "pending_platform_command_key_id",
        ):
            batch.drop_column(name)
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("platform_command_signing_keys")}
    if "ix_platform_command_signing_keys_status" in indexes:
        op.drop_index("ix_platform_command_signing_keys_status", table_name="platform_command_signing_keys")
    with op.batch_alter_table("platform_command_signing_keys") as batch:
        batch.drop_column("retired_at")
        batch.drop_column("activated_at")
        batch.drop_column("status")
