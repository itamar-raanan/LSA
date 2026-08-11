"""add pinned platform command trust

Revision ID: 0016
Revises: 0015
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "platform_command_signing_keys" not in tables:
        op.create_table(
            "platform_command_signing_keys",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("key_version", sa.Integer(), nullable=False),
            sa.Column("public_key", sa.String(64), nullable=False),
            sa.Column("private_key_ciphertext", sa.Text(), nullable=False),
            sa.Column("fingerprint", sa.String(64), nullable=False),
            sa.Column("supersedes_key_id", sa.String(36), sa.ForeignKey("platform_command_signing_keys.id"), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "key_version", name="uq_platform_command_key_version"),
        )
        op.create_index("ix_platform_command_signing_keys_tenant_id", "platform_command_signing_keys", ["tenant_id"])
        op.create_index("ix_platform_command_signing_keys_tenant_fingerprint", "platform_command_signing_keys", ["tenant_id", "fingerprint"], unique=True)

    for table_name, columns in (
        ("agent_enrollment_tokens", [("platform_command_key_id", sa.Column("platform_command_key_id", sa.String(36), nullable=True))]),
        ("linux_agents", [
            ("platform_command_key_id", sa.Column("platform_command_key_id", sa.String(36), nullable=True)),
            ("platform_command_key_fingerprint", sa.Column("platform_command_key_fingerprint", sa.String(64), nullable=True)),
            ("platform_envelope_sequence", sa.Column("platform_envelope_sequence", sa.Integer(), nullable=False, server_default="0")),
        ]),
    ):
        existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}
        with op.batch_alter_table(table_name) as batch:
            for name, column in columns:
                if name not in existing:
                    batch.add_column(column)

    for table_name in ("agent_enrollment_tokens", "linux_agents"):
        foreign_keys = sa.inspect(op.get_bind()).get_foreign_keys(table_name)
        if not any(
            foreign_key.get("referred_table") == "platform_command_signing_keys"
            and foreign_key.get("constrained_columns") == ["platform_command_key_id"]
            for foreign_key in foreign_keys
        ):
            with op.batch_alter_table(table_name) as batch:
                batch.create_foreign_key(
                    f"fk_{table_name}_platform_command_key_id",
                    "platform_command_signing_keys",
                    ["platform_command_key_id"],
                    ["id"],
                )

    inspector = sa.inspect(op.get_bind())
    for table_name in ("agent_enrollment_tokens", "linux_agents"):
        indexes = {index["name"] for index in inspector.get_indexes(table_name)}
        name = f"ix_{table_name}_platform_command_key_id"
        if name not in indexes:
            op.create_index(name, table_name, ["platform_command_key_id"])


def downgrade() -> None:
    for table_name in ("agent_enrollment_tokens", "linux_agents"):
        index_name = f"ix_{table_name}_platform_command_key_id"
        indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table_name)}
        if index_name in indexes:
            op.drop_index(index_name, table_name=table_name)
        existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}
        with op.batch_alter_table(table_name) as batch:
            foreign_keys = sa.inspect(op.get_bind()).get_foreign_keys(table_name)
            for foreign_key in foreign_keys:
                if (
                    foreign_key.get("referred_table") == "platform_command_signing_keys"
                    and foreign_key.get("constrained_columns") == ["platform_command_key_id"]
                    and foreign_key.get("name")
                ):
                    batch.drop_constraint(foreign_key["name"], type_="foreignkey")
            for name in ("platform_envelope_sequence", "platform_command_key_fingerprint", "platform_command_key_id"):
                if name in existing:
                    batch.drop_column(name)
    if "platform_command_signing_keys" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("platform_command_signing_keys")
