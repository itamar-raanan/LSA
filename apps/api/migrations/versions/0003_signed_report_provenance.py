"""Add signing keys and report signature provenance.

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "signing_keys" not in inspector.get_table_names():
        op.create_table(
            "signing_keys",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("host_id", sa.String(length=36), sa.ForeignKey("hosts.id")),
            sa.Column("name", sa.String(length=160), nullable=False),
            sa.Column("public_key", sa.String(length=64), nullable=False),
            sa.Column("fingerprint", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True)),
            sa.Column("revoked_at", sa.DateTime(timezone=True)),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_signing_keys_tenant_id", "signing_keys", ["tenant_id"])
        op.create_index("ix_signing_keys_host_id", "signing_keys", ["host_id"])
        op.create_index(
            "ix_signing_keys_tenant_fingerprint",
            "signing_keys",
            ["tenant_id", "fingerprint"],
            unique=True,
        )

    report_columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("reports")}
    if "signing_key_id" not in report_columns:
        op.add_column(
            "reports",
            sa.Column("signing_key_id", sa.String(length=36), sa.ForeignKey("signing_keys.id")),
        )
    if "signature_verified" not in report_columns:
        op.add_column(
            "reports",
            sa.Column("signature_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    report_columns = {column["name"] for column in inspector.get_columns("reports")}
    if "signature_verified" in report_columns:
        op.drop_column("reports", "signature_verified")
    if "signing_key_id" in report_columns:
        op.drop_column("reports", "signing_key_id")
    if "signing_keys" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("signing_keys")
