"""application inventory

Revision ID: 0009
Revises: 0008
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if "host_applications" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "host_applications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("host_id", sa.String(36), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("inventory_key", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("version", sa.String(300), nullable=True),
        sa.Column("architecture", sa.String(80), nullable=True),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("publisher", sa.String(300), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(80), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("running", sa.Boolean(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("host_id", "inventory_key", name="uq_host_application_identity"),
    )
    op.create_index("ix_host_applications_tenant_id", "host_applications", ["tenant_id"])
    op.create_index("ix_host_applications_host_id", "host_applications", ["host_id"])
    op.create_index("ix_host_applications_kind", "host_applications", ["kind"])
    op.create_index("ix_host_applications_name", "host_applications", ["name"])
    op.create_index("ix_host_applications_source", "host_applications", ["source"])
    op.create_index("ix_host_applications_last_seen_at", "host_applications", ["last_seen_at"])
    op.create_index(
        "ix_host_applications_host_active", "host_applications", ["host_id", "removed_at"]
    )


def downgrade() -> None:
    op.drop_table("host_applications")
