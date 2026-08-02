"""Add ingestion token lifecycle timestamps.

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Revision 0001 creates tables from the application's current metadata. A
    # brand-new installation may therefore already have these columns, while an
    # existing v0.1 database still needs them added explicitly.
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("ingestion_tokens")}
    if "expires_at" not in columns:
        op.add_column("ingestion_tokens", sa.Column("expires_at", sa.DateTime(timezone=True)))
    if "last_used_at" not in columns:
        op.add_column("ingestion_tokens", sa.Column("last_used_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("ingestion_tokens")}
    if "last_used_at" in columns:
        op.drop_column("ingestion_tokens", "last_used_at")
    if "expires_at" in columns:
        op.drop_column("ingestion_tokens", "expires_at")
