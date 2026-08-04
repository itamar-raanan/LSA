"""package identity for vulnerability correlation

Revision ID: 0010
Revises: 0009
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("host_applications")}
    if "source_package" not in columns:
        op.add_column("host_applications", sa.Column("source_package", sa.String(300), nullable=True))
    indexes = {index["name"] for index in inspector.get_indexes("host_applications")}
    if "ix_host_applications_source_package" not in indexes:
        op.create_index("ix_host_applications_source_package", "host_applications", ["source_package"])
    if "source_version" not in columns:
        op.add_column("host_applications", sa.Column("source_version", sa.String(300), nullable=True))
    if "purl" not in columns:
        op.add_column("host_applications", sa.Column("purl", sa.String(1000), nullable=True))


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("host_applications")}
    if "purl" in columns:
        op.drop_column("host_applications", "purl")
    if "source_version" in columns:
        op.drop_column("host_applications", "source_version")
    if "source_package" in columns:
        indexes = {index["name"] for index in inspector.get_indexes("host_applications")}
        if "ix_host_applications_source_package" in indexes:
            op.drop_index("ix_host_applications_source_package", table_name="host_applications")
        op.drop_column("host_applications", "source_package")
