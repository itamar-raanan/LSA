"""Add immutable evidence-vault metadata.

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("reports")}
    additions = [
        ("artifact_object_key", sa.Column("artifact_object_key", sa.String(length=500))),
        ("artifact_object_version", sa.Column("artifact_object_version", sa.String(length=1024))),
        ("artifact_size_bytes", sa.Column("artifact_size_bytes", sa.Integer())),
        ("artifact_content_type", sa.Column("artifact_content_type", sa.String(length=120))),
        ("artifact_stored_at", sa.Column("artifact_stored_at", sa.DateTime(timezone=True))),
        ("artifact_retention_until", sa.Column("artifact_retention_until", sa.DateTime(timezone=True))),
        ("artifact_deleted_at", sa.Column("artifact_deleted_at", sa.DateTime(timezone=True))),
    ]
    for name, column in additions:
        if name not in columns:
            op.add_column("reports", column)
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("reports")}
    if "ix_reports_artifact_object_key" not in indexes:
        op.create_index(
            "ix_reports_artifact_object_key",
            "reports",
            ["artifact_object_key"],
            unique=True,
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    indexes = {index["name"] for index in inspector.get_indexes("reports")}
    if "ix_reports_artifact_object_key" in indexes:
        op.drop_index("ix_reports_artifact_object_key", table_name="reports")
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("reports")}
    for name in [
        "artifact_deleted_at",
        "artifact_retention_until",
        "artifact_stored_at",
        "artifact_content_type",
        "artifact_size_bytes",
        "artifact_object_key",
        "artifact_object_version",
    ]:
        if name in columns:
            op.drop_column("reports", name)
