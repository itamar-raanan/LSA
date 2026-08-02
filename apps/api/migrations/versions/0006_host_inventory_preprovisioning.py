"""Add host inventory, safe deletion, and manual external-user roles.

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    user_columns = {column["name"] for column in sa.inspect(bind).get_columns("users")}
    if "role_source" not in user_columns:
        with op.batch_alter_table("users") as batch:
            batch.add_column(
                sa.Column("role_source", sa.String(30), nullable=False, server_default="manual")
            )
        bind.execute(
            sa.text("UPDATE users SET role_source = 'provider' WHERE auth_source != 'local'")
        )

    host_columns = {column["name"] for column in sa.inspect(bind).get_columns("hosts")}
    with op.batch_alter_table("hosts") as batch:
        if "system_info" not in host_columns:
            batch.add_column(sa.Column("system_info", sa.JSON(), nullable=False, server_default="{}"))
        if "deleted_at" not in host_columns:
            batch.add_column(sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    host_columns = {column["name"] for column in sa.inspect(bind).get_columns("hosts")}
    with op.batch_alter_table("hosts") as batch:
        if "deleted_at" in host_columns:
            batch.drop_column("deleted_at")
        if "system_info" in host_columns:
            batch.drop_column("system_info")
    user_columns = {column["name"] for column in sa.inspect(bind).get_columns("users")}
    if "role_source" in user_columns:
        with op.batch_alter_table("users") as batch:
            batch.drop_column("role_source")
