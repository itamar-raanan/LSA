"""allow cloned machine identifiers for managed agents

Revision ID: 0022
Revises: 0021
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


INDEX_NAME = "ix_hosts_tenant_machine"


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    indexes = {index["name"]: index for index in inspector.get_indexes("hosts")}
    existing = indexes.get(INDEX_NAME)
    if existing is not None and existing.get("unique"):
        op.drop_index(INDEX_NAME, table_name="hosts")
        op.create_index(INDEX_NAME, "hosts", ["tenant_id", "machine_id_hash"])
    elif existing is None:
        op.create_index(INDEX_NAME, "hosts", ["tenant_id", "machine_id_hash"])


def downgrade() -> None:
    op.drop_index(INDEX_NAME, table_name="hosts")
    op.create_index(
        INDEX_NAME,
        "hosts",
        ["tenant_id", "machine_id_hash"],
        unique=True,
    )
