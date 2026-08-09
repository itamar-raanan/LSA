"""data workspace query indexes

Revision ID: 0012
Revises: 0011
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


INDEXES: tuple[tuple[str, str, list[str]], ...] = (
    ("ix_hosts_tenant_active_hostname", "hosts", ["tenant_id", "deleted_at", "hostname"]),
    ("ix_hosts_tenant_active_score", "hosts", ["tenant_id", "deleted_at", "security_score"]),
    ("ix_hosts_tenant_active_scan", "hosts", ["tenant_id", "deleted_at", "last_scan_at"]),
    (
        "ix_host_applications_tenant_active_kind_name",
        "host_applications",
        ["tenant_id", "removed_at", "kind", "name"],
    ),
    (
        "ix_findings_report_category_severity",
        "findings",
        ["report_id", "category", "severity"],
    ),
    ("ix_findings_report_lifecycle", "findings", ["report_id", "lifecycle"]),
)


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    for name, table, columns in INDEXES:
        if table not in tables:
            continue
        existing = {item["name"] for item in inspector.get_indexes(table)}
        if name not in existing:
            op.create_index(name, table, columns)


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    for name, table, _ in reversed(INDEXES):
        if table not in tables:
            continue
        existing = {item["name"] for item in inspector.get_indexes(table)}
        if name in existing:
            op.drop_index(name, table_name=table)
