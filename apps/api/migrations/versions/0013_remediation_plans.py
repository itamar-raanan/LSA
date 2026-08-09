"""non-executable remediation planning

Revision ID: 0013
Revises: 0012
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if "remediation_plans" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "remediation_plans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("active_finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("host_id", sa.String(36), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("report_id", sa.String(36), sa.ForeignKey("reports.id"), nullable=False),
        sa.Column("control_id", sa.String(160), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("category", sa.String(80), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("current_state", sa.Text(), nullable=True),
        sa.Column("required_state", sa.Text(), nullable=True),
        sa.Column("remediation_summary", sa.Text(), nullable=False),
        sa.Column("affected_paths", sa.JSON(), nullable=False),
        sa.Column("reboot_required", sa.Boolean(), nullable=False),
        sa.Column("service_restart", sa.Boolean(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("canceled_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("canceled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancellation_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_remediation_plans_tenant_id", "remediation_plans", ["tenant_id"])
    op.create_index("ix_remediation_plans_finding_id", "remediation_plans", ["finding_id"])
    op.create_index(
        "uq_remediation_plans_active_finding_id",
        "remediation_plans",
        ["active_finding_id"],
        unique=True,
    )
    op.create_index("ix_remediation_plans_host_id", "remediation_plans", ["host_id"])
    op.create_index("ix_remediation_plans_report_id", "remediation_plans", ["report_id"])
    op.create_index("ix_remediation_plans_control_id", "remediation_plans", ["control_id"])
    op.create_index("ix_remediation_plans_status", "remediation_plans", ["status"])
    op.create_index("ix_remediation_plans_requested_by", "remediation_plans", ["requested_by"])
    op.create_index(
        "ix_remediation_plans_tenant_status_created",
        "remediation_plans",
        ["tenant_id", "status", "created_at"],
    )
    op.create_index(
        "ix_remediation_plans_host_control",
        "remediation_plans",
        ["host_id", "control_id"],
    )


def downgrade() -> None:
    op.drop_table("remediation_plans")
