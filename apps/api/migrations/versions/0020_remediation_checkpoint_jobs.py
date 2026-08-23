"""add remediation checkpoint jobs

Revision ID: 0020
Revises: 0019
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if "remediation_checkpoint_jobs" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "remediation_checkpoint_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column(
            "change_set_id",
            sa.String(36),
            sa.ForeignKey("remediation_change_sets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "validation_job_id",
            sa.String(36),
            sa.ForeignKey("remediation_validation_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("host_id", sa.String(36), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("linux_agents.id"), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("contract", sa.JSON(), nullable=False),
        sa.Column("contract_digest", sa.String(64), nullable=False),
        sa.Column("recovery_plan", sa.JSON(), nullable=False),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("receipt", sa.JSON(), nullable=True),
        sa.Column("receipt_signature", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    for name, columns in (
        ("ix_remediation_checkpoint_jobs_tenant_id", ["tenant_id"]),
        ("ix_remediation_checkpoint_jobs_change_set_id", ["change_set_id"]),
        ("ix_remediation_checkpoint_jobs_validation_job_id", ["validation_job_id"]),
        ("ix_remediation_checkpoint_jobs_host_id", ["host_id"]),
        ("ix_remediation_checkpoint_jobs_agent_id", ["agent_id"]),
        ("ix_remediation_checkpoint_jobs_status", ["status"]),
        ("ix_remediation_checkpoint_jobs_contract_digest", ["contract_digest"]),
        ("ix_remediation_checkpoint_jobs_requested_by", ["requested_by"]),
    ):
        op.create_index(name, "remediation_checkpoint_jobs", columns)
    op.create_index(
        "ix_remediation_checkpoint_jobs_agent_status_requested",
        "remediation_checkpoint_jobs",
        ["agent_id", "status", "requested_at"],
    )


def downgrade() -> None:
    op.drop_table("remediation_checkpoint_jobs")
