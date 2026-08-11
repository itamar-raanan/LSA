"""add signed remediation change sets

Revision ID: 0015
Revises: 0014
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    agent_columns = {column["name"] for column in inspector.get_columns("linux_agents")}
    if "capabilities_attested_at" not in agent_columns:
        op.add_column(
            "linux_agents",
            sa.Column("capabilities_attested_at", sa.DateTime(timezone=True), nullable=True),
        )
    change_set_tables = {
        "platform_change_signing_keys",
        "remediation_change_sets",
        "remediation_change_set_plans",
        "remediation_change_set_targets",
    }
    # Migration 0001 creates current metadata on a brand-new database. In that
    # bootstrap path these tables already exist and only the revision needs to advance.
    if change_set_tables <= tables:
        return
    if change_set_tables & tables:
        raise RuntimeError("Signed change-set schema is only partially present")

    op.create_table(
        "platform_change_signing_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("public_key", sa.String(64), nullable=False),
        sa.Column("private_key_ciphertext", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_platform_change_signing_keys_tenant_id",
        "platform_change_signing_keys",
        ["tenant_id"],
    )
    op.create_index(
        "ix_platform_change_signing_keys_tenant_fingerprint",
        "platform_change_signing_keys",
        ["tenant_id", "fingerprint"],
        unique=True,
    )

    op.create_table(
        "remediation_change_sets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("payload_schema_version", sa.String(20), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column(
            "signing_key_id",
            sa.String(36),
            sa.ForeignKey("platform_change_signing_keys.id"),
            nullable=True,
        ),
        sa.Column("maintenance_window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("maintenance_window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("batch_interval_minutes", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorized_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("canceled_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("canceled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancellation_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_remediation_change_sets_tenant_id", "remediation_change_sets", ["tenant_id"]
    )
    op.create_index("ix_remediation_change_sets_status", "remediation_change_sets", ["status"])
    op.create_index("ix_remediation_change_sets_digest", "remediation_change_sets", ["digest"])
    op.create_index(
        "ix_remediation_change_sets_signing_key_id", "remediation_change_sets", ["signing_key_id"]
    )
    op.create_index(
        "ix_remediation_change_sets_tenant_status_created",
        "remediation_change_sets",
        ["tenant_id", "status", "created_at"],
    )

    op.create_table(
        "remediation_change_set_plans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column(
            "change_set_id",
            sa.String(36),
            sa.ForeignKey("remediation_change_sets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("plan_id", sa.String(36), sa.ForeignKey("remediation_plans.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("change_set_id", "plan_id", name="uq_change_set_plan"),
    )
    op.create_index(
        "ix_remediation_change_set_plans_tenant_id", "remediation_change_set_plans", ["tenant_id"]
    )
    op.create_index(
        "ix_remediation_change_set_plans_change_set_id",
        "remediation_change_set_plans",
        ["change_set_id"],
    )
    op.create_index(
        "ix_remediation_change_set_plans_plan_id", "remediation_change_set_plans", ["plan_id"]
    )

    op.create_table(
        "remediation_change_set_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column(
            "change_set_id",
            sa.String(36),
            sa.ForeignKey("remediation_change_sets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("host_id", sa.String(36), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("linux_agents.id"), nullable=False),
        sa.Column("rollout_phase", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("change_set_id", "host_id", name="uq_change_set_target_host"),
    )
    op.create_index(
        "ix_remediation_change_set_targets_tenant_id",
        "remediation_change_set_targets",
        ["tenant_id"],
    )
    op.create_index(
        "ix_remediation_change_set_targets_change_set_id",
        "remediation_change_set_targets",
        ["change_set_id"],
    )
    op.create_index(
        "ix_remediation_change_set_targets_host_id", "remediation_change_set_targets", ["host_id"]
    )
    op.create_index(
        "ix_remediation_change_set_targets_agent_id", "remediation_change_set_targets", ["agent_id"]
    )


def downgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    for table_name in (
        "remediation_change_set_targets",
        "remediation_change_set_plans",
        "remediation_change_sets",
        "platform_change_signing_keys",
    ):
        if table_name in tables:
            op.drop_table(table_name)
    agent_columns = {
        column["name"] for column in sa.inspect(op.get_bind()).get_columns("linux_agents")
    }
    if "capabilities_attested_at" in agent_columns:
        op.drop_column("linux_agents", "capabilities_attested_at")
