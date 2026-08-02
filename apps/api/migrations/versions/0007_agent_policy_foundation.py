"""agent policy foundation

Revision ID: 0007
Revises: 0006
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


policy_mode = sa.Enum("disabled", "audit", "manual", "remediate", name="policymode")


def upgrade() -> None:
    # Revision 0001 creates the application's current metadata on a brand-new
    # installation. Existing databases at 0006 do not have these tables, while
    # a fresh database already does; support both paths without duplicate DDL.
    if "agent_policies" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "agent_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_agent_policy_name"),
    )
    op.create_index("ix_agent_policies_tenant_id", "agent_policies", ["tenant_id"])
    op.create_table(
        "agent_policy_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("policy_id", sa.String(36), sa.ForeignKey("agent_policies.id"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("default_mode", policy_mode, nullable=False),
        sa.Column("control_modes", sa.JSON(), nullable=False),
        sa.Column("settings", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("policy_id", "version", name="uq_agent_policy_version"),
    )
    op.create_index("ix_agent_policy_versions_tenant_id", "agent_policy_versions", ["tenant_id"])
    op.create_index("ix_agent_policy_versions_policy_id", "agent_policy_versions", ["policy_id"])
    op.create_table(
        "agent_groups",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("policy_id", sa.String(36), sa.ForeignKey("agent_policies.id"), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_agent_group_name"),
    )
    op.create_index("ix_agent_groups_tenant_id", "agent_groups", ["tenant_id"])
    op.create_index("ix_agent_groups_policy_id", "agent_groups", ["policy_id"])
    op.create_table(
        "agent_enrollment_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("group_id", sa.String(36), sa.ForeignKey("agent_groups.id"), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("token_prefix", sa.String(24), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agent_enrollment_tokens_tenant_id", "agent_enrollment_tokens", ["tenant_id"])
    op.create_index("ix_agent_enrollment_tokens_group_id", "agent_enrollment_tokens", ["group_id"])
    op.create_index("ix_agent_enrollment_tokens_token_prefix", "agent_enrollment_tokens", ["token_prefix"])
    op.create_index("ix_agent_enrollment_tokens_expires_at", "agent_enrollment_tokens", ["expires_at"])
    op.create_table(
        "linux_agents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("host_id", sa.String(36), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("group_id", sa.String(36), sa.ForeignKey("agent_groups.id"), nullable=False),
        sa.Column("ingestion_token_id", sa.String(36), sa.ForeignKey("ingestion_tokens.id"), nullable=False, unique=True),
        sa.Column("signing_key_id", sa.String(36), sa.ForeignKey("signing_keys.id"), nullable=False, unique=True),
        sa.Column("name", sa.String(253), nullable=False),
        sa.Column("public_key", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("agent_version", sa.String(40), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_policy_version", sa.Integer(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("host_id", name="uq_linux_agent_host"),
    )
    op.create_index("ix_linux_agents_tenant_id", "linux_agents", ["tenant_id"])
    op.create_index("ix_linux_agents_host_id", "linux_agents", ["host_id"])
    op.create_index("ix_linux_agents_group_id", "linux_agents", ["group_id"])
    op.create_index("ix_linux_agents_tenant_fingerprint", "linux_agents", ["tenant_id", "fingerprint"], unique=True)


def downgrade() -> None:
    op.drop_table("linux_agents")
    op.drop_table("agent_enrollment_tokens")
    op.drop_table("agent_groups")
    op.drop_table("agent_policy_versions")
    op.drop_table("agent_policies")
    policy_mode.drop(op.get_bind(), checkfirst=True)
