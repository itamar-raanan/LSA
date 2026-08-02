"""Add external identity, revocable sessions, and managed TLS.

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "identity_providers" not in tables:
        op.create_table(
            "identity_providers",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("provider_type", sa.String(30), nullable=False),
            sa.Column("issuer_url", sa.String(500)),
            sa.Column("client_id", sa.String(320)),
            sa.Column("secret_ciphertext", sa.Text()),
            sa.Column("config", sa.JSON(), nullable=False),
            sa.Column("is_enabled", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "name", name="uq_identity_provider_name"),
        )
        op.create_index("ix_identity_providers_tenant_id", "identity_providers", ["tenant_id"])
        op.create_index(
            "ix_identity_providers_provider_type", "identity_providers", ["provider_type"]
        )
    user_columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("users")}
    user_indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("users")}
    user_uniques = {
        item["name"] for item in sa.inspect(op.get_bind()).get_unique_constraints("users")
    }
    has_provider_foreign_key = any(
        item["constrained_columns"] == ["identity_provider_id"]
        for item in sa.inspect(op.get_bind()).get_foreign_keys("users")
    )
    with op.batch_alter_table("users") as batch:
        if "auth_source" not in user_columns:
            batch.alter_column("password_hash", existing_type=sa.String(300), nullable=True)
            batch.add_column(
                sa.Column("auth_source", sa.String(30), nullable=False, server_default="local")
            )
        if "identity_provider_id" not in user_columns:
            batch.add_column(sa.Column("identity_provider_id", sa.String(36)))
        if "external_subject" not in user_columns:
            batch.add_column(sa.Column("external_subject", sa.String(320)))
        if "last_login_at" not in user_columns:
            batch.add_column(sa.Column("last_login_at", sa.DateTime(timezone=True)))
        if not has_provider_foreign_key:
            batch.create_foreign_key(
                "fk_users_identity_provider", "identity_providers", ["identity_provider_id"], ["id"]
            )
        if "uq_user_external_identity" not in user_uniques:
            batch.create_unique_constraint(
                "uq_user_external_identity",
                ["tenant_id", "identity_provider_id", "external_subject"],
            )
        if "ix_users_auth_source" not in user_indexes:
            batch.create_index("ix_users_auth_source", ["auth_source"])
        if "ix_users_identity_provider_id" not in user_indexes:
            batch.create_index("ix_users_identity_provider_id", ["identity_provider_id"])
    if "user_sessions" not in tables:
        op.create_table(
            "user_sessions",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True)),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_user_sessions_tenant_id", "user_sessions", ["tenant_id"])
        op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
        op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])
    if "auth_transactions" not in tables:
        op.create_table(
            "auth_transactions",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("state_hash", sa.String(64), nullable=False, unique=True),
            sa.Column(
                "provider_id", sa.String(36), sa.ForeignKey("identity_providers.id"), nullable=False
            ),
            sa.Column("nonce", sa.String(160), nullable=False),
            sa.Column("code_verifier", sa.String(160), nullable=False),
            sa.Column("redirect_uri", sa.String(1000), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True)),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_auth_transactions_state_hash", "auth_transactions", ["state_hash"], unique=True
        )
        op.create_index("ix_auth_transactions_provider_id", "auth_transactions", ["provider_id"])
        op.create_index("ix_auth_transactions_expires_at", "auth_transactions", ["expires_at"])
    if "tls_certificates" not in tables:
        op.create_table(
            "tls_certificates",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
            sa.Column("certificate_chain_pem", sa.Text(), nullable=False),
            sa.Column("private_key_ciphertext", sa.Text(), nullable=False),
            sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
            sa.Column("subject", sa.String(500), nullable=False),
            sa.Column("issuer", sa.String(500), nullable=False),
            sa.Column("hostnames", sa.JSON(), nullable=False),
            sa.Column("not_valid_before", sa.DateTime(timezone=True), nullable=False),
            sa.Column("not_valid_after", sa.DateTime(timezone=True), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False),
            sa.Column("uploaded_by", sa.String(36), sa.ForeignKey("users.id")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_tls_certificates_tenant_id", "tls_certificates", ["tenant_id"])
        op.create_index(
            "ix_tls_certificates_fingerprint", "tls_certificates", ["fingerprint"], unique=True
        )
        op.create_index("ix_tls_certificates_is_active", "tls_certificates", ["is_active"])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "tls_certificates" in tables:
        op.drop_table("tls_certificates")
    if "auth_transactions" in tables:
        op.drop_table("auth_transactions")
    if "user_sessions" in tables:
        op.drop_table("user_sessions")
    user_columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("users")}
    user_indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("users")}
    user_uniques = {
        item["name"] for item in sa.inspect(op.get_bind()).get_unique_constraints("users")
    }
    provider_foreign_key = next(
        (
            item["name"]
            for item in sa.inspect(op.get_bind()).get_foreign_keys("users")
            if item["constrained_columns"] == ["identity_provider_id"] and item["name"]
        ),
        None,
    )
    with op.batch_alter_table("users") as batch:
        if "uq_user_external_identity" in user_uniques:
            batch.drop_constraint("uq_user_external_identity", type_="unique")
        if provider_foreign_key:
            batch.drop_constraint(provider_foreign_key, type_="foreignkey")
        if "ix_users_identity_provider_id" in user_indexes:
            batch.drop_index("ix_users_identity_provider_id")
        if "ix_users_auth_source" in user_indexes:
            batch.drop_index("ix_users_auth_source")
        for column in ("last_login_at", "external_subject", "identity_provider_id", "auth_source"):
            if column in user_columns:
                batch.drop_column(column)
        if "auth_source" in user_columns:
            batch.alter_column("password_hash", existing_type=sa.String(300), nullable=False)
    if "identity_providers" in tables:
        op.drop_table("identity_providers")
