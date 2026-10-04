"""Add bounded decision authorization leases and revocation generations."""

import sqlalchemy as sa
from alembic import op

revision = "20261005_authorization_leases"
down_revision = "20261004_agent_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in (
        "security_clients",
        "protected_agents",
        "agent_capability_grants",
        "security_destinations",
        "egress_policies",
    ):
        with op.batch_alter_table(table) as batch:
            batch.add_column(
                sa.Column(
                    "authorization_generation",
                    sa.Integer(),
                    nullable=False,
                    server_default="1",
                )
            )
    op.create_table(
        "decision_authorizations",
        sa.Column(
            "decision_id",
            sa.String(36),
            sa.ForeignKey("egress_events.id"),
            primary_key=True,
        ),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column(
            "security_client_id",
            sa.String(36),
            sa.ForeignKey("security_clients.id"),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            sa.String(36),
            sa.ForeignKey("protected_agents.id"),
            nullable=False,
        ),
        sa.Column(
            "grant_id",
            sa.String(36),
            sa.ForeignKey("agent_capability_grants.id"),
            nullable=False,
        ),
        sa.Column(
            "destination_id",
            sa.String(36),
            sa.ForeignKey("security_destinations.id"),
            nullable=False,
        ),
        sa.Column(
            "policy_id",
            sa.String(36),
            sa.ForeignKey("egress_policies.id"),
            nullable=False,
        ),
        sa.Column("client_generation", sa.Integer(), nullable=False),
        sa.Column("agent_generation", sa.Integer(), nullable=False),
        sa.Column("grant_generation", sa.Integer(), nullable=False),
        sa.Column("destination_generation", sa.Integer(), nullable=False),
        sa.Column("policy_generation", sa.Integer(), nullable=False),
        sa.Column("operation_fingerprint", sa.String(64), nullable=False),
        sa.Column("canonical_destination", sa.String(500), nullable=False),
        sa.Column("scheme", sa.String(20), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("resolved_addresses", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("resolution_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolution_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("maximum_uses", sa.Integer()),
        sa.Column("use_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_decision_authorization_org_expiry",
        "decision_authorizations",
        ["organization_id", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_decision_authorization_org_expiry", table_name="decision_authorizations"
    )
    op.drop_table("decision_authorizations")
    for table in (
        "egress_policies",
        "security_destinations",
        "agent_capability_grants",
        "protected_agents",
        "security_clients",
    ):
        with op.batch_alter_table(table) as batch:
            batch.drop_column("authorization_generation")
