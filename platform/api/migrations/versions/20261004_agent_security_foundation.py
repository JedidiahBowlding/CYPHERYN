"""Add the generic agent-security control-plane foundation."""

from alembic import op
import sqlalchemy as sa
import uuid

revision = "20261004_agent_security"
down_revision = "20260930_egress_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_clients",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("external_client_id", sa.String(255), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("environment", sa.String(80), nullable=False, server_default="production"),
        sa.Column("status", sa.String(30), nullable=False, server_default="active"),
        sa.Column("credential_reference", sa.String(300), nullable=False, server_default=""),
        sa.Column("credential_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("external_client_id", name="uq_security_client_oidc"),
    )
    op.create_index("ix_security_client_org_status", "security_clients", ["organization_id", "status"])
    op.create_table(
        "agent_capabilities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False, unique=True),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("risk_level", sa.String(30), nullable=False, server_default="standard"),
        sa.Column("status", sa.String(30), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    capability_table = sa.table(
        "agent_capabilities",
        sa.column("id", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.String),
        sa.column("risk_level", sa.String),
        sa.column("status", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    capability_names = (
        "web.read", "web.write", "email.read", "email.send", "calendar.read",
        "calendar.write", "commerce.search", "commerce.purchase", "filesystem.read",
        "filesystem.write", "database.read", "database.write", "network.external",
        "code.execute", "mcp.invoke", "agent.delegate", "agent.communicate",
    )
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    op.bulk_insert(
        capability_table,
        [
            {
                "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cypheryn-capability:{name}")),
                "name": name,
                "description": f"CYPHERYN standard agent capability: {name}",
                "risk_level": "standard",
                "status": "active",
                "created_at": now,
            }
            for name in capability_names
        ],
    )
    op.create_table(
        "security_destinations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("canonical_identifier", sa.String(500), nullable=False),
        sa.Column("destination_type", sa.String(60), nullable=False, server_default="hostname"),
        sa.Column("hostname", sa.String(255), nullable=False, server_default=""),
        sa.Column("service_identity", sa.String(255), nullable=False, server_default=""),
        sa.Column("environment", sa.String(80), nullable=False, server_default="production"),
        sa.Column("trust_state", sa.String(30), nullable=False, server_default="unknown"),
        sa.Column("reputation_metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id", "environment", "canonical_identifier",
            name="uq_security_destination_scope",
        ),
    )
    op.create_index(
        "ix_security_destination_org_trust", "security_destinations", ["organization_id", "trust_state"]
    )
    with op.batch_alter_table("protected_agents") as batch:
        batch.add_column(sa.Column("environment", sa.String(80), nullable=False, server_default="production"))
        batch.add_column(sa.Column("risk_level", sa.String(30), nullable=False, server_default="standard"))
        batch.add_column(sa.Column("owner_metadata", sa.JSON(), nullable=False, server_default="{}"))
        batch.add_column(
            sa.Column(
                "security_client_id",
                sa.String(36),
                sa.ForeignKey("security_clients.id", name="fk_protected_agent_security_client"),
            )
        )
        batch.add_column(sa.Column("credential_state", sa.String(30), nullable=False, server_default="managed"))
        batch.add_column(sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_index("ix_protected_agents_security_client_id", ["security_client_id"])
    op.execute("UPDATE protected_agents SET updated_at = created_at WHERE updated_at IS NULL")
    with op.batch_alter_table("protected_agents") as batch:
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)
    op.create_table(
        "agent_capability_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("protected_agents.id"), nullable=False),
        sa.Column("capability_id", sa.String(36), sa.ForeignKey("agent_capabilities.id"), nullable=False),
        sa.Column("environment", sa.String(80), nullable=False, server_default="production"),
        sa.Column("resource_scope", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("resource_scope_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="active"),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "agent_id", "capability_id", "environment", "resource_scope_hash",
            name="uq_agent_capability_scope",
        ),
    )
    op.create_index("ix_agent_capability_grant_agent", "agent_capability_grants", ["agent_id", "status"])
    with op.batch_alter_table("egress_policies") as batch:
        batch.add_column(sa.Column("policy_type", sa.String(50), nullable=False, server_default="egress"))
        batch.add_column(sa.Column("priority", sa.Integer(), nullable=False, server_default="100"))
    with op.batch_alter_table("egress_events") as batch:
        batch.alter_column("actor_id", existing_type=sa.String(36), nullable=True)
        batch.add_column(
            sa.Column(
                "security_client_id",
                sa.String(36),
                sa.ForeignKey("security_clients.id", name="fk_egress_event_security_client"),
            )
        )
        batch.add_column(sa.Column("capability", sa.String(160), nullable=False, server_default=""))
        batch.add_column(sa.Column("environment", sa.String(80), nullable=False, server_default="production"))
        batch.add_column(sa.Column("resource_scope", sa.JSON(), nullable=False, server_default="{}"))
        batch.add_column(sa.Column("data_classifications", sa.JSON(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("policy_trace", sa.JSON(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("policy_mode", sa.String(30), nullable=False, server_default="enforce"))
        batch.add_column(sa.Column("evaluated_decision", sa.String(32), nullable=False, server_default="BLOCK"))
        batch.add_column(sa.Column("effective_decision", sa.String(32), nullable=False, server_default="BLOCK"))
        batch.add_column(sa.Column("enforced_decision", sa.String(32), nullable=False, server_default="BLOCK"))
        batch.add_column(sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("request_id", sa.String(128), nullable=False, server_default=""))
        batch.add_column(sa.Column("idempotency_key_hash", sa.String(64), nullable=False, server_default=""))
        batch.add_column(sa.Column("nonce_hash", sa.String(64), nullable=False, server_default=""))
        batch.add_column(sa.Column("request_timestamp", sa.DateTime(timezone=True)))
        batch.create_unique_constraint("uq_egress_client_idempotency", ["security_client_id", "idempotency_key_hash"])
        batch.create_unique_constraint("uq_egress_client_nonce", ["security_client_id", "nonce_hash"])
    with op.batch_alter_table("audit_events") as batch:
        batch.alter_column("actor_id", existing_type=sa.String(36), nullable=True)
        batch.add_column(
            sa.Column(
                "security_client_id",
                sa.String(36),
                sa.ForeignKey("security_clients.id", name="fk_audit_event_security_client"),
            )
        )


def downgrade() -> None:
    # Development rollback only. Production rollback should deploy the previous
    # application while retaining additive security evidence and schema.
    with op.batch_alter_table("audit_events") as batch:
        batch.drop_column("security_client_id")
        batch.alter_column("actor_id", existing_type=sa.String(36), nullable=False)
    with op.batch_alter_table("egress_events") as batch:
        batch.drop_constraint("uq_egress_client_nonce", type_="unique")
        batch.drop_constraint("uq_egress_client_idempotency", type_="unique")
        for name in (
            "request_timestamp", "nonce_hash", "idempotency_key_hash", "request_id", "risk_score",
            "enforced_decision", "effective_decision", "evaluated_decision", "policy_mode",
            "policy_trace", "data_classifications", "resource_scope", "environment", "capability",
            "security_client_id",
        ):
            batch.drop_column(name)
        batch.alter_column("actor_id", existing_type=sa.String(36), nullable=False)
    with op.batch_alter_table("egress_policies") as batch:
        batch.drop_column("priority")
        batch.drop_column("policy_type")
    op.drop_table("agent_capability_grants")
    with op.batch_alter_table("protected_agents") as batch:
        batch.drop_index("ix_protected_agents_security_client_id")
        for name in (
            "updated_at", "credential_state", "security_client_id", "owner_metadata",
            "risk_level", "environment",
        ):
            batch.drop_column(name)
    op.drop_table("security_destinations")
    op.drop_table("agent_capabilities")
    op.drop_table("security_clients")
