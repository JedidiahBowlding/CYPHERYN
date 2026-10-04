"""Add durable trusted egress proxy execution receipts."""

import sqlalchemy as sa
from alembic import op

revision = "20261006_egress_proxy_receipts"
down_revision = "20261005_authorization_leases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "proxy_execution_receipts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("decision_id", sa.String(36), sa.ForeignKey("egress_events.id"), nullable=False),
        sa.Column(
            "organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column(
            "security_client_id",
            sa.String(36),
            sa.ForeignKey("security_clients.id"),
            nullable=False,
        ),
        sa.Column("agent_id", sa.String(36), sa.ForeignKey("protected_agents.id"), nullable=False),
        sa.Column("capability", sa.String(160), nullable=False),
        sa.Column("canonical_destination", sa.String(500), nullable=False),
        sa.Column("pinned_address", sa.String(45), nullable=False),
        sa.Column("method", sa.String(12), nullable=False),
        sa.Column("outcome", sa.String(80), nullable=False),
        sa.Column("security_reason", sa.String(500), nullable=False, server_default=""),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("request_body_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("request_classifications", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("response_status", sa.Integer()),
        sa.Column("bytes_sent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("bytes_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("redirect_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("latency_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        "ix_proxy_receipt_org_started",
        "proxy_execution_receipts",
        ["organization_id", "started_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_proxy_receipt_org_started", table_name="proxy_execution_receipts")
    op.drop_table("proxy_execution_receipts")
