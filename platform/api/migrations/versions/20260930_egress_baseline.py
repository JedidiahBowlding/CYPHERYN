"""Record the pre-Alembic CYPHERYN schema baseline.

Existing installations must verify the 20260930 egress migration and then stamp
this revision. It intentionally performs no schema mutation.
"""

revision = "20260930_egress_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
