# Ordered database migrations

CYPHERYN uses Alembic for ordered schema changes. Production startup does not run
destructive schema replacement or automatically downgrade the database.

## Existing installations

Before the first Alembic-managed release:

1. Back up PostgreSQL and verify the backup can be read.
2. Confirm the existing `20260930_agent_egress_firewall.sql` migration was applied.
3. Record the baseline without changing schema:

   ```bash
   cd platform/api
   alembic stamp 20260930_egress_baseline
   ```

4. Review the pending SQL:

   ```bash
   alembic upgrade head --sql > /tmp/cypheryn-agent-security.sql
   ```

5. Apply the ordered upgrade during a maintenance window:

   ```bash
   alembic upgrade head
   ```

6. Verify history and current revision:

   ```bash
   alembic history
   alembic current
   ```

`PLATFORM_DATABASE_URL` supplies the target connection. Do not put credentials in
`alembic.ini` or commit generated SQL containing environment-specific information.

## New development databases

The existing application bootstrap still creates the inherited baseline schema for
clean development databases. Stamp the baseline and run `alembic upgrade head`
before starting the upgraded application. Removing this transitional `create_all`
path requires a future complete baseline migration and is intentionally outside this
reviewable foundation milestone.

## Rollback

The production rollback strategy is application rollback while retaining additive
columns, security decisions and audit evidence. The migration includes a development
downgrade, but it drops Phase 1 control-plane tables and must not be used against
production without a verified backup and explicit data-loss approval.
