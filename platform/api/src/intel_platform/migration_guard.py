from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine


class DatabaseMigrationRequired(RuntimeError):
    pass


def required_revision(api_root: Path | None = None) -> str:
    root = api_root or Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    head = ScriptDirectory.from_config(config).get_current_head()
    if not head:
        raise DatabaseMigrationRequired("No ordered database migration head is configured")
    return head


def assert_database_current(engine: Engine, api_root: Path | None = None) -> None:
    expected = required_revision(api_root)
    with engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_revision()
    if current != expected:
        raise DatabaseMigrationRequired(
            "Database migration required: "
            f"current={current or 'unversioned'} expected={expected}. "
            "Back up PostgreSQL, then run 'alembic upgrade head' before starting production."
        )
