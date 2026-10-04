from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine

from intel_platform.migration_guard import (
    DatabaseMigrationRequired,
    assert_database_current,
    required_revision,
)


def test_agent_security_migrations_are_ordered_and_have_downgrade():
    api_root = Path(__file__).parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    scripts = ScriptDirectory.from_config(config)
    revisions = list(scripts.walk_revisions(base="base", head="heads"))
    assert [item.revision for item in reversed(revisions)] == [
        "20260930_egress_baseline",
        "20261004_agent_security",
        "20261005_authorization_leases",
    ]
    phase = scripts.get_revision("20261004_agent_security")
    assert phase is not None
    assert callable(phase.module.upgrade)
    assert callable(phase.module.downgrade)


def test_migration_files_do_not_contain_destructive_schema_replacement():
    api_root = Path(__file__).parents[1]
    for filename in (
        "20261004_agent_security_foundation.py",
        "20261005_authorization_leases.py",
    ):
        phase = (api_root / "migrations" / "versions" / filename).read_text(encoding="utf-8")
        assert "drop_all" not in phase
        assert "DROP DATABASE" not in phase.upper()
        assert "DROP SCHEMA" not in phase.upper()


def test_production_guard_rejects_unversioned_database(tmp_path):
    api_root = Path(__file__).parents[1]
    assert required_revision(api_root) == "20261005_authorization_leases"
    engine = create_engine(f"sqlite:///{tmp_path / 'unversioned.db'}")
    with pytest.raises(DatabaseMigrationRequired, match="alembic upgrade head"):
        assert_database_current(engine, api_root)
    engine.dispose()
