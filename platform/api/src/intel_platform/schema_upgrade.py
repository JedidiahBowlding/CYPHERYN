from sqlalchemy import inspect

from .database import engine

JOB_COLUMNS = {
    "requested_by_id": "VARCHAR(36)",
    "attempt": "INTEGER NOT NULL DEFAULT 0",
    "max_attempts": "INTEGER NOT NULL DEFAULT 3",
    "lease_owner": "VARCHAR(120)",
    "lease_expires_at": "DATETIME",
    "heartbeat_at": "DATETIME",
    "cancellation_requested_at": "DATETIME",
    "error_summary": "VARCHAR(500)",
}

FINDING_COLUMNS = {
    "evidence_observed_at": "DATETIME",
    "verification_job_id": "VARCHAR(36)",
    "verification_requested_at": "DATETIME",
    "last_verified_at": "DATETIME",
    "resolved_at": "DATETIME",
    "clean_observations": "INTEGER NOT NULL DEFAULT 0",
    "remediation_notes": "TEXT NOT NULL DEFAULT ''",
    "owner": "VARCHAR(200) NOT NULL DEFAULT ''",
    "due_at": "DATETIME",
    "verification_state": "VARCHAR(30) DEFAULT 'not_verified' NOT NULL",
    "direct_observed_at": "DATETIME",
    "provider_observed_at": "DATETIME",
    "verification_history": "JSON DEFAULT '[]' NOT NULL",
    "corroborating_providers": "JSON DEFAULT '[]' NOT NULL",
    "exception_reason": "TEXT NOT NULL DEFAULT ''",
    "exception_expires_at": "DATETIME",
    "risk_accepted_by_id": "VARCHAR(36)",
    "risk_accepted_at": "DATETIME",
    "monitoring_enabled": "BOOLEAN NOT NULL DEFAULT 0",
    "monitoring_interval_minutes": "INTEGER",
    "next_monitor_at": "DATETIME",
}

ORGANIZATION_COLUMNS = {
    "report_title": "VARCHAR(200) NOT NULL DEFAULT 'SignalTrace'",
    "report_accent": "VARCHAR(7) NOT NULL DEFAULT '#147d72'",
    "report_logo": "BLOB",
    "report_logo_mime": "VARCHAR(30) NOT NULL DEFAULT ''",
}

EVIDENCE_SOURCE_COLUMNS = {
    "provider_version": "VARCHAR(100) NOT NULL DEFAULT 'unknown'",
    "ruleset_version": "VARCHAR(100) NOT NULL DEFAULT 'unknown'",
    "previous_integrity_hash": "VARCHAR(64)",
    "integrity_hash": "VARCHAR(64)",
}

AUDIT_EVENT_COLUMNS = {
    "previous_integrity_hash": "VARCHAR(64)",
    "integrity_hash": "VARCHAR(64)",
}


def upgrade_existing_schema(target_engine=engine) -> None:
    """Small additive upgrade path until the project adopts Alembic migrations."""
    columns = {
        column["name"] for column in inspect(target_engine).get_columns("collection_jobs")
    }
    finding_columns = {
        column["name"] for column in inspect(target_engine).get_columns("findings")
    }
    organization_columns = {
        column["name"] for column in inspect(target_engine).get_columns("organizations")
    }
    evidence_source_columns = {
        column["name"] for column in inspect(target_engine).get_columns("evidence_sources")
    }
    audit_event_columns = {
        column["name"] for column in inspect(target_engine).get_columns("audit_events")
    }
    with target_engine.begin() as connection:
        for name, definition in JOB_COLUMNS.items():
            if name not in columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE collection_jobs ADD COLUMN {name} {definition}"
                )
        for name, definition in FINDING_COLUMNS.items():
            if name not in finding_columns:
                connection.exec_driver_sql(f"ALTER TABLE findings ADD COLUMN {name} {definition}")
        for name, definition in ORGANIZATION_COLUMNS.items():
            if name not in organization_columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE organizations ADD COLUMN {name} {definition}"
                )
        for name, definition in EVIDENCE_SOURCE_COLUMNS.items():
            if name not in evidence_source_columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE evidence_sources ADD COLUMN {name} {definition}"
                )
        for name, definition in AUDIT_EVENT_COLUMNS.items():
            if name not in audit_event_columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE audit_events ADD COLUMN {name} {definition}"
                )
        connection.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_relationship_claim "
            "ON relationships (investigation_id, subject_entity_id, predicate, "
            "object_entity_id, provider)"
        )
