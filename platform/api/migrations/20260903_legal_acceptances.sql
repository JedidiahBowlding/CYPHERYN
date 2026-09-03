-- Additive migration for deployments not initialized from SQLAlchemy metadata.
CREATE TABLE IF NOT EXISTS legal_acceptances (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id),
    terms_version VARCHAR(30) NOT NULL,
    responsible_use_version VARCHAR(30) NOT NULL,
    accepted_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_legal_acceptance_versions UNIQUE
        (user_id, terms_version, responsible_use_version)
);
CREATE INDEX IF NOT EXISTS ix_legal_acceptance_user_time
    ON legal_acceptances (user_id, accepted_at);
