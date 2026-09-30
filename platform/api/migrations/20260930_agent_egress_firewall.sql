-- CYPHERYN Agent Egress Firewall additive PostgreSQL migration.
-- Apply before deploying application code when automatic create_all is disabled.
-- Rollback is intentionally not destructive; retain these tables as security evidence.

CREATE TABLE IF NOT EXISTS protected_agents (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organizations(id),
  name VARCHAR(200) NOT NULL,
  agent_type VARCHAR(80) NOT NULL DEFAULT 'development_agent',
  owner_id VARCHAR(36) NOT NULL REFERENCES users(id),
  runtime VARCHAR(120) NOT NULL DEFAULT 'unknown',
  workspace VARCHAR(500) NOT NULL DEFAULT '',
  credential_reference VARCHAR(300) NOT NULL DEFAULT '',
  status VARCHAR(30) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS egress_policies (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organizations(id),
  name VARCHAR(200) NOT NULL,
  version VARCHAR(40) NOT NULL,
  scope JSONB NOT NULL DEFAULT '{}'::jsonb,
  rules JSONB NOT NULL DEFAULT '{}'::jsonb,
  enforcement_mode VARCHAR(30) NOT NULL DEFAULT 'enforce',
  state VARCHAR(30) NOT NULL DEFAULT 'draft',
  integrity_hash VARCHAR(64) NOT NULL,
  created_by_id VARCHAR(36) NOT NULL REFERENCES users(id),
  approved_by_id VARCHAR(36) REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL,
  activated_at TIMESTAMPTZ,
  CONSTRAINT uq_egress_policy_version UNIQUE (organization_id, name, version)
);

CREATE TABLE IF NOT EXISTS egress_events (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organizations(id),
  agent_id VARCHAR(36) NOT NULL REFERENCES protected_agents(id),
  actor_id VARCHAR(36) NOT NULL REFERENCES users(id),
  correlation_id VARCHAR(128) NOT NULL,
  action_type VARCHAR(160) NOT NULL,
  destination VARCHAR(500) NOT NULL,
  repository VARCHAR(300) NOT NULL DEFAULT '',
  normalized_request JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_hash VARCHAR(64) NOT NULL,
  decision VARCHAR(32) NOT NULL,
  reason_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
  human_reason VARCHAR(1000) NOT NULL,
  policy_id VARCHAR(36) REFERENCES egress_policies(id),
  policy_version VARCHAR(40) NOT NULL,
  approval_id VARCHAR(36),
  status VARCHAR(32) NOT NULL,
  execution_result JSONB NOT NULL DEFAULT '{}'::jsonb,
  verification_result JSONB NOT NULL DEFAULT '{}'::jsonb,
  previous_event_hash VARCHAR(64),
  event_hash VARCHAR(64),
  created_at TIMESTAMPTZ NOT NULL,
  executed_at TIMESTAMPTZ,
  verified_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS egress_artifacts (
  id VARCHAR(36) PRIMARY KEY,
  event_id VARCHAR(36) NOT NULL REFERENCES egress_events(id),
  filename VARCHAR(255) NOT NULL,
  verified_mime_type VARCHAR(100) NOT NULL,
  size INTEGER NOT NULL,
  sha256 VARCHAR(64) NOT NULL,
  classification JSONB NOT NULL DEFAULT '[]'::jsonb,
  findings JSONB NOT NULL DEFAULT '[]'::jsonb,
  ocr_status VARCHAR(40) NOT NULL DEFAULT 'not_applicable',
  quarantine_reference VARCHAR(500) NOT NULL DEFAULT '',
  redacted_artifact_reference VARCHAR(500) NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS egress_approvals (
  id VARCHAR(36) PRIMARY KEY,
  event_id VARCHAR(36) NOT NULL REFERENCES egress_events(id),
  requested_by_id VARCHAR(36) NOT NULL REFERENCES users(id),
  decided_by_id VARCHAR(36) REFERENCES users(id),
  action_hash VARCHAR(64) NOT NULL,
  token_hash VARCHAR(64) NOT NULL,
  state VARCHAR(30) NOT NULL DEFAULT 'pending',
  expires_at TIMESTAMPTZ NOT NULL,
  decided_at TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS egress_findings (
  id VARCHAR(36) PRIMARY KEY,
  organization_id VARCHAR(36) NOT NULL REFERENCES organizations(id),
  event_id VARCHAR(36) NOT NULL REFERENCES egress_events(id),
  severity VARCHAR(20) NOT NULL DEFAULT 'high',
  title VARCHAR(300) NOT NULL,
  description TEXT NOT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'open',
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_protected_agent_org_status ON protected_agents(organization_id, status);
CREATE INDEX IF NOT EXISTS ix_egress_policy_org_state ON egress_policies(organization_id, state);
CREATE INDEX IF NOT EXISTS ix_egress_event_org_time ON egress_events(organization_id, created_at);
CREATE INDEX IF NOT EXISTS ix_egress_event_decision ON egress_events(organization_id, decision);
CREATE INDEX IF NOT EXISTS ix_egress_event_hash ON egress_events(event_hash);
CREATE INDEX IF NOT EXISTS ix_egress_artifact_event ON egress_artifacts(event_id);
CREATE INDEX IF NOT EXISTS ix_egress_approval_event ON egress_approvals(event_id);
