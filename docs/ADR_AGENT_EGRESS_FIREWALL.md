# ADR: deterministic agent egress enforcement

Status: accepted for MVP
Date: 2026-09-30

## Context

Development agents can make technically valid outbound calls that accidentally publish private source code, screenshots, credentials, or business data. Prompt instructions are not a security boundary. CYPHERYN already supplies local identity, RBAC, evidence integrity, observability, and isolated scanner patterns.

## Decision

Add an authenticated, organization-scoped egress subsystem to the existing API. Normalize supported tool requests into canonical JSON; scan artifacts locally; apply deterministic versioned rules; persist the decision before execution; bind approvals to the SHA-256 hash of the canonical action; issue only single-use, expiring approval tokens; and verify observed execution state afterward.

Default behavior is fail closed. Public repository creation, private-to-public changes, sensitive public artifacts, unknown destinations, unhealthy mandatory scanners, and uninspectable artifacts cannot proceed. Repository creation and external publication require human approval unless an active policy explicitly identifies an approved private repository.

Policy administration requires organization-admin membership. A requester cannot approve their own action. Raw credentials and artifact bodies are not written to ordinary event records.

## Alternatives rejected

- LLM self-policing: nondeterministic and bypassable by prompt injection.
- Giving the agent policy-edit permissions: violates separation of duties.
- Sending content to hosted classification APIs by default: violates local-first data control.
- Reusing target testing authorization: it expresses a different legal and security decision.
- Automatically deleting unexpected repositories: destructive and inappropriate without explicit approval.

## Consequences

Protected clients must integrate the evaluate/execute/verify sequence. Unmediated tools remain outside the guarantee. The bounded GitHub adapter is testable and extensible, but system-wide enforcement will require an OS/CI proxy or dedicated local guard process in a later release.
