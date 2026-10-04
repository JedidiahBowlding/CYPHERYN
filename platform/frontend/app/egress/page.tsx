"use client";

import { useEffect, useMemo, useState } from "react";
import SectionPage from "../_components/SectionPage";
import "./egress.css";

const API = process.env.NEXT_PUBLIC_PLATFORM_API_URL ?? "http://localhost:8000";
const headers = {
  "X-Dev-Subject": "local-analyst",
  "X-Dev-Email": "analyst@cypheryn.local",
};

type Organization = { id: string; name: string };
type Overview = {
  protected_agents: number;
  evaluated_actions: number;
  allowed_actions: number;
  blocked_actions: number;
  pending_approvals: number;
  sensitive_artifacts: number;
  unexpected_public_repositories: number;
  enforcement_failures: number;
  provider_health: Record<string, string>;
};
type EgressEvent = {
  event_id: string;
  action_type: string;
  destination: string;
  repository: string;
  decision: string;
  reason_codes: string[];
  human_readable_reason: string;
  status: string;
  policy_id: string;
  policy_version: string;
  integrity_valid: boolean;
  created_at: string;
};
type ProxyReceipt = {
  proxy_request_id: string;
  decision_id: string;
  agent_id: string;
  capability: string;
  destination: string;
  method: string;
  outcome: string;
  security_reason: string;
  response_status: number | null;
  latency_ms: number;
  correlation_id: string;
  started_at: string;
};

export default function EgressPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [organizationId, setOrganizationId] = useState("");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [events, setEvents] = useState<EgressEvent[]>([]);
  const [receipts, setReceipts] = useState<ProxyReceipt[]>([]);
  const [decision, setDecision] = useState("");
  const [selected, setSelected] = useState<EgressEvent | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API}/api/v1/organizations`, { headers })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("Organizations unavailable")))
      .then((items: Organization[]) => {
        setOrganizations(items);
        setOrganizationId(items[0]?.id ?? "");
      })
      .catch((caught) => setError(caught.message));
  }, []);

  useEffect(() => {
    if (!organizationId) return;
    setError("");
    Promise.all([
      fetch(`${API}/api/v1/egress/overview?organization_id=${encodeURIComponent(organizationId)}`, { headers }),
      fetch(`${API}/api/v1/egress/events?organization_id=${encodeURIComponent(organizationId)}&limit=200`, { headers }),
      fetch(`${API}/api/v1/security/proxy-receipts?organization_id=${encodeURIComponent(organizationId)}&limit=100`, { headers }),
    ]).then(async ([summary, activity, proxyActivity]) => {
      if (!summary.ok || !activity.ok || !proxyActivity.ok) throw new Error("Egress telemetry is unavailable");
      setOverview(await summary.json());
      setEvents(await activity.json());
      setReceipts(await proxyActivity.json());
    }).catch((caught) => setError(caught.message));
  }, [organizationId]);

  const visibleEvents = useMemo(
    () => decision ? events.filter((event) => event.decision === decision) : events,
    [events, decision],
  );

  return (
    <SectionPage
      eyebrow="Agent security"
      title="Agent Egress Firewall"
      description="Deterministic outbound controls for development agents, with exact approvals and tamper-evident verification."
      action={organizations.length > 1 ? (
        <select aria-label="Organization" value={organizationId} onChange={(event) => setOrganizationId(event.target.value)}>
          {organizations.map((organization) => <option key={organization.id} value={organization.id}>{organization.name}</option>)}
        </select>
      ) : undefined}
    >
      {error && <p className="egress-error" role="alert">{error}</p>}
      <section className="egress-metrics" aria-label="Egress overview">
        {[
          ["Protected agents", overview?.protected_agents],
          ["Evaluated", overview?.evaluated_actions],
          ["Allowed", overview?.allowed_actions],
          ["Blocked", overview?.blocked_actions],
          ["Approvals", overview?.pending_approvals],
          ["Sensitive", overview?.sensitive_artifacts],
          ["Public attempts", overview?.unexpected_public_repositories],
          ["Failures", overview?.enforcement_failures],
        ].map(([label, value]) => <article key={label}><span>{label}</span><strong>{value ?? "—"}</strong></article>)}
      </section>
      <section className="egress-panel">
        <div className="egress-panel-heading">
          <div><p className="eyebrow">Enforcement ledger</p><h2>Outbound events</h2></div>
          <select aria-label="Filter by decision" value={decision} onChange={(event) => setDecision(event.target.value)}>
            <option value="">All decisions</option>
            {['ALLOW', 'BLOCK', 'REQUIRE_APPROVAL', 'ALLOW_WITH_REDACTION', 'QUARANTINE'].map((value) => <option key={value}>{value}</option>)}
          </select>
        </div>
        <div className="egress-table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Action</th><th>Destination</th><th>Decision</th><th>Verification</th></tr></thead>
            <tbody>
              {visibleEvents.map((event) => (
                <tr key={event.event_id} onClick={() => setSelected(event)} tabIndex={0} onKeyDown={(key) => key.key === "Enter" && setSelected(event)}>
                  <td>{new Date(event.created_at).toLocaleString()}</td>
                  <td>{event.action_type}</td>
                  <td>{event.repository || event.destination}</td>
                  <td><span className={`egress-decision ${event.decision.toLowerCase()}`}>{event.decision.replaceAll("_", " ")}</span></td>
                  <td>{event.status}</td>
                </tr>
              ))}
              {!visibleEvents.length && <tr><td colSpan={5}>No egress events have been recorded for this organization.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      <section className="egress-panel">
        <div className="egress-panel-heading">
          <div><p className="eyebrow">Trusted boundary</p><h2>Recent proxy executions</h2></div>
        </div>
        <div className="egress-table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Agent</th><th>Operation</th><th>Destination</th><th>Outcome</th><th>Latency</th><th>Trace</th></tr></thead>
            <tbody>
              {receipts.map((receipt) => (
                <tr key={receipt.proxy_request_id}>
                  <td>{new Date(receipt.started_at).toLocaleString()}</td>
                  <td>{receipt.agent_id}</td>
                  <td>{receipt.method} · {receipt.capability}</td>
                  <td>{receipt.destination}</td>
                  <td title={receipt.security_reason}>{receipt.outcome.replaceAll("_", " ")}</td>
                  <td>{receipt.latency_ms} ms</td>
                  <td title={receipt.correlation_id}>{receipt.correlation_id}</td>
                </tr>
              ))}
              {!receipts.length && <tr><td colSpan={7}>No trusted proxy executions have been recorded.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      {selected && (
        <section className="egress-panel egress-detail">
          <button type="button" onClick={() => setSelected(null)}>Close</button>
          <p className="eyebrow">Event detail</p>
          <h2>{selected.action_type}</h2>
          <p>{selected.human_readable_reason}</p>
          <dl>
            <div><dt>Destination</dt><dd>{selected.destination}</dd></div>
            <div><dt>Repository</dt><dd>{selected.repository || "Not supplied"}</dd></div>
            <div><dt>Policy</dt><dd>{selected.policy_id} v{selected.policy_version}</dd></div>
            <div><dt>Integrity</dt><dd>{selected.integrity_valid ? "Verified" : "Verification failed"}</dd></div>
            <div><dt>Reason codes</dt><dd>{selected.reason_codes.join(", ")}</dd></div>
          </dl>
          <a href={`${API}/api/v1/egress/events/${selected.event_id}/evidence`} target="_blank" rel="noreferrer">Export evidence JSON</a>
        </section>
      )}
    </SectionPage>
  );
}
