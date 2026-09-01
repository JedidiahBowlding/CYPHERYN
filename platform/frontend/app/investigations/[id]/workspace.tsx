"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useState } from "react";
import EvidenceGraph, {
  ClaimObservation,
  EvidenceSource,
  GraphEntity,
  GraphRelationship,
} from "./EvidenceGraph";
import DashboardNav from "../../_components/DashboardNav";
import { platformApiUrl } from "../../_lib/platformApi";

const API = platformApiUrl();
const headers = {
  "Content-Type": "application/json",
  "X-Dev-Subject": "local-analyst",
  "X-Dev-Email": "analyst@cypheryn.local",
};
type Job = {
  id: string;
  provider: string;
  status: string;
  result_count: number;
  attempt: number;
  max_attempts: number;
  lease_owner: string | null;
  error_summary: string | null;
  created_at: string;
};
type JobEvent = {
  id: string;
  job_id: string;
  event_type: string;
  from_status: string | null;
  to_status: string;
  message: string;
  details: Record<string, unknown>;
  occurred_at: string;
};
type ProviderDescriptor = {
  name: string;
  target_types: string[];
  requires_credentials: boolean;
  passive_only: boolean;
};
type ProviderConfiguration = {
  provider: string;
  enabled: boolean;
  credentials_configured: boolean;
};
type MonitorSchedule = {
  id: string;
  target_id: string;
  provider: string;
  interval_minutes: number;
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
};
type EvidenceChange = {
  id: string;
  provider: string;
  severity: string;
  summary: string;
  details: {
    changed_fields?: { field: string; before: string; after: string }[];
  };
  acknowledged_at: string | null;
  created_at: string;
};
type AnalysisSnapshot = {
  id: string;
  risk_score: number;
  risk_level: string;
  title: string;
  executive_summary: string;
  claims: { classification: string; statement: string; confidence: number }[];
  correlations: {
    classification: string;
    statement: string;
    confidence: number;
    limitation?: string;
  }[];
  recommendations: { priority: string; action: string; asset: string }[];
  metrics: Record<string, number>;
  created_at: string;
};
type NarrativeSnapshot = {
  id: string;
  analysis_snapshot_id: string;
  model: string;
  executive_summary: string;
  technical_summary: string;
  key_points: { text: string; claim_refs: number[] }[];
  classification: string;
  created_at: string;
};
type Workspace = {
  investigation: {
    id: string;
    organization_id: string;
    name: string;
    description: string;
    status: string;
    created_at: string;
  };
  targets: {
    id: string;
    authorization_id: string;
    target_type: string;
    canonical_value: string;
    include_descendants: boolean;
  }[];
  jobs: Job[];
  job_events?: JobEvent[];
  evidence_sources?: EvidenceSource[];
  claim_observations?: ClaimObservation[];
  entities: GraphEntity[];
  relationships: GraphRelationship[];
  monitor_schedules?: MonitorSchedule[];
  evidence_changes?: EvidenceChange[];
  analysis_snapshots?: AnalysisSnapshot[];
  narrative_snapshots?: NarrativeSnapshot[];
};

export type WorkspaceSection =
  "overview" | "graph" | "entities" | "relationships" | "jobs" | "monitoring";

export default function InvestigationWorkspace({
  id,
  section = "overview",
}: {
  id: string;
  section?: WorkspaceSection;
}) {
  const [data, setData] = useState<Workspace | null>(null);
  const [error, setError] = useState("");
  const [enqueueing, setEnqueueing] = useState(false);
  const [collectionMessage, setCollectionMessage] = useState("");
  const [page, setPage] = useState(1);
  const [addingTarget, setAddingTarget] = useState(false);
  const [targetTypeInput, setTargetTypeInput] = useState("domain");
  const [targetValue, setTargetValue] = useState("");
  const [monitorInterval, setMonitorInterval] = useState("1440");
  const [analyzing, setAnalyzing] = useState(false);
  const [narrating, setNarrating] = useState(false);
  const [analysisMessage, setAnalysisMessage] = useState("");
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [provider, setProvider] = useState("safe_mock");
  const [zapActiveApproved, setZapActiveApproved] = useState(false);
  const [configurations, setConfigurations] = useState<ProviderConfiguration[]>(
    [],
  );
  const [providers, setProviders] = useState<ProviderDescriptor[]>([
    {
      name: "safe_mock",
      target_types: [],
      requires_credentials: false,
      passive_only: true,
    },
    {
      name: "rdap",
      target_types: ["domain"],
      requires_credentials: false,
      passive_only: true,
    },
  ]);
  const load = useCallback(async () => {
    const response = await fetch(
      `${API}/api/v1/investigations/${id}/workspace`,
      { headers, cache: "no-store" },
    );
    if (!response.ok) throw new Error("Unable to load investigation");
    setData(await response.json());
  }, [id]);
  useEffect(() => {
    let active = true;
    load().catch((cause) => {
      if (active)
        setError(
          cause instanceof Error
            ? cause.message
            : "Unable to load investigation",
        );
    });
    return () => {
      active = false;
    };
  }, [load]);
  useEffect(() => {
    fetch(`${API}/api/v1/providers`, { headers })
      .then((response) => response.json())
      .then((value) => setProviders(value))
      .catch(() => undefined);
  }, []);
  useEffect(() => {
    if (!data?.investigation.organization_id) return;
    fetch(
      `${API}/api/v1/organizations/${data.investigation.organization_id}/providers`,
      { headers },
    )
      .then((response) => response.json())
      .then((value) => setConfigurations(value))
      .catch(() => undefined);
  }, [data?.investigation.organization_id]);
  const hasActiveJob =
    data?.jobs.some(
      (job) => job.status === "queued" || job.status === "running",
    ) ?? false;
  useEffect(() => {
    if (!hasActiveJob) return;
    const timer = window.setInterval(() => load().catch(() => undefined), 1000);
    return () => window.clearInterval(timer);
  }, [hasActiveJob, load]);
  async function queueProvider(
    providerName: string,
    targetId: string,
    activeAttackApproved = false,
  ) {
    const response = await fetch(`${API}/api/v1/investigations/${id}/collect`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        provider: providerName,
        target_id: targetId,
        active_attack_approved: activeAttackApproved,
      }),
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      throw new Error(
        `${providerName.replaceAll("_", " ")}: ${detail.detail ?? "could not be queued"}`,
      );
    }
    return (await response.json()) as Job;
  }
  async function collect() {
    setEnqueueing(true);
    setError("");
    setCollectionMessage("");
    try {
      const job = await queueProvider(
        effectiveProvider,
        selectedTargetId || data?.targets[0]?.id || "",
        effectiveProvider === "zap_active" && zapActiveApproved,
      );
      if (effectiveProvider === "zap_active") setZapActiveApproved(false);
      setCollectionMessage(
        `${effectiveProvider.replaceAll("_", " ")} queued successfully. Job ${job.id.slice(0, 8)} is ${job.status}.`,
      );
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Collection failed");
    } finally {
      setEnqueueing(false);
    }
  }
  async function addTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!data?.targets[0]) return;
    setAddingTarget(true);
    setError("");
    try {
      const response = await fetch(
        `${API}/api/v1/investigations/${id}/targets`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({
            authorization_id: data.targets[0].authorization_id,
            target_type: targetTypeInput,
            value: targetValue,
            include_descendants: targetTypeInput === "domain",
          }),
        },
      );
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        throw new Error(detail.detail ?? "Target could not be added");
      }
      const created = await response.json();
      setSelectedTargetId(created.id);
      setTargetValue("");
      await load();
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Target could not be added",
      );
    } finally {
      setAddingTarget(false);
    }
  }
  async function createMonitor() {
    if (!selectedTarget) return;
    setError("");
    const response = await fetch(
      `${API}/api/v1/investigations/${id}/monitors`,
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          target_id: selectedTarget.id,
          provider: effectiveProvider,
          interval_minutes: Number(monitorInterval),
          enabled: true,
        }),
      },
    );
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      setError(detail.detail ?? "Monitor could not be created");
      return;
    }
    await load();
  }
  async function toggleMonitor(schedule: MonitorSchedule) {
    await fetch(`${API}/api/v1/monitors/${schedule.id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ enabled: !schedule.enabled }),
    });
    await load();
  }
  async function acknowledgeChange(changeId: string) {
    await fetch(`${API}/api/v1/changes/${changeId}/acknowledge`, {
      method: "POST",
      headers,
    });
    await load();
  }
  async function generateAnalysis() {
    setAnalyzing(true);
    setError("");
    setAnalysisMessage("Updating risk analysis from the latest evidence…");
    const refreshNarrative = Boolean(data?.narrative_snapshots?.length);
    if (refreshNarrative) setNarrating(true);
    try {
      const response = await fetch(
        `${API}/api/v1/investigations/${id}/analysis`,
        {
          method: "POST",
          headers,
        },
      );
      if (!response.ok) throw new Error("Analysis could not be generated");
      await load();
      setAnalysisMessage(
        refreshNarrative
          ? "Risk analysis updated. Local AI is rewriting the summary…"
          : "Risk analysis updated successfully.",
      );
      if (refreshNarrative) {
        const narrativeResponse = await fetch(
          `${API}/api/v1/investigations/${id}/analysis/local-narrative`,
          { method: "POST", headers },
        );
        if (!narrativeResponse.ok) {
          const detail = await narrativeResponse.json().catch(() => ({}));
          setError(
            `Risk analysis updated, but local AI refresh failed: ${detail.detail ?? "local model unavailable"}`,
          );
          setAnalysisMessage(
            "Risk analysis saved. Local AI text was not changed.",
          );
          return;
        }
        await load();
        setAnalysisMessage(
          "Risk analysis and local AI summary are both current.",
        );
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Analysis failed");
      setAnalysisMessage("");
    } finally {
      setAnalyzing(false);
      setNarrating(false);
    }
  }
  async function downloadReport(style: "executive" | "technical") {
    setError("");
    const response = await fetch(
      `${API}/api/v1/investigations/${id}/reports/pdf?style=${style}`,
      { headers },
    );
    if (!response.ok) {
      setError("Generate an analysis snapshot before exporting a report");
      return;
    }
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = `cypheryn-${id.slice(0, 8)}-${style}.pdf`;
    link.click();
    URL.revokeObjectURL(url);
  }
  async function generateNarrative() {
    setNarrating(true);
    setError("");
    try {
      const response = await fetch(
        `${API}/api/v1/investigations/${id}/analysis/local-narrative`,
        { method: "POST", headers },
      );
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        throw new Error(
          detail.detail ?? "Local AI narrative could not be generated",
        );
      }
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Local AI failed");
    } finally {
      setNarrating(false);
    }
  }
  async function cancel(jobId: string) {
    setError("");
    try {
      const response = await fetch(`${API}/api/v1/jobs/${jobId}/cancel`, {
        method: "POST",
        headers,
      });
      if (!response.ok) throw new Error("Job could not be cancelled");
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Cancellation failed");
    }
  }
  if (error && !data) return <main className="detail-loading">{error}</main>;
  if (!data)
    return (
      <main className="detail-loading">Loading authorized workspace…</main>
    );
  const entityById = new Map(
    data.entities.map((entity) => [entity.id, entity]),
  );
  const selectedTarget =
    data.targets.find((item) => item.id === selectedTargetId) ??
    data.targets[0];
  const targetType = selectedTarget?.target_type;
  const availableProviders = providers.filter(
    (item) =>
      item.name === "safe_mock" ||
      !targetType ||
      item.target_types.includes(targetType),
  );
  const configured = new Map(
    configurations.map((item) => [item.provider, item]),
  );
  const readyProviders = availableProviders.filter((item) => {
    if (item.name === "zap_active") return false;
    const configuration = configured.get(item.name);
    if (configuration && !configuration.enabled) return false;
    return (
      !item.requires_credentials ||
      Boolean(configuration?.credentials_configured)
    );
  });
  const effectiveProvider = availableProviders.some(
    (item) => item.name === provider,
  )
    ? provider
    : (availableProviders[0]?.name ?? "safe_mock");
  async function collectAllReady() {
    if (!selectedTarget) return;
    setEnqueueing(true);
    setError("");
    setCollectionMessage("");
    try {
      const outcomes = await Promise.allSettled(
        readyProviders.map((item) =>
          queueProvider(item.name, selectedTarget.id),
        ),
      );
      const failures = outcomes.filter(
        (item) => item.status === "rejected",
      ) as PromiseRejectedResult[];
      if (failures.length)
        setError(
          `${failures.length} provider${failures.length === 1 ? "" : "s"} could not be queued. ${String(failures[0].reason)}`,
        );
      const queuedCount = outcomes.length - failures.length;
      if (queuedCount > 0)
        setCollectionMessage(
          `${queuedCount} provider job${queuedCount === 1 ? "" : "s"} queued successfully.`,
        );
      await load();
    } finally {
      setEnqueueing(false);
    }
  }
  const intelligence = data.entities.filter(
    (entity) => entity.entity_type === "intelligence_record",
  );
  const visibleIntelligence = intelligence.filter((entity) => {
    const evidenceTarget = intelligenceTarget(entity);
    return !selectedTarget || evidenceTarget === selectedTarget.canonical_value;
  });
  const identityProfiles = data.entities.filter(
    (entity) => entity.entity_type === "identity_profile",
  );
  const dnsSources = (data.evidence_sources ?? []).filter(
    (source) => source.provider === "dns_discovery",
  );
  const certificateSources = (data.evidence_sources ?? []).filter(
    (source) => source.provider === "certificate_transparency",
  );
  const webPosture = data.entities.find(
    (entity) => entity.entity_type === "web_posture",
  );
  const workspaceLinks = [
    { label: "Overview", path: `/investigations/${id}` },
    { label: "Graph", path: `/investigations/${id}/graph`, count: data.entities.length },
    { label: "Entities", path: `/investigations/${id}/entities`, count: data.entities.length },
    {
      label: "Relationships",
      path: `/investigations/${id}/relationships`,
      count: data.relationships.length,
    },
    { label: "Jobs", path: `/investigations/${id}/jobs`, count: data.jobs.length },
    {
      label: "Monitoring",
      path: `/investigations/${id}/monitoring`,
      count: data.monitor_schedules?.length ?? 0,
    },
  ];
  return (
    <main className="detail-page dashboard-detail-page">
      <DashboardNav
        workspaceName={data.investigation.name}
        workspaceLinks={workspaceLinks}
      />
      <div className={`detail-wrap section-${section}`}>
        <section className="detail-title">
          <div>
            <p className="eyebrow">Investigation workspace</p>
            <h1>{data.investigation.name}</h1>
            <p>
              {data.investigation.description ||
                "No investigation description provided."}
            </p>
          </div>
          <div className="detail-state">
            <span className={data.investigation.status.toLowerCase()} />
            {data.investigation.status}
          </div>
        </section>
        <section
          className="detail-panel collection-console"
          aria-label="Run collection"
        >
          <header>
            <div>
              <h2>Run collection</h2>
              <p>Select the exact target and the provider you want to run.</p>
            </div>
            <span>{readyProviders.length} providers ready</span>
          </header>
          <div className="collection-fields">
            <label>
              Target
              <select
                aria-label="Collection target"
                value={selectedTarget?.id ?? ""}
                onChange={(event) => setSelectedTargetId(event.target.value)}
              >
                {data.targets.map((item) => (
                  <option value={item.id} key={item.id}>
                    {item.canonical_value} ·{" "}
                    {item.target_type.replaceAll("_", " ")}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Provider
              <select
                aria-label="Collection provider"
                value={effectiveProvider}
                onChange={(event) => setProvider(event.target.value)}
              >
                {availableProviders.map((item) => (
                  <option value={item.name} key={item.name}>
                    {item.name.replaceAll("_", " ")}
                    {item.requires_credentials ? " · credentials saved" : ""}
                  </option>
                ))}
              </select>
            </label>
            <div className="collection-buttons">
              <button
                onClick={collect}
                disabled={
                  enqueueing ||
                  !data.targets.length ||
                  (effectiveProvider === "zap_active" && !zapActiveApproved)
                }
              >
                {enqueueing
                  ? "Queueing…"
                  : `▶ Run ${effectiveProvider.replaceAll("_", " ")}`}
              </button>
              <button
                className="queue-all-button"
                onClick={collectAllReady}
                disabled={enqueueing || !readyProviders.length}
              >
                Run all ready ({readyProviders.length})
              </button>
            </div>
            {effectiveProvider === "zap_active" && (
              <label className="active-attack-approval">
                <input
                  type="checkbox"
                  checked={zapActiveApproved}
                  onChange={(event) =>
                    setZapActiveApproved(event.target.checked)
                  }
                />
                I explicitly approve this active ZAP attack for the selected
                authorized target.
              </label>
            )}
          </div>
          <footer>
            <div>
              <strong>To recheck UDP/500:</strong> choose <b>104.131.175.81</b>,
              select <b>Censys</b>, then click Run Censys.
            </div>
            {collectionMessage && (
              <div className="collection-feedback" role="status">
                <span aria-hidden="true">✓</span>
                <b>{collectionMessage}</b>
                <Link href={`/investigations/${id}/jobs`}>
                  View job progress →
                </Link>
              </div>
            )}
          </footer>
        </section>
        <AnalysisPanel
          snapshots={data.analysis_snapshots ?? []}
          narrative={data.narrative_snapshots?.[0]}
          generating={analyzing}
          narrating={narrating}
          onGenerate={generateAnalysis}
          onNarrate={generateNarrative}
          onDownload={downloadReport}
          latestEvidenceAt={
            data.jobs.find((job) => job.status === "completed")?.created_at
          }
          statusMessage={analysisMessage}
        />
        <section className="detail-panel monitoring-panel" id="monitoring">
          <header>
            <div>
              <h2>Continuous monitoring</h2>
              <p>Durable rescans with evidence comparison and change alerts</p>
            </div>
            <div className="monitor-create">
              <select
                value={monitorInterval}
                onChange={(event) => setMonitorInterval(event.target.value)}
                aria-label="Monitoring frequency"
              >
                <option value="5">Every 5 minutes</option>
                <option value="60">Hourly</option>
                <option value="360">Every 6 hours</option>
                <option value="1440">Daily</option>
                <option value="10080">Weekly</option>
              </select>
              <button onClick={createMonitor} disabled={!selectedTarget}>
                Monitor {effectiveProvider.replaceAll("_", " ")}
              </button>
            </div>
          </header>
          <div className="monitor-layout">
            <div className="monitor-list">
              {(data.monitor_schedules ?? []).length ? (
                (data.monitor_schedules ?? [])
                  .slice((page - 1) * 10, page * 10)
                  .map((schedule) => (
                    <article key={schedule.id}>
                      <span
                        className={schedule.enabled ? "enabled" : "paused"}
                      />
                      <div>
                        <strong>
                          {schedule.provider.replaceAll("_", " ")}
                        </strong>
                        <small>
                          Every {formatInterval(schedule.interval_minutes)} ·
                          next {new Date(schedule.next_run_at).toLocaleString()}
                        </small>
                      </div>
                      <button onClick={() => toggleMonitor(schedule)}>
                        {schedule.enabled ? "Pause" : "Resume"}
                      </button>
                    </article>
                  ))
              ) : (
                <p className="monitor-empty">
                  Choose a target and provider above, then create a monitoring
                  schedule.
                </p>
              )}
              <Pagination
                page={page}
                total={(data.monitor_schedules ?? []).length}
                onChange={setPage}
              />
            </div>
            <div className="change-list">
              <h3>Change alerts</h3>
              {(data.evidence_changes ?? [])
                .slice((page - 1) * 10, page * 10)
                .map((change) => (
                  <article
                    className={change.acknowledged_at ? "acknowledged" : ""}
                    key={change.id}
                  >
                    <div>
                      <strong>{change.summary}</strong>
                      <small>
                        {new Date(change.created_at).toLocaleString()} ·{" "}
                        {change.severity}
                      </small>
                    </div>
                    {!change.acknowledged_at && (
                      <button onClick={() => acknowledgeChange(change.id)}>
                        Acknowledge
                      </button>
                    )}
                  </article>
                ))}
              {!(data.evidence_changes ?? []).length && (
                <p className="monitor-empty">
                  No evidence changes detected yet.
                </p>
              )}
            </div>
          </div>
        </section>
        <section className="detail-grid">
          <article className="detail-panel scope-panel">
            <header>
              <div>
                <h2>Authorized scope</h2>
                <p>Passive collection policy enforced</p>
              </div>
              <span>✓ Valid</span>
            </header>
            {data.targets.map((target) => (
              <div className="target-card" key={target.id}>
                <i>{target.target_type === "domain" ? "D" : "T"}</i>
                <div>
                  <strong>{target.canonical_value}</strong>
                  <small>
                    {target.target_type.replace("_", " ")} ·{" "}
                    {target.include_descendants
                      ? "descendants recorded"
                      : "exact target"}
                  </small>
                </div>
                <b>Authorized</b>
              </div>
            ))}
            <form className="target-add-form" onSubmit={addTarget}>
              <select
                value={targetTypeInput}
                onChange={(event) => setTargetTypeInput(event.target.value)}
                aria-label="New target type"
              >
                <option value="domain">Domain</option>
                <option value="ip_address">IP address</option>
                <option value="asn">ASN</option>
                <option value="url">URL</option>
                <option value="email_address">Email address</option>
                <option value="person">Person name</option>
                <option value="username">Username</option>
                <option value="organization">Organization</option>
                <option value="repository">Local or GitHub repository</option>
                <option value="container_image">Container image</option>
                <option value="sbom">SBOM file</option>
              </select>
              <input
                value={targetValue}
                onChange={(event) => setTargetValue(event.target.value)}
                required
                placeholder="Add an authorized target"
              />
              <button disabled={addingTarget}>
                {addingTarget ? "Adding…" : "+ Add target"}
              </button>
              <small>
                Uses this investigation’s existing authorization record.
              </small>
            </form>
          </article>
          <article className="detail-panel job-panel" id="jobs">
            <header>
              <div>
                <h2>Durable job activity</h2>
                <p>Leased worker execution with bounded retries</p>
              </div>
              {hasActiveJob && <span className="queue-live">Live</span>}
            </header>
            {data.jobs.length === 0 ? (
              <div className="empty-state">
                <span>◎</span>
                <strong>No collection jobs yet</strong>
                <p>
                  Queue the synthetic collector to validate durable execution
                  before connecting providers.
                </p>
              </div>
            ) : (
              <>
                <div className="job-list">
                  {data.jobs.slice((page - 1) * 10, page * 10).map((job) => (
                    <div className="job-row" key={job.id}>
                      <span className={job.status} />
                      <div>
                        <strong>{job.provider.replace("_", " ")}</strong>
                        <small>
                          Attempt {job.attempt}/{job.max_attempts} ·{" "}
                          {job.result_count} results
                          {job.error_summary ? ` · ${job.error_summary}` : ""}
                        </small>
                      </div>
                      <b>{job.status}</b>
                      {(job.status === "queued" ||
                        job.status === "running") && (
                        <button onClick={() => cancel(job.id)}>Cancel</button>
                      )}
                    </div>
                  ))}
                  <Pagination
                    page={page}
                    total={data.jobs.length}
                    onChange={setPage}
                  />
                </div>
                <div className="job-timeline">
                  <h3>Execution history</h3>
                  {(data.job_events ?? []).slice(0, 8).map((event) => (
                    <div className="job-event" key={event.id}>
                      <i className={event.to_status} />
                      <div>
                        <strong>{event.event_type.replaceAll("_", " ")}</strong>
                        <small>{event.message}</small>
                      </div>
                      <time>
                        {new Date(event.occurred_at).toLocaleTimeString([], {
                          hour: "2-digit",
                          minute: "2-digit",
                          second: "2-digit",
                        })}
                      </time>
                    </div>
                  ))}
                </div>
              </>
            )}
          </article>
        </section>
        {certificateSources.length > 0 && (
          <section className="detail-panel certificate-results">
            <header>
              <div>
                <h2>Certificate transparency</h2>
                <p>
                  Passive certificate names constrained to the authorized domain
                </p>
              </div>
              <span>
                {Number(
                  certificateSources[0].redacted_payload.certificate_count ?? 0,
                )}{" "}
                certificates
              </span>
            </header>
            <div className="certificate-name-list">
              {(
                (certificateSources[0].redacted_payload.discovered_domains ??
                  []) as unknown[]
              ).length ? (
                (
                  (certificateSources[0].redacted_payload.discovered_domains ??
                    []) as unknown[]
                ).map((value) => (
                  <span key={String(value)}>{String(value)}</span>
                ))
              ) : (
                <p>
                  No subdomains were present in certificate transparency
                  results.
                </p>
              )}
            </div>
          </section>
        )}
        {webPosture && <WebPostureResult entity={webPosture} />}
        {identityProfiles.length > 0 && (
          <section className="detail-panel identity-results">
            <header>
              <div>
                <h2>Public identity candidates</h2>
                <p>Passive public-profile matches; corroboration is required</p>
              </div>
              <span>{identityProfiles.length} candidates</span>
            </header>
            <div className="identity-grid">
              {identityProfiles.map((entity) => (
                <IdentityCandidate entity={entity} key={entity.id} />
              ))}
            </div>
          </section>
        )}
        {dnsSources.length > 0 && (
          <section className="detail-panel dns-results">
            <header>
              <div>
                <h2>DNS discovery</h2>
                <p>Passive records and automatically enriched addresses</p>
              </div>
              <span>{dnsSources.length} names resolved</span>
            </header>
            {dnsSources.slice(0, 20).map((source) => (
              <div className="dns-source" key={source.id}>
                <h3>{source.query}</h3>
                <div className="dns-record-grid">
                  {Object.entries(
                    (source.redacted_payload.records ?? {}) as Record<
                      string,
                      unknown[]
                    >,
                  ).map(([type, values]) => (
                    <article key={type}>
                      <strong>{type}</strong>
                      {values.length ? (
                        values.map((value, index) => (
                          <span key={`${type}-${index}`}>{String(value)}</span>
                        ))
                      ) : (
                        <small>No record</small>
                      )}
                    </article>
                  ))}
                </div>
              </div>
            ))}
          </section>
        )}
        {intelligence.length > 0 && (
          <section className="detail-panel intelligence-results">
            <header>
              <div>
                <h2>Threat intelligence results</h2>
                <p>
                  Results for{" "}
                  {selectedTarget?.canonical_value ?? "the selected target"}
                </p>
              </div>
              <span className="intel-target-count">
                {visibleIntelligence.length} provider result
                {visibleIntelligence.length === 1 ? "" : "s"}
              </span>
            </header>
            {visibleIntelligence.length ? (
              <div className="intel-result-grid">
                {visibleIntelligence.map((entity) => (
                  <IntelligenceResult entity={entity} key={entity.id} />
                ))}
              </div>
            ) : (
              <div className="intel-empty">
                No threat-intelligence provider has returned evidence for this
                target yet. Choose another target above or run its providers.
              </div>
            )}
          </section>
        )}
        {data.entities.length > 0 && (
          <EvidenceGraph
            entities={data.entities}
            relationships={data.relationships}
            sources={data.evidence_sources ?? []}
            observations={data.claim_observations ?? []}
          />
        )}
        <section className="detail-panel evidence-panel" id="entities">
          <header>
            <div>
              <h2>Evidence-backed entities</h2>
              <p>Every item retains provider, confidence, and claim class</p>
            </div>
            <span>{data.entities.length} observed</span>
          </header>
          {data.entities.length === 0 ? (
            <div className="evidence-empty">
              <strong>Your evidence graph starts here.</strong>
              <p>
                Queue synthetic collection to create normalized entities and
                relationships without touching a real external provider.
              </p>
              <button onClick={collect} disabled={enqueueing}>
                {enqueueing ? "Queueing…" : "Queue safe mock collection"}
              </button>
            </div>
          ) : (
            <div className="entity-grid">
              {data.entities.slice((page - 1) * 12, page * 12).map((entity) => (
                <div className="entity-card" key={entity.id}>
                  <span>{entity.entity_type.slice(0, 3).toUpperCase()}</span>
                  <div>
                    <strong>{entity.canonical_value}</strong>
                    <small>{entity.entity_type.replace("_", " ")}</small>
                  </div>
                  <b>{entity.confidence}%</b>
                </div>
              ))}
              <Pagination
                page={page}
                total={data.entities.length}
                pageSize={12}
                onChange={setPage}
              />
            </div>
          )}
        </section>
        {data.relationships.length > 0 && (
          <section
            className="detail-panel relationship-panel"
            id="relationships"
          >
            <header>
              <div>
                <h2>Observed relationships</h2>
                <p>Facts remain distinct from derived and AI claims</p>
              </div>
            </header>
            {data.relationships
              .slice((page - 1) * 10, page * 10)
              .map((relationship) => (
                <div className="relationship-row" key={relationship.id}>
                  <strong>
                    {
                      entityById.get(relationship.subject_entity_id)
                        ?.canonical_value
                    }
                  </strong>
                  <span>{relationship.predicate.replaceAll("_", " ")}</span>
                  <strong>
                    {
                      entityById.get(relationship.object_entity_id)
                        ?.canonical_value
                    }
                  </strong>
                  <b>{relationship.confidence}%</b>
                </div>
              ))}
            <Pagination
              page={page}
              total={data.relationships.length}
              onChange={setPage}
            />
          </section>
        )}
        {error && <div className="form-error">{error}</div>}
      </div>
    </main>
  );
}

function Pagination({
  page,
  total,
  pageSize = 10,
  onChange,
}: {
  page: number;
  total: number;
  pageSize?: number;
  onChange: (page: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (pages <= 1) return null;
  return (
    <nav className="pagination" aria-label="Results pages">
      <button disabled={page <= 1} onClick={() => onChange(page - 1)}>
        ← Previous
      </button>
      <span>
        Page {page} of {pages} · {total} records
      </span>
      <button disabled={page >= pages} onClick={() => onChange(page + 1)}>
        Next →
      </button>
    </nav>
  );
}

function IntelligenceResult({ entity }: { entity: GraphEntity }) {
  const a = entity.attributes;
  const stats = (a.analysis_stats ?? {}) as Record<string, number>;
  return (
    <article className="intel-result">
      <header>
        <span>{entity.provider.replaceAll("_", " ")}</span>
        <b>
          {String(a.verdict ?? a.kind ?? "lookup complete").replaceAll(
            "_",
            " ",
          )}
        </b>
      </header>
      {a.kind === "virustotal_verdict" && (
        <div className="verdict-counts">
          <span>
            <strong>{stats.malicious ?? 0}</strong>Malicious
          </span>
          <span>
            <strong>{stats.suspicious ?? 0}</strong>Suspicious
          </span>
          <span>
            <strong>{stats.harmless ?? 0}</strong>Harmless
          </span>
          <span>
            <strong>{stats.undetected ?? 0}</strong>Undetected
          </span>
        </div>
      )}
      {a.kind === "otx_pulse_summary" && (
        <p>
          <strong>{Number(a.pulse_count ?? 0)}</strong> matching OTX pulses ·{" "}
          <strong>{((a.malware_families ?? []) as unknown[]).length}</strong>{" "}
          malware families
        </p>
      )}
      {a.kind === "threatfox_summary" && (
        <p>
          <strong>{Number(a.match_count ?? 0)}</strong> exact ThreatFox records
          · {String(a.query_status ?? "unknown")}
        </p>
      )}
      {a.kind === "censys_host_summary" && (
        <>
          <p>
            <strong>{Number(a.service_count ?? 0)}</strong> observed public
            services ·{" "}
            {String(
              ((a.operating_system ?? {}) as Record<string, unknown>).product ??
                "OS unknown",
            )}
          </p>
          <div className="service-pills">
            {((a.services ?? []) as Record<string, unknown>[]).map(
              (service) => (
                <span key={`${service.port}-${service.transport}`}>
                  {String(service.protocol)} {String(service.port)}/
                  {String(service.transport)}
                </span>
              ),
            )}
          </div>
        </>
      )}
      {Array.isArray(a.malware_families) && a.malware_families.length > 0 && (
        <small>Malware: {a.malware_families.map(String).join(", ")}</small>
      )}
    </article>
  );
}

function intelligenceTarget(entity: GraphEntity) {
  const prefix = `${entity.provider}:`;
  const withoutProvider = entity.canonical_value.startsWith(prefix)
    ? entity.canonical_value.slice(prefix.length)
    : entity.canonical_value;
  const separator = withoutProvider.indexOf(":");
  return separator >= 0
    ? withoutProvider.slice(separator + 1)
    : withoutProvider;
}

function IdentityCandidate({ entity }: { entity: GraphEntity }) {
  const attributes = entity.attributes;
  return (
    <article className="identity-card">
      <header>
        <div>
          <strong>{String(attributes.display_name ?? attributes.login)}</strong>
          <small>
            @{String(attributes.login)} · {String(attributes.source)}
          </small>
        </div>
        <b>{entity.confidence}% match</b>
      </header>
      {attributes.bio ? <p>{String(attributes.bio)}</p> : null}
      <dl>
        {attributes.company ? (
          <div>
            <dt>Company</dt>
            <dd>{String(attributes.company)}</dd>
          </div>
        ) : null}
        {attributes.location ? (
          <div>
            <dt>Location</dt>
            <dd>{String(attributes.location)}</dd>
          </div>
        ) : null}
        <div>
          <dt>Public repositories</dt>
          <dd>{String(attributes.public_repositories ?? 0)}</dd>
        </div>
        <div>
          <dt>Followers</dt>
          <dd>{String(attributes.followers ?? 0)}</dd>
        </div>
      </dl>
      <footer>
        <span>Candidate, not confirmed identity</span>
        <a
          href={String(attributes.profile_url)}
          target="_blank"
          rel="noreferrer"
        >
          View source →
        </a>
      </footer>
    </article>
  );
}

function formatInterval(minutes: number) {
  if (minutes % 10080 === 0) return `${minutes / 10080} week(s)`;
  if (minutes % 1440 === 0) return `${minutes / 1440} day(s)`;
  if (minutes % 60 === 0) return `${minutes / 60} hour(s)`;
  return `${minutes} minute(s)`;
}

function AnalysisPanel({
  snapshots,
  narrative,
  generating,
  narrating,
  onGenerate,
  onNarrate,
  onDownload,
  latestEvidenceAt,
  statusMessage,
}: {
  snapshots: AnalysisSnapshot[];
  narrative?: NarrativeSnapshot;
  generating: boolean;
  narrating: boolean;
  onGenerate: () => void;
  onNarrate: () => void;
  onDownload: (style: "executive" | "technical") => void;
  latestEvidenceAt?: string;
  statusMessage: string;
}) {
  const snapshot = snapshots[0];
  const analysisStale = Boolean(
    snapshot &&
    latestEvidenceAt &&
    new Date(latestEvidenceAt) > new Date(snapshot.created_at),
  );
  const narrativeStale = Boolean(
    snapshot && narrative && narrative.analysis_snapshot_id !== snapshot.id,
  );
  return (
    <section className="detail-panel analysis-panel" id="analysis">
      <header>
        <div>
          <h2>Evidence-based risk analysis</h2>
          <p>
            Deterministic scoring with source-linked claims and explicit
            limitations
          </p>
        </div>
        <div className="analysis-actions">
          <button onClick={onGenerate} disabled={generating}>
            {generating
              ? narrating
                ? "Refreshing analysis + AI…"
                : "Analyzing…"
              : snapshot
                ? narrative
                  ? "Refresh analysis + AI"
                  : "Refresh analysis"
                : "Generate analysis"}
          </button>
          {snapshot && (
            <>
              <button onClick={onNarrate} disabled={narrating}>
                {narrating
                  ? "Local AI working…"
                  : narrative
                    ? "Refresh local AI"
                    : "Generate local AI"}
              </button>
              <button onClick={() => onDownload("executive")}>
                Executive PDF
              </button>
              <button onClick={() => onDownload("technical")}>
                Technical PDF
              </button>
            </>
          )}
        </div>
      </header>
      {statusMessage && (
        <div className="analysis-progress" role="status" aria-live="polite">
          {(generating || narrating) && <i aria-hidden="true" />}
          <span>{statusMessage}</span>
        </div>
      )}
      {(analysisStale || narrativeStale) && (
        <div className="analysis-stale" role="status">
          <strong>New scan evidence is available.</strong>
          <span>
            {analysisStale
              ? "The risk analysis predates the latest completed scan. "
              : ""}
            {narrativeStale
              ? "The local AI text belongs to an older analysis."
              : ""}
          </span>
          <button onClick={onGenerate} disabled={generating}>
            Update now
          </button>
        </div>
      )}
      {!snapshot ? (
        <div className="analysis-empty">
          <strong>No analysis snapshot yet</strong>
          <p>
            Generate a snapshot from the investigation’s current persisted
            evidence.
          </p>
        </div>
      ) : (
        <>
          <div className="risk-summary">
            <div className={`risk-score ${snapshot.risk_level}`}>
              <strong>{snapshot.risk_score}</strong>
              <span>/100</span>
              <b>{snapshot.risk_level}</b>
            </div>
            <div>
              <h3>{snapshot.title}</h3>
              <p>{snapshot.executive_summary}</p>
              <small>
                Generated {new Date(snapshot.created_at).toLocaleString()}
              </small>
            </div>
          </div>
          {narrative && (
            <div className="local-narrative">
              <header>
                <span>{narrative.classification.replaceAll("_", " ")}</span>
                <b>{narrative.model} · local only</b>
              </header>
              <p>{narrative.executive_summary}</p>
              {narrative.key_points.length > 0 && (
                <ul>
                  {narrative.key_points.map((item, index) => (
                    <li key={index}>
                      {item.text}
                      <small>
                        Claim references: {item.claim_refs.join(", ")}
                      </small>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
          {snapshots.length > 1 && (
            <div className="risk-trend">
              <h3>Risk history</h3>
              <div>
                {[...snapshots].reverse().map((item) => (
                  <span
                    key={item.id}
                    title={`${item.risk_score}/100 · ${new Date(item.created_at).toLocaleString()}`}
                  >
                    <i
                      className={`risk-height-${Math.min(100, Math.max(5, Math.ceil(item.risk_score / 5) * 5))}`}
                    />
                    <small>{item.risk_score}</small>
                  </span>
                ))}
              </div>
            </div>
          )}
          <div className="analysis-columns">
            <article>
              <h3>Supported claims</h3>
              {snapshot.claims.length ? (
                snapshot.claims.map((claim, index) => (
                  <div className="analysis-item" key={index}>
                    <span>{claim.classification.replaceAll("_", " ")}</span>
                    <p>{claim.statement}</p>
                    <b>{claim.confidence}%</b>
                  </div>
                ))
              ) : (
                <p className="analysis-none">
                  No active evidence-backed claims.
                </p>
              )}
            </article>
            <article>
              <h3>Prioritized actions</h3>
              {snapshot.recommendations.length ? (
                snapshot.recommendations.map((item, index) => (
                  <div className="analysis-item" key={index}>
                    <span>{item.priority}</span>
                    <p>
                      {item.action}
                      <small>{item.asset}</small>
                    </p>
                  </div>
                ))
              ) : (
                <p className="analysis-none">
                  No remediation actions are currently required.
                </p>
              )}
            </article>
          </div>
          {snapshot.correlations.map((item, index) => (
            <div className="correlation-note" key={index}>
              <strong>
                {item.classification.replaceAll("_", " ")} · {item.confidence}%
              </strong>
              <p>{item.statement}</p>
              {item.limitation && <small>{item.limitation}</small>}
            </div>
          ))}
        </>
      )}
    </section>
  );
}

function WebPostureResult({ entity }: { entity: GraphEntity }) {
  const a = entity.attributes;
  const http = a.http as Record<string, unknown>;
  const https = a.https as Record<string, unknown>;
  const headers = https.headers as Record<string, unknown>;
  const certificate = a.certificate as Record<string, unknown>;
  return (
    <section className="detail-panel web-posture-result">
      <header>
        <div>
          <h2>TLS and web security posture</h2>
          <p>Bounded HEAD/GET validation on standard web ports</p>
        </div>
        <span>HTTPS {String(https.status)}</span>
      </header>
      <div className="posture-grid">
        <article>
          <strong>HTTP redirect</strong>
          <b>
            {String(http.status)} → {String(http.location)}
          </b>
        </article>
        <article>
          <strong>Certificate expiry</strong>
          <b>
            {certificate.expires_at
              ? new Date(String(certificate.expires_at)).toLocaleDateString()
              : "Unavailable"}
          </b>
          <small>
            {Object.values(
              (certificate.issuer ?? {}) as Record<string, unknown>,
            )
              .map(String)
              .join(" · ")}
          </small>
        </article>
        {Object.entries(headers).map(([name, value]) => (
          <article key={name}>
            <strong>{name.replaceAll("-", " ")}</strong>
            <b className={value ? "present" : "missing"}>
              {value ? "Present" : "Missing"}
            </b>
          </article>
        ))}
      </div>
    </section>
  );
}
