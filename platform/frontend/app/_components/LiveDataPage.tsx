"use client";
import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";
import SectionPage from "./SectionPage";
import FindingHelp from "./FindingHelp";
const API = process.env.NEXT_PUBLIC_PLATFORM_API_URL ?? "http://localhost:8000";
const headers = {
  "X-Dev-Subject": "local-analyst",
  "X-Dev-Email": "analyst@signaltrace.local",
};
type Investigation = {
  id: string;
  name: string;
  status: string;
  created_at: string;
};
type Entity = {
  id: string;
  entity_type: string;
  canonical_value: string;
  display_value: string;
  last_seen_at: string;
};
type Job = { id: string; status: string; provider: string };
type Workspace = {
  investigation: Investigation;
  targets: { target_type: string; canonical_value: string }[];
  jobs: Job[];
  evidence_sources: { id: string }[];
  entities: Entity[];
  relationships: { id: string }[];
};
type Provider = {
  name: string;
  target_types: string[];
  passive_only: boolean;
  requires_credentials: boolean;
  available: boolean;
  version: string | null;
};
type Configuration = {
  provider: string;
  enabled: boolean;
  credentials_configured: boolean;
};
type Finding = {
  id: string;
  investigation_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  confidence: number;
  asset_value: string;
  provider: string;
  evidence_observed_at: string | null;
  verification_job_id: string | null;
  verification_requested_at: string | null;
  last_verified_at: string | null;
  resolved_at: string | null;
  clean_observations: number;
  remediation_notes: string;
  owner: string;
  due_at: string | null;
  verification_state: string;
  direct_observed_at: string | null;
  provider_observed_at: string | null;
  verification_history: Array<{
    observed_at: string;
    classification: string;
    direct_state: string;
    provider: string;
  }>;
  corroborating_providers: string[];
  exception_reason: string;
  exception_expires_at: string | null;
  risk_accepted_by_id: string | null;
  risk_accepted_at: string | null;
  monitoring_enabled: boolean;
  monitoring_interval_minutes: number | null;
  next_monitor_at: string | null;
  created_at: string;
};
type Mode =
  "overview" | "assets" | "graph" | "intelligence" | "findings" | "reports";
const copy = {
  overview: [
    "Overview",
    "Current workspace",
    "Live counts from persisted investigations and collected evidence.",
  ],
  assets: [
    "Assets",
    "Normalized inventory",
    "Entities observed by collection jobs across your investigations.",
  ],
  graph: [
    "Exposure graph",
    "Evidence relationships",
    "Open an investigation's interactive graph using persisted entities and relationships.",
  ],
  intelligence: [
    "Intelligence",
    "Collection providers",
    "Installed provider capabilities and configuration state for this organization.",
  ],
  findings: [
    "Findings",
    "Analyst review",
    "Evidence-linked observations requiring analyst review.",
  ],
  reports: [
    "Reports",
    "Evidence exports",
    "Download current investigation workspaces as provenance-preserving JSON.",
  ],
} as const;
function download(workspace: Workspace) {
  const blob = new Blob([JSON.stringify(workspace, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${workspace.investigation.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-report.json`;
  a.click();
  URL.revokeObjectURL(url);
}
export default function LiveDataPage({ mode }: { mode: Mode }) {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]),
    [providers, setProviders] = useState<Provider[]>([]),
    [configs, setConfigs] = useState<Configuration[]>([]),
    [findings, setFindings] = useState<Finding[]>([]),
    [stixInvestigation, setStixInvestigation] = useState(""),
    [stixFile, setStixFile] = useState<File | null>(null),
    [stixMessage, setStixMessage] = useState(""),
    [loading, setLoading] = useState(true),
    [error, setError] = useState("");
  async function importStix(event: FormEvent) {
    event.preventDefault();
    const investigationId = stixInvestigation || workspaces[0]?.investigation.id;
    if (!investigationId || !stixFile) return;
    setStixMessage("Validating and importing…");
    try {
      const bundle = JSON.parse(await stixFile.text());
      const response = await fetch(
        `${API}/api/v1/investigations/${investigationId}/stix/import`,
        {
          method: "POST",
          headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({
            bundle,
            source: stixFile.name,
            default_ttl_days: 90,
          }),
        },
      );
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "STIX import failed");
      setStixMessage(
        `Imported ${result.imported}, updated ${result.updated}, correlated ${result.correlations}. ` +
          `${result.expired_indicators} expired indicator(s) suppressed.`,
      );
    } catch (caught) {
      setStixMessage(caught instanceof Error ? caught.message : "STIX import failed");
    }
  }
  async function updateFinding(
    id: string,
    update: {
      status?: string;
      remediation_notes?: string;
      owner?: string;
      exception_reason?: string;
      exception_expires_at?: string;
      monitoring_enabled?: boolean;
      monitoring_interval_minutes?: number;
    },
  ) {
    const response = await fetch(`${API}/api/v1/findings/${id}`, {
      method: "PATCH",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify(update),
    });
    if (response.ok) {
      const updated = await response.json();
      setFindings((current) =>
        current.map((item) => (item.id === id ? updated : item)),
      );
    }
  }
  async function acceptRisk(id: string) {
    const reason = window.prompt("Why is this risk being accepted?");
    if (!reason?.trim()) return;
    const expires = new Date();
    expires.setDate(expires.getDate() + 30);
    await updateFinding(id, {
      status: "risk_accepted",
      exception_reason: reason.trim(),
      exception_expires_at: expires.toISOString(),
    });
  }
  async function markFalsePositive(id: string) {
    const reason = window.prompt("Why is this finding a false positive?");
    if (!reason?.trim()) return;
    await updateFinding(id, {
      status: "false_positive",
      exception_reason: reason.trim(),
    });
  }
  async function verifyFinding(id: string) {
    setError("");
    const response = await fetch(`${API}/api/v1/findings/${id}/verify`, {
      method: "POST",
      headers,
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      setError(detail.detail ?? "Verification could not be queued");
      return;
    }
    const job = await response.json();
    setFindings((current) =>
      current.map((item) =>
        item.id === id
          ? {
              ...item,
              status: "verifying",
              verification_job_id: job.id,
              verification_requested_at: new Date().toISOString(),
              verification_state: "queued",
              clean_observations: 0,
            }
          : item,
      ),
    );
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      const check = await fetch(`${API}/api/v1/findings/${id}`, {
        headers,
        cache: "no-store",
      });
      if (!check.ok) continue;
      const updated: Finding = await check.json();
      if (updated.verification_state !== "queued") {
        setFindings((current) =>
          current.map((item) => (item.id === id ? updated : item)),
        );
        return;
      }
    }
    setError("Verification is still running. Refresh shortly for the result.");
  }
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const or = await fetch(`${API}/api/v1/organizations`, {
          headers,
          cache: "no-store",
        });
        if (!or.ok) throw new Error("Organizations could not be loaded");
        const orgs = await or.json();
        const groups = await Promise.all(
          orgs.map((org: { id: string }) =>
            fetch(`${API}/api/v1/organizations/${org.id}/investigations`, {
              headers,
              cache: "no-store",
            }).then((r) => {
              if (!r.ok) throw new Error("Investigations could not be loaded");
              return r.json();
            }),
          ),
        );
        const investigations: Investigation[] = groups.flat();
        const loaded = await Promise.all(
          investigations.map((i) =>
            fetch(`${API}/api/v1/investigations/${i.id}/workspace`, {
              headers,
              cache: "no-store",
            }).then((r) => {
              if (!r.ok) throw new Error("Evidence could not be loaded");
              return r.json();
            }),
          ),
        );
        const pr = await fetch(`${API}/api/v1/providers`, {
          headers,
          cache: "no-store",
        });
        const descriptors = pr.ok ? await pr.json() : [];
        const [cg, fg] = await Promise.all([
          Promise.all(
            orgs.map((org: { id: string }) =>
              fetch(`${API}/api/v1/organizations/${org.id}/providers`, {
                headers,
                cache: "no-store",
              }).then((r) => (r.ok ? r.json() : [])),
            ),
          ),
          Promise.all(
            orgs.map((org: { id: string }) =>
              fetch(`${API}/api/v1/organizations/${org.id}/findings`, {
                headers,
                cache: "no-store",
              }).then((r) => (r.ok ? r.json() : [])),
            ),
          ),
        ]);
        if (active) {
          setWorkspaces(loaded);
          setProviders(descriptors);
          setConfigs(cg.flat());
          setFindings(fg.flat());
        }
      } catch (c) {
        if (active)
          setError(c instanceof Error ? c.message : "Data could not be loaded");
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, []);
  const entities = useMemo(
    () =>
      workspaces.flatMap((w) =>
        w.entities.map((e) => ({ ...e, investigation: w.investigation })),
      ),
    [workspaces],
  );
  const jobs = workspaces.flatMap((w) => w.jobs),
    sources = workspaces.flatMap((w) => w.evidence_sources),
    relationships = workspaces.flatMap((w) => w.relationships);
  const [title, eyebrow, description] = copy[mode];
  let content;
  if (loading) content = <Empty title="Loading persisted data…" detail="" />;
  else if (error)
    content = (
      <Empty
        title="Data unavailable"
        detail={`${error}. Confirm the local API is running on port 8000.`}
      />
    );
  else if (mode === "overview")
    content = (
      <>
        <div className="live-metrics">
          <article>
            <strong>{workspaces.length}</strong>
            <span>Investigations</span>
          </article>
          <article>
            <strong>
              {
                jobs.filter((j) => ["queued", "running"].includes(j.status))
                  .length
              }
            </strong>
            <span>Active jobs</span>
          </article>
          <article>
            <strong>{entities.length}</strong>
            <span>Observed entities</span>
          </article>
          <article>
            <strong>{sources.length}</strong>
            <span>Evidence sources</span>
          </article>
        </div>
        <InvestigationList workspaces={workspaces} />
      </>
    );
  else if (mode === "assets")
    content = entities.length ? (
      <div className="truth-table">
        <div className="truth-row truth-head">
          <span>Type</span>
          <span>Canonical value</span>
          <span>Investigation</span>
          <span>Last observed</span>
        </div>
        {entities.map((e) => (
          <div className="truth-row" key={e.id}>
            <span>{e.entity_type.replaceAll("_", " ")}</span>
            <strong>{e.display_value || e.canonical_value}</strong>
            <Link href={`/investigations/${e.investigation.id}`}>
              {e.investigation.name}
            </Link>
            <time>{new Date(e.last_seen_at).toLocaleString()}</time>
          </div>
        ))}
      </div>
    ) : (
      <Empty
        title="No observed assets"
        detail="Run a collection provider from an investigation. Normalized entities will appear after evidence is ingested."
      />
    );
  else if (mode === "graph")
    content = workspaces.length ? (
      <div className="record-grid">
        {workspaces.map((w) => (
          <article key={w.investigation.id}>
            <span>
              {w.entities.length} nodes · {w.relationships.length} edges
            </span>
            <h2>{w.investigation.name}</h2>
            <p>
              {w.targets.map((t) => t.canonical_value).join(", ") ||
                "No target"}
            </p>
            <Link href={`/investigations/${w.investigation.id}`}>
              Open interactive graph →
            </Link>
          </article>
        ))}
      </div>
    ) : (
      <Empty
        title="No investigation graphs"
        detail="Create an investigation and collect evidence to build a graph."
      />
    );
  else if (mode === "intelligence")
    content = (
      <>
        <form className="stix-import" onSubmit={importStix}>
          <div>
            <span className="eyebrow">STIX 2.1</span>
            <h2>Import threat intelligence bundle</h2>
            <p>
              Indicators expire after their supplied validity window, or after 90 days when
              the publisher provides no expiration.
            </p>
          </div>
          <label>
            Investigation
            <select
              value={stixInvestigation || workspaces[0]?.investigation.id || ""}
              onChange={(event) => setStixInvestigation(event.target.value)}
            >
              {workspaces.map((workspace) => (
                <option key={workspace.investigation.id} value={workspace.investigation.id}>
                  {workspace.investigation.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Bundle file
            <input
              type="file"
              accept="application/json,.json"
              onChange={(event) => setStixFile(event.target.files?.[0] ?? null)}
            />
          </label>
          <button type="submit" disabled={!stixFile || workspaces.length === 0}>
            Import bundle
          </button>
          {stixMessage && <output>{stixMessage}</output>}
        </form>
        <div className="truth-table provider-table">
          <div className="truth-row truth-head">
            <span>Provider</span>
            <span>Mode</span>
            <span>Targets</span>
            <span>Configuration</span>
            <span>Health</span>
          </div>
          {providers.map((p) => {
            const c = configs.find((x) => x.provider === p.name);
            return (
              <div className="truth-row" key={p.name}>
                <strong>{p.name.replaceAll("_", " ")}</strong>
                <span>{p.passive_only ? "Passive" : "Active"}</span>
                <span>{p.target_types.join(", ")}</span>
                <span>
                  {!p.available
                    ? "Unavailable · tool not installed"
                    : !(c?.enabled ?? !p.requires_credentials)
                      ? "Unavailable · disabled"
                      : p.requires_credentials && !c?.credentials_configured
                        ? "Unavailable · credentials missing"
                        : "Ready"}
                </span>
                <span>
                  {p.available
                    ? `Healthy · ${p.version || "version unknown"}`
                    : "Not installed"}
                </span>
              </div>
            );
          })}
        </div>
      </>
    );
  else if (mode === "findings")
    content = findings.length ? (
      <div className="finding-records">
        {findings.map((f) => (
          <article className={`finding-record ${f.severity}`} key={f.id}>
            <header>
              <span>{f.severity}</span>
              <b>{f.status}</b>
            </header>
            <div className="finding-title-row">
              <h2>{f.title}</h2>
              <FindingHelp finding={f} />
            </div>
            <strong>{f.asset_value}</strong>
            <p>{f.description}</p>
            <div className={`verification-verdict ${f.verification_state}`}>
              <span>Independent verdict</span>
              <strong>{f.verification_state.replaceAll("_", " ")}</strong>
            </div>
            <div className="finding-lifecycle">
              <div>
                <span>Evidence freshness</span>
                <strong>
                  {f.evidence_observed_at
                    ? formatEvidenceAge(f.evidence_observed_at)
                    : "Unknown"}
                </strong>
              </div>
              <div>
                <span>Provider observed</span>
                <strong>
                  {f.provider_observed_at
                    ? new Date(f.provider_observed_at).toLocaleString()
                    : "Unknown"}
                </strong>
              </div>
              <div>
                <span>Directly observed</span>
                <strong>
                  {f.direct_observed_at
                    ? new Date(f.direct_observed_at).toLocaleString()
                    : "Not yet"}
                </strong>
              </div>
              <div>
                <span>Clean observations</span>
                <strong>{f.clean_observations}/2 required</strong>
              </div>
              <div>
                <span>Last verified</span>
                <strong>
                  {f.last_verified_at
                    ? new Date(f.last_verified_at).toLocaleString()
                    : "Not yet"}
                </strong>
              </div>
            </div>
            {f.verification_history.length > 0 && (
              <details className="verification-history">
                <summary>Verification history</summary>
                {f.verification_history
                  .slice()
                  .reverse()
                  .slice(0, 5)
                  .map((entry, index) => (
                    <div key={`${entry.observed_at}-${index}`}>
                      <strong>
                        {entry.classification.replaceAll("_", " ")}
                      </strong>
                      <span>
                        {new Date(entry.observed_at).toLocaleString()} · direct
                        probe {entry.direct_state}
                      </span>
                    </div>
                  ))}
              </details>
            )}
            <div className="remediation-fields">
              <label>
                Owner
                <input
                  defaultValue={f.owner}
                  placeholder="Assign an owner"
                  onBlur={(event) =>
                    updateFinding(f.id, { owner: event.target.value })
                  }
                />
              </label>
              <label>
                Remediation notes
                <textarea
                  defaultValue={f.remediation_notes}
                  placeholder="What changed, where, and how it was verified"
                  onBlur={(event) =>
                    updateFinding(f.id, {
                      remediation_notes: event.target.value,
                    })
                  }
                />
              </label>
            </div>
            {f.exception_reason && (
              <div className="exception-summary">
                <strong>{f.status.replaceAll("_", " ")}</strong>
                <span>{f.exception_reason}</span>
                {f.exception_expires_at && (
                  <span>
                    Expires {new Date(f.exception_expires_at).toLocaleDateString()}
                  </span>
                )}
              </div>
            )}
            <footer>
              <span>
                {f.provider.replaceAll("_", " ")} · {f.confidence}% confidence
                {f.corroborating_providers.length > 0
                  ? ` · corroborated by ${f.corroborating_providers.join(", ").replaceAll("_", " ")}`
                  : ""}
              </span>
              <Link href={`/investigations/${f.investigation_id}`}>
                Review evidence →
              </Link>
            </footer>
            <div className="finding-actions">
              <label className="finding-monitor-control">
                Monitoring frequency
                <select
                  value={String(f.monitoring_interval_minutes ?? 1440)}
                  onChange={(event) =>
                    updateFinding(f.id, {
                      monitoring_interval_minutes: Number(event.target.value),
                      monitoring_enabled: true,
                    })
                  }
                >
                  <option value="60">Hourly</option>
                  <option value="360">Every 6 hours</option>
                  <option value="1440">Daily</option>
                  <option value="10080">Weekly</option>
                </select>
              </label>
              <button
                onClick={() =>
                  updateFinding(f.id, {
                    monitoring_enabled: !f.monitoring_enabled,
                  })
                }
              >
                {f.monitoring_enabled ? "Pause monitoring" : "Enable monitoring"}
              </button>
              <button
                className="verify-button"
                onClick={() => verifyFinding(f.id)}
              >
                {f.verification_state === "queued"
                  ? "Verification queued"
                  : "Run direct verification"}
              </button>
              {f.status !== "acknowledged" && f.status !== "resolved" && (
                <button
                  onClick={() =>
                    updateFinding(f.id, { status: "acknowledged" })
                  }
                >
                  Acknowledge
                </button>
              )}
              {f.status !== "resolved" && (
                <button
                  onClick={() => updateFinding(f.id, { status: "resolved" })}
                >
                  Resolve
                </button>
              )}
              {f.status !== "dismissed" && (
                <button
                  onClick={() => updateFinding(f.id, { status: "dismissed" })}
                >
                  Dismiss
                </button>
              )}
              {f.status !== "risk_accepted" && (
                <button onClick={() => acceptRisk(f.id)}>Accept risk (30 days)</button>
              )}
              {f.status !== "false_positive" && (
                <button onClick={() => markFalsePositive(f.id)}>False positive</button>
              )}
              {f.status !== "open" && (
                <button onClick={() => updateFinding(f.id, { status: "open" })}>
                  Reopen
                </button>
              )}
            </div>
          </article>
        ))}
      </div>
    ) : (
      <Empty
        title="No persisted findings"
        detail="No collection result currently meets an implemented evidence-backed finding rule."
      />
    );
  else
    content = workspaces.length ? (
      <div className="record-grid">
        {workspaces.map((w) => (
          <article key={w.investigation.id}>
            <span>
              {w.evidence_sources.length} sources · {w.entities.length} entities
              · {w.relationships.length} relationships
            </span>
            <h2>{w.investigation.name}</h2>
            <p>Snapshot generated from the current persisted workspace.</p>
            <div className="record-actions">
              <Link href={`/investigations/${w.investigation.id}`}>Review</Link>
              <button onClick={() => download(w)}>Download JSON</button>
            </div>
          </article>
        ))}
      </div>
    ) : (
      <Empty
        title="No reports available"
        detail="Create an investigation before exporting a report."
      />
    );
  return (
    <SectionPage
      title={title}
      eyebrow={eyebrow}
      description={description}
      action={
        <Link className="new-button" href="/investigations/new">
          ＋ New investigation
        </Link>
      }
    >
      {content}
      {mode === "overview" && (
        <p className="data-footnote">
          {relationships.length} persisted relationships · {providers.length}{" "}
          installed provider adapters
        </p>
      )}
    </SectionPage>
  );
}
function InvestigationList({ workspaces }: { workspaces: Workspace[] }) {
  return workspaces.length ? (
    <div className="record-grid">
      {workspaces
        .slice()
        .sort(
          (a, b) =>
            Date.parse(b.investigation.created_at) -
            Date.parse(a.investigation.created_at),
        )
        .map((w) => (
          <article key={w.investigation.id}>
            <span>
              {w.jobs.length} jobs · {w.entities.length} entities
            </span>
            <h2>{w.investigation.name}</h2>
            <p>
              {w.targets
                .map((t) => `${t.target_type}: ${t.canonical_value}`)
                .join(", ") || "No target configured"}
            </p>
            <Link href={`/investigations/${w.investigation.id}`}>
              Open workspace →
            </Link>
          </article>
        ))}
    </div>
  ) : (
    <Empty
      title="No investigations"
      detail="Create your first authorized investigation to begin collecting evidence."
    />
  );
}
function Empty({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="truth-state">
      <h2>{title}</h2>
      {detail && <p>{detail}</p>}
    </div>
  );
}

function formatEvidenceAge(value: string) {
  const hours = Math.max(0, (Date.now() - Date.parse(value)) / 3_600_000);
  if (hours < 1) return `${Math.max(1, Math.round(hours * 60))} minutes old`;
  if (hours < 48) return `${Math.round(hours)} hours old`;
  return `${Math.round(hours / 24)} days old`;
}
