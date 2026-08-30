"use client";

import { FormEvent, useEffect, useState } from "react";
import SectionPage from "../_components/SectionPage";

const API = process.env.NEXT_PUBLIC_PLATFORM_API_URL ?? "http://localhost:8000";
const headers = { "X-Dev-Subject": "local-analyst", "X-Dev-Email": "analyst@cypheryn.local" };
type Organization = { id: string; name: string };
type Investigation = { id: string; name: string };
type Rule = { id: string; title: string; rule_id: string; level: string; logsource: Record<string, string>; tags: string[]; updated_at: string };
type Detection = { id: string; source: string; signature: string; severity: string; src_ip: string | null; src_port: number | null; dest_ip: string | null; dest_port: number | null; protocol: string; correlated_entity_ids: string[]; observed_at: string };

export default function DetectionsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [organizationId, setOrganizationId] = useState("");
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [investigationId, setInvestigationId] = useState("");
  const [rules, setRules] = useState<Rule[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [sigmaFile, setSigmaFile] = useState<File | null>(null);
  const [logFile, setLogFile] = useState<File | null>(null);
  const [logSource, setLogSource] = useState("suricata");
  const [authorized, setAuthorized] = useState(false);
  const [message, setMessage] = useState("");

  async function loadRules(org: string) {
    if (!org) return;
    const response = await fetch(`${API}/api/v1/organizations/${org}/detection-rules`, { headers, cache: "no-store" });
    if (response.ok) setRules(await response.json());
  }
  async function loadDetections(investigation: string) {
    if (!investigation) return;
    const response = await fetch(`${API}/api/v1/investigations/${investigation}/network-detections`, { headers, cache: "no-store" });
    if (response.ok) setDetections(await response.json());
  }
  useEffect(() => {
    (async () => {
      const response = await fetch(`${API}/api/v1/organizations`, { headers });
      if (!response.ok) return;
      const loaded = await response.json();
      setOrganizations(loaded);
      if (loaded[0]) setOrganizationId(loaded[0].id);
    })();
  }, []);
  useEffect(() => {
    if (!organizationId) return;
    void loadRules(organizationId);
    fetch(`${API}/api/v1/organizations/${organizationId}/investigations`, { headers })
      .then((response) => response.ok ? response.json() : [])
      .then((loaded) => { setInvestigations(loaded); setInvestigationId(loaded[0]?.id ?? ""); });
  }, [organizationId]);
  useEffect(() => { void loadDetections(investigationId); }, [investigationId]);

  async function importSigma(event: FormEvent) {
    event.preventDefault();
    if (!sigmaFile || !organizationId) return;
    const response = await fetch(`${API}/api/v1/organizations/${organizationId}/detection-rules/sigma`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ content: await sigmaFile.text() }),
    });
    const result = await response.json().catch(() => ({}));
    setMessage(response.ok ? `Sigma rule imported: ${result.title}.` : result.detail ?? "Sigma import failed.");
    if (response.ok) await loadRules(organizationId);
  }
  async function importLog(event: FormEvent) {
    event.preventDefault();
    if (!logFile || !investigationId || !authorized) return;
    const response = await fetch(`${API}/api/v1/investigations/${investigationId}/network-detections/${logSource}`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/x-ndjson", "X-Analysis-Authorization": "confirmed" },
      body: logFile,
    });
    const result = await response.json().catch(() => ({}));
    setMessage(response.ok ? `Imported ${result.imported}; correlated ${result.correlated}; skipped ${result.skipped}.` : result.detail ?? "Log import failed.");
    if (response.ok) await loadDetections(investigationId);
  }
  async function download(format: "sigma" | "suricata") {
    const response = await fetch(`${API}/api/v1/organizations/${organizationId}/detection-rules/${format}/export`, { headers });
    if (!response.ok) return setMessage("Export failed.");
    const url = URL.createObjectURL(await response.blob());
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = format === "sigma" ? "cypheryn-sigma-rules.yml" : "cypheryn-stix.rules";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return <SectionPage title="Detection engineering" eyebrow="Phase 10" description="Manage portable detections and correlate authorized network telemetry with investigation assets.">
    <div className="detection-selectors">
      <label>Organization<select value={organizationId} onChange={(event) => setOrganizationId(event.target.value)}>{organizations.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <label>Investigation<select value={investigationId} onChange={(event) => setInvestigationId(event.target.value)}>{investigations.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <label className="authorization-check"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />I confirm these logs are authorized for analysis.</label>
    </div>
    <div className="detection-actions">
      <form onSubmit={importSigma}><span className="eyebrow">Sigma</span><h2>Import a detection rule</h2><p>Validated YAML with title, logsource, detection selections, and condition.</p><input type="file" accept=".yml,.yaml,text/yaml" onChange={(event) => setSigmaFile(event.target.files?.[0] ?? null)} /><button disabled={!sigmaFile}>Import Sigma</button></form>
      <form onSubmit={importLog}><span className="eyebrow">Network telemetry</span><h2>Import JSON-lines logs</h2><p>Suricata EVE alerts or Zeek JSON logs, limited to 10 MiB and 5,000 events.</p><select value={logSource} onChange={(event) => setLogSource(event.target.value)}><option value="suricata">Suricata EVE</option><option value="zeek">Zeek JSON</option></select><input type="file" accept=".json,.jsonl,.ndjson" onChange={(event) => setLogFile(event.target.files?.[0] ?? null)} /><button disabled={!logFile || !authorized}>Import telemetry</button></form>
    </div>
    <div className="detection-export"><button onClick={() => download("sigma")}>Export Sigma rules</button><button onClick={() => download("suricata")}>Export Suricata rules from STIX</button></div>
    {message && <div className="collection-feedback" role="status">{message}</div>}
    <section className="detection-records"><header><div><span className="eyebrow">Portable content</span><h2>Sigma rules</h2></div><strong>{rules.length}</strong></header>{rules.length ? rules.map((rule) => <article key={rule.id}><header><b>{rule.title}</b><strong>{rule.level}</strong></header><p>{Object.entries(rule.logsource).map(([key,value]) => `${key}: ${value}`).join(" · ")}</p><code>{rule.rule_id}</code></article>) : <p>No Sigma rules imported yet.</p>}</section>
    <section className="detection-records"><header><div><span className="eyebrow">Correlated telemetry</span><h2>Network detections</h2></div><strong>{detections.length}</strong></header>{detections.length ? detections.map((item) => <article className={item.severity} key={item.id}><header><b>{item.signature}</b><strong>{item.severity}</strong></header><p>{item.source} · {item.src_ip ?? "unknown"}:{item.src_port ?? "–"} → {item.dest_ip ?? "unknown"}:{item.dest_port ?? "–"} · {item.protocol || "unknown protocol"}</p><p>{item.correlated_entity_ids.length ? `${item.correlated_entity_ids.length} investigation asset match(es)` : "No investigation asset match"}</p><time>{new Date(item.observed_at).toLocaleString()}</time></article>) : <p>No Suricata or Zeek telemetry imported for this investigation.</p>}</section>
  </SectionPage>;
}
