"use client";

import { useEffect, useState } from "react";
import SectionPage from "../_components/SectionPage";

const API = process.env.NEXT_PUBLIC_PLATFORM_API_URL ?? "http://localhost:8000";
const headers = {
  "X-Dev-Subject": "local-analyst",
  "X-Dev-Email": "analyst@signaltrace.local",
};
type Organization = { id: string; name: string };
type Investigation = { id: string; name: string; status: string };

export default function ReportsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [organizationId, setOrganizationId] = useState("");
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [message, setMessage] = useState("");
  const [brandTitle, setBrandTitle] = useState("SignalTrace");
  const [brandAccent, setBrandAccent] = useState("#147d72");
  const [brandLogo, setBrandLogo] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${API}/api/v1/organizations`, { headers })
      .then((response) => response.json())
      .then((items: Organization[]) => {
        setOrganizations(items);
        setOrganizationId(items[0]?.id ?? "");
      });
  }, []);

  useEffect(() => {
    if (!organizationId) return;
    fetch(`${API}/api/v1/organizations/${organizationId}/investigations`, { headers })
      .then((response) => response.json())
      .then(setInvestigations);
    fetch(`${API}/api/v1/organizations/${organizationId}/report-branding`, { headers })
      .then((response) => response.json())
      .then((branding) => {
        setBrandTitle(branding.report_title);
        setBrandAccent(branding.report_accent);
      });
  }, [organizationId]);

  async function saveBranding() {
    const response = await fetch(`${API}/api/v1/organizations/${organizationId}/report-branding`, {
      method: "PUT",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ report_title: brandTitle, report_accent: brandAccent, logo_data_url: brandLogo }),
    });
    setMessage(response.ok ? "Report branding saved." : "Could not save report branding.");
  }

  function readLogo(file?: File) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setBrandLogo(String(reader.result));
    reader.readAsDataURL(file);
  }

  async function schedule(investigation: Investigation) {
    const response = await fetch(`${API}/api/v1/investigations/${investigation.id}/report-schedules`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ style: "technical", interval_minutes: 10080, enabled: true }),
    });
    setMessage(response.ok ? `Weekly technical report scheduled for ${investigation.name}.` : "Scheduling failed.");
  }

  async function download(investigation: Investigation, kind: string) {
    setMessage(`Preparing ${kind} export…`);
    const pdf = kind === "executive" || kind === "technical";
    const endpoint = pdf
      ? `${API}/api/v1/investigations/${investigation.id}/reports/pdf?style=${kind}`
      : `${API}/api/v1/investigations/${investigation.id}/reports/export?format=${kind}`;
    const response = await fetch(endpoint, { headers });
    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      setMessage(result.detail ?? "Export failed");
      return;
    }
    const disposition = response.headers.get("content-disposition") ?? "";
    const name = disposition.match(/filename="([^"]+)"/)?.[1] ?? `signaltrace-${kind}`;
    const digest = response.headers.get("x-content-sha256") ?? "unavailable";
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    link.click();
    URL.revokeObjectURL(url);
    setMessage(`${name} downloaded · SHA-256 ${digest}`);
  }

  return (
    <SectionPage
      title="Reports"
      eyebrow="Phase 13"
      description="Executive, remediation, machine-readable, and evidence-timeline exports with SHA-256 integrity hashes."
    >
      <section className="report-controls">
        <label>
          Organization
          <select value={organizationId} onChange={(event) => setOrganizationId(event.target.value)}>
            {organizations.map((organization) => (
              <option value={organization.id} key={organization.id}>{organization.name}</option>
            ))}
          </select>
        </label>
        {message && <p className="report-status">{message}</p>}
      </section>
      <section className="report-branding">
        <div><span>Report branding</span><h2>Organization identity</h2></div>
        <label>Report title<input value={brandTitle} onChange={(event) => setBrandTitle(event.target.value)} /></label>
        <label>Accent color<input type="color" value={brandAccent} onChange={(event) => setBrandAccent(event.target.value)} /></label>
        <label>PNG or JPEG logo<input type="file" accept="image/png,image/jpeg" onChange={(event) => readLogo(event.target.files?.[0])} /></label>
        <button onClick={saveBranding}>Save branding</button>
      </section>
      <div className="record-grid report-grid">
        {investigations.map((investigation) => (
          <article key={investigation.id}>
            <span>{investigation.status}</span>
            <h2>{investigation.name}</h2>
            <p>Includes provider timestamps, direct observations, resolved findings, and lifecycle history.</p>
            <div className="report-downloads">
              <button onClick={() => download(investigation, "executive")}>Executive PDF</button>
              <button onClick={() => download(investigation, "technical")}>Technical PDF</button>
              <button onClick={() => download(investigation, "json")}>JSON</button>
              <button onClick={() => download(investigation, "csv")}>Findings CSV</button>
              <button onClick={() => download(investigation, "stix")}>STIX 2.1</button>
              <button onClick={() => download(investigation, "timeline")}>Timeline CSV</button>
              <button onClick={() => schedule(investigation)}>Schedule weekly PDF</button>
            </div>
          </article>
        ))}
      </div>
    </SectionPage>
  );
}
