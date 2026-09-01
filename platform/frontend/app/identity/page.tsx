"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import SectionPage from "../_components/SectionPage";
import { platformApiUrl } from "../_lib/platformApi";

const API = platformApiUrl();
const headers = { "X-Dev-Subject": "local-analyst", "X-Dev-Email": "analyst@cypheryn.local" };
type Candidate = { id: string; entity_type: string; canonical_value: string; confidence: number; attributes: Record<string, unknown>; investigationId: string; investigationName: string };

export default function IdentityPage() {
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [message, setMessage] = useState("");
  useEffect(() => {
    (async () => {
      const orgResponse = await fetch(`${API}/api/v1/organizations`, { headers });
      if (!orgResponse.ok) return setMessage("Organizations could not be loaded.");
      const organizations = await orgResponse.json();
      const investigationGroups = await Promise.all(organizations.map((org: { id: string }) => fetch(`${API}/api/v1/organizations/${org.id}/investigations`, { headers }).then((response) => response.ok ? response.json() : [])));
      const investigations = investigationGroups.flat();
      const workspaces = await Promise.all(investigations.map((item: { id: string; name: string }) => fetch(`${API}/api/v1/investigations/${item.id}/workspace`, { headers, cache: "no-store" }).then(async (response) => ({ item, workspace: response.ok ? await response.json() : { entities: [] } }))));
      setCandidates(workspaces.flatMap(({ item, workspace }) => workspace.entities.filter((entity: Candidate) => ["identity_profile", "breach_exposure"].includes(entity.entity_type)).map((entity: Candidate) => ({ ...entity, investigationId: item.id, investigationName: item.name }))));
    })();
  }, []);
  async function review(candidate: Candidate, status: "confirmed" | "false_positive") {
    const evidence = window.prompt(status === "confirmed" ? "What evidence corroborates this identity?" : "Why is this a false positive?");
    if (!evidence?.trim()) return;
    const response = await fetch(`${API}/api/v1/entities/${candidate.id}/identity-review`, { method: "PATCH", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify({ status, evidence_note: evidence.trim() }) });
    const updated = await response.json().catch(() => ({}));
    if (!response.ok) return setMessage(updated.detail ?? "Review could not be saved.");
    setCandidates((current) => current.map((item) => item.id === candidate.id ? { ...item, confidence: updated.confidence, attributes: updated.attributes } : item));
    setMessage(`Identity candidate marked ${status.replace("_", " ")}.`);
  }
  return <SectionPage title="Identity exposure" eyebrow="Phase 11" description="Review permission-gated username and breach evidence without treating public profile matches as identity proof.">
    <section className="identity-guidance"><article><span className="eyebrow">Username discovery</span><h2>Maigret</h2><p>Add an authorized username target, then run the Maigret provider from its investigation. Results below remain candidates until reviewed.</p></article><article><span className="eyebrow">Verified breach search</span><h2>Have I Been Pwned</h2><p>Save an HIBP API key in Settings and verify the domain in your HIBP dashboard. Email searches use the hashed-account range API.</p><Link href="/settings">Configure HIBP →</Link></article></section>
    {message && <div className="collection-feedback" role="status">{message}</div>}
    <section className="identity-candidates"><header><div><span className="eyebrow">Analyst review</span><h2>Identity evidence</h2></div><strong>{candidates.length}</strong></header>{candidates.length ? candidates.map((candidate) => { const status = String(candidate.attributes.review_status ?? "unreviewed"); return <article className={status} key={candidate.id}><header><div><b>{String(candidate.attributes.site ?? candidate.attributes.verified_domain ?? candidate.entity_type.replaceAll("_", " "))}</b><span>{candidate.investigationName}</span></div><strong>{status.replaceAll("_", " ")}</strong></header><p>{String(candidate.attributes.profile_url ?? `${candidate.attributes.breach_count ?? 0} breach record(s)`)}</p><div className="identity-confidence"><span>Match confidence</span><b>{candidate.confidence}%</b></div><p>{String(candidate.attributes.disclaimer ?? "Breach metadata only; no passwords or breach contents retained.")}</p><footer><Link href={`/investigations/${candidate.investigationId}`}>Open investigation</Link><button onClick={() => review(candidate, "confirmed")}>Confirm with evidence</button><button onClick={() => review(candidate, "false_positive")}>Mark false positive</button></footer></article>; }) : <p>No identity evidence collected yet. Add a username, email, or verified-domain target to an investigation.</p>}</section>
  </SectionPage>;
}
