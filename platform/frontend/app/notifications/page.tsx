"use client";

import { FormEvent, useEffect, useState } from "react";
import SectionPage from "../_components/SectionPage";

const API = process.env.NEXT_PUBLIC_PLATFORM_API_URL ?? "http://localhost:8000";
const headers = { "X-Dev-Subject": "local-analyst", "X-Dev-Email": "analyst@signaltrace.local" };
type Organization = { id: string; name: string };
type Notification = { id: string; event_type: string; severity: string; title: string; message: string; occurrence_count: number; last_seen_at: string; read_at: string | null; external_suppressed_reason: string; email_status: string; webhook_status: string };
type Preferences = { email_enabled: boolean; email_to: string; webhook_enabled: boolean; webhook_url: string; webhook_secret_configured: boolean; quiet_start_hour: number | null; quiet_end_hour: number | null; maintenance_starts_at: string | null; maintenance_ends_at: string | null; dedupe_minutes: number };
const defaults: Preferences = { email_enabled: false, email_to: "", webhook_enabled: false, webhook_url: "", webhook_secret_configured: false, quiet_start_hour: null, quiet_end_hour: null, maintenance_starts_at: null, maintenance_ends_at: null, dedupe_minutes: 60 };

export default function NotificationsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [organizationId, setOrganizationId] = useState("");
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [preferences, setPreferences] = useState<Preferences>(defaults);
  const [webhookSecret, setWebhookSecret] = useState("");
  const [message, setMessage] = useState("");
  async function load(id: string) {
    if (!id) return;
    const [alerts, settings] = await Promise.all([
      fetch(`${API}/api/v1/organizations/${id}/notifications`, { headers, cache: "no-store" }),
      fetch(`${API}/api/v1/organizations/${id}/notification-preferences`, { headers, cache: "no-store" }),
    ]);
    if (alerts.ok) setNotifications(await alerts.json());
    if (settings.ok) setPreferences(await settings.json());
  }
  useEffect(() => { (async () => { const response = await fetch(`${API}/api/v1/organizations`, { headers }); if (!response.ok) return; const loaded = await response.json(); setOrganizations(loaded); if (loaded[0]) setOrganizationId(loaded[0].id); })(); }, []);
  useEffect(() => { void load(organizationId); }, [organizationId]);
  async function save(event: FormEvent) {
    event.preventDefault();
    const response = await fetch(`${API}/api/v1/organizations/${organizationId}/notification-preferences`, { method: "PUT", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify({ ...preferences, webhook_secret: webhookSecret || undefined }) });
    const result = await response.json().catch(() => ({}));
    setMessage(response.ok ? "Notification preferences saved." : result.detail ?? "Preferences could not be saved.");
    if (response.ok) { setPreferences(result); setWebhookSecret(""); }
  }
  async function markRead(id: string) {
    const response = await fetch(`${API}/api/v1/notifications/${id}/read`, { method: "PATCH", headers });
    if (response.ok) setNotifications((current) => current.map((item) => item.id === id ? { ...item, read_at: new Date().toISOString() } : item));
  }
  return <SectionPage title="Notification center" eyebrow="Phase 12" description="Finding lifecycle, monitoring health, delivery status, deduplication, and quiet-period controls.">
    <label className="notification-org">Organization<select value={organizationId} onChange={(event) => setOrganizationId(event.target.value)}>{organizations.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label>
    <form className="notification-preferences" onSubmit={save}><header><div><span className="eyebrow">Delivery controls</span><h2>Alert preferences</h2></div><button>Save preferences</button></header><div className="notification-options"><label><input type="checkbox" checked={preferences.email_enabled} onChange={(event) => setPreferences((current) => ({ ...current, email_enabled: event.target.checked }))} />Email notifications</label><label>Email recipient<input type="email" value={preferences.email_to} onChange={(event) => setPreferences((current) => ({ ...current, email_to: event.target.value }))} placeholder="security@example.com" /></label><label><input type="checkbox" checked={preferences.webhook_enabled} onChange={(event) => setPreferences((current) => ({ ...current, webhook_enabled: event.target.checked }))} />Webhook notifications</label><label>HTTPS webhook URL<input type="url" value={preferences.webhook_url} onChange={(event) => setPreferences((current) => ({ ...current, webhook_url: event.target.value }))} placeholder="https://alerts.example/hooks/signaltrace" /></label><label>Webhook signing secret<input type="password" value={webhookSecret} onChange={(event) => setWebhookSecret(event.target.value)} placeholder={preferences.webhook_secret_configured ? "Stored — leave blank to keep" : "Optional HMAC secret"} /></label><label>Deduplicate for minutes<input type="number" min="1" max="10080" value={preferences.dedupe_minutes} onChange={(event) => setPreferences((current) => ({ ...current, dedupe_minutes: Number(event.target.value) }))} /></label><label>Quiet start hour (UTC)<input type="number" min="0" max="23" value={preferences.quiet_start_hour ?? ""} onChange={(event) => setPreferences((current) => ({ ...current, quiet_start_hour: event.target.value === "" ? null : Number(event.target.value) }))} /></label><label>Quiet end hour (UTC)<input type="number" min="0" max="23" value={preferences.quiet_end_hour ?? ""} onChange={(event) => setPreferences((current) => ({ ...current, quiet_end_hour: event.target.value === "" ? null : Number(event.target.value) }))} /></label><label>Maintenance starts<input type="datetime-local" value={preferences.maintenance_starts_at?.slice(0,16) ?? ""} onChange={(event) => setPreferences((current) => ({ ...current, maintenance_starts_at: event.target.value ? new Date(event.target.value).toISOString() : null }))} /></label><label>Maintenance ends<input type="datetime-local" value={preferences.maintenance_ends_at?.slice(0,16) ?? ""} onChange={(event) => setPreferences((current) => ({ ...current, maintenance_ends_at: event.target.value ? new Date(event.target.value).toISOString() : null }))} /></label></div></form>
    {message && <div className="collection-feedback" role="status">{message}</div>}
    <section className="notification-list"><header><div><span className="eyebrow">In-app alerts</span><h2>Recent notifications</h2></div><strong>{notifications.filter((item) => !item.read_at).length} unread</strong></header>{notifications.length ? notifications.map((item) => <article className={`${item.severity} ${item.read_at ? "read" : "unread"}`} key={item.id}><header><div><b>{item.title}</b><span>{item.event_type.replaceAll(".", " ")}</span></div>{!item.read_at && <button onClick={() => markRead(item.id)}>Mark read</button>}</header><p>{item.message}</p><footer><span>{new Date(item.last_seen_at).toLocaleString()}{item.occurrence_count > 1 ? ` · repeated ${item.occurrence_count} times` : ""}</span><span>Email: {item.email_status} · Webhook: {item.webhook_status}{item.external_suppressed_reason ? ` · ${item.external_suppressed_reason.replaceAll("_", " ")}` : ""}</span></footer></article>) : <p>No notifications yet. Finding and job lifecycle alerts will appear here.</p>}</section>
  </SectionPage>;
}
