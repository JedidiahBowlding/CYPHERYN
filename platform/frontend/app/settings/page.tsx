"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import SectionPage from "../_components/SectionPage";

const API = process.env.NEXT_PUBLIC_PLATFORM_API_URL ?? "http://localhost:8000";
const headers = {
  "Content-Type": "application/json",
  "X-Dev-Subject": "local-analyst",
  "X-Dev-Email": "analyst@signaltrace.local",
};
type Controls = {
  enabled: boolean;
  kill_switch: boolean;
  jobs_per_hour: number;
  timeout_seconds: number;
  failure_threshold: number;
  cooldown_seconds: number;
  consecutive_failures: number;
  circuit_open_until: string | null;
  last_error: string | null;
};
type Provider = { name: string; requires_credentials: boolean };
type SavedProvider = {
  provider: string;
  enabled: boolean;
  credentials_configured: boolean;
  updated_at: string;
  settings: Record<string, unknown>;
};
type Assurance = {
  requirements: Array<{ name: string; status: string; evidence: string }>;
  providers: Array<{ provider: string; mode: string; version: string; ready: boolean; configuration: string; health: string }>;
};
const defaults: Controls = {
  enabled: true,
  kill_switch: false,
  jobs_per_hour: 60,
  timeout_seconds: 20,
  failure_threshold: 3,
  cooldown_seconds: 300,
  consecutive_failures: 0,
  circuit_open_until: null,
  last_error: null,
};

export default function Page() {
  const [organizationId, setOrganizationId] = useState("");
  const [provider, setProvider] = useState("safe_mock");
  const [providers, setProviders] = useState<Provider[]>([]);
  const [savedProviders, setSavedProviders] = useState<SavedProvider[]>([]);
  const [controls, setControls] = useState(defaults);
  const [message, setMessage] = useState("");
  const [secret, setSecret] = useState("");
  const [username, setUsername] = useState("");
  const [taxiiUrl, setTaxiiUrl] = useState("");
  const [identityConfidence, setIdentityConfidence] = useState(70);
  const [identitySites, setIdentitySites] = useState(50);
  const [saving, setSaving] = useState(false);
  const [assurance, setAssurance] = useState<Assurance | null>(null);

  const loadSaved = useCallback(async (id: string) => {
    const response = await fetch(
      `${API}/api/v1/organizations/${id}/providers`,
      { headers, cache: "no-store" },
    );
    if (response.ok) setSavedProviders(await response.json());
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const [o, p] = await Promise.all([
          fetch(`${API}/api/v1/organizations`, { headers }).then((r) =>
            r.json(),
          ),
          fetch(`${API}/api/v1/providers`, { headers }).then((r) => r.json()),
        ]);
        setProviders(p);
        if (o[0]) {
          setOrganizationId(o[0].id);
          await loadSaved(o[0].id);
        }
      } catch {
        setMessage("Provider controls could not be loaded.");
      }
    })();
  }, [loadSaved]);

  useEffect(() => {
    if (!organizationId) return;
    fetch(`${API}/api/v1/organizations/${organizationId}/platform-assurance`, {
      headers,
      cache: "no-store",
    })
      .then((response) => response.json())
      .then(setAssurance)
      .catch(() => setAssurance(null));
    fetch(
      `${API}/api/v1/organizations/${organizationId}/providers/${provider}/runtime`,
      { headers, cache: "no-store" },
    )
      .then((r) => {
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then(setControls)
      .catch(() => setMessage("Provider controls could not be loaded."));
  }, [organizationId, provider]);

  useEffect(() => {
    if (provider !== "taxii") return;
    const saved = savedProviders.find((item) => item.provider === "taxii");
    setTaxiiUrl(String(saved?.settings?.collection_url ?? ""));
  }, [provider, savedProviders]);

  useEffect(() => {
    if (provider !== "maigret") return;
    const saved = savedProviders.find((item) => item.provider === "maigret");
    setIdentityConfidence(Number(saved?.settings?.minimum_confidence ?? 70));
    setIdentitySites(Number(saved?.settings?.top_sites ?? 50));
  }, [provider, savedProviders]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMessage("Saving…");
    let credentials: Record<string, string> | undefined;
    if (provider === "openvas" && username && secret)
      credentials = { username, password: secret };
    else if (provider === "taxii" && secret)
      credentials = { token: secret };
    else if (secret)
      credentials =
        provider === "censys"
          ? { personal_access_token: secret }
          : provider === "urlhaus" || provider === "abuse_ch"
            ? { auth_key: secret }
            : provider === "katana_authenticated"
              ? { authorization_header: secret }
              : { api_key: secret };
    const response = await fetch(
      `${API}/api/v1/organizations/${organizationId}/providers/${provider}`,
      {
        method: "PUT",
        headers,
        body: JSON.stringify({
          enabled: controls.enabled,
          credentials,
          settings: {
            kill_switch: controls.kill_switch,
            jobs_per_hour: controls.jobs_per_hour,
            timeout_seconds: controls.timeout_seconds,
            failure_threshold: controls.failure_threshold,
            cooldown_seconds: controls.cooldown_seconds,
            ...(provider === "taxii"
              ? { collection_url: taxiiUrl, default_ttl_days: 90 }
              : {}),
            ...(provider === "maigret"
              ? { minimum_confidence: identityConfidence, top_sites: identitySites }
              : {}),
          },
        }),
      },
    );
    if (response.ok) {
      setSecret("");
      setUsername("");
      await loadSaved(organizationId);
    }
    setMessage(
      response.ok
        ? `${provider.replaceAll("_", " ")} saved successfully.`
        : "Provider configuration could not be saved.",
    );
    setSaving(false);
  }

  const descriptor = providers.find((p) => p.name === provider);
  const setNumber = (key: keyof Controls, value: string) =>
    setControls((current) => ({ ...current, [key]: Number(value) }));
  return (
    <SectionPage
      title="Settings"
      eyebrow="Organization controls"
      description="Configure provider credentials and defensive collection limits."
    >
      {assurance && (
        <section className="platform-assurance" aria-labelledby="platform-assurance-title">
          <header>
            <div>
              <h2 id="platform-assurance-title">Platform assurance</h2>
              <p>Live enforcement evidence for the platform-wide requirements.</p>
            </div>
            <strong>{assurance.requirements.length}/{assurance.requirements.length}</strong>
          </header>
          <div className="assurance-grid">
            {assurance.requirements.map((requirement) => (
              <article key={requirement.name}>
                <span>{requirement.status}</span>
                <h3>{requirement.name}</h3>
                <p>{requirement.evidence}</p>
              </article>
            ))}
          </div>
          <p className="assurance-summary">
            {assurance.providers.filter((item) => item.ready).length} of {assurance.providers.length} providers ready. Unready integrations remain unavailable until installed, enabled, and configured.
          </p>
        </section>
      )}
      <section
        className="saved-providers"
        aria-labelledby="saved-providers-title"
      >
        <header>
          <div>
            <h2 id="saved-providers-title">Saved providers</h2>
            <p>Persistent configurations stored for this organization.</p>
          </div>
          <strong>{savedProviders.length}</strong>
        </header>
        {savedProviders.length ? (
          <div className="saved-provider-list">
            {savedProviders.map((item) => (
              <button
                type="button"
                className={item.provider === provider ? "selected" : ""}
                onClick={() => setProvider(item.provider)}
                key={item.provider}
              >
                <span
                  className={
                    item.enabled ? "provider-led enabled" : "provider-led"
                  }
                />
                <span>
                  <b>{item.provider.replaceAll("_", " ")}</b>
                  <small>
                    {item.enabled ? "Enabled" : "Disabled"}
                    {providers.find((p) => p.name === item.provider)
                      ?.requires_credentials
                      ? item.credentials_configured
                        ? " · credentials stored"
                        : " · credentials missing"
                      : " · no credentials required"}
                  </small>
                </span>
                <time>{new Date(item.updated_at).toLocaleString()}</time>
              </button>
            ))}
          </div>
        ) : (
          <p className="saved-provider-empty">
            No provider configuration has been saved yet.
          </p>
        )}
      </section>
      <form className="provider-controls" onSubmit={save}>
        <header>
          <div>
            <h2>{provider.replaceAll("_", " ")} controls</h2>
            <p>
              Availability, credentials, rate, timeout, and failure isolation.
            </p>
          </div>
          <div className="provider-control-head">
            <select
              value={provider}
              onChange={(e) => {
                setProvider(e.target.value);
                setSecret("");
              }}
            >
              {providers.map((p) => (
                <option value={p.name} key={p.name}>
                  {p.name.replaceAll("_", " ")}
                </option>
              ))}
            </select>
            <span className={controls.circuit_open_until ? "open" : "closed"}>
              {controls.circuit_open_until ? "Circuit open" : "Circuit closed"}
            </span>
          </div>
        </header>
        {descriptor?.requires_credentials && (
          <div className="credential-fields">
            {provider === "taxii" && (
              <label>
                TAXII 2.1 collection objects URL
                <input
                  type="url"
                  value={taxiiUrl}
                  onChange={(e) => setTaxiiUrl(e.target.value)}
                  placeholder="https://server.example/api-root/collections/id/objects/"
                  required
                />
              </label>
            )}
            {provider === "openvas" && (
              <label>
                Greenbone username
                <input
                  type="text"
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin"
                />
              </label>
            )}
            <label>
              {provider === "taxii"
                ? "Bearer token"
                : provider === "openvas"
                ? "Greenbone password"
                : provider === "censys"
                ? "Personal access token"
                : provider === "urlhaus" || provider === "abuse_ch"
                  ? "Auth key"
                  : provider === "katana_authenticated"
                    ? "Authorization header value"
                    : "API key"}
              <input
                type="password"
                autoComplete="off"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder="Leave blank to keep stored secret"
              />
            </label>
            {provider === "openvas" && (
              <p className="field-help">
                Enter both fields to replace the locally encrypted Greenbone credentials.
              </p>
            )}
          </div>
        )}
        <div className="control-switches">
          <label>
            <input
              type="checkbox"
              checked={controls.enabled}
              onChange={(e) =>
                setControls((c) => ({ ...c, enabled: e.target.checked }))
              }
            />{" "}
            Provider enabled
          </label>
          <label>
            <input
              type="checkbox"
              checked={controls.kill_switch}
              onChange={(e) =>
                setControls((c) => ({ ...c, kill_switch: e.target.checked }))
              }
            />{" "}
            Emergency kill switch
          </label>
        </div>
        <div className="control-fields">
          {provider === "maigret" && (
            <>
              <label>
                Minimum candidate confidence
                <input type="number" min="50" max="95" value={identityConfidence} onChange={(e) => setIdentityConfidence(Number(e.target.value))} />
              </label>
              <label>
                Ranked sites checked
                <input type="number" min="10" max="500" value={identitySites} onChange={(e) => setIdentitySites(Number(e.target.value))} />
              </label>
            </>
          )}
          {(
            [
              ["jobs_per_hour", "Jobs per hour"],
              ["timeout_seconds", "Timeout seconds"],
              ["failure_threshold", "Failure threshold"],
              ["cooldown_seconds", "Cooldown seconds"],
            ] as [keyof Controls, string][]
          ).map(([key, label]) => (
            <label key={key}>
              {label}
              <input
                type="number"
                min="1"
                value={String(controls[key] ?? 1)}
                onChange={(e) => setNumber(key, e.target.value)}
              />
            </label>
          ))}
        </div>
        <footer>
          <span>
            {controls.consecutive_failures} consecutive failures
            {controls.last_error ? ` · ${controls.last_error}` : ""}
          </span>
          <button disabled={!organizationId || saving}>
            {saving ? "Saving…" : "Save provider"}
          </button>
        </footer>
        {message && (
          <p className="control-message" role="status">
            {message}
          </p>
        )}
      </form>
    </SectionPage>
  );
}
