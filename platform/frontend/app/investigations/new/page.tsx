"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
const API_URL =
  process.env.NEXT_PUBLIC_PLATFORM_API_URL ?? "http://localhost:8000";
type Target = { id: string; canonical_value: string; target_type: string };
async function api<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Dev-Subject": "local-analyst",
      "X-Dev-Email": "analyst@cypheryn.local",
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ detail: "Request failed" }));
    throw new Error(
      typeof error.detail === "string" ? error.detail : "Request failed",
    );
  }
  return response.json() as Promise<T>;
}
export default function NewInvestigation() {
  const router = useRouter();
  const [status, setStatus] = useState<
    "idle" | "saving" | "complete" | "error"
  >("idle");
  const [message, setMessage] = useState("");
  const [created, setCreated] = useState<Target | null>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus("saving");
    setMessage("");
    const data = new FormData(event.currentTarget);
    try {
      const organization = await api<{ id: string }>("/api/v1/organizations", {
        name: data.get("organization"),
      });
      const investigation = await api<{ id: string }>(
        `/api/v1/organizations/${organization.id}/investigations`,
        { name: data.get("name"), description: data.get("description") },
      );
      const now = new Date();
      const until = new Date(now);
      until.setDate(until.getDate() + 30);
      const authorization = await api<{ id: string }>(
        `/api/v1/organizations/${organization.id}/authorizations`,
        {
          basis: data.get("basis"),
          passive_allowed: true,
          active_allowed: data.get("activeAllowed") === "on",
          valid_from: now.toISOString(),
          valid_until: until.toISOString(),
        },
      );
      const target = await api<Target>(
        `/api/v1/investigations/${investigation.id}/targets`,
        {
          authorization_id: authorization.id,
          target_type: data.get("targetType"),
          value: data.get("target"),
          include_descendants: data.get("descendants") === "on",
        },
      );
      setCreated(target);
      setStatus("complete");
      setTimeout(() => router.push(`/investigations/${investigation.id}`), 500);
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : "Unable to create investigation",
      );
      setStatus("error");
    }
  }
  return (
    <main className="workflow-page">
      <header className="workflow-top">
        <Link href="/investigations">← Investigations</Link>
        <div className="workflow-brand">
          <span>S</span>CYPHERYN
        </div>
        <p>Authorized collection only</p>
      </header>
      <div className="workflow-wrap">
        <section className="workflow-intro">
          <p className="eyebrow">New investigation</p>
          <h1>Define authorized scope.</h1>
          <p>
            Create an evidence-backed investigation with explicit passive or
            bounded active permission.
          </p>
          <ol>
            <li className="current">
              <span>1</span>Investigation
            </li>
            <li>
              <span>2</span>Authorization
            </li>
            <li>
              <span>3</span>Target
            </li>
          </ol>
        </section>
        <form className="scope-form" onSubmit={submit}>
          <div className="form-section">
            <Title
              n="01"
              title="Investigation details"
              copy="Name the workspace and describe the defensive objective."
            />
            <label>
              Investigation name
              <input
                name="name"
                required
                minLength={2}
                placeholder="External attack surface review"
              />
            </label>
            <label>
              Organization
              <input
                name="organization"
                required
                minLength={2}
                placeholder="Example Corporation"
              />
            </label>
            <label>
              Description
              <textarea
                name="description"
                rows={3}
                placeholder="Review authorized infrastructure and identify unexpected exposure."
              />
            </label>
          </div>
          <div className="form-section">
            <Title
              n="02"
              title="Authorization record"
              copy="Record why this organization is permitted to assess the target."
            />
            <label>
              Authorization basis
              <textarea
                name="basis"
                required
                minLength={5}
                rows={3}
                placeholder="Written authorization held by the security team…"
              />
            </label>
            <div className="check-label">
              <input
                id="activeAllowed"
                type="checkbox"
                name="activeAllowed"
                aria-label="Permit bounded active service observation"
              />
              <span>
                <strong>Permit bounded active service observation</strong>
                <small>
                  Allows exact-IP connection checks by the local observer. Use
                  only for infrastructure you own or have explicit permission to
                  test.
                </small>
              </span>
            </div>
            <div className="policy-note">
              <strong>Scope enforcement</strong>
              <p>
                Passive collection is always available. Active observation
                requires this explicit authorization and an exact IP target.
              </p>
            </div>
          </div>
          <div className="form-section">
            <Title
              n="03"
              title="Initial target"
              copy="Add the first asset. The API validates and canonicalizes it."
            />
            <div className="field-row">
              <label>
                Target type
                <select name="targetType" defaultValue="domain">
                  <option value="domain">Domain</option>
                  <option value="ip_address">IP address</option>
                  <option value="asn">ASN</option>
                  <option value="url">URL</option>
                  <option value="email_address">Email address</option>
                  <option value="person">Person name</option>
                  <option value="username">Username</option>
                  <option value="organization">Organization name</option>
                  <option value="repository">Local or GitHub repository</option>
                  <option value="container_image">Container image</option>
                  <option value="sbom">SBOM file</option>
                </select>
              </label>
              <label>
                Target value
                <input
                  name="target"
                  required
                  placeholder="example.com or 203.0.113.10"
                />
              </label>
            </div>
            <label className="check-label">
              <input
                aria-label="Include discovered descendants"
                type="checkbox"
                name="descendants"
                defaultChecked
              />
              <span>
                <strong>Include discovered descendants</strong>
                <small>
                  New assets are recorded for review; they do not automatically
                  expand active scope.
                </small>
              </span>
            </label>
          </div>
          {status === "error" && (
            <div className="form-error" role="alert">
              {message}
            </div>
          )}
          {status === "complete" && created && (
            <div className="form-success">
              <span>✓</span>
              <div>
                <strong>Authorized investigation created</strong>
                <p>
                  {created.canonical_value} was registered as a{" "}
                  {created.target_type.replace("_", " ")}.
                </p>
              </div>
            </div>
          )}
          <footer className="form-actions">
            <Link href="/investigations">Cancel</Link>
            <button disabled={status === "saving" || status === "complete"}>
              {status === "saving"
                ? "Creating…"
                : status === "complete"
                  ? "Created"
                  : "Create authorized investigation"}
            </button>
          </footer>
        </form>
      </div>
    </main>
  );
}
function Title({ n, title, copy }: { n: string; title: string; copy: string }) {
  return (
    <div className="form-section-title">
      <span>{n}</span>
      <div>
        <h2>{title}</h2>
        <p>{copy}</p>
      </div>
    </div>
  );
}
