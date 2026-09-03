"use client";
import Link from "next/link";
import Image from "next/image";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import { platformApiUrl } from "../../_lib/platformApi";
const API_URL = platformApiUrl();
type Target = { id: string; canonical_value: string; target_type: string };
type Organization = { id: string; name: string };
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
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [organizationId, setOrganizationId] = useState("new");
  useEffect(() => {
    fetch(`${API_URL}/api/v1/organizations`, {
      headers: {
        "X-Dev-Subject": "local-analyst",
        "X-Dev-Email": "analyst@cypheryn.local",
      },
      cache: "no-store",
    })
      .then((response) => (response.ok ? response.json() : []))
      .then((items: Organization[]) => {
        setOrganizations(items);
        if (items.length) setOrganizationId(items[0].id);
      })
      .catch(() => setOrganizations([]));
  }, []);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus("saving");
    setMessage("");
    const data = new FormData(event.currentTarget);
    try {
      const organization = organizationId === "new"
        ? await api<{ id: string }>("/api/v1/organizations", {
            name: data.get("organization"),
          })
        : { id: organizationId };
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
          active_scope_confirmed: data.get("activeScopeConfirmed") === "on",
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
          <Image
            src="/cypheryn-logo.png"
            alt="CYPHERYN shield"
            width={1254}
            height={1254}
          />
          <span>CYPHERYN</span>
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
              Organization workspace
              <select
                aria-label="Investigation organization"
                value={organizationId}
                onChange={(event) => setOrganizationId(event.target.value)}
              >
                {organizations.map((organization) => (
                  <option value={organization.id} key={organization.id}>
                    {organization.name} · use saved providers
                  </option>
                ))}
                <option value="new">Create a new organization</option>
              </select>
            </label>
            {organizationId === "new" && (
              <label>
                New organization name
                <input
                  name="organization"
                  required
                  minLength={2}
                  placeholder="Example Corporation"
                />
              </label>
            )}
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
            <label className="check-label">
              <input
                aria-label="Confirm ownership or authorization for active testing"
                type="checkbox"
                name="activeScopeConfirmed"
              />
              <span>
                <strong>I own this target or have authorization to assess it</strong>
                <small>
                  This confirmation is mandatory when active testing is enabled.
                  CYPHERYN access does not grant third-party authorization.
                </small>
              </span>
            </label>
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
            <button
              aria-label="Create authorized investigation"
              title="Create authorized investigation"
              disabled={status === "saving" || status === "complete"}
            >
              {status === "saving"
                ? "Creating…"
                : status === "complete"
                  ? "Created"
                  : "Create"}
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
