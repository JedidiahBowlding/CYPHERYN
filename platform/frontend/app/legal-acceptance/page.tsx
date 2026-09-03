"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import LegalFooter from "../_components/LegalFooter";
import { platformApiUrl } from "../_lib/platformApi";

type LegalStatus = { required: boolean; accepted: boolean; terms_version: string; responsible_use_version: string; effective_date: string };
const AUTH_HEADERS = { "Content-Type": "application/json", "X-Dev-Subject": "local-analyst", "X-Dev-Email": "analyst@cypheryn.local" };

export default function LegalAcceptancePage() {
  const router = useRouter();
  const params = useSearchParams();
  const [status, setStatus] = useState<LegalStatus | null>(null);
  const [agreed, setAgreed] = useState(false);
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetch(`${platformApiUrl()}/api/v1/legal/status`, { cache: "no-store", headers: AUTH_HEADERS })
      .then(async (response) => {
        if (!response.ok) throw new Error("Unable to load the current agreements.");
        const value = (await response.json()) as LegalStatus;
        setStatus(value);
        if (!value.required) router.replace(params.get("returnTo") || "/investigations");
      })
      .catch((error: Error) => setMessage(error.message));
  }, [params, router]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!agreed || !status) return;
    setSaving(true); setMessage("");
    const response = await fetch(`${platformApiUrl()}/api/v1/legal/acceptance`, {
      method: "POST", headers: AUTH_HEADERS,
      body: JSON.stringify({ accepted: true, terms_version: status.terms_version, responsible_use_version: status.responsible_use_version }),
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: "Acceptance could not be recorded." }));
      setMessage(typeof error.detail === "string" ? error.detail : "Acceptance could not be recorded.");
      setSaving(false); return;
    }
    router.replace(params.get("returnTo") || "/investigations");
  }

  return <main className="legal-page acceptance-page">
    <section className="acceptance-card">
      <p className="legal-kicker">Required before platform access</p>
      <h1>Review responsible-use terms</h1>
      <p>CYPHERYN is for lawful, authorized cybersecurity and OSINT. Authentication does not grant permission to scan or investigate a third party.</p>
      {status && <p className="agreement-version">Terms v{status.terms_version} · Responsible Use v{status.responsible_use_version} · Effective {status.effective_date}</p>}
      <form onSubmit={submit}>
        <label className="acceptance-control">
          <input type="checkbox" checked={agreed} onChange={(event) => setAgreed(event.target.checked)} />
          <span>I agree to the <Link href="/terms" target="_blank">Terms of Service</Link> and <Link href="/responsible-use" target="_blank">Responsible Use Policy</Link>.</span>
        </label>
        <button type="submit" disabled={!agreed || !status || saving}>{saving ? "Saving…" : "Accept"}</button>
        {message && <p className="legal-error" role="alert">{message}</p>}
      </form>
      <nav className="auth-legal-links" aria-label="Authentication legal links"><Link href="/terms">Terms</Link><Link href="/responsible-use">Responsible Use</Link><Link href="/privacy">Privacy</Link></nav>
    </section>
    <LegalFooter />
  </main>;
}
