import Link from "next/link";
import LegalFooter from "./LegalFooter";

export default function LegalDocument({ title, version, children }: { title: string; version: string; children: React.ReactNode }) {
  return (
    <main className="legal-page">
      <header className="legal-header">
        <Link href="/">← CYPHERYN</Link>
        <span>Legal &amp; responsible use</span>
      </header>
      <article className="legal-document">
        <h1>{title}</h1>
        <dl className="legal-meta"><div><dt>Version</dt><dd>{version}</dd></div><div><dt>Effective</dt><dd>September 3, 2026</dd></div><div><dt>Last updated</dt><dd>September 3, 2026</dd></div></dl>
        {children}
      </article>
      <LegalFooter />
    </main>
  );
}
