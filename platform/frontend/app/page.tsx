import Link from "next/link";
import Image from "next/image";

const features = [
  {
    number: "01",
    title: "Evidence, not guesses",
    copy: "Normalize provider responses into source-linked entities, relationships, findings, and defensible claims.",
  },
  {
    number: "02",
    title: "Continuous visibility",
    copy: "Schedule rescans, compare evidence over time, acknowledge changes, and track findings through resolution.",
  },
  {
    number: "03",
    title: "Local-first intelligence",
    copy: "Keep provider credentials encrypted locally and generate constrained narratives without sending evidence to hosted AI.",
  },
  {
    number: "04",
    title: "Attack-surface discovery",
    copy: "Map domains, DNS, certificates, public services, identities, and related infrastructure inside an explicitly authorized scope.",
  },
  {
    number: "05",
    title: "Threat enrichment",
    copy: "Bring provider verdicts, pulse matches, malware associations, and reputation records into one consistent evidence model.",
  },
  {
    number: "06",
    title: "Remediation verification",
    copy: "Rescan known assets, compare evidence snapshots, and show whether an exposure is new, persistent, changed, or resolved.",
  },
];

const platformAreas = [
  {
    title: "Discover",
    copy: "Build an inventory from authorized domains, IP addresses, services, certificates, DNS records, and public identities.",
  },
  {
    title: "Enrich",
    copy: "Query installed intelligence providers and preserve the source, retrieval time, target, payload hash, and authorization context.",
  },
  {
    title: "Correlate",
    copy: "Connect entities and observations in an evidence graph so analysts can trace why a finding exists and what it affects.",
  },
  {
    title: "Improve",
    copy: "Prioritize findings, explain likely attack paths, track remediation, schedule rescans, and verify security changes over time.",
  },
];

export default function LandingPage() {
  return (
    <main className="landing-page">
      <nav className="landing-nav">
        <Link className="landing-brand" href="/">
          <Image src="/cypheryn-logo.png" alt="" width={1254} height={1254} />
          <span>CYPHERYN</span>
        </Link>
        <div>
          <a href="#platform">Platform</a>
          <a href="#capabilities">Capabilities</a>
          <a href="#workflow">Workflow</a>
          <Link className="landing-login" href="/dashboard">
            Open platform
          </Link>
        </div>
      </nav>
      <section className="landing-hero">
        <div className="hero-copy">
          <p className="landing-kicker">
            <i /> Defensive intelligence platform
          </p>
          <h1>
            Follow every signal.<span>Prove every finding.</span>
          </h1>
          <p className="hero-lede">
            CYPHERYN turns authorized OSINT, attack-surface observations, and
            threat intelligence into evidence you can inspect, compare, and act
            on.
          </p>
          <div className="hero-actions">
            <Link href="/investigations/new">Start an investigation</Link>
            <Link href="/dashboard">View live dashboard →</Link>
          </div>
          <dl>
            <div>
              <dt>Passive-first</dt>
              <dd>Safe collection by default</dd>
            </div>
            <div>
              <dt>Source-linked</dt>
              <dd>Every claim retains evidence</dd>
            </div>
            <div>
              <dt>Local AI</dt>
              <dd>Constrained, private summaries</dd>
            </div>
          </dl>
        </div>
        <div className="logo-banner" aria-label="CYPHERYN identity banner">
          <div className="banner-grid" />
          <div className="banner-orbit orbit-one" />
          <div className="banner-orbit orbit-two" />
          <Image
            src="/cypheryn-logo.png"
            alt="CYPHERYN connected intelligence shield logo"
            width={1254}
            height={1254}
            priority
          />
          <div className="banner-label">
            <span>Signal acquired</span>
            <strong>Correlate · Verify · Defend</strong>
          </div>
        </div>
      </section>
      <section className="landing-overview" id="platform">
        <header>
          <div>
            <p className="landing-kicker">One evidence workspace</p>
            <h2>Know what is exposed, why it matters, and whether the fix worked.</h2>
          </div>
          <p>
            CYPHERYN is a local-first cyber-intelligence platform for defenders,
            security engineers, and authorized assessors. It combines collection,
            normalization, graph analysis, finding management, and continuous
            verification without treating a provider response as unquestionable truth.
          </p>
        </header>
        <div className="overview-grid">
          {platformAreas.map((area, index) => (
            <article key={area.title}>
              <span>0{index + 1}</span>
              <h3>{area.title}</h3>
              <p>{area.copy}</p>
            </article>
          ))}
        </div>
      </section>
      <section className="landing-features" id="capabilities">
        <header>
          <p className="landing-kicker">Intelligence you can defend</p>
          <h2>From raw observations to clear action.</h2>
        </header>
        <div>
          {features.map((feature) => (
            <article key={feature.number}>
              <span>{feature.number}</span>
              <h3>{feature.title}</h3>
              <p>{feature.copy}</p>
            </article>
          ))}
        </div>
      </section>
      <section className="landing-roles">
        <header>
          <p className="landing-kicker">Two perspectives. One authorization boundary.</p>
          <h2>Understand the attacker&apos;s view. Operate as a defender.</h2>
          <p>
            CYPHERYN supports defensive monitoring and authorized offensive analysis.
            Active collection is scope-controlled, auditable, and separated from the
            evidence used to support conclusions.
          </p>
        </header>
        <div>
          <article>
            <span>Defense</span>
            <h3>Reduce uncertainty across your environment.</h3>
            <ul>
              <li>Inventory externally visible assets and services.</li>
              <li>Prioritize evidence-backed exposures and threat associations.</li>
              <li>Track owners, status, remediation notes, and verification history.</li>
              <li>Detect changes through scheduled monitoring and comparison.</li>
            </ul>
          </article>
          <article>
            <span>Authorized offense</span>
            <h3>See how permitted targets appear from the outside.</h3>
            <ul>
              <li>Model relationships an attacker could use for reconnaissance.</li>
              <li>Identify public services, weak posture, and unexpected exposure.</li>
              <li>Explain plausible attack paths without overstating the evidence.</li>
              <li>Keep active testing constrained to recorded, approved scope.</li>
            </ul>
          </article>
        </div>
      </section>
      <section className="landing-workflow" id="workflow">
        <div>
          <p className="landing-kicker">The operating loop</p>
          <h2>Scope. Collect. Correlate. Monitor.</h2>
        </div>
        <ol>
          <li>
            <b>01</b>
            <span>
              <strong>Authorize scope</strong>Record exactly what may be
              observed.
            </span>
          </li>
          <li>
            <b>02</b>
            <span>
              <strong>Run providers</strong>Collect durable, normalized
              evidence.
            </span>
          </li>
          <li>
            <b>03</b>
            <span>
              <strong>Investigate graph</strong>Trace entities, services, and
              claims.
            </span>
          </li>
          <li>
            <b>04</b>
            <span>
              <strong>Watch change</strong>Rescan and manage the finding
              lifecycle.
            </span>
          </li>
        </ol>
      </section>
      <section className="landing-assurance">
        <div>
          <p className="landing-kicker">Trust through verification</p>
          <h2>Built to preserve the difference between data, evidence, and judgment.</h2>
        </div>
        <div className="assurance-points">
          <p><strong>Provenance retained</strong>Provider, target, time, authorization, and payload integrity travel with collected evidence.</p>
          <p><strong>Capabilities verified</strong>Provider readiness progresses from supported to installed, configured, healthy, and live verified.</p>
          <p><strong>Changes remain reviewable</strong>Previous and current evidence stay available so a closed finding can be independently checked.</p>
        </div>
      </section>
      <footer className="landing-footer">
        <div className="landing-brand">
          <Image src="/cypheryn-logo.png" alt="" width={1254} height={1254} />
          <span>CYPHERYN</span>
        </div>
        <p>Authorized intelligence. Evidence-grounded decisions.</p>
        <Link href="/dashboard">Enter platform →</Link>
      </footer>
    </main>
  );
}
