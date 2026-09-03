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

const architectureLayers = [
  {
    title: "Authorized workspace",
    copy: "Analysts define the target, ownership, purpose, and permitted collection boundary before work begins.",
  },
  {
    title: "Durable collection",
    copy: "Workers run provider jobs asynchronously, preserve status and retries, and normalize observations into a common model.",
  },
  {
    title: "Evidence and correlation",
    copy: "Entities, relationships, provider payloads, hashes, timestamps, and claims remain connected in one reviewable record.",
  },
  {
    title: "Verification loop",
    copy: "Monitoring, rescans, comparisons, alerts, and finding lifecycle controls show what changed and whether remediation held.",
  },
];

const securityControls = [
  ["Authorization first", "Passive and active operations retain scope and authorization context."],
  ["Isolated active tools", "Higher-risk scanners run through a separately trusted, resource-bounded orchestrator."],
  ["Secret-conscious operation", "Provider credentials stay encrypted and are excluded from evidence, logs, and tool environments."],
  ["Tamper-evident evidence", "Linked integrity records and signed checkpoints make unauthorized history changes detectable."],
  ["Private analyst assistance", "Local AI can explain evidence without making unsupported findings or replacing analyst judgment."],
  ["Provider truthfulness", "Readiness distinguishes supported, installed, configured, healthy, and live-verified integrations."],
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
          <a href="#architecture">Architecture</a>
          <a href="#security">Security</a>
          <a href="#workflow">Workflow</a>
          <Link className="landing-login" href="/dashboard">
            Log in to dashboard
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
            <Link href="/dashboard">Log in to dashboard →</Link>
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
      <section className="landing-architecture" id="architecture">
        <header>
          <p className="landing-kicker">How the platform works</p>
          <h2>A complete path from authorization to verified remediation.</h2>
          <p>
            CYPHERYN is not a page of disconnected lookups. It is an operational
            system that keeps collection, provenance, analysis, and change history
            together throughout an investigation.
          </p>
        </header>
        <div className="architecture-flow">
          {architectureLayers.map((layer, index) => (
            <article key={layer.title}>
              <span>{String(index + 1).padStart(2, "0")}</span>
              <h3>{layer.title}</h3>
              <p>{layer.copy}</p>
            </article>
          ))}
        </div>
        <div className="architecture-note">
          <strong>Local-first by design</strong>
          <p>
            Deploy with containers on macOS, Windows, Linux, or private infrastructure.
            PostgreSQL preserves operational data, Redis coordinates durable jobs,
            isolated runners handle active tools, and optional providers extend the
            platform without becoming a requirement for basic operation.
          </p>
        </div>
      </section>
      <section className="landing-security" id="security">
        <header>
          <div>
            <p className="landing-kicker">Security boundaries</p>
            <h2>Built for evidence that has to survive scrutiny.</h2>
          </div>
          <p>
            Cybersecurity software should make its boundaries visible. CYPHERYN
            records what was authorized, separates observations from conclusions,
            limits active execution, and tells operators when a capability has
            actually been verified—not merely listed.
          </p>
        </header>
        <div className="security-grid">
          {securityControls.map(([title, copy]) => (
            <article key={title}>
              <i aria-hidden="true" />
              <div><h3>{title}</h3><p>{copy}</p></div>
            </article>
          ))}
        </div>
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
        <div className="footer-main">
          <div className="footer-intro">
            <div className="landing-brand">
              <Image src="/cypheryn-logo.png" alt="" width={1254} height={1254} />
              <span>CYPHERYN</span>
            </div>
            <p>
              Local-first cyber intelligence for attack-surface discovery, threat
              enrichment, evidence correlation, vulnerability operations, and
              remediation verification.
            </p>
            <small>Authorized intelligence. Evidence-grounded decisions.</small>
          </div>
          <div className="footer-links">
            <div>
              <strong>Platform</strong>
              <a href="#capabilities">Capabilities</a>
              <a href="#architecture">Architecture</a>
              <a href="#security">Security boundaries</a>
              <Link href="/dashboard">Log in to dashboard</Link>
            </div>
            <div>
              <strong>Resources</strong>
              <a href="https://github.com/JedidiahBowlding/CYPHERYN" target="_blank" rel="noreferrer">GitHub repository</a>
              <a href="https://github.com/JedidiahBowlding/CYPHERYN/blob/main/docs/TUTORIAL.md" target="_blank" rel="noreferrer">Operator tutorial</a>
              <a href="https://github.com/JedidiahBowlding/CYPHERYN/blob/main/README.md" target="_blank" rel="noreferrer">Installation guide</a>
              <a href="https://github.com/JedidiahBowlding/CYPHERYN/security" target="_blank" rel="noreferrer">Security policy</a>
            </div>
            <div>
              <strong>Use responsibly</strong>
              <p>Use active capabilities only on systems you own or have explicit permission to assess.</p>
              <Link href="/terms">Terms</Link>
              <Link href="/responsible-use">Responsible Use</Link>
              <Link href="/privacy">Privacy</Link>
              <Link href="/security">Security</Link>
              <a href="https://github.com/JedidiahBowlding/CYPHERYN/issues" target="_blank" rel="noreferrer">Contact</a>
            </div>
          </div>
        </div>
        <div className="footer-bottom">
          <span>© {new Date().getUTCFullYear()} CYPHERYN. Open-source defensive security engineering.</span>
          <span>Passive-first · Source-linked · Local-first</span>
        </div>
      </footer>
    </main>
  );
}
