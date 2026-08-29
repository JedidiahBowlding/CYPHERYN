import Link from "next/link";

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
];

export default function LandingPage() {
  return (
    <main className="landing-page">
      <nav className="landing-nav">
        <Link className="landing-brand" href="/">
          <img src="/signaltrace-logo.png" alt="" />
          <span>SignalTrace</span>
        </Link>
        <div>
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
            SignalTrace turns authorized OSINT, attack-surface observations, and
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
        <div className="logo-banner" aria-label="SignalTrace identity banner">
          <div className="banner-grid" />
          <div className="banner-orbit orbit-one" />
          <div className="banner-orbit orbit-two" />
          <img
            src="/signaltrace-logo.png"
            alt="SignalTrace radar spider logo"
          />
          <div className="banner-label">
            <span>Signal acquired</span>
            <strong>Correlate · Verify · Defend</strong>
          </div>
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
      <footer className="landing-footer">
        <div className="landing-brand">
          <img src="/signaltrace-logo.png" alt="" />
          <span>SignalTrace</span>
        </div>
        <p>Authorized intelligence. Evidence-grounded decisions.</p>
        <Link href="/dashboard">Enter platform →</Link>
      </footer>
    </main>
  );
}
