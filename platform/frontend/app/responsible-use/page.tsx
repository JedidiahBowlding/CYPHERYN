import LegalDocument from "../_components/LegalDocument";

export const metadata = { title: "Responsible Use Policy — CYPHERYN", description: "Plain-language rules for authorized defensive security and OSINT." };

export default function ResponsibleUsePage() {
  return <LegalDocument title="CYPHERYN Responsible Use Policy" version="1.0">
    <section><h2>The rule</h2><p><strong>You may use CYPHERYN for authorized defensive security and lawful OSINT activities.</strong></p><p><strong>You may not use CYPHERYN to attack, compromise, harm, stalk, defraud, or unlawfully investigate other people or systems.</strong></p></section>
    <section><h2>Permitted examples</h2><ul><li>Scanning your own domain or infrastructure.</li><li>Investigating your organization&apos;s public attack surface.</li><li>Assessing a client&apos;s infrastructure under valid authorization.</li><li>Defensive threat intelligence and lawful OSINT research.</li><li>Preparing for an authorized penetration test.</li></ul></section>
    <section><h2>Prohibited examples</h2><ul><li>Scanning targets without required authorization.</li><li>Attempting unauthorized access or stealing credentials.</li><li>Deploying malware or conducting destructive attacks.</li><li>Using collected information for harassment, stalking, fraud, or impersonation.</li><li>Circumventing access controls without authorization.</li></ul><p>These examples are illustrative, not exhaustive. Follow applicable law, contracts, provider rules, and the rights of others.</p></section>
    <section><h2>Active testing</h2><p>Passive public-data collection and active interaction are different. Before active collection, record a current authorization that identifies the scope, authorizer, purpose, permitted activity, and validity period. Stop if scope or authority is uncertain.</p></section>
    <section><h2>Report concerns</h2><p>Report product vulnerabilities through the process on the <a href="/security">Security page</a>. Do not test CYPHERYN infrastructure beyond the authorization provided there.</p></section>
  </LegalDocument>;
}
