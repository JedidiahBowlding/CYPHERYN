import LegalDocument from "../_components/LegalDocument";

export const metadata = { title: "Security — CYPHERYN", description: "Responsible disclosure and authorized-testing expectations for CYPHERYN." };

export default function SecurityPage() {
  return <LegalDocument title="CYPHERYN Security & Responsible Disclosure" version="1.0">
    <section><h2>Report a vulnerability privately</h2><p>Use <a href="https://github.com/JedidiahBowlding/CYPHERYN/security/advisories/new" target="_blank" rel="noreferrer">GitHub private vulnerability reporting</a> for suspected security vulnerabilities. Include affected version, reproduction conditions, impact, and a safe proof of concept. Do not include credentials, personal data, or customer investigation data.</p></section>
    <section><h2>Testing expectations</h2><p>Test only systems and accounts you own or for which you have explicit authorization. Do not access other users&apos; data, degrade service, perform denial of service, use social engineering, deploy malware, establish persistence, or exceed the scope granted by an operator.</p></section>
    <section><h2>Coordinated disclosure</h2><p>Allow reasonable time to investigate and remediate before public disclosure. The project will assess good-faith reports, but this page does not grant blanket authorization or override applicable law, third-party terms, or an operator&apos;s written scope.</p></section>
    <section><h2>Operational incidents</h2><p>For an urgent incident affecting a deployed instance, contact that deployment&apos;s operator. The open-source project cannot access or administer independent installations.</p></section>
  </LegalDocument>;
}
