type HelpFinding = {
  title: string;
  description: string;
  asset_value: string;
  provider: string;
  severity: string;
};

function guidance(finding: HelpFinding) {
  const text = `${finding.title} ${finding.description}`.toLowerCase();
  if (/open port|public service|exposed service|ike|rdp|ssh|database/.test(text))
    return {
      attack: "An internet user could identify this reachable service, fingerprint its software, and test exposed authentication or known weaknesses. A successful attempt could provide unauthorized access or reveal internal information.",
      fix: "Confirm the service is required. Restrict it with a host or cloud firewall, allowlist trusted source addresses, patch the service, disable default accounts, and require strong authentication. Rescan after the change.",
    };
  if (/tls|ssl|certificate|cipher|https/.test(text))
    return {
      attack: "Weak or incorrect transport security can let an attacker impersonate the service, downgrade protection, or exploit clients that accept an untrusted connection.",
      fix: "Renew and correctly deploy the certificate, remove obsolete TLS versions and ciphers, enable automatic renewal, and verify the full certificate chain from outside your network.",
    };
  if (/dns|nameserver|subdomain|domain takeover|zone transfer/.test(text))
    return {
      attack: "A DNS configuration weakness may expose internal naming data, redirect visitors, or allow an abandoned hostname to be claimed through a third-party service.",
      fix: "Remove stale records, restrict zone transfers, verify third-party resource ownership, use registrar MFA and registry lock, and enable DNSSEC where your provider supports it.",
    };
  if (/malware|malicious|reputation|blacklist|pulse|virus|abuse/.test(text))
    return {
      attack: "Threat feeds associate this asset with suspicious activity. Visitors or systems may be redirected, served malicious content, blocked by security products, or exposed through a compromised host.",
      fix: "Inspect the host and deployment pipeline, preserve logs, remove unauthorized files or redirects, rotate affected credentials, patch the entry point, and request feed review only after the asset is clean.",
    };
  if (/header|cookie|content.security|clickjack|xss|cors/.test(text))
    return {
      attack: "Missing browser protections can make phishing, clickjacking, script injection, cross-origin data access, or session theft easier when another application weakness is present.",
      fix: "Set the recommended security headers at the reverse proxy or application, use Secure/HttpOnly/SameSite cookies, restrict allowed origins, and test the affected pages before deployment.",
    };
  if (/breach|credential|email|password|identity/.test(text))
    return {
      attack: "Public identity or breach exposure can support password reuse attacks, targeted phishing, account recovery abuse, and impersonation.",
      fix: "Reset reused credentials, enable phishing-resistant MFA, review active sessions and recovery methods, monitor sign-ins, and train the affected user to recognize targeted messages.",
    };
  if (/dependency|package|cve|vulnerab|outdated|component/.test(text))
    return {
      attack: "An attacker may be able to exercise a known weakness in this component through the application paths that use it, potentially affecting confidentiality, integrity, or availability.",
      fix: "Upgrade to the vendor-fixed version, remove the component if unused, review the advisory for required configuration changes, run tests, deploy, and confirm the old version is no longer exposed.",
    };
  return {
    attack: "This evidence describes an externally observable condition that could help an attacker discover the asset, select a relevant technique, or combine it with another weakness.",
    fix: "Validate the observation against the affected asset, reduce unnecessary exposure, apply the relevant vendor or configuration guidance, document the change, and run direct verification again.",
  };
}

export default function FindingHelp({ finding }: { finding: HelpFinding }) {
  const help = guidance(finding);
  return (
    <span className="finding-help">
      <button type="button" aria-label={`Explain risk and remediation for ${finding.title}`}>?</button>
      <span className="finding-help-card" role="tooltip">
        <strong>How this could be attacked</strong>
        <span>{help.attack}</span>
        <strong>How to fix it</strong>
        <span>{help.fix}</span>
        <small>{finding.asset_value} · {finding.severity} · {finding.provider.replaceAll("_", " ")}</small>
      </span>
    </span>
  );
}
