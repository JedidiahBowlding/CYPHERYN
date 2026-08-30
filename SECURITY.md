# CYPHERYN Security Policy

## Supported versions

Security fixes are applied to the latest release on the `main` branch. Pre-1.0 releases may contain breaking changes; the latest `0.8.x` release line is the current supported line once published.

## Reporting a vulnerability

Do not disclose vulnerabilities, credentials, private targets, collected evidence, or exploit details in a public GitHub issue.

Use GitHub's **Report a vulnerability** private-reporting feature for this repository when it is enabled. If the feature is unavailable, the repository owner must enable **Settings → Security → Private vulnerability reporting** before a private reporting channel can be claimed. No security email address has been invented for this project.

Include affected versions, reproducible steps using a safe local target, impact, and any suggested mitigation. Do not include real API keys or third-party data.

## Response expectations

Maintainers aim to acknowledge a private report within seven calendar days, provide an initial assessment within fourteen days, and coordinate disclosure after a fix. These are targets, not contractual service levels.

## Scope and safe testing

CYPHERYN application code, authorization boundaries, credential handling, scanner isolation, evidence integrity, release artifacts, and official container images are in scope. Test only systems you own or are explicitly authorized to assess. Do not run active scanning against unrelated public infrastructure, degrade third-party services, access other users' data, or use AI to expand target scope.

Inherited SpiderFoot behavior and external provider availability may be upstream concerns, but CYPHERYN wrappers and security claims remain in scope.
