# Third-party notices

SignalTrace includes and interoperates with third-party software. This file is a release-facing summary; dependency lockfiles and individual license files remain authoritative.

## SpiderFoot

This repository contains inherited SpiderFoot 4 source code under its original module names and notices.

- Upstream project: https://github.com/smicallef/spiderfoot
- Upstream author: Steve Micallef and contributors
- License: MIT; the upstream copyright and permission notice are preserved in the repository `LICENSE`
- SignalTrace use: optional isolated legacy OSINT capability and retained upstream source

The SpiderFoot name is used only to identify the upstream component. SignalTrace is the product identity of this repository's new platform.

## Other dependencies and services

SignalTrace uses open-source Python, JavaScript, container, database, threat-intelligence, and security-tool dependencies. Some integrations are separate services with their own licenses and terms, including PostgreSQL, Greenbone/OpenVAS, Ollama, and optional local collection tools.

External intelligence providers impose their own acceptable-use, retention, attribution, quota, and redistribution requirements. Configuring an API key does not transfer those rights to SignalTrace or its operator.

Before a public or commercial release:

1. Generate software bills of materials for every distributed image.
2. Produce dependency license reports from the locked Python and npm environments.
3. Review container base-image and optional-tool licenses.
4. Preserve all required copyright notices and source offers.
5. Review trademarks separately from open-source copyright licenses.

See `LICENSE_AUDIT.md` for the existing detailed assessment.
