# License Audit

**Audit date:** 2026-08-25  
**Status:** Engineering assessment, not legal advice.

## Findings

### SpiderFoot

The local `LICENSE` is the MIT License with copyright notice `Copyright 2022 Steve Micallef <steve@binarypool.com>`. It permits use, copying, modification, distribution, sublicensing, and sale, subject to inclusion of the copyright and permission notice in all copies or substantial portions. Warranty is disclaimed.

Requirements for this project:

- preserve the upstream `LICENSE` in source and distributed images/artifacts containing SpiderFoot;
- retain copyright/license headers in modified files;
- identify SpiderFoot and modifications in third-party notices;
- do not imply that MIT removes obligations imposed by data providers, bundled tools, trademarks, privacy law, or dependency licenses;
- review every optional external CLI/tool before including `Dockerfile.full` functionality in a distributed image.

Primary source: [SpiderFoot repository and license](https://github.com/smicallef/spiderfoot).

### IntelOwl

The upstream repository identifies IntelOwl as **AGPL-3.0**. AGPL has strong source-availability obligations, including network interaction provisions. Independent-service deployment is an architectural recommendation, not a claim that obligations disappear.

Requirements:

- preserve license and notices;
- keep an exact source/build record for the deployed version;
- obtain legal review before modifying, distributing, offering a modified network service, or combining code across boundaries;
- integrate using the documented API rather than copying IntelOwl implementation into proprietary platform services;
- inventory analyzer/container licenses separately because the umbrella license does not settle every bundled tool/data-source term.

Primary source: [IntelOwl repository](https://github.com/intelowlproject/IntelOwl).

### Maltego

Maltego application code, branding, content, and commercial services must be treated as proprietary unless a specific artifact carries an explicit license. Official SDK packages and documentation may have their own license/terms, which must be captured at the exact version used.

Allowed only after version-specific review:

- implement an optional connector with the official SDK;
- implement independently designed entity/link/enrichment concepts;
- consume or produce an openly documented interchange format.

Prohibited project assumptions:

- “public documentation” does not grant a right to copy the product UI, content, icons, transforms, or code;
- package availability does not prove redistribution rights;
- functional inspiration does not justify copying distinctive trade dress or proprietary behavior.

Primary source: [Maltego Transforms SDK overview](https://docs.maltego.com/en/support/solutions/articles/15000062349-maltego-transforms-sdk-overview).

## Dependency and data-source obligations

The local Python requirements include CherryPy, Mako, D3/Sigma assets, cryptography libraries, document parsers, and other packages. The 233 modules connect to numerous external services. Before M1 release and on every dependency update:

1. Generate an SBOM for Python, JavaScript, OS packages, images, and optional CLI tools.
2. Resolve each component to exact version, source, license expression, copyright, and distribution obligations.
3. Flag copyleft, source-available, non-commercial, field-of-use, unknown, deprecated, or unmaintained components.
4. Maintain `THIRD_PARTY_NOTICES` and source-offer artifacts where required.
5. Scan for vulnerabilities and secrets; sign images and attest builds.

External services also impose API terms, rate limits, retention rules, attribution, and restrictions on derived data. Provider enablement must require a terms record with owner, approved uses, jurisdictions, retention, redistribution/export permissions, and review date.

## Product licensing controls

- Attach `license_policy_id` and provider terms version to every configured integration.
- Block exports that violate provider redistribution terms.
- Keep raw evidence retention configurable by provider and jurisdiction.
- Record exact collector/analyzer/model versions in reports.
- Render third-party attribution in distributed software and, where required, reports.
- Never remove upstream notices during UI rebranding.

## Release gate

No production or customer distribution until counsel/security sign off on:

- SpiderFoot fork/notice handling;
- IntelOwl AGPL deployment and any modifications;
- every enabled analyzer and external provider;
- Maltego SDK/interoperability use, if any;
- SBOM, notices, source-offer process, trademarks, and report/export rights.

