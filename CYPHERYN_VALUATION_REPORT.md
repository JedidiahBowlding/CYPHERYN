# CYPHERYN Software Valuation Report

Valuation date: 2026-09-01  
Repository examined: `https://github.com/JedidiahBowlding/CYPHERYN`  
Exact HEAD examined: `ce94368bc29ae89ca3b6231b8d821ed825412de3`  
Application version: `0.9.0`

## Important status and scope

This is an internal strategic valuation analysis, not a qualified or certified appraisal, IRS appraisal, fairness opinion, audit opinion, legal opinion, or investment recommendation. A qualified independent appraiser and appropriate legal/tax/accounting advisers may be required for tax, charitable contribution, financing, litigation, financial reporting, insurance, or a regulated transaction.

No financial statements, customer contracts, bank records, capitalization table, employment agreements, IP assignments, domain purchase records, trademark file, tax returns, or management representations were supplied. Revenue and customer metrics are therefore **unknown and treated as zero for valuation purposes**, not asserted as fact. Currency is U.S. dollars.

## Executive valuation

| Measure | Range | Confidence |
| --- | ---: | --- |
| **1. Distressed / asset-sale value** | **$40,000–$125,000** | Medium |
| **2. Current fair market value** | **$200,000–$600,000** | Low–Medium |
| **3. Technical replacement value** | **$950,000–$3,050,000** | Medium |
| **4. Strategic acquisition value** | **$500,000–$1,800,000** | Low |
| **5. Potential value with $1M ARR** | **$3,000,000–$6,000,000** | Low–Medium |
| **6. Potential value with $10M ARR** | **$35,000,000–$70,000,000** | Low |

**Most defensible single current value: $350,000.**

This is not the midpoint by default. $350,000 gives meaningful value to a verified, deployable, unusually well-documented security platform while applying severe discounts for MIT availability, no verified revenue or users, a three-day public history, founder/key-person concentration, inherited code, experimental federation, single-node production, no patent portfolio, and buyer integration/support cost. It is the amount most plausibly defensible in an arm’s-length technology/IP asset negotiation without a demonstrated revenue pipeline or uniquely motivated acquirer.

## 1. Verified project state

| Attribute | Verified state |
| --- | --- |
| HEAD | `ce94368bc29ae89ca3b6231b8d821ed825412de3` |
| Version | 0.9.0 in API and frontend manifests |
| Releases/tags | One public release/tag: `v0.9.0` |
| Public history | 52 commits, 2026-08-29 through 2026-09-01 |
| Contributors | Two GitHub identities; ownership/common-control relationship not established |
| GitHub adoption | 0 stars, 0 forks, 0 watchers, 0 open issues at valuation date |
| Repository | Public, approximately 27 MiB working tree and 1,073 files excluding `.git` |
| Owned platform code | Approximately 29,000 lines across API source/tests and frontend application, before generated/vendor exclusions |
| Inherited engine | Approximately 55,000 Python lines in `spiderfoot/` and `modules/`; separately copyrighted/treated as inherited |
| Languages | Python, TypeScript/React, JavaScript, CSS, shell/Compose/Caddy configuration |
| API | FastAPI, Pydantic, SQLAlchemy, PostgreSQL, Uvicorn |
| Frontend | React 19, TypeScript, vinext/Vite, Tailwind tooling |
| Tests | Latest maturity audit records 156 owned API tests plus two rendered frontend tests; broader inherited audit recorded 1,665 executed, 1,630 passing and 35 skipped |
| Coverage | Latest maturity audit records 66% owned API coverage and 75% worker gate; focused modules have enforced thresholds |
| CI/CD | Eight workflows: cross-platform, tests, CodeQL, security/supply chain, PostgreSQL federation, two-node federation, release, and Pages |
| Supply chain | Dependency audits, Gitleaks, CodeQL alert gate, five-image Trivy High/Critical gates, SBOMs, checksums and provenance attestations |
| Deployment | Docker Compose, production overlay, Caddy/Auth0, health checks, exact deployment manifest and clean production commit evidence |
| Production evidence | V2 audit records deployed commit `088b542...`, exact image identities, root-owned manifest and live domain/auth/header checks |
| Federation | Ed25519 node identity, explicit trust states, signed closed-schema assertions, replay/expiry/revocation, PostgreSQL concurrency and two-node independence tests |
| Blockchain | Architecture research only; expressly no prototype, contract, chain dependency or token |
| License | MIT; copyright notices include CYPHERYN contributors and Steve Micallef/SpiderFoot provenance |
| Documentation | Extensive architecture, operations, security, provider, federation, cross-platform, release and audit documentation |

The codebase is technically substantial but unusually young. Commit count and line count do not prove months or years of independent commercial development, originality, customer validation, or maintainability under a team. The valuation therefore relies on observable functionality and verification, not claimed effort.

## 2. Asset a buyer would receive

Subject to confirmed title and transaction terms, the transferable package could include:

- CYPHERYN-owned API, frontend, worker/job, database, reporting, graph, evidence, finding/remediation and monitoring code;
- provider adapters and the trusted scanner-orchestration design;
- authorization controls and defensive active-scanning boundaries;
- SHA-256 evidence/audit chains and Ed25519 checkpoint/offline-verifier system;
- experimental federation protocol, node identity, privacy schema, replay/revocation and resilience work;
- Compose/Caddy deployment, cross-platform utilities, CI/CD and release/supply-chain controls;
- tests, runbooks, architecture records, threat models and audits;
- brand assets, GitHub repository, `cypheryn.com` if separately owned and conveyed, and accumulated technical know-how; and
- goodwill and founder assistance only if expressly included.

It would not automatically include third-party provider accounts/data, Auth0 or cloud accounts, DigitalOcean infrastructure, API credentials, customer data, third-party trademarks, non-transferable service licenses, or ownership of third-party open-source code. A transaction must inventory every dependency, asset account, domain registrar record, secret, contributor right and production service separately.

## 3. Open-source and IP analysis

CYPHERYN is publicly available under the MIT License. Anyone already has broad rights to use, copy, modify, publish, distribute, sublicense and sell copies while preserving notices. A buyer cannot withdraw those rights from copies already distributed. This sharply reduces source-code exclusivity and prevents valuing the repository like secret proprietary software.

MIT does not prevent a buyer from selling hosted services, enterprise packaging, support, proprietary future modules, certified builds, managed deployments or a dual-distribution offering where the buyer owns the relevant copyright. Commercial value can reside in execution, trusted releases, brand, domain, customer relationships, deployment expertise, roadmap, support organization, and future code—not merely access to source.

Material IP diligence issues:

- No contributor license agreement or contributor IP-assignment framework was found. Two GitHub identities contributed; their legal identity, employer obligations and assignments must be confirmed.
- The root notice includes Steve Micallef and inherited SpiderFoot code. That MIT code can be commercialized with notices, but is not exclusive CYPHERYN IP and must not be valued as owned invention.
- Intel/service names, provider APIs and scanner binaries remain third-party assets governed by their own licenses and terms.
- CI-generated SBOMs improve diligence, but transaction counsel should run a complete license scan for copyleft, notice, source-offer and SaaS/network-copyleft obligations before closing.
- No patent portfolio, filed patent application, registered trademark evidence, or trade-secret program was found in the repository. Public architecture has little trade-secret value.
- Brand/trademark, domain and copyright are separate rights. A GitHub repository transfer alone does not convey the domain or trademark rights.

This is a technical reading of repository evidence, not a legal title opinion.

## 4. Replacement-cost valuation

Estimated competent-team hours to recreate the **verified CYPHERYN-owned platform**, using available third-party open source rather than rewriting inherited SpiderFoot:

| Workstream | Low hours | Base hours | High hours |
| --- | ---: | ---: | ---: |
| Product/security architecture | 300 | 450 | 650 |
| Backend API and data model | 900 | 1,200 | 1,700 |
| Frontend, graph and UX | 600 | 850 | 1,200 |
| Authentication/authorization | 250 | 375 | 550 |
| Discovery and provider adapters | 800 | 1,150 | 1,700 |
| Normalization, findings and remediation | 500 | 700 | 1,000 |
| Durable worker, schedules and monitoring | 600 | 850 | 1,200 |
| Scanner isolation/orchestrator/network policy | 450 | 650 | 900 |
| Evidence, reporting and exports | 500 | 700 | 950 |
| Integrity chains/checkpoints/verifier | 350 | 500 | 700 |
| Federation/crypto/concurrency/chaos | 700 | 950 | 1,300 |
| Production deployment/Auth0/Caddy | 450 | 625 | 850 |
| CI/CD, SBOM, scanning and release | 450 | 625 | 850 |
| QA/SDET and regression automation | 800 | 1,050 | 1,450 |
| Cross-platform setup and documentation | 500 | 700 | 950 |
| Product/visual design and brand assets | 150 | 225 | 350 |
| Engineering leadership, audit and hardening | 300 | 475 | 650 |
| **Total** | **8,600** | **12,075** | **16,900** |

Current U.S. BLS reference medians include software developers at $135,980, QA/testers at $104,300, information-security analysts at $129,180, web/interface designers at $104,000, and technical writers at $90,390. Fully loaded senior-team or specialist-contractor rates are higher after benefits, payroll burden, recruiting, management, equipment, nonproductive time and risk. This model uses blended effective rates of approximately $110/$145/$180 per productive hour.

| Case | Hours × blended cost | Estimated recreation cost |
| --- | --- | ---: |
| Low | 8,600 × $110 | $946,000 |
| Base | 12,075 × $145 | $1,750,875 |
| High | 16,900 × $180 | $3,042,000 |

Rounded technical replacement value: **$950,000–$3,050,000**.

This is not fair market value. A buyer can reuse public CYPHERYN and SpiderFoot code rather than recreate it, and must still fund integration, support, sales, compliance and product-market validation. The cost approach is also uncertain because the very short history does not substantiate actual labor consumed.

## 5. Technical asset quality

| Dimension | Score / 10 | Evidence and valuation effect |
| --- | ---: | --- |
| Architecture | 8.6 | Clear API/worker/frontend boundaries, local-first behavior, separate trusted scanner orchestrator; increases reuse value. |
| Maintainability | 7.2 | Typed owned platform and extensive docs, but large routing/orchestration surfaces and inherited legacy code remain. |
| Test maturity | 7.8 | Cross-platform suites, provider contracts, concurrency and two-node tests; overall owned coverage remains moderate. |
| Cybersecurity posture | 8.8 | Explicit authorization, redaction, isolation, headers, CodeQL triage and threat models; strong for pre-revenue software. |
| Supply-chain security | 9.0 | Dependency/secret/container gates, five SBOMs, attestations and release checks materially reduce diligence risk. |
| Documentation | 9.1 | Unusually deep architecture, operations, tutorials, audits and ADRs; materially improves transferability. |
| Reproducibility | 8.8 | Exact source/image manifest and clean deployment proof; database migration practice remains weaker. |
| Deployment maturity | 7.8 | Compose/Caddy/Auth0 and health checks work, but no proven fleet, HA or enterprise installer history. |
| Observability | 8.4 | Worker/queue/provider metrics, structured redacted logs and readiness endpoints. |
| Fault tolerance | 7.7 | Durable jobs, cancellation, two-node federation and chaos tests; production is a single application node. |
| Privacy architecture | 9.0 | Closed federation schema, prohibited-field tests and conservative blockchain privacy boundary. |
| Cryptographic architecture | 8.5 | Standard SHA-256/Ed25519, independent verification and clear limitations; no formal protocol audit. |
| Federation maturity | 7.4 | Technically meaningful and tested, but explicitly experimental with no production network adoption. |
| Cross-platform support | 8.5 | Hosted macOS, Windows and Linux validation plus Docker-first setup. |
| Developer onboarding | 8.6 | README, doctor/setup tooling, runbooks and optional-provider behavior are strong. |
| Operational maturity | 6.8 | One very recent production deployment, short observation period, key-person dependence and no enterprise SLA evidence. |
| Commercial readiness | 3.8 | No verified customers, ARR, pricing system, sales motion, support team, legal/compliance package or adoption. |

## 6. Product and market position

Gartner projected worldwide information-security spending near $240–244 billion in 2026, including approximately $121 billion of security software in its 2025 forecast update. This demonstrates a large addressable sector, not CYPHERYN market share.

CYPHERYN overlaps with:

- Tenable/Rapid7/Qualys in exposure and vulnerability workflow;
- Shodan/Censys in internet asset intelligence, although CYPHERYN does not own a comparable internet-wide sensor/data corpus;
- Recorded Future, CrowdStrike and Microsoft in threat-intelligence enrichment, without their proprietary telemetry;
- Maltego in relationship graph investigation;
- SpiderFoot in OSINT collection, partly through inherited technology;
- MISP/OpenCTI in intelligence interchange and collaboration; and
- security-validation/orchestration products through isolated active tools and remediation verification.

It is not equivalent to any mature vendor. Incumbents have proprietary datasets, global sensors, enterprise sales/support, certifications, integrations, customer references and long operating histories.

CYPHERYN-specific differentiation is the combination of local-first deployment, authorization-aware active assessment, evidence provenance/integrity, remediation/rescan lifecycle, isolated scanner execution, provider readiness semantics, and privacy-bounded federation without a central control plane. Federation is **moderate strategic differentiation today**: technically uncommon and credible, but experimental and commercially unproven. It could become high differentiation after independent production nodes, interoperability, customer demand and governance are proven.

Blockchain architecture contributes modest documentation/option value only—approximately tens of thousands of dollars inside replacement value, not a separate blockchain-company premium.

## 7. Comparable transactions

Publicly disclosed transactions demonstrate strategic demand but are not direct valuation multiples for CYPHERYN:

| Company | Year | Disclosed value | Maturity/relevance | Strategic rationale |
| --- | ---: | ---: | --- | --- |
| Bit Discovery / Tenable | 2022 | $43.8M cash net of acquired cash | Operating EASM company; closest disclosed category comparison | Added external attack-surface discovery to Tenable |
| Ermetic / Tenable | 2023 | Approximately $244M consideration | Established CNAPP/CIEM company with customers | Unified cloud exposure and identity context |
| Bionic / CrowdStrike | 2023 | Price not disclosed officially; press reported about $350M | Funded ASPM company | Code-to-runtime cloud-risk visibility |
| Expanse / Palo Alto Networks | 2020 | Approximately $670M cash/stock plus $130M replacement equity | Mature internet-scale ASM/data platform | Combined outside-in attack surface with platform telemetry |
| Recorded Future / Mastercard | 2024 | $2.65B announced | 1,900+ clients in 75 countries; scaled threat-intelligence business | Added intelligence to payments/fraud/security services |

These companies had teams, customers, proprietary data, distribution and operating histories. Their prices should not be used to imply CYPHERYN is worth millions or billions today. Reliable public evidence for genuinely pre-revenue open-source security-code asset sales is sparse; undisclosed outcomes cannot support a numeric comparable method.

## 8. Actual commercial position

| Metric | Verified status |
| --- | --- |
| Revenue / ARR / MRR | No evidence supplied; treated as $0 |
| Paying customers | None verified |
| Active users | Unknown; GitHub adoption signals are zero |
| Enterprise contracts/pilots | None verified |
| Partnerships/channel | None verified |
| Distribution | Public GitHub, project website and one production deployment |
| Community | Two contributor identities, zero stars/forks/watchers/issues |

No SaaS multiple is applied to current revenue because no current revenue was established.

## 9. Valuation methodologies

### A. Adjusted replacement cost

Replacement cost is $0.95M–$3.05M. Applying combined 65–90% marketability/duplication/integration discounts for MIT availability, no traction, inherited code, technical debt, buyer support burden and short operating history implies approximately **$150,000–$900,000**. The range is wide and is used as a cross-check, not the sole answer.

### B. Comparable software/IP transactions

Disclosed cyber acquisitions start far above CYPHERYN but involve commercial organizations, proprietary data and customers. Applying stage and traction discounts exceeding 95% to even the smallest close category transaction produces an unhelpfully broad sub-$2M indication. A more defensible code-and-know-how comparable range is **$100,000–$500,000**, with low confidence due to sparse disclosed pre-revenue asset sales.

### C. Pre-revenue technology acquisition

A build-versus-buy buyer might pay for 3–9 months of accelerated roadmap, documented security architecture and a deployable base, but not the full hypothetical rebuild. Estimated indication: **$200,000–$700,000**.

### D. Strategic value

An MSSP, OSINT vendor, vulnerability platform or defense integrator with an immediate product gap could avoid architecture, federation, scanner-isolation, integrity and deployment work. After integration and retention costs, indication: **$500,000–$1,800,000**. This requires a motivated buyer; no evidence indicates one currently exists.

### E. Risk-adjusted future commercial value

Future value is highly sensitive to sales execution, retention, pricing and capital. Discounting hypothetical ARR outcomes for probability, time, future investment and dilution supports only **$200,000–$650,000** today absent pipeline evidence. It does not justify capitalizing an unbuilt revenue stream at a full SaaS multiple.

### Reconciliation

The current fair-market range is **$200,000–$600,000**. The lower half reflects what a general technology buyer can reproduce by adopting the MIT repository; the upper half requires credible ownership diligence, clean transfer, founder transition assistance and a buyer who values the verified hardening/federation work.

## 10. Strategic acquirers

Potential buyer categories—not claims of interest—include:

- MSSPs/MDR providers: add a customer-facing exposure/evidence/remediation portal and private deployment option;
- vulnerability/exposure vendors: accelerate evidence integrity, remediation verification and isolated scanner orchestration;
- CTI/OSINT vendors: add investigation graph, local-first collection, provider normalization and federated assertions;
- defense/government integrators: use independent nodes and privacy-bounded sharing in disconnected or sovereign environments;
- cyber insurers/risk firms: add auditable evidence and rescan-based remediation tracking;
- enterprise security platforms: acquire architecture/team know-how for on-premises or sovereign deployment; and
- OEM/security appliance vendors: package a branded local intelligence console.

An ordinary financial buyer would value current cash flow near zero and focus on liquidation assets. Strategic premium could be 1.5–4× the most defensible current estimate, bounded here at $1.8M because integration, provenance and adoption remain unproven.

## 11. Future ARR scenarios—not current value

Current 2Q26 evidence cited by Software Equity Group places median public SaaS EV/TTM revenue near 3.2× and security near 4.3×; private-company data cited by SaaS Capital and iMerge has clustered around roughly 3.75–5.3× depending on quality, backing and growth. Smaller, concentrated, founder-dependent companies generally trade below scaled public leaders. The scenarios assume recurring gross-margin software revenue, acceptable churn, clean IP, and credible growth; otherwise use lower multiples.

| Hypothetical ARR | Illustrative multiple/value logic | Potential company value | Confidence |
| ---: | --- | ---: | --- |
| $100,000 | Asset floor plus early customer signal; strict ARR multiple is unstable | $500,000–$1,200,000 | Low |
| $500,000 | Approximately 3–6× with size/key-person discount | $1,500,000–$3,000,000 | Low–Medium |
| $1,000,000 | Approximately 3–6× | **$3,000,000–$6,000,000** | Low–Medium |
| $3,000,000 | Approximately 3.5–6.5× | $10,500,000–$19,500,000 | Low |
| $10,000,000 | Approximately 3.5–7×, dependent on growth/retention | **$35,000,000–$70,000,000** | Low |

High growth, net retention above 110%, diversified enterprise customers, strong gross margins and low churn could push upward. Services-heavy revenue, concentration, weak retention, provider cost, security incidents or slow growth push downward.

## 12. Commercial business models

Best near-term value creation:

1. **Managed enterprise deployment/support**—fits local-first/security-sensitive buyers and creates early services-backed recurring contracts.
2. **MSSP/OEM licensing**—leverages multi-customer distribution without building a large direct sales force.
3. **Hosted single-tenant SaaS**—higher recurring value but requires multi-tenancy, compliance, uptime, support and data-governance investment.
4. **Enterprise federation/private networks**—potential differentiation after protocol governance and real multi-node operation.
5. **Compliance/evidence reporting**—sell auditable workflows and retention integrations rather than raw scanner output.
6. **Premium integrations/API/support**—commercial packaging around provider certification, SLAs and lifecycle management.
7. **Professional services**—useful for entry and implementation, but lower multiple if it dominates revenue.

A cryptocurrency/token model is not justified.

## 13. Brand, domain and presence

`CYPHERYN` is distinctive and the `.com` domain is useful, but there is no verified traffic, search demand, revenue, registered trademark, backlinks or buyer competition. Standalone domain/brand value is therefore estimated conservatively at **$1,000–$10,000**, subject to registrar/title and trademark clearance. Visual identity and polished documentation add transferability, not a large separate intangible value. Zero GitHub stars/forks/watchers means repository reputation currently adds little standalone goodwill.

## 14. Key discounts

Approximate valuation effects overlap and must not be mechanically multiplied:

- no verified revenue/customers/pipeline: very high discount;
- MIT public availability and nonexclusive source: 40–70% discount to proprietary-code replacement logic;
- three-day public history and one release: 20–40% operating-history discount;
- founder/key-person and two-identity concentration: 15–35%;
- unclear contributor assignment/CLA and inherited provenance: 10–30% until diligence closes;
- experimental federation and no production federation network: 10–25% on claimed differentiation;
- single production application node/no enterprise scale evidence: 15–30%;
- third-party providers/scanners and API terms: 10–25%;
- no patents/trade secrets: removes exclusivity premium rather than creating a direct charge;
- buyer integration, support and productization: $150,000–$750,000 depending buyer; and
- compliance, support, sales and maintenance organization not yet present: major company-value discount.

## 15. Value-enhancement roadmap

Costs are rough external/internal cash-equivalent estimates, excluding founder opportunity cost.

| Rank | Action | Difficulty | Time | Estimated cost | Expected valuation impact |
| ---: | --- | --- | --- | ---: | --- |
| 1 | Close 3–5 paid enterprise/MSSP pilots with defined renewal metrics | High | 3–9 months | $75k–$300k | Very high; proves willingness to pay and creates references |
| 2 | Reach $500k–$1M diversified ARR with retention data | High | 9–18 months | $300k–$1.5M GTM/product | Transformative; enables revenue methodology |
| 3 | Execute contributor IP assignments/CLA and complete license/title diligence | Medium | 1–3 months | $15k–$75k | High; removes transaction blocker |
| 4 | Obtain named enterprise references and quantified remediation outcomes | Medium | 4–12 months | $25k–$150k | High; reduces product-market risk |
| 5 | Complete independent penetration test/architecture assessment and remediate findings | Medium | 2–4 months | $30k–$120k | Medium–high; validates security claims |
| 6 | Build repeatable production HA/multi-node federation and publish interoperability results | High | 3–8 months | $100k–$400k | Medium–high; converts federation from experimental to product |
| 7 | Establish commercial packaging, pricing, support SLA and sustainable open-core/enterprise policy | Medium | 2–4 months | $30k–$150k | Medium–high; makes acquisition economics legible |
| 8 | Pursue SOC 2 readiness/type examination when customer demand warrants | High | 6–15 months | $100k–$350k | Medium–high for enterprise sales; low before demand |
| 9 | File/clear CYPHERYN trademark and formalize domain/brand ownership | Low–Medium | 3–12 months | $3k–$20k | Low–medium; protects brand and transaction perimeter |
| 10 | Create MSSP/OEM/API partnerships and certified integration ecosystem | High | 6–18 months | $150k–$600k | High if contracts/distribution result |

A published federation specification and third-party implementation should be part of action 6. Patents should be pursued only if counsel identifies genuinely novel, commercially useful claims; filings without defensible novelty may destroy value.

## 16. Confidence and information that changes value

- Distressed value—**Medium**: repository quality is observable; auction demand and title are unknown.
- Current FMV—**Low–Medium**: no actual bids, financials, contracts or IP assignments.
- Replacement value—**Medium**: workstreams are observable, but actual productivity and reuse vary widely.
- Strategic value—**Low**: depends on a specific buyer’s roadmap and retention of know-how.
- $1M ARR scenario—**Low–Medium**: market multiples are observable, but revenue quality is hypothetical.
- $10M ARR scenario—**Low**: growth, retention, margins, competition and capital structure are unknowable.

Material upward evidence would include signed recurring contracts, verified ARR/MRR, net/gross retention, pipeline conversion, usage telemetry, enterprise references, clean IP assignments, independent security assessment, production uptime, multiple real federated nodes, provider economics and a credible support/sales team. Downward evidence would include disputed ownership, license violations, leaked secrets, security incidents, unaffordable provider costs, nonfunctional production, customer concentration, churn or inability to maintain the inherited code.

## Sources

- [U.S. BLS software developer and QA compensation](https://www.bls.gov/ooh/computer-and-information-technology/software-developers.htm)
- [U.S. BLS information-security analyst compensation](https://www.bls.gov/ooh/computer-and-information-technology/information-security-analysts.htm)
- [U.S. BLS web/interface designer compensation](https://www.bls.gov/ooh/computer-and-information-technology/web-developers.htm)
- [U.S. BLS technical-writer compensation](https://www.bls.gov/ooh/media-and-communication/technical-writers.htm)
- [Gartner 2025–2026 information-security spending forecast](https://www.gartner.com/en/newsroom/press-releases/2025-07-29-gartner-forecasts-worldwide-end-user-spending-on-information-security-to-total-213-billion-us-dollars-in-2025)
- [Software Equity Group 2Q26 SaaS report](https://softwareequity.com/research/quarterly-saas-report)
- [SaaS Capital private valuation multiples](https://www.saas-capital.com/blog-posts/private-saas-company-valuations-multiples/)
- [Tenable SEC filing: Bit Discovery and Ermetic consideration](https://www.sec.gov/Archives/edgar/data/1660280/000166028024000033/tenb-20231231.htm)
- [Palo Alto Networks announcement: Expanse](https://www.paloaltonetworks.com/company/press/2020/palo-alto-networks-announces-intent-to-acquire-expanse)
- [Mastercard announcement: Recorded Future](https://investor.mastercard.com/investor-news/investor-news-details/2024/Mastercard-Invests-in-Continued-Defense-of-Global-Digital-Economy-With-Acquisition-of-Recorded-Future/default.aspx)
- [CrowdStrike announcement: Bionic](https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-acquire-bionic-extend-cloud-security-leadership)
- [Tenable attack-surface management product](https://www.tenable.com/products/attack-surface-management)
- [Rapid7 security platform](https://www.rapid7.com/products/)

## Final judgment

CYPHERYN CURRENT VALUE RANGE:
$200,000 – $600,000

MOST DEFENSIBLE CURRENT ESTIMATE:
$350,000

REPLACEMENT VALUE:
$950,000 – $3,050,000

STRATEGIC BUYER RANGE:
$500,000 – $1,800,000

Current value is substantially below engineering replacement cost because a buyer can lawfully use the public MIT code, revenue and customer demand are unverified, the public operating history is only days long, ownership/contributor diligence is incomplete, and substantial integration, support, compliance and go-to-market investment remains. The gap is not a judgment that the engineering lacks quality; it is the market discount for nonexclusivity, execution risk and absent commercial proof.
