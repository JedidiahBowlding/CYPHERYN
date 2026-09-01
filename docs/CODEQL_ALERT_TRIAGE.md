# CodeQL alert triage

This register distinguishes a successful CodeQL workflow from the disposition of
the findings it produced. The 2026-08-31 review inspected all 33 alerts, including
the reported source, sink, reachability, attacker influence, data sensitivity, and
security purpose of the affected operation.

## Disposition register

| Alert | Rule | Disposition | Technical rationale |
| ---: | --- | --- | --- |
| 1–2 | JavaScript incomplete sanitization | Fixed | Graph label escaping used single replacements and was reachable with provider-controlled labels. `replaceAll` now escapes every occurrence before DOM insertion. |
| 3–6 | Clear-text sensitive storage | False positive | CodeQL propagates a credential embedded in an outbound provider URL into the HTTP response and then the public-feed cache. The sink receives downloaded public threat data—not the request URL, credential, request headers, or authorization record. Cache callers use fixed labels or public indicator/CVE identifiers. An attacker may influence provider response content, but that content is the intended cache payload and has no credential semantics. |
| 7–9 | Clear-text sensitive logging | Fixed plus residual false-positive flow | Real direct leaks were removed from Abusix and Flickr, a credential-bearing BitcoinWhosWho path is now `noLog`, and URL logs redact credential query-name variants. The remaining CodeQL path treats a credential-bearing request URL and its response/error as the same tainted value despite the redaction boundary; the generic sink is not itself proof that a secret reaches logs. Regression tests cover all three concrete controls. |
| 10 | Overly permissive regex range | Fixed | The unintended ASCII range was replaced with an explicit hexadecimal class. |
| 11–16 | Incomplete URL substring sanitization | Fixed | Cloud/provider URL decisions now compare parsed, normalized hostnames against exact approved hostnames or label-boundary suffixes instead of substring membership. |
| 17–22 | Incomplete URL substring sanitization | Fixed | TruffleHog result paths are resolved only from enumerated directory entries beneath the configured root; arbitrary URL/path fragments no longer authorize filesystem access. |
| 23 | Incomplete URL substring sanitization | False positive | The value is the `Set-Cookie` response header and the substring `ASP.NET` is used only to emit a technology-classification observation. It is not a URL sanitizer, redirect decision, fetch destination, authorization check, or security boundary. Provider-controlled text can affect only the resulting technology label. |
| 24 | Incomplete URL substring sanitization | Fixed | WikiLeaks host handling now validates the parsed hostname rather than accepting a substring match. |
| 25–26 | Path injection | Fixed | API-local imports are confined to a configured isolated root, resolved canonically, and selected through enumerated directory entries. Traversal and symlink escape regression cases are rejected. |
| 27–28 | Weak sensitive-data hashing | False positive | SHA-224 creates a deterministic cache filename for a public-data lookup key. It is not password hashing, credential verification, encryption, signing, or a secrecy control. CodeQL's credential taint originates in an outbound URL and is conservatively propagated through the provider response into a public CVE/indicator cache label. No secret is accepted or authenticated at this sink. |
| 29 | Insecure default protocol | Fixed | The legacy TLS helper now requires TLS 1.2 or newer rather than negotiating an insecure default. |
| 30–33 | Insecure protocol | Fixed | The four platform HTTP clients now construct TLS contexts with a TLS 1.2 minimum. Certificate verification and hostname verification remain enabled. |

Alerts 3–9, 23, and 27–28 are reviewed individually in GitHub. Any dismissal
must reference the alert-specific rationale above; bulk dismissal is prohibited.
New or reopened High/Critical alerts block the `main` CodeQL workflow.
