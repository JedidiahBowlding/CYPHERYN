CYPHERYN overview
====================

CYPHERYN turns authorized OSINT, attack-surface observations, identity and
source-code intelligence, vulnerability evidence, and threat feeds into a
durable investigation record.

Core capabilities
-----------------

* Explicit passive and active authorization scope.
* Durable jobs with leases, retries, cancellation, heartbeats, and recovery.
* DNS, IP, certificate, service, web-posture, identity, code, and supply-chain evidence.
* VirusTotal, OTX, Censys, Shodan, GreyNoise, AbuseIPDB, URLhaus, abuse.ch, and TAXII enrichment.
* Interactive entity and relationship graph.
* Finding ownership, status, remediation guidance, rescans, and evidence comparison.
* Scheduled monitoring, alerts, evidence-grounded reports, and local AI assistance.

Getting started
---------------

The root ``README.md`` is the authoritative setup guide for macOS and Windows.
The recommended start command is ``python3 scripts/setup.py --start`` on macOS
or WSL and ``py scripts/setup.py --start`` in Windows PowerShell.

Security boundary
-----------------

CYPHERYN is for asset owners and explicitly authorized assessments. Active
providers may run only inside recorded scope. Provider credentials are encrypted
at rest, and AI-generated narrative never replaces the underlying evidence.
