# Phase 9 deployment evaluation

## Current decision

Do not run a full OpenCTI or MISP stack concurrently with Greenbone on the current
Docker Desktop allocation of 8 GB RAM.

OpenCTI includes the platform, workers, Elasticsearch, Redis, RabbitMQ, and object
storage. Its platform Node.js process alone has an 8 GB default memory limit. This is
not a safe fit while Greenbone is importing feeds and performing scans.

The official MISP Docker deployment is lighter than OpenCTI but still adds MISP core,
MariaDB/MySQL, Redis, mail, background workers, and optionally MISP modules. It should
be deployed later using the official slim images after either increasing Docker memory
or defining mutually exclusive Greenbone/MISP operating profiles.

## Implemented interoperability layer

SignalTrace now stores normalized STIX 2.1 objects independently of either product.
The importer supports indicators, malware, campaigns, threat actors, infrastructure,
attack patterns, tools, vulnerabilities, identities, locations, and relationships.

Indicators are correlated with investigation assets only while active. Publisher
expiration is honored. Indicators without `valid_until` receive a configurable 90-day
default lifetime, preventing old intelligence from creating permanent matches.

This storage and correlation layer is the integration boundary for later TAXII,
OpenCTI GraphQL, and MISP REST synchronization.

## Deployment gate

Re-evaluate deployment when Docker has at least 16 GB allocated or Greenbone and the
threat-intelligence platform can run in separate profiles. MISP slim is the preferred
first local server; OpenCTI is better reserved for a larger host or cloud VM.
