# CodeQL release policy

A successful CodeQL workflow proves that analysis completed; it does not prove that
the result contains no findings. CYPHERYN release evidence tracks these separately:

1. workflow conclusion for every analyzed language;
2. total unresolved alert count and severity distribution;
3. every dismissed alert with its exact technical rationale and reviewer;
4. unresolved High/Critical count, which must be zero before release.

Alerts are triaged individually for reachability, attacker control, data sensitivity,
and exploitability. Legitimate defects require a regression test. False positives may
be dismissed only after their rationale is recorded in GitHub and the release audit.
Bulk dismissal is prohibited.

The `Unresolved High/Critical Alert Gate` runs after hosted analysis on `main` and
fails independently when a High or Critical CodeQL alert remains open. A release must
record both jobs and may not substitute one for the other.
