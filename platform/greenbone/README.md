# Local Greenbone / OpenVAS

This directory contains the official Greenbone Community Containers deployment used by
SignalTrace Phase 8. The web interface is published only on the local machine at
`https://127.0.0.1`.

## Commands

```bash
./start-greenbone.sh
./status-greenbone.sh
python3 ./secure-default-account.py
./stop-greenbone.sh
```

The first startup copies and loads several vulnerability feeds and can take a long time.
Do not remove the Docker volumes unless you intentionally want to erase feeds, scan targets,
tasks, reports, and Greenbone accounts.

Run `secure-default-account.py` once after the first successful startup. It replaces the
factory password with a random credential and saves that credential through SignalTrace's
encrypted provider configuration API. The generated password is never printed or written in
plain text.

Only scan systems for which you have explicit authorization. SignalTrace applies its active
authorization policy before it queues an OpenVAS scan.
