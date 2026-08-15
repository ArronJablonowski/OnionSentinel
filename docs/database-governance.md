# Database Governance

The machine-readable source of truth is
`operations/quality/database-governance.json`; validate it with
`python3 operations/validate-database-governance.py`. The catalog is deliberately
secret-free and points only to repository controls. It never inventories live
rows, credentials, hostnames, or runtime database paths.

## Ownership boundary

| Database | Authority | Recovery source | Current version owner |
| --- | --- | --- | --- |
| Mac alert-store SQLite | Alerts, analyst state, jobs, notification/enrichment, incidents, PCAP, analysis | Hourly verified SQLite backup and daily recovery bundle | Persisted aggregate schema version 1 |
| Investigation-harness SQLite | Investigation runs and hash-chained trace/provenance ledgers | Daily recovery bundle and maintenance prerequisite backup | Persisted harness schema version 5 |
| n8n PostgreSQL | n8n workflows, encrypted credentials, and execution metadata | Daily custom-format dump plus matching runtime configuration | Pinned upstream n8n migrations |
| Alert-store PostgreSQL | Job shadow, assets/DHCP, Software Inventory, and AC Hunter | Optional daily custom-format dump | Four persisted Onion Sentinel component schemas |
| Relay SQLite | Alert deduplication and durable delivery outbox | Operator-controlled encrypted Relay runtime archive | Relay startup schema; version not yet persisted |

Security Onion databases are not Onion Sentinel-owned and are intentionally not
in this catalog. Onion Sentinel access to them remains read-only. Static JSON,
Markdown reports, evidence artifacts, prompts, agent memory, credential/session
files, and cache files are governed by their own custody contracts and are not
misrepresented as databases.

## Qualification semantics

The validator fails on a missing database, missing ownership/recovery field,
duplicate identifier, invalid objective, unsafe or absent source anchor, unknown
state, or apparent secret material. It emits only entry and declared-gap counts.
It does not read live data or treat a documented weakness as accepted.

The initial catalog recorded eight concrete gaps. The alert-store aggregate
version and atomic startup migration are now implemented in source, leaving six:

- Relay SQLite does not persist an aggregate schema version and its startup DDL
  is not one atomic migration;
- the four Mac database backup classes are owner-only but are not encrypted at
  rest by the backup workflow itself.

Those gaps are the next ARR-39 slices. Version and transaction work must land
with production-shaped copy tests and rollback coverage before backup encryption
changes. Encryption must preserve unattended backup, bounded restore-drill, key
loss recovery, owner-only custody, and manifest verification without placing a
key or passphrase in Git, Linear, logs, or the backup artifact itself.

## Release and restore rule

Catalog validation is a source release gate, not a substitute for a restore
drill. ARR-39 can close only after the declared gaps are removed and exact
production-shaped evidence proves transactional migrations, corruption and
relationship checks, encrypted backup generation, isolated restore, recovery
objectives, growth/maintenance telemetry, and provenance preservation for every
entry. Live migration or restore remains a separately controlled operation with
an exact rollback point.
