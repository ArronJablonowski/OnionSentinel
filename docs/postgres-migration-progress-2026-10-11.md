# Onion Sentinel repair and PostgreSQL migration — 2026-10-11

## Actual deployment state

**Full PostgreSQL application cutover has NOT occurred.** n8n, inventory and
AC-Hunter already use PostgreSQL. The live alert store, Python dashboard readers,
investigation harness and Relay outbox still depend on SQLite. Queue shadow
projection is not an authoritative queue migration.

The base release marker is `a940f6fade0c49732e16373b344b5c9ca15133d9` with scoped
source/runtime repairs; this is not an exact full-main deployment.

## Repairs applied to source and Mac runtime

- Dashboard grouping expression now matches the existing expression index.
- Visible-page enrichment resolves representative alert IDs through the primary
  key instead of sorting historical enrichment JSON.
- Artifact indexing for a visible page selects matching alert filenames rather
  than reading the complete prompt/analysis corpus.
- Read-only dashboard connections have a 500 ms busy limit and three-second
  progress deadline. Writer connection semantics are unchanged.
- Alert fetches time out after 15 seconds. Live ingestion no longer discards a
  successful response unless the actual filter/page request URL changed.
- Live SQLite journal mode was converted to WAL; application writers and workers
  were restored afterward. No alert purge or model-policy change was performed.
- Pipeline metrics aggregate event counts/bytes in SQLite instead of transferring
  over a million event records into Node for repeated JavaScript filtering. An
  expression/covering time index supports those windowed aggregates.

Browser verification showed populated alerts, 68 active grouped detections and
an investigation in second-opinion review. Subsequently, SQLite verified a new
analysis record created at `2026-10-11 09:26:28.321-06:00`, generated at
`2026-10-11 09:26:22-06:00`, and an AI durable-job completion at
`2026-10-11 09:26:48.095-06:00` (748 completed AI jobs). Earlier callback timeouts
remain part of the record. Incident response still has two pending jobs and no
new completion proven today. Do not conflate AI analysis with IR completion.

After the scoped metrics repair, host health returned HTTP 200 in 0.099 s,
host metrics HTTP 200 in 1.281 s, and dashboard metrics HTTP 200 in 0.350 s.
Owner-only screenshot:
`/Users/aj_lobster/n8n-local/logs/qualification/alerts-loading-fixed-20261011.png`.

## Verified PostgreSQL staging copies

`n8n/bin/stage-sqlite-to-postgres.py` reads a consistent SQLite transaction and
copies all non-internal table rows into the isolated
`onion_sentinel_migration` schema of the existing protected local alert-store
PostgreSQL service. It preserves SQLite value types, blobs and original table
DDL, and verifies SHA-256 for every payload plus each table's row count inside
the same PostgreSQL transaction. Failures roll back without exposing COPY data.

| Store | Snapshot | Tables | Rows | Status |
| --- | --- | ---: | ---: | --- |
| Alert store | `62065aab1b324990b9c24635b3015495` | 32 | 2,645,650 | verified staging only |
| Investigation harness | `be2bdbe3d56b48e8af03620b856a3da4` | 9 | 20,519 | verified staging only |

These copies are tagged row archives, **not native application tables or a live
replica**. They contain the point-in-time snapshot, not later writes. The loader
now captures index/trigger/view definitions, sequence state and SQLite metadata
from the same transaction for **future snapshots**. The two verified copies
above predate that extension and lack that manifest. Do not treat them as fully
qualified restore/cutover artifacts, delete SQLite databases or redirect clients to
this staging schema. No new credentials or LAN database listener was introduced.

## Remaining work / cutover gates

1. Port the complete alert-plus-work-intent transaction boundary to native
   PostgreSQL, including analyst/reanalysis fencing, group summary maintenance,
   leases, notification/cache/PCAP state and rollback semantics. Moving only jobs
   breaks the existing atomicity contract.
2. Port every Python direct-SQLite reader/writer: dashboard, prompt builders,
   schedulers, intake/maintenance/evaluator utilities and harness ledger stores.
   Translate date, JSON, conflict, PRAGMA, rowid and trigger semantics explicitly;
   do not use an untested SQL string-replacement adapter.
3. Produce a complete schema manifest and typed-table loader, validate all
   constraints and indexes, and qualify synthetic concurrency, crash/lease
   recovery, database restart, backup and isolated restore tests.
4. Reconcile a final consistent snapshot/delta during a coordinated writer
   pause, switch all consumers together, then verify actual new ingest and a
   completed real investigation with durable evidence. Preserve a tested rollback.
5. Relay migration needs administrative access to `aj@10.88.8.8`. Public-key SSH
   authentication failed in this session. Restore approved operator access before
   changing that host; do not weaken restricted evidence keys or alter Security
   Onion to bypass this blocker.
6. Retain at most two backup generations per the user's rolling-backup policy;
   do not re-enable seven/ten-copy retention or nightly bundles silently.

Production qualification remains incomplete. Do not claim ARR-85 complete,
start a qualifying soak from these repairs alone, or mark any Linear issue Done.
The ARR connector was unavailable; do not create issues in unrelated workspaces.
