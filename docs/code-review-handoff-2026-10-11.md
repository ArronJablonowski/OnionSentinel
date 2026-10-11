# Repository QA and production handoff — 2026-10-11

## Scope and fixed defects

Reviewed the pending modularization and the application/deployment boundaries,
ran the complete unittest discovery suite, source-quality/security/governance
gates, installer preflight, dependency audit, and live health/data-flow probes.
This is substantial regression QA, not a claim that every possible defect has
been eliminated.

- Grouped alert pages retain their primary-key enrichment fast path, but query
  earlier members when the representative has no enrichment or only errors.
- Invalid enrichment JSON no longer aborts the best-member enrichment query.
- Durable-job monitoring aggregates have covering indexes for status/time and
  completion time. A production stack sample showed SQLite table-page reads
  holding the shared connection mutex while other query workers waited; live
  health/metrics probes timed out. Query-plan regression tests require covering
  index access. Post-deploy latency must still be verified under real load.
- AI page evidence includes grouped members and noncanonical legacy filenames,
  without opening unrelated canonical historical prompt artifacts.
- The repository model catalog includes the two newer supported models as
  disabled entries. Existing operator-selected production routes are preserved;
  this change does not enable or replace an agent model.
- Historical model-upgrade characterization excludes newly added catalog entries
  when reconstructing the byte-exact prior template. Reviewed migration digests
  are unchanged.
- The standalone untrusted-telemetry gate uses explicit unittest discovery so
  extracted test helpers are importable without ambient `PYTHONPATH` setup.
- The pending modularization preserves public test identities, installer shell
  behavior, and exporter entry points. Maintained source files are capped at
  1,000 physical lines, including comments; the frozen v1 contract is the
  hash-bound exception described in the modularization architecture document.

## Verification

- Python syntax: 802 production source files.
- JavaScript syntax: 246 files, checked individually.
- Shell syntax: Mac installers/owners, operation scripts, Relay and Security
  Onion wrappers.
- Node production dependency audit: zero reported vulnerabilities.
- Endpoint response governance, credential governance, database governance,
  untrusted telemetry, source-size/module-quality and secret scanning gates.
- Installer validate-only preflight passed before production mutation.
- Full unittest discovery: **5,120 tests passed**, 119.056 seconds. The
  malformed-JSON enrichment regression also passed after that run.
- Maintained code-size gate passed; largest maintained file: 989 physical lines.
- Module-quality gate passed with 37 non-growing ratchet warnings.
- The predeployment SLO probe timed out fetching metrics; the soak reporter
  returned `qualified=false`, `status=failed`, with no running healthy clock.
  Neither result is concealed or treated as release qualification.

## Unresolved items / next agent

### PCAP broker operational failure — remote access required

At 11:03 Denver time the local health API returned fresh Relay telemetry with
`state=operational_failure`, `processed=0`, `operational_failures=1`. Its
`reason=capture_telemetry_healthy` describes the capture protection check, not
the broker's underlying error. The earlier default and dedicated-key Relay SSH
attempts were denied. No remote write or Security Onion change was made.

An authorized Relay operator should inspect `so-pcap-broker.service` journal,
spool mount/readiness and bounded broker transport failures. Preserve the exact
failure before changing anything. Improve categorical error telemetry after
identifying the actual cause; do not relabel the failure as healthy merely
because no PCAP request is currently pending. Relay address: `10.88.8.8`.

### Full PostgreSQL migration remains incomplete

The authoritative alert store and harness still use SQLite. Typed row archives
in the PostgreSQL migration schema are staging evidence, not application tables
or a production cutover. Follow `postgres-migration-progress-2026-10-11.md` for
remaining adapter, concurrency, restore, consistency and rollback work. Never
delete SQLite or point application queries at the staging archive.

### Operational release qualification remains open

ARR-85 completion is not proven. Historical 48-hour attempts were invalidated
by latency, queue, maintenance and monitor-history defects. Telegram rotation
ARR-135 remains operator-controlled unless independently verified. Repository
tests and a healthy endpoint do not close these release gates. The ARR Linear
workspace remains unavailable; no issue was created in another workspace.

### Provider failures and queue backlog need separate diagnosis

Predeployment health reported public-enrichment provider errors and stale-cache
fallbacks; metrics showed a substantial n8n post-commit backlog. Investigations
and post-commit completions were advancing, so lifetime failure counters alone
are not proof of a current outage. Inspect sanitized recent error categories,
rate limits, credentials, retry ages and workflow policy; do not expose tokens
or replay the entire historical backlog indiscriminately.

### Remaining maintainability debt

Eight extracted Security Onion exporter functions retain their measured legacy
complexity under non-growing ratchet ceilings. The 1,957-line frozen v1 query
contract cannot be split without a separately versioned coordinated migration.
See `architecture/modularization-size-pass-2026-10-11.md`. The source exporter
refactor is not deployed to Security Onion as part of this Mac release.

## Deployment status

Pending the final complete-suite result, verified recovery backup, exact Git
revision handoff, and the installer investigation-idle guard. Do not interpret
this pending section as deployment evidence.
