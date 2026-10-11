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
- Production installation checks the operator-controlled credential lifecycle
  inventory before staging runtime files, acquiring worker guards, or changing
  services. A missing inventory previously failed only at alert-store startup,
  after production had been stopped and replaced. The new regression asserts
  exit 78 and no runtime-directory mutation; reconciliation classifies this
  exact read-only preflight and rejects command/path substitutions.
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
- Complete predeployment unittest discovery: **5,120 tests passed**,
  114.133 seconds, including the malformed-JSON regression.
- Final complete suite after the installer-preflight repair: **5,122 tests
  passed**, 111.471 seconds. Source quality, secrets, shell syntax and source-only
  installer validation were rerun successfully.
- Node suite: **564 tests passed**, including both covering-index query plans.
- Maintained code-size gate passed; largest maintained file: 989 physical lines.
- Module-quality gate passed with 37 non-growing ratchet warnings.
- The predeployment SLO probe timed out fetching metrics; the soak reporter
  returned `qualified=false`, `status=failed`, with no running healthy clock.
  Neither result is concealed or treated as release qualification.

## Unresolved items / next agent

### Deployment blocked — operator credential inventory required

The attempted deployment of `58fac8c58d39a7c00db9edd4269d963c86d1db6c`
failed because the private runtime file
`/Users/aj_lobster/n8n-local/config/service-identity-inventory.json` is missing.
The source-only credential catalog check cannot prove deployed credential
lifecycle compliance. Do not remove the startup gate, use an empty enablement
manifest, or invent activation/approval/rotation records to make it pass.

An authorized operator must maintain the actual owner-only (0600) inventory
described in `security/service-identity-lifecycle.md`, using the example schema
and truthful lifecycle records for every enabled identity. Validate without
printing its contents:

```sh
python3 operations/validate-credential-governance.py --deployed-runtime \
  --catalog operations/security/credential-governance.json \
  --inventory /Users/aj_lobster/n8n-local/config/service-identity-inventory.json
```

Once it passes, rerun the exact new Git revision's qualification, create fresh
bounded digest handoffs, drain investigations using their normal guard, deploy,
and reconcile every managed artifact. The previous handoffs are evidence of
the failed attempt, not reusable admission or successful application receipts.

### Covering-index fix is not yet deployed

Rollback restored the prior durable-job module, so the new metrics covering
indexes are not installed. Post-recovery bounded probes at 11:50 Denver time
returned HTTP 200, but alert-store health took 5.543 seconds, metrics 8.462
seconds and the alert API 5.094 seconds. Production is online, not latency/SLO
qualified. After approved deployment, verify index creation and `EXPLAIN QUERY
PLAN`, repeated health/metrics/UI requests under concurrent investigation load,
queue throughput and SQLite writer contention. Only then start a fresh soak;
no previous automated healthy clock is acceptable evidence.

The exact-recovery probe at 11:55 returned HTTP 200 but metrics took 11.007
seconds, further confirming that short healthy periods are not sustained
latency qualification. The restarted prior maintenance job passed summary
consistency at 11:56:25 with zero bad filters, missing summaries or orphans.
Its first online-backup attempt reached the bounded deadline at 11:57:25 and
continued its existing bounded retry policy. Do not claim a new verified backup
until the maintenance log records `backup_ok` and `maintenance_complete`.

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

**Not deployed successfully.** Code commits through `58fac8c5` were pushed to
GitHub branch `modularize-macstudio-installer`; the additional early credential
preflight repair and this handoff are committed with the final QA follow-up.
There was no main-branch merge or Security Onion/Relay deployment.

A verified rolling recovery bundle was created at
`/Users/aj_lobster/n8n-local/recovery_backups/20261011T110318-0600` before the
attempt. No database restore was performed. Recovery restored all 886 managed
artifacts to their independently recorded predeployment digests, then restored
the two changed investigation-skill policies by their exact predeployment
digests. Non-release environment settings are unchanged. The live release marker
is back to `a940f6fade0c49732e16373b344b5c9ca15133d9`, which already had scoped
patches; this is not a claim of single-commit full-tree reconciliation.

Two scripts had pre-existing local retention-only patches absent from Git:
`bin/backup-onion-sentinel-runtime.py` and
`bin/maintain-alert-store-sqlite.zsh`. They were initially retained on replacement
code; a read-only import check exposed a missing rolled-back dependency and the
first maintenance invocation failed before creating its snapshot. The local
"keep two" patches were then reconstructed against historical source and proved
byte-exact using both independent predeployment SHA-256 values. Those exact
prior versions were restored, and normal maintenance was triggered again.
`retention-rollback.json` records this final recovery; there are no retained
replacement exceptions. Newly added
runtime code was moved into recoverable owner-only quarantine. The web and
alert-store services, scheduled maintenance and AI lanes were reloaded; the
temporary investigation drain marker was removed. The previously disabled
nightly full-backup service was not enabled.

Owner-only evidence (0700 directory, 0600 reports) is in
`/Users/aj_lobster/n8n-local/logs/qualification/code-qa-20261011-58fac8c5`:
deployment logs, predeployment digest handoffs, backup/QA reports,
`rollback-receipt.json`, `rollback-verification.json`,
`configuration-rollback.json`, and `environment-after.json`. Initial recovery
verification reported two changed skill policies; the subsequent configuration
rollback report records their exact restoration. `recovery-final-verification.json`
then confirmed zero changed configuration paths, no temporary investigation
pause, and HTTP 200 from web health, alert-store health, metrics and the alert
API. The later `recovery-exact-verification.json` also checks both restored
retention-patched scripts. Metrics recorded 388 completed incident-response jobs (previously 387)
and the post-commit backlog down to 5,254; this proves resumed progress, not
that the remaining backlog or latency is resolved. Do not treat the release
marker or a passing health request as deployment acceptance evidence.
