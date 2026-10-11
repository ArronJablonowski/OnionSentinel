# Onion Sentinel data-flow repair handoff — 2026-10-08

Backup cleanup notice — October 9: at the user's explicit request, Mac SQLite
backup snapshots, historical database recovery copies, and qualification SQLite
snapshots were permanently removed. Do not assume the earlier Mac snapshot paths
in this historical log are still restorable. Live databases were preserved.
Exact removal receipt: `~/n8n-local/logs/qualification/backup-cleanup-20261009.json`.
Backup schedules were not disabled by this cleanup.

Rolling retention update — October 9: both source and runtime backup defaults
now retain two completed generations per backup type (formerly 10 SQLite and 7
full-runtime bundles). Existing hourly SQLite maintenance stays enabled; the
nightly full-runtime backup job remains unloaded. Older generations roll off
after a successful verified replacement; a third copy may exist during creation.
Twenty retention/maintenance tests passed. Receipt:
`~/n8n-local/logs/qualification/rolling-backup-retention-20261009.json`.

Latest status: see **Linux inventory implementation review** at the end. Earlier
failure descriptions are historical; subsequent repair logs supersede them.
Linux downstream support is now implemented and locally tested in source, but
has not been deployed across hosts or validated against real Linux data.

## User intent and authority

Drop all incoming alerts whose original event time is before today, remove those
alerts from the local database, verify current events reach Onion Sentinel,
repair data-flow issues, and document anything not resolved. Security Onion data
has not been purged. Do not rotate credentials or issue live OSQuery as a workaround.

## Completed and deployed locally

- Runtime: `/Users/aj_lobster/n8n-local`; repository: `/Users/aj_lobster/gitProjects/OnionSentinel`.
- Enforced cutoff: original event date must be at least local today in
  `America/Denver`, starting 2026-10-08 00:00:00 -06:00 (06:00 UTC).
  It rolls forward daily. Receipt time is not an admission timestamp.
- Owner-only policy: `config/alert_ingestion_policy.json` in runtime.
  Source example: `n8n/config/alert_ingestion_policy.example.json`.
- Forced SSH intake drops old or missing/invalid-time events with
  `ok=true`, `retryable=false`, `status=dropped`. This terminal acknowledgement
  lets the Relay mark delivery complete; no alert-store call is made.
- HTTP `/alert` independently drops these events before scoring, persistence,
  notifications, or queue admission. Original `security_onion.raw_event.@timestamp`
  takes precedence over normalized timestamps.
- Both drop paths were tested live with synthetic **old** events; no synthetic
  current alert was inserted or used as proof of real upstream traffic.
- Cancelled 57,518 pending historical enrichment/post-commit jobs, retaining their
  terminal audit records. Updated PostgreSQL shadow revisions for those jobs.
- Purged 77,744 local historical alerts plus their live observable/status/group
  rows. All were before the cutoff; no current alert was deleted. Historical
  investigation, durable-job, custody, and filesystem artifacts were preserved.
- Verified backup before purge:
  `/Users/aj_lobster/n8n-local/logs/qualification/pre-today-purge-20261008T0751.sqlite3`
  (owner-only, SQLite quick_check=ok, 77,744 alerts). Restoring it will reintroduce
  purged alerts, so do not restore it casually.
- Purge and queue-change SQL receipts are under runtime `logs/qualification/`:
  `purge-before-today-20261008.sql`, `retire-pre-today-pending-jobs-20261008.sql`.
- Compacted live SQLite from about 7.9 GiB to 1.7 GiB; quick_check=ok.
  This restored disk admission below 75%, and dashboard refresh succeeded.
- Restored unloaded harness-maintenance LaunchAgent; latest report status=ok.
- SQLite maintenance obtained a verified backup after briefly stopping the
  alert-store; latest successful receipt was 07:47:40 MDT.
- Alert-store, dashboard and n8n are online. Intake and investigation workers remain
  enabled. All pipeline pending/processing counts were zero after cleanup.

## Source / deployment identity

The configured base release marker remains
`a940f6fade0c49732e16373b344b5c9ca15133d9`. This is now a **scoped live patch**,
not an exact unchanged a940 release or a newly qualified production release.

Isolated source commit: `a087848c05efb2ab245108074ef986502a71ef55`, branch
`upgrade-sol-astra-catalog`, worktree `/tmp/onion-model-upgrade.QWggGo`.
The admission changes were also copied into the main checkout without discarding
its pre-existing dirty edits. Main is not committed or merged.

Three patched runtime source hashes (SHA-256):

- `bin/onion-sentinel-alert-intake.py`: `cdea425aa58f0cad9e80936a46f4aada03f5d636740f3577d4202e3bc4e6ec3f`
- `alert_store/lib/alert_event_admission.js`: `55bffc6c17b45057860dcd9e46009df7ddae79c2dfa384a92d9bda1aa2fd4931`
- `alert_store/services/alert_ingest_orchestrator.js`: `a8ca9080206f78c3da14730f332cda87e87674dd55c267261e34ef7af3c68107`

Validation: isolated Python suite 4,556 passed, 86 skipped, 4,736 subtests passed;
Node suite 544 passed using runtime dependencies via NODE_PATH. Focused final
admission/orchestrator/service/route tests: 15 passed. The initial Node attempt
without runtime dependencies failed because sqlite3 was missing, not due to
the admission patch. Main cutoff test and git diff --check passed.

## Remaining issues requiring another agent

### P1 — Current upstream alerts are not yet proven

Before cutoff, latest received events progressed through August 24–26, despite
October 8 local receipt times. After cutoff, local receipt time stopped at
07:45:43 MDT and the alert table was empty after purge. Do not claim current
events are flowing based on heartbeat timestamps or today's UI report date.

Relay: `aj@10.88.8.8`; Mac intake destination: `10.77.7.201`;
Security Onion: `192.168.1.7`. Administrator SSH with default credentials and
explicit `/Users/aj_lobster/.ssh/pi_ed25519` both failed `Permission denied
(publickey)` with strict host checking. Existing restricted evidence credentials
reach the broker but do not grant shell access.

Next operator prerequisite: restore authorized Relay administrator access or
have an operator inspect it locally. Do not bypass forced-command restrictions.
Then inspect actual deployed timer/service, outbox age/count, poll cursor/window,
and latest Security Onion indexed event time. Determine whether the cause is
queued historical delivery, an old export cursor/window, or absent live sensor
data. Preserve the cursor/outbox before any repair; do not assume a reset is safe.

Relevant source: `relay/app/relay_application.py`, `relay/app/alert_outbox.py`,
`relay/app/alert_delivery.py`, `security-onion/bin/export-recent-alerts`,
`docs/security-onion-relay-architecture.md`.

Acceptance: a real event with original timestamp >= current Denver midnight
arrives in local alerts, appears in the UI with both event and receipt times,
and completes downstream processing. Verify older events stay terminally dropped.
Do not fabricate an alert or treat a test-only inserted event as upstream proof.

### P1 — Software inventory still stale / upstream query incomplete

`python3 bin/evaluate-operational-slos.py` currently fails on stale software
inventory (~3.96 million seconds old). `logs/software-inventory.jsonl` at
2026-10-08T13:20:43.743Z reports broker exit 4: Security Onion software inventory
query incomplete. Collector LaunchAgent is loaded, last exit=1. Its configured
page_size=500. Diagnose actual deployed upstream wrapper response/page bounds,
complete/truncated flags, broker/source version drift and source observation age.
Do not mark incomplete data fresh or weaken completeness checks.

### P1 — SQLite contention / shadow convergence still needs qualification

Backups failed repeatedly overnight with SQLITE_BUSY. Taking the store offline
allowed the verified backup to finish. This fixes backup freshness, not the root
cause of contention. One direct read also hit SQLITE_BUSY after restart.
Cancelling historical queues reduced load, but a recurring reliability fix is
still needed. Check write-gate/transaction durations, online backup behavior,
shadow projection batching, and bounded busy retries under current traffic.

After cancellation, shadow projection had zero errors but about 48,019 pending
revisions at 07:52 MDT and was actively converging. That is distinct from the
now-empty investigation/enrichment pipeline. Verify eventual exact SQLite/Postgres
reconciliation; do not erase its outbox to hide backlog.

### P2 — Disk admission headroom remains narrow

Compaction restored admission and dashboard refresh. Disk remains near the 75%
new-work threshold. Keep the new verified purge backup and existing recovery
bundles. Audit redundant backup retention and growth before deleting anything;
do not weaken the disk safety limit. No backups were deleted during this task.

### P2 — UI receipt time can look like event time

The report factory prioritizes `last_seen` over original `timestamp`;
`first_seen`/`last_seen` are local receipt times. Clearly label these as received
times and display original event time separately. Source:
`onion-sentinel-dashboard/scripts/dashboard_alert_report_factory.py` and
`dashboard_alert_repository.py`. This misleading display was diagnosed but not
changed in this scoped intake/database repair.

### P2 — Existing dependency/security and release gates

Prior npm audit reported one high-severity transitive undici vulnerability.
No dependency upgrade was made here. Repair and retest separately.
ARR Linear access remains unavailable; don't create ARR issues in another workspace.
ARR-135 Telegram rotation, full-main deployment and production qualification are
not complete. No issue was marked Done and no new 48-hour soak was declared.

## Repair log — 2026-10-08T08:01:54-06:00

- Work in progress. Administrator SSH from the operator workstation succeeds on both Relay and Security Onion; no credential rotation or forced-command bypass was needed.
- Relay exports contain genuine October 8 events (latest inspected window 13:45–13:54 UTC), but FIFO delivery is blocked behind approximately 876,000 pending records beginning August 27. Poll timer paused for a verified SSD backup before queue repair.
- Mac shadow projection is converging with zero reported failures (20,272 pending at inspection). Software inventory remains incomplete; investigation continues.

### Verified Mac repairs

- Separated original event time from receipt time in report models and detail summaries. Original `security_onion.raw_event.@timestamp` takes precedence; invalid/missing event time no longer becomes today's receipt/build time. Table/detail receipt labels now say **Received**. Regression tests cover old original timestamps with recent receipt timestamps.
- Replaced the SQLite CLI `.backup` step with an owner-only Python online backup helper: 256-page steps, bounded busy retries, a monotonic deadline, and removal of incomplete temporary snapshots on failure. Existing verification and retention controls remain. The store stayed online while maintenance completed at **2026-10-08 08:22:59 MDT**, including `quick_check=ok`; no `backup_busy` occurred in that run.
- Replaced whole-table shadow reconciliation with bounded 500-ID pages and capped difference samples. The previous checker exhausted Node's 4 GiB heap; the repaired checker completed with **227,369 SQLite rows = 227,369 PostgreSQL rows; zero pending, missing, extra, or mismatched records** at 14:14:10 UTC. No shadow outbox entries were erased.
- Updated transitive `undici` from **6.28.0 to 6.29.0**. The deployed dependency graph now reports **zero npm audit vulnerabilities**. Native SQLite binaries were preserved; 543 Node tests passed against the staged dependency graph.
- Audited six distinct plaintext backup snapshots; equal sizes did not imply equal hashes. Losslessly compressed the four oldest snapshots to owner-only `.backup.gz` files, verified each decompressed SHA-256 against its source, then removed only the redundant uncompressed representation. Reclaimed **24,614,879,625 bytes**. The latest pre-repair backup, purge backup, recovery bundles, and all snapshot contents remain preserved. Mac disk use fell to approximately 72% (257 GiB available before the new online snapshot). Restore a compressed archive into a separate file with gzip; never restore historical data over the live database casually.
- Compression receipts: `~/n8n-local/logs/qualification/data-flow-backup-compression-20261008.jsonl`.

### Scoped source/deployment qualification

- Isolated worktree: `/tmp/onion-data-flow-20261008`, based on the actual deployed `a940f6fade0c49732e16373b344b5c9ca15133d9` sources. Repair commit: `a5113d2e4edec6b07c505fda982f0f1087deb0c9`; handoff-validator compatibility commit: `4cf36ef1b5e6ab7743c3d8b6942d7986b373bd55`.
- The handoff validator incorrectly treated long multi-component source/destination paths as opaque credentials. Credential checks now operate per path component; private-key, protected-runtime, traversal, authorization and drift controls remain. All 22 handoff tests passed, including new long-path and credential-component cases.
- Current main-checkout endpoint-response, credential, module-quality, untrusted-telemetry and database-governance gates all exited zero. The older deployed baseline lacks several newer governance scripts; initial attempts there correctly failed as missing scripts. Validation was then performed using the current repository gates. Existing database-governance declared gaps remain outside this scoped patch.
- Deployed-baseline tests: 543 Node tests; 84 alert/dashboard tests; 4 original-event/receipt regressions; 5 online-backup tests; 5 baseline maintenance tests; 1 timeline test; 3 dashboard-shell tests. Main-version maintenance tests: 8 passed. Handoff tests: 22 passed. Shell syntax and `git diff --check` passed.
- Owner-only runtime rollback files and previous undici directory: `~/n8n-local/deploy-backups/data-flow-20261008/`. Drift-checked manifest: `logs/qualification/data-flow-apply-20261008-v2.json`, decision `apply_authorized`, eight exact managed artifacts.
- Source changes were mirrored into the main checkout without committing or discarding its existing edits. The runtime still reports the base release marker; this remains a scoped live patch, not a full-main deployment or a newly declared production soak.
- An old synthetic event was rejected by live HTTP intake with `status=dropped`, `stored=false`, `reason=event_before_today`. No synthetic current event was used as upstream proof.

### Software inventory: diagnosed upstream blocker

- Administrator read-only inspection confirmed **`logs-osquery_manager.result-default` does not exist**. Elasticsearch returns `index_not_found_exception`, not a valid paginated result. No alternate OSQuery result index was found; action metadata and osquerybeat service logs do not substitute for software-result observations.
- Bounded read-only Zeek software and HTTP user-agent queries both succeeded (two successful shards, zero failures; 43 and 37 buckets in the tested one-day/100-item window). Changing page size cannot repair the absent OSQuery result dataset.
- The collector's incomplete/failure state and last complete snapshot are preserved. Restoring the scheduled upstream software-result producer is still required. No live OSQuery was issued, no empty dataset was fabricated, and completeness/freshness checks were not weakened.
- ARR workspace access, ARR-135 rotation, full-main production qualification and a 48-hour soak remain unclaimed. No credentials were rotated and no issues were created in another workspace.

### Relay activation and real-data acceptance

- Preserved the complete pre-repair Relay database at `/mnt/onion-sentinel-pcap-spool/data-flow-repair-20261008/pre-historical-outbox.sqlite3` (9,200,103,424 bytes, SQLite quick_check OK). The compact replacement removes historical/invalid outbox rows from active delivery, while the full original evidence remains in that backup. Security Onion source data and export cursor were not reset.
- Retired 938,094 historical/invalid outbox rows from the original snapshot. Preserved 140,048 seen-alert records, all dead-letter records, and 21,426 current-day outbox entries at activation, including 401 rows that arrived during reconciliation. Recovered a hot rollback journal before swapping; reset retained in-flight entries to pending for safe retry. Activation used verified file hashes and an atomic replacement.
- Receipt: `/mnt/onion-sentinel-pcap-spool/data-flow-repair-20261008/queue-retirement-receipt.json`. Relay root filesystem now uses 46%, with about 15 GiB free. Both `so-alert-poll.timer` and `so-pcap-broker.timer` are active.
- Two resumed poll cycles completed successfully, each posting 1,000 alerts and reporting `alert_relay=ok`. The first completed cycle still had 20,603 current-day pending entries: **delivery is restored, but catch-up is not finished**. This is current-day FIFO catch-up, not proof of zero ingestion latency.
- At 14:42:06 UTC, the Mac contained **2,000 real current-day alerts**, with original timestamps from 00:00:01 through 00:49:17 MDT and last receipt 08:41:36 MDT. **1,002 n8n post-commit jobs and 1,188 public-enrichment jobs had completed**; additional work remained queued. AI/incident-response jobs were pending/processing, so a completed AI investigation is not claimed. Low-severity store-only events legitimately skip AI analysis.
- Both HTTP and Relay SSH intake rejected an October 7 test event with terminal `event_before_today`. No fabricated current event was used as proof. The original admission policy remains in place.
- Store and dashboard health endpoints returned OK. Dashboard refresh generated nine report groups. Browser verification confirmed live **Last Received**, **First Received**, and **Original event time** fields. Full detail loads successfully after refreshing the report corpus; the earlier transient missing-detail response was resolved.

### Final live-traffic backup correction and deployment receipts

- The first bounded incremental backup worked while the store was online, but a heavier catch-up run exposed repeated snapshot restarts during concurrent writes: two 60-second deadlines expired. This was recorded rather than treated as success.
- Added a pinned read transaction before the online copy, preventing WAL commits from repeatedly restarting the snapshot while writers remain online. Five backup tests passed again. A new **2,287,824,896-byte snapshot containing 2,000 alerts completed under live Relay/worker traffic and passed quick_check**. Evidence: `logs/qualification/data-flow-live-backup-evidence-20261008.json`; snapshot: `logs/qualification/live-traffic-snapshot-20261008.sqlite3`.
- Final isolated repair revision: `ee47270a30d1f979e852fc29ccdec9a731500948`. Live-card timestamp patch revision: `a0f756b6475645b6ac2c9fa9cb29e0a75eb6d9f4`. Newer main-only shell features were excluded from the deployed patch; main retains those features.
- Drift-checked manifests v2, v3, and v4 have applied acknowledgements bound to request digests, exact artifact hashes, rollback revisions, and verification evidence. Each returned `noop_already_applied` after acknowledgement. V4 supersedes only the v2 backup helper. Files: `~/n8n-local/logs/qualification/data-flow-apply-20261008-v{2,3,4}.json`.
- Current Mac disk use is approximately **73%, 251 GiB available** after additional verified snapshots. The 75% admission guard remains unchanged. Backup growth still needs normal retention management; compressed archives and new qualification snapshots are retained.

### Status at repair handoff

| Item | Result |
| --- | --- |
| Historical FIFO prevents current-day delivery | Repaired; real current-day traffic and downstream jobs verified; catch-up continues |
| SQLite backup contention | Pinned online snapshot verified under concurrent traffic; bounded retries retained |
| Shadow convergence/checker OOM | Exact reconciliation passed; checker memory bounded; no outbox erase |
| Disk pressure | Relay 46%, Mac approximately 73%; recoverable evidence preserved |
| Misleading event/receipt display | Patched in reports, timelines, table, and live/mobile cards; browser verified |
| undici vulnerability | Updated to 6.29.0; deployed npm audit zero vulnerabilities |
| Software inventory | **Blocked upstream:** scheduled OSQuery result dataset absent; last complete snapshot preserved |
| ARR/Telegram rotation/full release/48-hour soak | Remain outstanding; not performed or claimed by this scoped repair |

Restoring software inventory requires restoring the scheduled OSQuery result producer on Security Onion, then rerunning the complete export. No live OSQuery or fabricated empty result index was introduced. All pre-existing repository edits remain intact.

Final maintenance verification: the already-running pre-fix attempt reached a third bounded timeout; the following retry picked up the pinned-snapshot helper and completed at **08:44:27 MDT**, with `backup_ok` and `maintenance_complete quick_check=ok`. Verified scheduled-maintenance snapshot: `~/n8n-local/alert_store_backups/alerts.sqlite3.20261008T084111-0600.backup`.

### OSQuery follow-up diagnosis — 2026-10-08, approximately 08:49 MDT

Read-only administrator SSH investigation on Security Onion 3.1.0 found a missing scheduled producer, not evidence of renamed software fields:

- Installed Osquery Manager integration is 1.25.0, installed June 9, 2026 (older 1.18.0 policy objects also exist). Endpoint Elastic Agent is 9.0.8; the Mac Studio checked in successfully during this investigation.
- The latest stored endpoint Fleet policy (`endpoints-initial`, revision 51) enables the OSQuery input but contains no configured packs/schedule. Its result/action-response streams have null query placeholders; enabling the input alone does not schedule inventory.
- All 18 saved `osquery-pack` objects are disabled. `incident-response` contains hourly `select * from apps;`, and `it-compliance` contains daily apps/Homebrew/Windows/Linux package queries, but neither pack is active or assigned to an agent policy in its saved references.
- The installed result mapping still contains `osquery.name`, `osquery.bundle_identifier`, and `osquery.bundle_short_version` as keyword fields. The result dataset is still `osquery_manager.result`; no alternative OSQuery result index/data stream exists.
- Latest stored live-query action is August 23; latest document in the legacy action-response index is August 8. These timestamps describe retained metadata, not proof of a precise failure date. Retention may explain why older result indices have disappeared, but their deletion was not proven.
- Elastic's official changelog describes 1.25.0 as schema-metadata generation, not a rename of these fields. Newer changes to scheduled-query correlation fields do not explain this export failure, which occurs because its whole result index is absent.
- Conclusion: there is presently no scheduled inventory query in the effective policy to produce fresh results. There is no evidence from this inspection proving that an update disabled a previously active pack. A narrowly scoped inventory pack assigned to the endpoint policy is the appropriate repair; enabling entire forensic packs would collect unrelated data.

No live OSQuery, policy changes, credential changes, or pack enablement were performed for this diagnostic follow-up. Reference: https://www.elastic.co/docs/reference/integrations/osquery_manager

### Software inventory restored — 2026-10-08 09:00 MDT

At the operator's explicit request, configured the supported Kibana OSQuery pack API over administrator SSH. Created `onionsentinel-software-inventory` (ID `394383ef-aca4-459f-bb0a-150922ce8ee7`) enabled and assigned only to `endpoints-initial`. Five platform-filtered queries collect macOS application name/bundle/version/path, Homebrew package metadata, Windows installed programs, and Linux DEB/RPM package metadata. The 18 existing forensic/compliance packs remain disabled. No one-off live query was issued.

Validated initially with a 60-second scheduled interval, then changed all five queries to **3600 seconds (hourly)** and confirmed that setting through the GET pack API. The request uses snapshot mode; the compiled older-agent configuration omits that explicit flag, relying on Elastic's default snapshot behavior. The initial policy revision advanced from 51 to 52 and was acknowledged by the three online Macs.

The previously missing `logs-osquery_manager.result-default` dataset now exists. Genuine results arrived from Mac Studio, Mac mini, and MacBook Air. A later check counted 1,990 result documents across those hosts; this includes repeated validation observations and is not a unique-software count. Windows/Linux queries are configured for matching agents but were not validated on online Windows/Linux hosts. Sleeping/offline endpoints will collect when they receive the policy and run the schedule.

Triggered the existing hourly OnionSentinel software-inventory collector. At **15:00:08 UTC**, it reported `status=ok`, `complete=true`, no error, and every source fresh/complete: **1,141 OSQuery application observations across three pages**, 79 Zeek software observations, and 64 HTTP-user-agent observations (**1,284 normalized records total**). These are software observations, not necessarily distinct products. Homebrew/Windows/Linux results are available in Security Onion; OnionSentinel's existing installed-software adapter currently imports the macOS apps dataset only. Existing network-derived adapters remain unchanged.

This resolves the earlier missing-OSQuery-source blocker. Verification receipt: `~/n8n-local/logs/qualification/software-inventory-restored-20261008.json`. Security Onion's owner-only before-state, API requests/responses, and result evidence are under `/root/onionsentinel-software-inventory-20261008/`. Rollback is to disable this specific pack through Kibana; no other packs or credential settings were modified. Existing release/rotation/soak limitations remain separate.

### Linux inventory verification — 2026-10-08 09:23 MDT

Both `appletv` and `LivingRoom` are checking in online and acknowledge endpoint policy revision 53 (hourly inventory). Security Onion contains 1,793 genuine DEB-package observations from `appletv`, timestamped approximately 09:09:07 MDT, including package name, version, architecture, and Ubuntu host metadata. `LivingRoom` started OSQuery at 09:10:32 MDT and accepted a configuration update at 09:11:48 MDT; no result documents were present at this check and no error appeared in its recent OSQuery logs. Its first hourly run is still unverified; healthy check-in alone is not proof of package collection. No schedule was changed or live query issued. Linux package results are in Security Onion; OnionSentinel's existing installed-software importer still only imports macOS apps, so Linux visibility in its software-inventory page is not claimed.

## Next-agent task: add Linux package support to OnionSentinel

### Requested outcome

Extend OnionSentinel's software-inventory ingestion and dashboard so installed Linux packages collected by the existing OSQuery schedule appear as installed software on their correct hosts. Security Onion already receives Linux results; the remaining gap is the exporter/importer contract and downstream presentation. Preserve the existing macOS and network-observed inventory behavior.

### Verified starting point

- Security Onion: `aj@192.168.1.7`; Mac Studio: `aj_lobster@10.77.7.201`; Relay: `aj@10.88.8.8`.
- Enabled pack: `onionsentinel-software-inventory`, ID `394383ef-aca4-459f-bb0a-150922ce8ee7`, assigned to `endpoints-initial`. All five platform-filtered queries run hourly (3600 seconds). Endpoint policy revision 53 was acknowledged by both Linux hosts.
- Linux queries already configured:
  - `linux_deb`: `SELECT name, version, arch FROM deb_packages;`
  - `linux_rpm`: `SELECT name, version, release, arch FROM rpm_packages;`
- Results land in `logs-osquery_manager.result-default`. Verified scheduled-query discriminator: `action_id = pack_onionsentinel-software-inventory_linux_deb`; RPM query is configured but a real RPM result has not been verified. Inspect actual deployed fields before relying on a newer Elastic correlation-field convention.
- At 09:23 MDT on October 8, `appletv` (Ubuntu 22.04.5) had **1,793 DEB package observations**, collected at approximately 09:09:07 MDT. Verified fields include `host.name`, `host.os.type=linux`, `host.os.platform=ubuntu`, `host.os.version`, `osquery.name`, `osquery.version`, and `osquery.arch`. Example: `accountsservice`, version `22.07.5-2ubuntu1.6`, architecture `amd64`.
- `LivingRoom` (Ubuntu 24.04.5) was online with OSQuery connected and policy revision 53, but no package results had arrived at that inspection. Recheck after its scheduled run; do not count agent check-in as inventory evidence.
- The result counts above are observations, not a claim of distinct package names or complete fleet coverage.

### Current implementation gap and entry points

Security Onion's `/usr/local/sbin/export-software-observations` currently defines installed software only as `osquery_apps`, requiring `osquery.bundle_identifier` and using `osquery.bundle_short_version`. Linux package rows lack those application fields, so they are excluded. The issue cannot be fixed by refreshing the dashboard alone or relabeling Linux rows as macOS applications.

On the Mac, inspect the source counterparts in `/Users/aj_lobster/gitProjects/OnionSentinel` and the deployed modules under `~/n8n-local/bin/`:

- `collect-software-inventory.py` and `software_inventory_workflow.py`
- `software_inventory_contract.py`, `software_inventory_validation.py`
- `software_inventory_normalization.py`, `software_inventory_record_normalization.py`
- `software_inventory_transport.py`

Trace the Relay's allowlisted software export request/response handling, the database publication path, and dashboard source/status rendering before changing the cross-host contract. Locate repository versions of the Security Onion helper and Relay code rather than editing only installed copies.

### Implementation requirements

1. Add explicit, bounded Linux DEB/RPM installed-software sources with correct dataset/query filtering and package fields. Preserve package manager, architecture, and RPM release where the normalized schema supports them; deliberately extend the schema if needed rather than silently discarding identity/version distinctions.
2. Preserve normalized stable host identity and OS metadata. Never label Linux packages as Darwin apps or network-inferred software. Distinguish installed evidence from Zeek/HTTP observations.
3. Update the Security Onion exporter, Relay allowlists/contracts, Mac validation/normalization, persistence, and dashboard together wherever their fixed source enumerations require it. Preserve bounded pagination, cursor validation, shard/completeness checks, last-good snapshot handling, and per-source freshness.
4. Define empty-source behavior correctly: a valid complete zero-result RPM query on a DEB-only fleet must not be confused with a missing index, failed shards, transport failure, or a truncated export. Do not weaken failure handling to make inventory appear green.
5. Account for repeated hourly snapshots and host/package/version/architecture identity. Do not interpret every repeated observation as a newly installed package. If absence/removal is represented, require complete host snapshot coverage before asserting uninstallation.
6. Keep the existing software-only schedule. Do not enable broad forensic packs, change credentials, or issue one-off live queries just to manufacture validation evidence.

### Acceptance and handoff evidence

- Demonstrate genuine Linux package rows from `appletv` through Security Onion export, Relay transport, Mac ingestion/database, and the software-inventory dashboard, with correct host, Linux OS, package name/version, and installed-evidence labeling.
- Recheck `LivingRoom` and report actual collection coverage separately. Verify real RPM rows if an RPM host is available; otherwise explicitly mark RPM runtime coverage unverified while testing the normalization with clearly labeled fixtures.
- Test pagination beyond 500 records (the verified DEB snapshot has 1,793 observations), duplicate/repeated snapshots, architecture/version distinctions, valid empty results, failed/incomplete export retention, and existing macOS/Zeek/HTTP regressions.
- Confirm the dashboard exposes Linux data and meaningful per-source freshness, rather than only returning successful collection metadata.
- Preserve pre-existing checkout edits and the prior scoped runtime patches. Follow the project's cross-host deployment/drift/rollback gates; do not declare a full-main deployment or production soak from this change.
- Append changed files, revisions, deployed artifact hashes, rollback locations, test results, real host/source counts, and any remaining coverage gaps to this same document.

Existing verification and rollback material remains under Security Onion `/root/onionsentinel-software-inventory-20261008/` and Mac `~/n8n-local/logs/qualification/software-inventory-restored-20261008.json`. The earlier missing-result-index blocker is resolved; Linux downstream support is the new task.

## Linux inventory implementation review — 2026-10-08

### Implemented in source, not deployed

Reviewed the complete repair log and retained all existing checkout/runtime patches.
The remaining Linux exporter/importer gap is implemented in the main checkout:

- Explicit `osquery_deb` / `osquery_rpm` sources use the fixed OSQuery result index,
  Linux OS filter and exact scheduled `action_id` discriminator. No live query,
  schedule change, credential change or new remote write was issued.
- Composite pagination now binds host, package name, version, architecture and
  RPM release. Missing release stays JSON null in Elasticsearch cursors, rather
  than being converted to an empty-string cursor that could skip buckets.
- Stable pseudonymous host references use the same hostname digest as macOS.
  Package evidence IDs include architecture and release, so repeated hourly
  observations remain stable and different architectures/releases remain distinct.
- Explicit `package_manager`, `architecture`, `package_release` metadata travels
  through exporter, Relay validation, Mac normalization, PostgreSQL and dashboard
  evidence details. DEB evidence cannot claim an RPM release. Linux records are
  installed/high-confidence and platform=linux, not Darwin apps or passive inference.
- Additive PostgreSQL migration preserves historical rows, extends the source
  constraint and adds bounded metadata columns. Schema version stays 1 because the
  extension is additive; existing macOS/network rows remain readable.
- Version-disagreement checks now compare like architectures/package managers,
  while detecting RPM release differences within the same architecture.
- Existing strict request allowlists, page-size limits, shard checks, source audit,
  original window binding, advancing/bound cursors, and last-good-state handling
  remain. A complete zero-result RPM export is empty evidence, not a failed query.
- Collection is opt-in with boolean `linux_packages_enabled`; absent/false retains
  the existing three-source collector. Existing three-source state/config files
  remain compatible. Five-source failure reports retain Linux failure status.
  The live config has **not** been changed to enable this flag.
- No installed/removed transition is inferred from these rolling observation
  snapshots. Absence alone is not evidence of uninstallation.

Changed source files:

- `security-onion/bin/export-software-observations`
- `relay/app/incident_evidence_software.py`
- `n8n/bin/software_inventory_{contract,normalization,record_normalization,state_validation,validation,workflow}.py`
- `n8n/config/software-inventory.example.json`
- `n8n/postgres/software-inventory-schema.sql`
- `n8n/alert_store/lib/postgres_software_store.js` and its test
- `onion-sentinel-dashboard/software_inventory_{state,query,os_correlation,response_projection}.py`
- `onion-sentinel-dashboard/scripts/dashboard_software_inventory_page.py`
- `tests/test_linux_software_inventory.py`, `tests/test_software_inventory_restricted_contract.py`

Changes are uncommitted; no main merge or full release was performed. Exact source
SHA-256 hashes for all 19 changed implementation/test files are in the owner-only
receipt `/Users/aj_lobster/n8n-local/logs/qualification/linux-inventory-source-20261008.json`.
These are **source artifact hashes**, not deployed Linux-support hashes. Existing
runtime rollback material and release marker were left unchanged.

### Verification

- 196 focused Python tests and 729 subtests passed, including legacy inventory
  collectors, endpoint caches, Relay contracts, queries and UI compatibility.
- Linux fixtures cover full exporter -> broker -> importer -> dashboard validation,
  1,001 rows across three pages, null release cursors, architecture/release identity,
  duplicate-page rejection, empty RPM results, failed shards, invalid metadata,
  source opt-in and version-conflict behavior. These fixtures are not real fleet data.
- Full Node alert-store suite: 563 passed.
- PostgreSQL 16 schema tested in a temporary network-disabled container: legacy
  schema -> additive migration -> idempotent repeat -> macOS/DEB/RPM metadata
  roundtrip all succeeded. The temporary container was removed; production DB
  schema was not modified.
- Module-quality gate passed (6 ratcheting warnings); database-governance and
  endpoint-response gates passed; 9 untrusted-telemetry tests passed; diff check passed.
- Broad main Python run stopped on two failures outside the inventory paths:
  `test_ai_model_routing.py::test_repo_template_assigns_approved_models_to_every_agent`
  and `test_evaluation_artifact_retention.py::test_flat_bin_clis_publish_owner_only_content_free_receipts`.
  It passed 1,668 tests before stopping. Those failures were not diagnosed or fixed
  by this Linux implementation. Do not report the whole main suite as passing.

### Remaining deployment / real-data acceptance

This session cannot repeat the other workstation's administrator access:
`ssh -o BatchMode=yes aj@10.88.8.8 hostname` rejects public-key authentication;
`ssh -o BatchMode=yes aj@192.168.1.7 hostname` times out. Credentials and SSH
restrictions were not changed. Remote deployment and fresh inspection of
`appletv` / `LivingRoom` / any RPM host are therefore unverified.

Using authorized operator access, deploy the coordinated source artifacts through
the existing drift/rollback gates. Preserve before-state and old active inventory
snapshot. Apply the PostgreSQL migration and corresponding store/dashboard code;
install the fixed exporter and Relay validator; then enable
`linux_packages_enabled=true` in the owner-only live collector config. Do not
enable the flag before both upstream contracts are ready. Do not overwrite the
other scoped live patches or use the blocked full installer as a shortcut.

Trigger the existing collector, verify a complete five-source snapshot, and prove
real DEB rows/host metadata from `appletv` through database and dashboard. Recheck
`LivingRoom` separately. RPM runtime coverage remains unverified unless a real
RPM endpoint's scheduled results are available; do not substitute fixtures as
runtime proof. Preserve last-good state and disable the feature flag if the new
collection fails; retain the additive schema rather than deleting historical rows.

### Current production observation (10:11 MDT)

Dashboard/alert-store health remained OK, with 16,865 genuine October 8 alerts
stored; newest original event was 06:29 MDT and latest receipt 10:11 MDT.
This proves current-day delivery, not real-time catch-up. Operational evaluation
still reports enrichment backlog older than 15 minutes. Capacity/catch-up review,
the two broad-suite failures, coordinated Linux deployment, real Linux coverage,
ARR access/Telegram rotation/full-release qualification and any new soak remain
outstanding. No ARR issue was marked Done.
