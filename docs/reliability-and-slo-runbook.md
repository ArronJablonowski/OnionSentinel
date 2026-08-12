# Reliability And SLO Runbook

This is the current operational reference for the production reliability
controls introduced on 2026-07-13. Older planning documents are historical
context when they disagree with this file.

## Reliability Boundaries

```mermaid
flowchart LR
  SO["Security Onion restricted export"] --> POLL["Alert poll service"]
  POLL --> OUTBOX["Relay SQLite outbox"]
  OUTBOX --> INTAKE["Mac forced SSH intake"]
  INTAKE --> STORE["alert-store /alert commit"]
  STORE --> DB["SQLite alerts and analyst state"]
  STORE --> POST["Durable n8n post-commit jobs"]
  POST --> N8N["n8n Markdown writer"]
  STORE --> JOBS["Durable AI and enrichment jobs"]
  STORE --> PCAPQ["Durable PCAP requests"]
  PCAPQ --> BROKER["Independent PCAP broker service"]
  BROKER --> SO
  BROKER --> SSD["Relay SSD spool"]
  SSD --> PARSER["Mac Zeek and TShark parser"]
  PARSER --> AI["Local AI analysis"]
```

The alert poller and PCAP broker are separate systemd jobs. A slow capture,
large rsync, or parser backlog cannot stop alert polling or five-minute
heartbeats. Public enrichment is asynchronous: `/alert` commits the alert and
a durable enrichment job before returning, while provider calls run after the
ingest transaction closes.

## Relay Services

| Unit | Schedule | Responsibility |
| --- | --- | --- |
| `so-alert-poll.service` | `so-alert-poll.timer`, every 5 minutes | Restricted export, durable outbox delivery, heartbeat. |
| `so-pcap-broker.service` | `so-pcap-broker.timer`, one minute after the prior run completes | Sample `/nsm` telemetry, claim one request, stream bounded chunks to SSD, checksum, Mac transfer, completion. |
| `so-storage-health.service` | `so-storage-health.timer`, hourly | External-mount identity, capacity, temperature, and read-only SMART health. |

The legacy combined `so-alert-relay.timer` is disabled by the current installer
and retained only for controlled rollback compatibility.

The broker outer watchdog is 3,900 seconds and the systemd start limit is 70
minutes. This deliberately exceeds two independently bounded 30-minute rsync
legs plus export/checksum overhead. Interrupted transfers retain `.part` files
and resume with `--append-verify`.

```bash
systemctl list-timers --all so-alert-poll.timer so-pcap-broker.timer so-storage-health.timer --no-pager
systemctl status so-alert-poll.service so-pcap-broker.service so-storage-health.service --no-pager
journalctl -u so-alert-poll.service -u so-pcap-broker.service -u so-storage-health.service -n 100 --no-pager
```

The runtime-only relay outbox records an alert before delivery, leases it while
a worker owns it, and marks it delivered only after a successful per-item Mac
acknowledgement. Interrupted deliveries return to pending. `alert_id` is the
idempotency key, so replay cannot create a second outbox item. A bounded SSH
batch uses a dedicated forced-command key and pinned host key; permanent
message rejection is dead-lettered without blocking healthy rows.

Security Onion export uses timestamp plus `_id` ordering and Elasticsearch
`search_after` pagination. The page size is 500, normal ceiling is 5,000, and
hard cap is 20,000. Treat `query.saturated=true` as a backlog alarm rather than
a complete successful poll.

## Durable Mac Jobs

`alert-store` owns a reusable SQLite job queue. AI analysis, public enrichment,
and n8n post-commit reports use unique `(job_type, dedupe_key)` jobs with
priorities, attempts, leases, exponential retry, and terminal states. Restarts
requeue expired leases.

Every claim receives an opaque `lease_token`. Heartbeats, completion, and
failure transitions use compare-and-set updates against that token, so a stale
worker cannot complete work after a replacement worker has recovered the
expired lease. The AI worker renews its lease every 60 seconds during legitimate
long inference and terminates its process group if ownership is lost. Enqueueing
new evidence while a job is processing sets one coalesced rerun instead of
discarding the update or creating an unbounded duplicate queue.

During rolling upgrades, any legacy `processing` row without a lease token is
recovered immediately even when its old expiry timestamp is still in the
future. A tokenless worker cannot prove ownership under the current protocol,
so waiting for that timestamp would strand work without improving safety.

```bash
curl -fsS http://127.0.0.1:8787/jobs/stats
curl -fsS http://127.0.0.1:8787/jobs/status
curl -fsS http://127.0.0.1:8787/metrics
```

The preferred alert path does not place n8n before persistence. The forced SSH
wrapper submits each item to alert-store loopback; alert-store atomically stores
the alert and queues enrichment, AI, PCAP, notification, and report intent.
After commit, the `n8n_post_commit` worker calls the committed-alert webhook.
The workflow validates the shared token and committed payload before atomically
writing one deterministic Markdown report. An n8n outage can delay reports but
cannot lose or roll back alerts.

## Bounded Runtime Resources

All network and subprocess boundaries have explicit ceilings. Alert-store
rejects request bodies over `ALERT_STORE_MAX_REQUEST_BYTES`, admits at most
`ALERT_STORE_MAX_ACTIVE_POSTS` concurrent mutation requests, and configures
header, request, keepalive, socket-request, and connection limits. Health reads
remain available during mutation saturation. The Docker compatibility proxy
has independent connect, idle, and connection limits.

Relay SSH control output, webhook responses, and PCAP-control responses are
bounded in memory. Packet bytes continue to stream directly to the relay SSD;
diagnostic stdout and stderr never share that unbounded path. Alert batching
tracks encoded bytes once per item, avoiding repeated serialization as a batch
grows. On the Mac Studio, HTTP JSON reads, scheduler output, prompt packages,
legacy SSH artifacts, Zeek/TShark output, and extracted archives all enforce
size and timeout limits before entering memory or disk.

Public enrichment uses a bounded memory L1 in front of the durable SQLite L2.
Normalized cache keys prevent casing, URL-fragment, trailing-dot, and equivalent
IPv6 forms from spending duplicate requests. Concurrent misses for one
provider/indicator are single-flight coalesced. A provider rate slot is reserved
atomically only after both cache tiers miss, preventing concurrent workers from
exceeding free-tier limits or racing cache rows.

Expired evidence is retained only for the configured stale-on-error window. It
can be returned when a provider refresh fails, but the record and provider
summary are explicitly marked `stale_cache`. Unknown zero-confidence results
use a shorter negative TTL. L1 entries, SQLite rows, and raw provider JSON are
bounded by independent entry and byte ceilings, and an hourly retention pass
prevents the cache from becoming a memory or disk exhaustion path.

The defaults and recovery-safe overrides are documented in `n8n/.env.example`
and `relay/config/config.example.json`. Increase a limit only after measuring a
valid production payload; never remove a ceiling to work around malformed input.

PCAP requests retain broker state and separate parser state:

```text
pending -> claimed -> fulfilled
analysis_status: pending -> processing -> completed | failed
```

Automatic requests coalesce on stable alert-group identity. A pending request
may be reused, but a leased request is never mutated. The parser reports to
`/pcap/analysis-status` and deletes raw broker-managed artifacts only after
validated Zeek and TShark evidence is durable.

The broker queue is intentionally serial at the relay. Critical and high work
is always preemptive. Medium, low, and informational requests receive bounded
aging: after `PCAP_PRIORITY_MAX_WAIT_SECONDS` (20 minutes by default), they are
selected oldest-first across those tiers. Fresh work remains severity ordered,
then closest-to-retention-expiry, with creation time as the final tie breaker.
This preserves urgent response while preventing a continuous medium-alert
stream from starving older low-priority packet evidence.

PCAP health treats either a fresh transfer heartbeat or a terminal request
completed within the prior three minutes as queue progress. The bounded
completion grace covers the broker timer's intentional one-minute handoff
without emitting a false failure/recovery pair. It does not hide a stopped
worker: once the grace expires, old pending work and stale claimed work become
warnings again, and the operational SLO fails when no forward progress exists.

## Dashboard Service Boundary

Dashboard generation and serving are asynchronous presentation
work, not part of alert commit, PCAP transfer, enrichment, or inference. The
supported path is:

```text
refresh-soc-dashboard.py
  -> $HOME/n8n-local/onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py
  -> $HOME/SOC Alerts Web
  -> com.arron.onion-sentinel.web on port 8766
```

The refresh worker uses a non-overlap lock. Alert-store writes live beacon JSON
to its runtime data directory and the served dashboard tree. The dedicated web
service exposes only Onion Sentinel static files and an explicit SOC API
allowlist; its admin session and password state live under `$HOME/n8n-local`.

The Hermes LAN Portal is outside Onion Sentinel's ownership boundary. Hermes
may link to `http://10.77.7.225:8766/` but must exclude Onion Sentinel from all
builder, copy, stale-cleanup, iframe, reverse-proxy, and authentication jobs.
CI guards active Onion Sentinel scripts against `$HOME/.hermes` and
`$HOME/report_portal` paths. Hermes/OpenClaw failures therefore cannot block or
alter SOC dashboard publication.

## Alert Identity

Durable work uses a v2 SHA-256 identity built from rule identity, dataset,
source, destination, destination port, and transport. Severity, routing,
suppression, triage, and analyst state are excluded because they can change
without changing the detection.

The dashboard uses legacy group IDs during the compatibility period.
`alert_group_alias` maps each legacy group to stable v2 identity. The mapping
is refreshed with every single-group summary update and backfilled at startup.

## AI Context And Model Authority

`$HOME/n8n-local/config/ai_model_settings.json` is the model-routing source of
truth; the LaunchAgent does not hardcode a model. Prompt packages include group
timeline, public enrichment, parsed PCAP evidence, analyst state, suppression or
acknowledgement reason, and bounded prior local analyses. AI workers report
`processing`, `completed`, and `failed` durable job transitions.

Local inference has a ten-minute request budget and a 4,096-token output cap.
Ollama JSON mode constrains response syntax, and the runner accepts the first
complete JSON object when a model appends harmless trailing text. Truly
malformed output still fails the durable job and remains visible in the LLM
analysis log rather than being guessed or silently discarded.

## Container Reproducibility

Compose pins n8n and PostgreSQL by immutable image digest and enables
`no-new-privileges`. The alert-store proxy is read-only except for bounded
`tmpfs`. To update: pull and inspect the intended version, record its digest,
recreate the stack, validate workflow activation and synthetic intake, and roll
back to the previous digest if any gate fails. Never use a floating `latest`
tag in production Compose.

## SLOs And Alerts

The AI worker reconciles durable `ai_analysis` queue intent against current AI,
prompt, and parsed-PCAP artifact timestamps before selecting more work. This
prevents an already-satisfied group from remaining pending indefinitely after
a duplicate alert or recovery replay re-enqueues its stable group ID.
Durable jobs preserve `last_completed_at` across later re-enqueues so health
monitoring can prove forward progress without confusing current pending state
with the absence of a prior successful run.

The scheduler carries `stable_group_id` from selection through every durable
job callback. During a rolling upgrade, alert-store also resolves a legacy
dashboard group ID through `alert_group_alias` before changing job state. This
compatibility belongs at the serialized SQLite write boundary; it prevents a
successful analysis from leaving its stable V2 queue row pending merely because
an older worker completed with the former group identifier.

PCAP requests persist `transfer_duration_seconds` from relay claim through the
terminal broker update. This includes Security Onion export, both resumable
transfer hops, checksum verification, and Mac ingest. The System Health PCAP
workflow log displays the elapsed time; legacy rows are backfilled from
`claimed_at` and `completed_at` when both timestamps are available.

| Signal | Target | Warning / action |
| --- | --- | --- |
| Relay heartbeat | Successful every 5 minutes | Critical when older than 20 minutes. |
| Alert ingest | Normal error rate 0; p95 below 500 ms | Investigate sustained errors or p95 above 1 second. |
| Enrichment jobs | Oldest pending below 15 minutes; cache remains inside configured row/byte ceilings | Inspect provider latency, keys, cache hit/miss/error counters, stale fallbacks, worker retries, and `/metrics.enrichment_cache`. |
| AI jobs | Active processing advances within 15 minutes; an idle worker does not leave the same pending work undrained for 30 minutes | Inspect PCAP evidence arrival, Ollama, LaunchAgent, leases, and failed jobs. Both the oldest pending job and the last completion must be older than 30 minutes before an idle-worker failure is raised; this prevents a new job after a quiet period from inheriting an old completion clock. An actively claimed job retains the tighter progress deadline. |
| PCAP broker | No request older than 20 minutes without fresh transfer progress or a fresh capture-protection hold | Fresh 30-second transfer heartbeats receive bounded, size-aware queue grace. Byte-level request progress takes precedence over the between-run broker summary during a long transfer. A relay `capture_protection_hold` is advisory-only for three minutes and pauses soak qualification; stale hold telemetry without transfer progress, stale claimed work, or operational failures alert normally. |
| Zeek capture loss during PCAP export | Latest worker maximum at or below the Settings-page threshold (5.0 percent by default); Zeek/Suricata local packet loss at or below 0.1 percent | When work is pending, the relay defers before claim and between chunks when telemetry is missing, stale, or above threshold. Security Onion reads and relay-to-Mac rsync are both capped at 4 MiB/s by default. Keep the timer paused if a controlled export breaches the target. |
| Relay SSD | Below 75 percent used with at least 200 GiB free | Stop new streams before spool exhaustion. |
| Relay root SD card | Below 75 percent used with at least 2 GiB free | Stop new writes, prune seven-day relay-owned evidence, and alert before the 80 percent hard ceiling. |
| Mac Studio data volume | Below 75 percent used with at least 50 GiB free after projected work | Reject new alert/enrichment writes, PCAP intake/extraction, AI work, and backups before the 80 percent hard ceiling. Heartbeats and drain/cleanup state remain available. |
| Security Onion `/nsm` | Managed by Security Onion | Report utilization as telemetry only. Onion Sentinel stages zero bytes, runs no retention writer, never deletes native captures, and does not refuse read-only PCAP exports based on disk use. |
| Relay SSD SMART | Healthy, zero media/critical errors, stable unsafe-shutdown baseline, below 70 C | Telegram failure after the configured consecutive-failure threshold; inspect disk, bridge, power, and previous-boot journal. |
| SQLite | `PRAGMA quick_check` returns `ok` | Stop writers, back up, follow DB recovery runbook. |
| SO export | `query.saturated=false` | Increase poll frequency or diagnose backlog before raising caps. |

Run `operations/verify-stack.zsh` with `PCAP_TIMER_EXPECTED_STATE=safety-hold`
when controlled transfer qualification has breached the capture-loss target and
the relay PCAP timer is intentionally disabled. The default remains `active` so
an unexplained stopped timer still fails normal deployment verification.
The verifier opens alert-store SQLite read-only and waits through bounded live
writer locks; a transient WAL commit must not be reported as corruption.

The stream manifest uses Security Onion-local signed chunk capabilities. A
normal capture rotation cannot invalidate an in-flight manifest merely because
the directory listing changed; the wrapper validates the exact authorized
source identity and rejects substitutions. A healthy run must leave
zero Onion Sentinel packet artifacts or work directories under `/nsm`.

Security Onion applies no total wall-clock limit to a healthy read. The relay
observes the growing partial file and terminates a stream only when no bytes
arrive for the configured idle interval. This permits large, slow captures to
finish without allowing an indefinitely stalled SSH process.

`/metrics` reports aggregate ingest counters and latency, durable job depth and
age, PCAP state and age, Telegram outbox state, SQLite size, and a bounded
`pipeline` snapshot. Pending PCAP age is measured from the latest request
refresh because repeated detections can update an existing group request
without creating another row. It contains no secrets or raw alert payloads.

The pipeline snapshot covers alert ingest, public enrichment, PCAP transfer,
PCAP analysis, and AI analysis. Each stage reports queued and active counts,
oldest-item age, known and unknown byte backlog, 15-minute/1-hour/24-hour input
and completion rates, pressure ratio, and count- and byte-based drain ETAs.
`eta_seconds=0` means no backlog. A null ETA with queued work means no recent
completion rate exists and must be treated as stalled or not yet measurable,
not as healthy. Unknown-size items remain explicit rather than being guessed.

Generate a content-free harness observability view from the owner-only trace
database and current SLO snapshot:

```bash
python3 "$HOME/n8n-local/bin/report-harness-observability.py"
```

The report contains aggregate status, stage and event counts; active age and
terminal/model latency; failure classes; model/provider routes; tool status and
truncation; evidence/hypothesis/decision counts; and the current queue and disk
signals. It never emits case or alert identifiers, queries, evidence values,
terminal reasons, or transcript content. Token and retry fields explicitly say
`available: false` when the selected provider/runtime did not supply durable
usage metadata; absence must not be represented as zero usage.

Disk samples are captured at most every five minutes. After sufficient history,
the snapshot reports net byte growth and a projected time to the 75-percent
start limit. It also projects utilization after the known byte backlog lands;
the SLO evaluator fails before that projection reaches 75 percent. The event
and disk-sample rows contain only stage transitions, identifiers, byte counts,
and timestamps and are pruned after seven days by default. They are operational
telemetry, not the source of truth for alert, analyst, or queue state.

The Mac Studio LaunchAgent runs `evaluate-operational-slos.py` through the
existing stateful stack monitor every five minutes. The CLI owns bounded local
probes, the pure policy modules own timestamp, capacity/recovery, threshold,
and snapshot projection, and `operational_slo_state.py` owns owner-only
state/history persistence.
It fails the monitor when
the heartbeat is older than 20 minutes, enrichment is older than 15 minutes,
an active AI claim has made no state progress for 15 minutes, an idle AI worker
has left pending work undrained with no completion for 30 minutes, a PCAP request is older
than 20 minutes without a fresh large-transfer heartbeat, recent PCAP workflow
warnings exist, ingest errors increase, runtime disk use reaches 75 percent,
or a verified backup becomes stale. The monitor sends one Telegram transition
message and one recovery message rather than repeating the same alarm every
cycle. Its runtime-only snapshot is
`$HOME/n8n-local/logs/operational-slo-snapshot.json`. A bounded 14-day history
is retained in `operational-slo-history.jsonl`; its `soak.healthy_since` clock
resets on any failed evaluation and `soak.qualified_48h` becomes true only
after 48 uninterrupted hours.

When the alert-store PostgreSQL shadow is enabled, the same five-minute
monitor performs an exact read-only SQLite/PostgreSQL reconciliation before
evaluating the SLOs. Clean-row drift fails immediately. Transactionally dirty
outbox rows receive a five-minute projection grace period, after which they
also fail. The timestamped result is stored owner-only at
`$HOME/n8n-local/logs/postgres-shadow-reconciliation.json`.

Transient local HTTP probe failures receive one bounded retry before they are
converted to a concise named probe error; persistent failures still fail the
same monitor cycle, and tracebacks are never placed in Telegram. Failure and recovery
notifications use `send-telegram-notification.py`, which reads only the two
Telegram fields from `.env` as inert data, retries transient network failures
three times, and reports only a bounded status class. The stack monitor also
runs the narrow Onion Sentinel web guard before declaring a web identity
failure, allowing a stopped or deregistered exact LaunchAgent to self-heal.

## Verified Recovery Bundles

Hourly alert-store maintenance continues to make online SQLite backups and run
`PRAGMA quick_check`. It uses a bounded busy timeout and retry window so an
ordinary alert-store write transaction cannot create a false backup outage.
Temporary backup targets from interrupted runs are removed only after they are
30 minutes old, while completed backups are promoted atomically after their own
independent `quick_check` succeeds. The hourly backup directory is owner-only
(`0700`), direct regular backup and recovery artifacts are stripped of ACLs and
normalized to `0600`, and a symlinked backup root fails the durable maintenance
transition without being followed.
A separate daily LaunchAgent creates an atomic recovery
bundle under `$HOME/n8n-local/recovery_backups` containing:

- an independently verified SQLite backup;
- an n8n PostgreSQL custom-format dump validated with `pg_restore --list`;
- when the alert-store PostgreSQL shadow is enabled, a separate custom-format
  shadow dump validated with `pg_restore --list`;
- the local `.env`, n8n encryption configuration, model/prompt configuration,
  and agent memories needed to decrypt and restore the operational runtime;
- a manifest with byte counts, SHA-256 hashes, and the alert-row count.

Recovery bundles are mode `0700` with files mode `0600`, retained for seven
days, and never copied into Git. They contain secrets and operational data, so
replicate them only to an operator-controlled encrypted backup target. A copy
on the same Mac protects against application corruption, not host or disk loss.

```bash
# Create and verify a bundle immediately.
python3 "$HOME/n8n-local/bin/backup-onion-sentinel-runtime.py"

# Inspect metadata without exposing secret-bearing archive contents.
python3 -m json.tool "$HOME/n8n-local/recovery_backups/$(ls -1 "$HOME/n8n-local/recovery_backups" | tail -1)/manifest.json"
```

The SQLite SLO is healthy when the newest hourly backup is at most two hours
old. The PostgreSQL/runtime SLO is healthy when the newest daily bundle is at
most 26 hours old. When the alert-store shadow is enabled, its dump is also
required to be no older than 26 hours; omission fails the SLO instead of
silently publishing a partial bundle.

## Production Soak

After a reliability deployment, preserve 48 continuous hours of SLO snapshots
before declaring the milestone qualified. The soak passes only when heartbeat
age remains below 20 minutes, ingest errors do not increase, durable AI and
enrichment work continues to drain, no PCAP request remains stale, both backup
SLOs remain healthy, SQLite maintenance stays green, and relay storage health
does not transition to failed. A reboot or service interruption resets the
continuous-soak clock; an expected empty PCAP or expired historical request
does not.

Generate the current acceptance report without changing production state:

```bash
python3 "$HOME/n8n-local/bin/report-production-soak.py"
```

The report requires at least 48 continuous healthy hours, no failed samples,
at least 90 percent of the expected five-minute samples, and no gap between
samples longer than 12 minutes. Before 48 hours it reports `in_progress`, not a
false pass. Runtime-only JSON and Markdown reports are written under
`$HOME/n8n-local/logs/soak-reports` and contain operational metrics rather than
alert payloads.

## Isolated Restore Drill

Run a complete restore drill against the newest recovery bundle without
stopping or writing to production:

```bash
python3 "$HOME/n8n-local/bin/run-recovery-restore-drill.py"
```

The drill verifies every manifest hash, copies and opens SQLite read-only,
runs `PRAGMA quick_check`, compares the restored alert-row count with the
manifest, and inspects the secret archive for required n8n encryption material
without extracting it. It then restores the PostgreSQL custom-format dump into
a disposable container using the exact pinned production image. The container
has `--network none`, a temporary data filesystem, no production credentials,
and is forcibly removed on success or failure. The drill passes only when the
n8n schema and workflow table are present. If the bundle contains the
alert-store shadow, the drill independently restores that dump and requires
the `onion_sentinel_queue` schema-version and durable-job tables. Its
runtime-only result is stored under `$HOME/n8n-local/logs/restore-drills`.

## Verification Baseline

The isolated 2026-07-13 ingest test used a temporary database and port, 1,000
synthetic alerts, and 50 concurrent clients. All requests returned HTTP 200 at
532.5 requests per second. Median latency was 91.7 ms, p95 was 108.5 ms,
maximum latency was 109.2 ms, and SQLite integrity returned `ok`.

An online SQLite backup was restored to a separate temporary database and
returned `quick_check=ok` with all 7,243 alert rows present at the time of the
drill. The temporary load and restore databases were removed afterward.

Repeat stress tests only against an isolated temporary database. Never insert
synthetic rows into the live alert store.

The 2026-07-14 staged-artifact qualification is retained as historical evidence,
but that data plane is retired. On 2026-07-15, failed 34 GiB exports demonstrated
that a tar plus matching work directory could consume roughly twice the request
size and pressure `/nsm`. Those artifacts were removed and the architecture was
changed to stateless per-rotation streaming. A new qualification must show zero
Onion Sentinel packet artifacts and no Onion Sentinel work directory under
`/nsm` throughout the request.

## Recovery Checks

```bash
# Mac Studio
curl -fsS http://127.0.0.1:8787/health
curl -fsS http://127.0.0.1:8787/metrics
cd "$HOME/n8n-local" && /usr/local/bin/docker compose ps
sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" 'PRAGMA quick_check;'

# Relay
systemctl is-active so-alert-poll.timer so-pcap-broker.timer so-storage-health.timer
journalctl -u so-alert-poll.service -u so-pcap-broker.service -u so-storage-health.service -n 80 --no-pager
```

Before committing, run the secret scan, alert-data checks, unit tests, and
`git diff --check`. Runtime databases, outbox files, packet artifacts, generated
reports, provider responses, and live configuration remain outside Git.

## PCAP Spool Capacity

The production relay spool is a 1 TB ext4 SSD mounted by UUID at
`/mnt/onion-sentinel-pcap-spool` with `noatime,nosuid,nodev,noexec`. The `pcap`
directory is owned by `soalert`; the filesystem root is not generally writable.
Current relay limits are 128 GiB per artifact, a 200 GiB free-space reserve, and
a 75 percent high-water mark. The Security Onion wrapper considers at most 12
time-overlapping source rotations, bounds each source to 1.1 GiB, and permits
one low-priority stream at a time. It scans each source once with a combined
tagged/untagged BPF and caps source reads at 4 MiB/s. `/nsm` utilization is
telemetry only because Onion Sentinel writes no packet artifacts on Security
Onion. Fresh Zeek capture-loss telemetry is a workload-protection gate: pending
PCAP work is deferred before claim or between chunks when the latest worker
maximum exceeds the Settings-page threshold (5 percent by default). Brief
telemetry-only gaps receive a three-minute SLO grace period; a measured threshold
breach still pauses qualification immediately. The broker timer uses a five-minute post-completion cooldown
and processes one request per invocation.
Successful checksum-verified relay artifacts are deleted only after the durable
alert-store completion acknowledgement. Retryable failures retain the relay SSD
copy, preserve transfer stage and byte progress, and use bounded exponential
backoff. The 24-hour abandoned-artifact retention remains a safety net for lost
broker state rather than the normal cleanup path.

The relay-to-Mac key is restricted by source address and a forced-command
intake wrapper. The wrapper permits only per-request directory preparation or
cleanup, inbound rsync server mode, and size/SHA-256 verification under
`$HOME/n8n-local/pcap-evidence/artifacts`. It cannot obtain a shell, select an
arbitrary destination, send files from the Mac, or enable rsync deletion.
If verification rejects a stale or corrupt destination, the relay removes only
that request directory, forces rsync checksum comparison, and retries once from
its already verified SSD copy. A second rejection remains a hard failure.

Mac archive extraction rejects traversal, links, device/FIFO entries, more
than 2,048 archive members, more than 40 GiB expanded data, or more than 256
PCAP files by default. Configure these through the placeholder-safe
`PCAP_MAX_ARCHIVE_MEMBERS`, `PCAP_MAX_EXTRACTED_BYTES`, and `PCAP_MAX_FILES`
environment variables.

Security Onion runs no Onion Sentinel retention writer. The production path is
read-only, creates no Security Onion artifact, and leaves native capture
retention to Security Onion.

## Deployment Qualification History

During the 2026-07-13 controlled reboot validation, the Raspberry Pi did not
return to ICMP or SSH and required a hard power cycle. After recovery, the OS
reached multi-user in about 9 seconds and the Sabrent USB SSD enumerated and
mounted about 29 seconds after kernel start. No undervoltage, USB reset, UAS,
I/O, or ext4 errors were present in the recovered boot. Alert polling, PCAP
processing, NTP, and the n8n heartbeat then passed.

The failed boot could not be diagnosed because the Pi had volatile journal
storage. The relay installer now retains a size-capped 14 days of journal data,
and only the PCAP worker uses `RequiresMountsFor` on the external spool. A
missing SSD cannot block alert polling. Treat unattended soft reboot as an open
deployment qualification item until at least three consecutive reboot drills
pass and `journalctl -b -1` remains available after each boot.

The relay reboot gate passed on 2026-07-14. Three consecutive unattended soft
reboots returned unique boot IDs, mounted the ext4 SSD at
`/mnt/onion-sentinel-pcap-spool`, restored the enabled `so-alert-poll.timer` and
`so-pcap-broker.timer`, and returned SMART `PASSED`. After the final boot the
first alert poll exported and durably delivered a nonzero batch with an empty
outbox, and produced a fresh successful Mac Studio health event. Keep
the legacy combined `so-alert-relay.timer` disabled; the split poll and PCAP
timers are the production units.

## Dashboard Event Stream Concurrency

The SOC alert event stream uses a short-lived, single-flight snapshot cache and
a five-second poll interval. Concurrent dashboard tabs therefore share one
SQLite/report snapshot instead of independently scanning the same runtime
state. Keep this cache bounded and invalidate the underlying API response
caches after analyst mutations.

After Onion Sentinel web-service changes, hold at least four event streams open and issue repeated
`/healthz` requests. Health must remain responsive while the streams are
connected. This check protects against a regression where long-lived browser
tabs consume all dashboard request capacity.

The desktop and mobile API-rendered alert tables preserve an explicitly open
detail only across an in-page data refresh. Expansion state is never written
to browser storage, so a fresh navigation or reload starts collapsed and
cannot resurrect stale analyst context. Responsive acceptance covers 320,
390, 768, 1024, and 1440 pixel widths with no document-level horizontal
overflow; the mobile suppression textarea remains 16 px to prevent iOS zoom.
