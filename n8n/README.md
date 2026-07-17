# n8n, Alert-Store, and AI Analysis Node

This directory restores the Mac Studio Docker n8n stack, the Node.js alert-store service, SQLite storage, local AI analysis scripts, daily rollups, and launchd supervision.

## Files

| Path | Purpose |
| --- | --- |
| `docker-compose.yml` | Runs n8n and an `alert-store` Docker-network proxy. |
| `.env.example` | Placeholder Telegram and enrichment settings. Copy to runtime `.env`; never commit live `.env`. |
| `workflows/security-onion-configurable-scoring.workflow.json` | n8n alert intake workflow export. |
| `workflows/code/` | Reviewable JavaScript sources rendered into the alert workflow export. |
| `bin/sync-alert-intake-workflow.py` | Deterministically syncs node source and durable post-commit connections into the portable workflow JSON. |
| `bin/onion-sentinel-alert-intake.py` | Mac forced-command SSH wrapper for bounded relay batches and per-item alert-store acknowledgements. |
| `bin/install-alert-intake-authorized-key.py` | Backup-first, newline-safe installer for the dedicated forced-command relay key. |
| `ssh/authorized_keys.alert-intake.example` | Least-privilege authorized-key template for the relay alert-intake key. |
| `workflows/onion-sentinel-pcap-broker.workflow.json` | n8n PCAP broker proxy workflow export. |
| `bin/sync-pcap-broker-workflow.py` | Deterministically renders and checks the metadata-only PCAP broker proxy routes. |
| `alert_store/` | Host-native SQLite-backed alert scoring, suppression, notification, and report logic. |
| `alert_store/lib/correlation_context.js` | Bounded observable normalization shared by alert ingestion and correlation retrieval. |
| `alert_store/lib/pipeline_metrics.js` | Bounded stage throughput, queue-age, backlog, drain-ETA, and disk-projection observability. |
| `alert_store/config/scoring_rules.json` | Tunable local filtering/scoring policy. |
| `bin/` | Local AI prompt, analysis, scheduler, rollup, and stack management scripts. |
| `bin/maintain-alert-store-sqlite.zsh` | Hourly SQLite `quick_check`, verified backup, and recovery-candidate maintenance. |
| `bin/backup-onion-sentinel-runtime.py` | Daily atomic SQLite, PostgreSQL, and secret-bearing runtime recovery bundle. |
| `bin/report-production-soak.py` | Read-only 48-hour SLO coverage and acceptance reporter. |
| `bin/run-recovery-restore-drill.py` | Full SQLite and network-isolated disposable PostgreSQL restore qualification. |
| `bin/maintain-pcap-evidence.py` | Runtime-only PCAP artifact and derived-analysis retention helper; dry-run by default. |
| `bin/backfill-ai-correlation-context.py` | Idempotently indexes historical AI artifacts through alert-store without writing SQLite directly. |
| `bin/agent_memory.py` | Shared role-aware Markdown memory library with relevance retrieval, validation, locking, deduplication, and expiry. |
| `bin/manage-agent-memory.py` | Query/writeback CLI adapter for SOC Analyst, Incident Responder, SIEM Engineer, Cyber Threat Intel, and Threat Hunter workflows. |
| `bin/verify-agent-memory.py` | Read-only deployment verifier for every agent prompt, role memory, shared memory, permissions, and retrieval contract. |
| `config/soc_analyst_system_prompt.md` | SOC analyst system prompt used for alert analysis. |
| `config/siem_engineer_system_prompt.md` | SIEM engineering prompt used for periodic tuning and detection recommendations. |
| `config/threat_hunter_system_prompt.md` | Threat hunter prompt used for hunt hypothesis and query recommendation work. |
| `config/cyber_threat_intel_system_prompt.md` | Cyber threat intelligence analyst prompt used for intelligence briefs, indicators, and enrichment context. |
| `config/incident_responder_system_prompt.md` | Incident responder prompt used for response planning and future host artifact collection guidance. |
| `config/ai_model_settings.json` | Local/cloud/hybrid AI routing defaults. |
| `agent-memory/` | Sanitized starter Markdown memory files for individual Cyber Security Agents plus shared cross-agent memory. Installed into `$HOME/n8n-local/soc-alerts/agent-memory` only if missing. |
| `launchd/` | Mac Studio LaunchAgents for stack supervision, AI jobs, PCAP parsing, and dry-run PCAP retention. |

## Install on Mac Studio

```bash
cd /path/to/OnionSentinel
n8n/bin/install-macstudio-stack.zsh
```

The host-native alert-store requires Node.js 20.17 or newer. The installer
copies the committed lockfile and runs `npm ci --omit=dev`; do not replace this
with an unlocked production install. The locked `sqlite3` runtime has no known
production dependency advisories at the time of this release.

The installer creates or updates:

- `$HOME/n8n-local`
- `$HOME/Documents/SOC Alerts` symlink
- `$HOME/.hermes/scripts/build_soc_alerts_dashboard.py`
- `$HOME/report_portal/report_portal.py`
- LaunchAgents under `~/Library/LaunchAgents`

It does not overwrite an existing `$HOME/n8n-local/.env`.

Agent memory is not a replacement for SQLite analysis history or the Markdown
report corpus. The active SOC Analyst retrieves a small set of relevant role
and shared records for each alert, then may propose reusable `memory_candidates`
after a successful analysis. Deterministic code validates and atomically writes
accepted candidates. Medium/high-confidence role lessons are eligible;
cross-agent shared lessons require high confidence. Entries carry provenance,
reinforcement counts, and expiry dates, and model-observed memory is always
treated as context rather than proof.

The same memory interface is available to every agent role:

```bash
$HOME/n8n-local/bin/manage-agent-memory.py \
  --agent threat-hunter prepare --evidence-json /path/to/bounded-evidence.json

$HOME/n8n-local/bin/manage-agent-memory.py \
  --agent siem-engineer writeback \
  --response-json /path/to/agent-response.json \
  --analysis-id <analysis-id>
```

`prepare` returns the system prompt, relevant individual memory, relevant shared
memory, canonical file paths, and writeback contract as one bounded execution
package. Agent harnesses should use this operation rather than assembling those
inputs independently. `query` remains available for read-only memory inspection.

The non-SOC agent workflows remain manual/planned, but their prompts and the CLI
now use the same read/write contract so future harnesses do not create separate
memory formats.

Verify the complete five-agent memory contract after installation or prompt
maintenance:

```bash
$HOME/n8n-local/bin/verify-agent-memory.py
```

The command is read-only and exits nonzero if any prompt, individual memory,
shared memory, managed Markdown section, file permission, or retrieval path is
missing. Agent filenames are defined once in `bin/agent_memory.py`; the query,
writeback, tests, and verifier all consume that same registry.

The installer runs the verifier with `--initialize`. This idempotently creates
missing memory files or adds managed boundaries to legacy files while preserving
all operator-authored Markdown. It refuses partially malformed boundaries.

## Timestamp Format

Onion Sentinel records and displays project timestamps in the operator's local
timezone with an explicit UTC offset. Use ISO 8601 with the `T` separator
replaced by two spaces, for example:

```text
2026-07-05  21:34:40-06:00
```

Incoming UTC values from Security Onion, enrichment APIs, or older workflow
exports are normalized to this local-offset format before they are stored in
SQLite, generated reports, status JSON, and dashboard output.

## Configure Secrets

```bash
nano $HOME/n8n-local/.env
chmod 0600 $HOME/n8n-local/.env
```

Set:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `TELEGRAM_ALERT_LEVELS=critical,high`

Create an n8n variable named `RELAY_WEBHOOK_TOKEN`. Set the runtime-only
`N8N_POST_COMMIT_TOKEN` in `$HOME/n8n-local/.env` to the same value. The
committed-alert webhook reads `$vars.RELAY_WEBHOOK_TOKEN`; alert-store sends the
matching header only after the alert transaction commits. This keeps live token
material out of workflow JSON, workflow history, and execution snapshots.

## Durable Alert Intake And Report Handoff

The production ordering is:

```text
Pi outbox -> forced SSH intake -> alert-store commit -> durable n8n_post_commit job -> n8n Markdown report
```

Render and verify the workflow export before importing it:

```bash
python3 n8n/bin/sync-alert-intake-workflow.py
python3 n8n/bin/sync-alert-intake-workflow.py --check
```

The legacy `Security Onion Alert Webhook` path remains import-compatible for
rollback, but it ends at `Acknowledge Durable Alert Commit`; it must not write a
report. Only `Committed Alert Webhook -> Validate Committed Alert -> Write SOC
Markdown Report` reaches the writer. This prevents a rolling deployment from
creating reports both before and after the durable database commit.

The writer derives a deterministic filename from `committed_at` and
`report_job_id`, writes a temporary file in the destination directory, and
atomically renames it. If n8n writes the report but its response is lost, the
retry replaces that same file rather than creating another report.

Post-commit worker settings are runtime-only:

- `N8N_POST_COMMIT_URL=http://127.0.0.1:5678/webhook/onion-sentinel-committed-alert`
- `N8N_POST_COMMIT_TOKEN=<same value as the n8n RELAY_WEBHOOK_TOKEN variable>`
- `N8N_POST_COMMIT_INTERVAL_MS=5000`
- `N8N_POST_COMMIT_TIMEOUT_MS=30000`
- `N8N_POST_COMMIT_MAX_ATTEMPTS=12`
- `N8N_POST_COMMIT_BASE_RETRY_SECONDS=15`

Configure these live-only values without exposing the token in process
arguments or output:

```bash
printf '%s' "$RUNTIME_TOKEN" | python3 bin/configure-post-commit-env.py \
  --env-file "$HOME/n8n-local/.env"
```

Do not put the real token in Git or a literal shell command.

Install the dedicated relay public key with the newline-safe helper:

```bash
cat /path/to/macstudio-alert-ingest_ed25519.pub |
  "$HOME/n8n-local/bin/install-alert-intake-authorized-key.py"
```

Do not construct or append this entry with escaped `\\n` shell strings. The
helper validates one Ed25519 public key, preserves existing admin and forced
entries, creates a mode-0600 backup, and writes one real newline-delimited
record per key. The identity must be separate from admin, Security Onion, and
PCAP keys. The forced wrapper accepts only
`onion-sentinel-alert-intake batch`, limits batch bytes and item count, calls
only `127.0.0.1:8787/alert`, and returns a bounded acknowledgement per item.

Run `tests/test_alert_store_post_commit.py` before deployment. It starts an
isolated alert-store and mock n8n endpoint, proves that an n8n outage cannot
roll back alert persistence, then proves recovery and duplicate replay produce
exactly one successful report handoff.

Import `workflows/onion-sentinel-pcap-broker.workflow.json` when PCAP request
fulfillment is enabled. Create an n8n variable named `PCAP_BROKER_TOKEN` and
set it to the same value as the Pi relay `pcap_broker.token`. The broker
workflow reads `$vars.PCAP_BROKER_TOKEN`, which keeps live packet-evidence
broker secrets out of workflow JSON, workflow history, and execution snapshots.
The relay should point `pcap_broker.url` at `http://10.77.7.225:5678/webhook`,
use `requests_method: "POST"`, and map:

```json
{
  "requests": "/pcap-requests",
  "claim": "/pcap-claim",
  "progress": "/pcap/progress",
  "retry": "/pcap-retry",
  "complete": "/pcap-complete"
}
```

Run `python3 n8n/bin/sync-pcap-broker-workflow.py --check` before import. The
retry route carries only request id, failed stage, bounded error text, and retry
delay. Alert-store stores the attempt count and next-attempt timestamp; no PCAP
bytes pass through n8n.

The n8n proxy keeps alert-store private to Docker while exposing only the
relay-safe PCAP broker metadata operations to the relay VLAN. PCAP tar files
move separately through the relay SSD spool and rsync.

Parsed PCAP evidence is handled on the Mac Studio, not inside Security Onion,
the Pi relay, or Git. Install Zeek/zeek-cut and TShark on the Mac Studio and
ensure `zeek`, `zeek-cut`, and `tshark` are on `PATH` for LaunchAgents, or set
`ZEEK_BIN`, `ZEEK_CUT_BIN`, and `TSHARK_BIN` in the runtime environment. The
Mac-side worker is:

```bash
/opt/homebrew/bin/brew install zeek wireshark
```

```text
$HOME/n8n-local/bin/process-pcap-evidence.py
```

Runtime-only paths:

```text
$HOME/n8n-local/pcap-evidence/artifacts
$HOME/n8n-local/soc-alerts/pcap-analysis
```

The preferred artifact path keeps n8n as the control plane and uses the relay
as the bulk data plane. The relay asks Security Onion for a bounded export,
spools the artifact on the relay SSD, rsyncs it to
`pcap-evidence/artifacts/<request_id>/`, verifies size/SHA256 on the Mac Studio,
then completes the request through n8n/alert-store. The worker reads fulfilled
`pcap_requests`, extracts the local artifact, runs Zeek first for structured
network logs, runs TShark for protocol hierarchy/conversation corroboration,
and writes bounded JSON/Markdown summaries for the SOC Analyst prompt builder.
Raw PCAPs, extracted captures, and generated PCAP analysis artifacts must remain
out of Git.

Broker-managed raw archives are deleted from the Mac immediately after both
Zeek and TShark commands succeed and the derived JSON/Markdown files are
atomically written and reopened. A missing tool, failed parser command, partial
output, or direct/manual `--pcap` input preserves the raw file. Use
`--retain-artifact` only during controlled troubleshooting. Derived summaries
remain available to the SOC Analyst and dashboard after raw deletion.

Use `n8n/bin/maintain-pcap-evidence.py` for runtime retention. Its
`--analyzed-only --apply` mode is the five-minute safety net for a crash between
analysis publication and raw deletion. It requires validated successful Zeek
and TShark command records and refuses cleanup paths outside
`$HOME/n8n-local`. It also reconciles exact request directories associated with
terminal no-packet, expired, or oversize database outcomes. Age-based cleanup
remains dry-run unless explicitly applied.

`launchd/com.arron.soc.pcap-retention.plist` installs a five-minute
analyzed-only cleanup. It cannot delete an unparsed or partially parsed request.

Mac disk-heavy jobs share `bin/disk_capacity.py`. New PCAP intake, archive
extraction, AI analysis, and runtime backups stop at 75 percent projected use
or when the 50 GiB reserve would be consumed. The hard operational ceiling is
80 percent. Restricted PCAP intake records the expected artifact size before
rsync and rechecks remaining capacity on every retry. A failed size/SHA-256
verification triggers cleanup of only that request directory and one fresh
checksum-forced retry from the relay's verified SSD copy.

Alert-store applies the same policy at the new-write boundary. `/alert` and
`/enrich` return HTTP 507 before a write can consume the reserve. Relay
heartbeats remain accepted, while analysis, PCAP completion, and cleanup state
can still be recorded so the system can drain safely.

Optional enrichment keys are also set in `$HOME/n8n-local/.env`. Blank or
placeholder values are treated as disabled, so a source can be enabled or
rotated by editing `.env` and restarting `alert-store`.

| Source | Environment variable | Notes |
| --- | --- | --- |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP reputation; free accounts are commonly limited to 1,000 checks/day. |
| GreyNoise | `GREYNOISE_API_KEY` | Internet scanner/noise context; cache aggressively. |
| Shodan InternetDB | none | Keyless public IP exposure context; throttled locally. |
| OTX | `OTX_API_KEY` | IP/domain/URL/hash pulse context. |
| URLhaus | `URLHAUS_AUTH_KEY` | Malware URL lookups; URLs are redacted before submission. |
| VirusTotal | `VIRUSTOTAL_API_KEY` | High/critical only by default; throttled to 4 requests/minute. |
| urlscan.io | `URLSCAN_API_KEY` | Search-only by default; active URL submission remains disabled unless `URLSCAN_SUBMIT_ENABLED=true`. |
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_API_KEY` | Public redacted URL checks. |
| PhishTank | `PHISHTANK_API_KEY` | Public redacted URL phishing checks. |
| MalwareBazaar | `MALWAREBAZAAR_AUTH_KEY` | Hash lookups only; no file downloads. |
| ThreatFox | `THREATFOX_AUTH_KEY` | IOC lookups for domains, hashes, and C2 indicators. |
| Shodan | `SHODAN_API_KEY` | Authenticated host API; separate from keyless InternetDB. |
| Censys | `CENSYS_API_TOKEN` or `CENSYS_API_ID` + `CENSYS_API_SECRET` | Authenticated exposed-service IP context. Personal Access Tokens use the Censys Platform API; set optional `CENSYS_ORGANIZATION_ID` when your account requires an organization header. |

Censys Platform HTTP `422` responses with `insufficient balance` mean the PAT
was accepted but the selected account has no lookup credits. Onion Sentinel
records the provider error and its per-provider circuit contains retries; alert
ingestion, other enrichment providers, and AI analysis continue independently.
| CISA KEV | none | Public CVE catalog; cached with vulnerability TTL. |
| EPSS | none | Public CVE exploit probability; cached with vulnerability TTL. |
| NVD | `NVD_API_KEY` optional | CVE metadata; key raises NVD's allowed request rate. |

Enrichment behavior knobs:

- `ENRICHMENT_CACHE_TTL_SECONDS=86400`
- `ENRICHMENT_VULN_CACHE_TTL_SECONDS=86400`
- `ENRICHMENT_TIMEOUT_MS=5000`
- `VIRUSTOTAL_MINIMUM_LEVEL=high`
- `URLSCAN_SUBMIT_ENABLED=false`

Alert-store runtime model:

- `com.arron.soc.alert-store` runs the real Node.js alert-store on the Mac host.
- The Docker Compose `alert-store` service is only a TCP proxy so n8n workflows
  can keep using `http://alert-store:8787`.
- The host launcher parses `.env` as literal `KEY=VALUE` data and never sources
  it as shell code, so API keys containing shell metacharacters remain data.
- Do not run the SQLite-writing alert-store process inside Docker against the
  macOS bind-mounted DB. That path produced repeat `SQLITE_IOERR` and index
  corruption during summary rebuilds.
- The LAN portal sends acknowledge, suppress, and expose transitions to
  `http://127.0.0.1:8787/analyst-status`. Alert-store is the production owner
  of `analyst_alert_group_state` writes and automatically reopens an
  acknowledged group after its stored observation count increases.
- Manual PCAP requests are posted to `http://127.0.0.1:8787/pcap/request` so
  the portal does not become a second SQLite queue writer. Alert-store also
  serializes relay claim, completion, and operator requeue mutations.
- Enrichment uses one serialized queue per provider. Provider rate limits and
  cache writes stay coherent, while unrelated providers run concurrently. A
  three-failure circuit opens for 60 seconds by default so one unhealthy API
  cannot hold the rest of the enrichment pipeline. No enrichment network call
  holds the SQLite ingest write gate.

Enrichment scheduler safety knobs:

- `ENRICHMENT_CIRCUIT_FAILURE_THRESHOLD=3`
- `ENRICHMENT_CIRCUIT_RESET_MS=60000`
- Eligible Telegram notifications are committed to `notification_outbox` in
  the same SQLite transaction as their alert. A background worker delivers up
  to ten due messages per pass with bounded exponential backoff and records
  terminal failures after the configured attempt limit. `/health` exposes
  outbox counts without message contents or credentials.

Telegram outbox safety knobs:

- `TELEGRAM_OUTBOX_INTERVAL_MS=15000`
- `TELEGRAM_OUTBOX_BASE_RETRY_SECONDS=30`
- `TELEGRAM_OUTBOX_MAX_RETRY_SECONDS=3600`
- `TELEGRAM_OUTBOX_MAX_ATTEMPTS=8`

The outbox worker is intentionally independent of alert ingestion. Telegram
timeouts cannot roll back a committed alert or make n8n replay it. Restarting
alert-store resumes due outbox rows from SQLite.

Alert-store ingestion safety knob:

- `ALERT_STORE_MAX_REQUEST_BYTES=10485760`
- `ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS=30000`
- `ALERT_STORE_SQLITE_JOURNAL_MODE=DELETE`
- `ALERT_STORE_SQLITE_SYNCHRONOUS=FULL`
- `ALERT_STORE_SQLITE_TEMP_STORE=DEFAULT`
- `PIPELINE_EVENT_RETENTION_HOURS=168`
- `PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS=300`

`ALERT_STORE_MAX_REQUEST_BYTES` caps each `/alert` and `/enrich` POST body
before Node buffers it in memory. Keep it high enough for full-fidelity Security
Onion alert JSON, but low enough that a malformed relay/n8n request cannot
consume unbounded memory during a spike.

The SQLite knobs give write-contention windows time to clear and keep durability
behavior explicit. Use `DELETE` journaling with `FULL` synchronous writes for
the Mac Studio host-native alert-store database. `WAL` is not safe on the old
Docker Desktop bind-mounted writer path because it can produce `SQLITE_IOERR`
restart loops. Dashboard builders should open the database read-only, and write
paths should use the same busy timeout.

Pipeline observability records compact transition rows instead of copying alert
payloads. `/metrics` derives 15-minute, 1-hour, and 24-hour rates; queue ages;
known and unknown byte backlog; drain ETAs; and projected disk pressure from
those rows plus current durable queue state. Retention is bounded by
`PIPELINE_EVENT_RETENTION_HOURS`. Disk sampling is rate-limited by
`PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS` so health polling cannot create a write
storm. A null ETA while work is queued means the stage has no usable recent
completion rate; operators and monitors must not interpret it as zero delay.

## SQLite Durability Maintenance

The Mac Studio installer deploys `com.arron.soc.alert-store-maintenance`, which
runs hourly and executes:

```text
$HOME/n8n-local/bin/maintain-alert-store-sqlite.zsh
```

The maintenance job:

- runs `PRAGMA quick_check` against the live alert-store DB;
- verifies `alert_group_summary` still matches the raw `alerts` table and calls
  the local alert-store `/refresh-groups` repair endpoint if grouped state is
  stale;
- creates a verified SQLite `.backup` copy under
  `$HOME/n8n-local/alert_store_backups`;
- waits through normal writer contention with a 60-second SQLite busy timeout
  and bounded backup retries instead of treating a transient lock as database
  corruption;
- removes abandoned `.backup.tmp` files only after they are 30 minutes old and
  atomically promotes a temporary backup only after its own `quick_check`;
- keeps the newest 48 verified backups by default;
- if corruption is detected, preserves the malformed DB and writes a recovered
  candidate with SQLite `.recover`;
- sends Telegram on failure and recovery transitions when
  `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are present in the runtime `.env`;
- does not swap a recovered DB into production unless
  `ALERT_STORE_AUTO_RECOVER=1` is explicitly set for that run.

Manual run:

```bash
$HOME/n8n-local/bin/maintain-alert-store-sqlite.zsh
tail -80 "$HOME/n8n-local/logs/alert-store-sqlite-maintenance.log"
```

AI queue diagnostics:

```bash
$HOME/n8n-local/bin/check-ai-queue-consistency.py
$HOME/n8n-local/bin/check-ai-queue-consistency.py --json
```

The diagnostic checks SQLite `quick_check`, grouped-summary drift, invalid
filter states, stale AI prompt packages, and orphan prompt packages. It is
read-only by default. Use `--delete-resolved-prompts` or
`--delete-orphan-prompts` only during deliberate cleanup.

PCAP request broker safety knobs:

- `PCAP_REQUEST_DEFAULT_WINDOW_SECONDS=120`
- `PCAP_REQUEST_MAX_WINDOW_SECONDS=300`
- `PCAP_CLAIM_LEASE_SECONDS=1800`
- `PCAP_PRIORITY_MAX_WAIT_SECONDS=1200`
- `PCAP_AUTO_REQUEST_LEVELS=critical,high,medium,low,informational`

`PCAP_REQUEST_MAX_WINDOW_SECONDS` caps the requested packet window before any
Security Onion export occurs. PCAP artifacts are transferred out-of-band by the
relay SSD spool and rsync; alert-store no longer accepts inline PCAP blobs or
artifact chunks through n8n.
`PCAP_CLAIM_LEASE_SECONDS` controls when alert-store requeues interrupted
relay claims so stale `claimed` rows do not strand PCAP work forever.

`PCAP_AUTO_REQUEST_LEVELS` controls server-side automatic PCAP request
creation during `/alert` ingest. The production default queues PCAP evidence
for every newly stored, non-suppressed alert with a known triage level. Pending
work coalesces by stable alert-group identity and is selected
with critical and high requests always preemptive. Medium, low, and
informational requests older than `PCAP_PRIORITY_MAX_WAIT_SECONDS` switch to
oldest-first selection, preventing continuous medium traffic from starving
older captures. Fresh work remains severity ordered, then retention ordered.
Set `PCAP_AUTO_REQUEST_LEVELS` to an empty value during maintenance to disable
auto-queueing without changing dashboard/manual request behavior.

PCAP bytes are not posted through n8n. The broker workflow is metadata-only:
it accepts requests, lets the relay claim work, and records completion
metadata after the relay moves artifacts through the SSD spool and restricted
rsync path. Keep this separation so a large packet archive cannot overload the
n8n webhook or alert-store JSON parser.

System Health separates PCAP broker conditions into operational warnings and
diagnostic counters. Stale pending/claimed requests and unexpected failures
raise `warning_count`; valid negative evidence (`no matching packets found`)
and legacy empty-output wrapper failures are counted separately. Transfer
failures should be resolved in the relay SSD spool, restricted SSH wrapper, or
rsync path, not by reintroducing inline artifact uploads through n8n.

If the live n8n PCAP broker workflow is edited through a database restore or
manual import, confirm the active workflow version contains the same node
parameters as `workflows/onion-sentinel-pcap-broker.workflow.json`. A stale
active workflow history row can make `/pcap-requests` ignore its requested
`status=pending` filter even when the workflow entity looks correct. Re-save
and activate the workflow in n8n, or restore the active workflow history from
the current workflow entity during a controlled maintenance window.

PCAP request state is stored in alert-store SQLite. Alert-store queues,
validates, claims, and records fulfillment metadata through:

- `POST /pcap/request`
- `GET /pcap/requests?status=pending`
- `POST /pcap/claim`
- `POST /pcap/progress` (proxied as `/webhook/pcap/progress`)
- `POST /pcap/retry` (proxied as `/webhook/pcap-retry`)
- `POST /pcap/complete`

Alert-store never connects directly to Security Onion and never shells out for
packet capture. Fulfillment is brokered through the relay and the restricted
Security Onion wrapper.

Once a fulfilled capture is copied to the Mac Studio runtime evidence directory,
`process-pcap-evidence.py` converts it into LLM-safe artifacts:

```bash
$HOME/n8n-local/bin/process-pcap-evidence.py --request-id <request_id>
```

The local AI prompt builder automatically includes matching parsed PCAP evidence
from `$HOME/n8n-local/soc-alerts/pcap-analysis` when analyzing the alert. If the
broker metadata exists but the artifact has not been copied to the Mac yet, the
prompt records that as an evidence gap rather than inventing packet contents.

Before extraction, the parser rejects path traversal, links, device entries,
more than `PCAP_MAX_ARCHIVE_MEMBERS`, more than `PCAP_MAX_EXTRACTED_BYTES` of
expanded regular files, or more than `PCAP_MAX_FILES` packet files. The
sanitized `.env.example` defaults are 2,048 members, 40 GiB expanded, and 256
PCAP files. Keep these limits aligned with the relay and Mac storage budgets.

Alert-store exposes a request-only broker for packet-capture evidence:

```text
POST /pcap/request
GET /pcap/requests?status=pending&limit=25
```

`POST /pcap/request` validates and queues a bounded request in SQLite. It never
contacts Security Onion and never runs shell commands. The request must include
a reason and enough tuple/timing information to identify the flow, or an
existing `alert_id`/`group_id` that alert-store can resolve from SQLite. The
relay/Security Onion fulfillment path is intentionally separate and should use
a dedicated forced-command SSH wrapper with its own time-window and size limits.

Example request body:

```json
{
  "group_id": "example-group-id",
  "requested_by": "soc-analyst",
  "reason": "Packet headers would confirm whether this repeated TLS alert is one flow or many short sessions.",
  "max_window_seconds": 120
}
```

The preferred forced-SSH intake submits directly to alert-store. Alert-store
atomically stores the alert and a durable enrichment job before acknowledging
the relay. The legacy n8n rollback route retains an `Enrich Alert` marker before
its own `POST /alert`, but it is not the production commit boundary. A
background worker then extracts only public
indicators, redacts URL query strings and credentials, skips private
IPs/internal hostnames, checks configured sources, writes normalized records
into `alerts.enrichment_json`, and caches results in SQLite. Provider latency
does not hold the alert ingest transaction open.

Indicator extraction covers public IPv4s, domains, full URLs/URIs, file hashes,
and CVEs from common ECS, Suricata, and Security Onion raw-event shapes. Local
DNS traffic is still enriched when the queried DNS name is public; the local
source host and local resolver IP are skipped, but fields such as
`dns.question.name`, Suricata `dns.rrname`/`dns.query`, TLS SNI, HTTP host,
URL fields, and related host fields can produce public domain/URL lookups.
Existing enrichment provider responses are intentionally ignored during
extraction so refresh jobs do not submit indicators found only inside previous
third-party `raw_response` payloads.

To retroactively enrich rows stored before the dedicated enrichment stage, run
the backfill utility against the host-native alert-store. Start with a dry run
or small limit, confirm SQLite integrity, then run larger batches:

```bash
cd $HOME/n8n-local
PATH="/opt/homebrew/bin:$PATH" BACKFILL_DRY_RUN=1 BACKFILL_LIMIT=25 ALERT_STORE_DB="$HOME/n8n-local/alert_store_data/alerts.sqlite3" ALERT_STORE_ENRICH_URL="http://127.0.0.1:8787/enrich" node "$HOME/n8n-local/bin/backfill-public-enrichment.js"
PATH="/opt/homebrew/bin:$PATH" BACKFILL_LIMIT=250 ALERT_STORE_DB="$HOME/n8n-local/alert_store_data/alerts.sqlite3" ALERT_STORE_ENRICH_URL="http://127.0.0.1:8787/enrich" node "$HOME/n8n-local/bin/backfill-public-enrichment.js"
sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "PRAGMA quick_check;"
```

The backfill uses the same `/enrich` endpoint, API-key gating, cache, privacy
filters, and rate-limit handling as live workflow ingestion.

## Validate

```bash
cd $HOME/n8n-local
/usr/local/bin/docker compose ps
curl -fsS http://127.0.0.1:5678/healthz
curl -fsS http://127.0.0.1:8787/health
/usr/local/bin/docker exec n8n node -e 'fetch("http://alert-store:8787/health").then(r=>r.text()).then(console.log)'
```

## AI Analysis

The scheduler picks unanalyzed grouped alerts by severity first, newest first within each severity:

1. Critical
2. High
3. Medium
4. Low
5. Informational

Durable AI work is keyed by `stable_group_id`. The scheduler preserves that
identity in its selected row and uses it for `processing`, `completed`, and
`failed` callbacks. Alert-store accepts legacy dashboard group IDs during a
rolling upgrade by resolving `alert_group_alias` before updating the stable
queue row; new workers must always send the stable ID directly.

Run a dry check:

```bash
$HOME/n8n-local/bin/auto-run-ai-analysis.py --dry-run
```

Artifacts:

- prompts: `$HOME/n8n-local/soc-alerts/ai-prompts`
- analysis JSON/Markdown: `$HOME/n8n-local/soc-alerts/ai-analysis`
- daily rollups: `$HOME/n8n-local/soc-alerts/daily-rollups`

The prompt builder retrieves a bounded set of cross-alert correlation
candidates from `alert_observables`. Strong shared facts and temporal proximity
rank above common ports, protocols, datasets, and rule names. Prior model
assessments are included only as hypotheses that the current run must validate
against current evidence.

Completed runs are indexed through alert-store's idempotent
`POST /analysis/result` endpoint. The AI worker does not write SQLite. If that
endpoint is temporarily unavailable after a successful inference, a compact
pending payload is retained under
`$HOME/n8n-local/soc-alerts/llm-analysis-logs/analysis-index-pending` and retried
before the next model call.

After restoring historical AI artifacts, dry-run and then apply the correlation
history backfill:

```bash
$HOME/n8n-local/bin/backfill-ai-correlation-context.py --dry-run
$HOME/n8n-local/bin/backfill-ai-correlation-context.py
```

The backfill is idempotent by `analysis_id`. Artifacts whose source alert has
aged out of the operational database are reported as skipped because no trusted
stable group identity remains to attach them to.
