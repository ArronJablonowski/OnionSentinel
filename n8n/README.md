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
| `alert_store/lib/enrichment_cache.js` | Bounded L1 and durable SQLite L2 cache with normalized keys, single-flight misses, negative TTLs, and stale-on-error recovery. |
| `alert_store/lib/correlation_context.js` | Bounded observable normalization shared by alert ingestion and correlation retrieval. |
| `alert_store/lib/pipeline_metrics.js` | Bounded stage throughput, queue-age, backlog, drain-ETA, and disk-projection observability. |
| `alert_store/config/scoring_rules.json` | Tunable local filtering/scoring policy. |
| `bin/` | Local AI prompt, analysis, scheduler, rollup, and stack management scripts. |
| `bin/maintain-alert-store-sqlite.zsh` | Hourly SQLite `quick_check`, verified backup, and recovery-candidate maintenance. |
| `bin/backup-onion-sentinel-runtime.py` | Daily atomic SQLite, PostgreSQL, and secret-bearing runtime recovery bundle. |
| `bin/maintain-investigation-harness.py` | Owner-only harness trace integrity, bounded retention, WAL checkpoint, and disk-accounting pass. |
| `bin/report-production-soak.py` | Read-only 48-hour SLO coverage and acceptance reporter. |
| `bin/run-recovery-restore-drill.py` | Full SQLite and network-isolated disposable PostgreSQL restore qualification. |
| `bin/ensure-onion-sentinel-web.py` | One-minute service-identity guard that safely recovers the dedicated dashboard port, bootstraps the exact allowlisted LaunchAgent if launchd lost the job, and refuses unknown listeners. |
| `bin/send-telegram-notification.py` | Shared bounded Telegram sender that parses only allowlisted credentials as data, retries transient network failures, and emits concise status without tracebacks or secrets. |
| `bin/maintain-pcap-evidence.py` | Runtime-only PCAP artifact and derived-analysis retention helper; dry-run by default. |
| `bin/backfill-ai-correlation-context.py` | Idempotently indexes historical AI artifacts through alert-store without writing SQLite directly. |
| `bin/detection_validation.py` | Deterministic deployed-rule and packet-predicate validator; emits bounded semantics and never exposes raw payloads. |
| `bin/asset_inventory.py` | Strict time-aware asset inventory loader and exact identifier resolver. |
| `bin/collect-dhcp-asset-discovery.py` | Scheduled fixed-query DHCP identity collector with bounded truncation splitting and optional 1–30 day historical backfill. |
| `bin/collect-software-inventory.py` | Hourly, last-good snapshot collector for fixed endpoint-reported, Zeek software, and HTTP User-Agent observations through the existing restricted relay lane. |
| `bin/ac_hunter_contract.py` | Shared named-operation contract for the forced Mac-to-Relay AC Hunter transport; callers cannot supply an upstream URL, method, redirect, proxy, or TLS setting. |
| `bin/promote-dhcp-asset.py` | Explicit fingerprint-bound operator promotion of one DHCP identity with collision checks, rollback copy, validation, and atomic inventory update. |
| `bin/export-adjudicated-analysis-replays.py` | Exports append-only human adjudications into a private mode-0600 replay suite. |
| `bin/agent_memory.py` | Shared role-aware Markdown memory library with relevance retrieval, validation, locking, deduplication, and expiry. |
| `bin/manage-agent-memory.py` | Query/writeback CLI adapter for SOC Analyst, Incident Responder, SIEM Engineer, Cyber Threat Intel, and Threat Hunter workflows. |
| `bin/verify-agent-memory.py` | Read-only deployment verifier for every agent prompt, role memory, shared memory, permissions, and retrieval contract. |
| `bin/onion_sentinel_harness.py` | Disabled-by-default investigation control plane with role policy, budgets, durable state, evidence/model/tool/decision ledgers, memory gates, and a hash-chained audit trace. |
| `bin/harness_contracts.py` | Immutable job identity, secret-safe metadata, skill attestation, evidence counting, and terminal ledger-manifest contracts. |
| `bin/harness_policy.py` | Package-free harness activation, identity, capability, budget, authorization, and policy-file contracts. |
| `bin/harness_query_contract.py` | Bounded query-result counting, truncation detection, and provenance-bound per-query status resolution. |
| `bin/harness_store_foundation.py` | Owner-only SQLite connection/schema lifecycle, audit logging, event insertion, mutability, and stage-update foundation. |
| `bin/harness_store_decision_repository.py` | Evidence-bound hypothesis revision and decision ledger repository. |
| `bin/harness_store_execution_repository.py` | Atomic budget reservation and immutable model/tool-call ledgers. |
| `bin/harness_store_run_repository.py` | Atomic run creation, event/stage transitions, and evidence registration repository. |
| `config/investigation_harness_policy.json` | Safe checked-in harness policy template (`enabled: false`, `mode: shadow`); the installer preserves the operator-owned runtime copy. |
| `config/investigation_harness_policy.schema.json` | Strict JSON Schema for the versioned harness policy contract. |
| `../operations/evaluate-harness-traces.py` | Read-only integrity and aggregate-quality evaluator for the private runtime harness database. |
| `config/soc_analyst_system_prompt.md` | SOC analyst system prompt used for alert analysis. |
| `config/siem_engineer_system_prompt.md` | SIEM engineering prompt used for periodic tuning and detection recommendations. |
| `config/threat_hunter_system_prompt.md` | Threat hunter prompt used for hunt hypothesis and query recommendation work. |
| `config/cyber_threat_intel_system_prompt.md` | Cyber threat intelligence analyst prompt used for intelligence briefs, indicators, and enrichment context. |
| `config/incident_responder_system_prompt.md` | Incident responder prompt used for response planning and future host artifact collection guidance. |
| `config/*_second_opinion_prompt.md` | Independent reviewer prompts for all five Cyber Security Agent roles. Reviewers receive the same bounded evidence without the primary conclusion. |
| `config/disagreement_adjudicator_system_prompt.md` | Code-owned closed-choice shadow adjudicator policy used only after a material primary/reviewer disagreement. |
| `config/ai_model_settings.json` | Enabled Ollama/GPT CLI roster, exact per-agent primary, optional second-opinion, and optional independent adjudicator route assignments, legacy compatibility fields, and MaxMind paths. |
| `config/detection_playbooks.json` | Versioned, code-owned exact-ID validation playbooks for signature-specific discriminators and rule-drift checks. |
| `config/investigation_skills.json` | Versioned shadow-mode procedural skill registry with deterministic triggers, evidence requirements, bounded pivot plans, alternative hypotheses, stopping rules, and digest-bound selections. |
| `config/investigation_skills.schema.json` | Strict JSON Schema for the investigation skill registry and its non-bypassable learning/promotion gates. |
| `config/asset_inventory.example.json` | Empty sanitized template for the operator-owned runtime asset inventory. |
| `config/software-inventory.example.json` | Disabled-by-default configuration for the restricted Software Inventory collector. |
| `config/ac-hunter.example.json` | Disabled, non-secret Mac client configuration for AC Hunter Deep Review. Live credentials remain in a separate owner-only runtime file. |
| `agent-memory/` | Sanitized starter Markdown memory files for individual Cyber Security Agents plus shared cross-agent memory. Installed into `$HOME/n8n-local/soc-alerts/agent-memory` only if missing. |
| `launchd/` | Mac Studio LaunchAgents for stack supervision, AI jobs, PCAP parsing, and dry-run PCAP retention. |

## Install on Mac Studio

```bash
cd /path/to/OnionSentinel
release_id="$(git rev-parse --verify HEAD)"
ONION_SENTINEL_RELEASE_ID="$release_id" n8n/bin/install-macstudio-stack.zsh
```

The host-native alert-store requires Node.js 20.17 or newer. The installer
copies the committed lockfile and runs `npm ci --omit=dev`; do not replace this
with an unlocked production install. The locked `sqlite3` runtime has no known
production dependency advisories at the time of this release.

The installer validates and persists the exact release ID before deployment.
For a commit-less disaster recovery only,
`ALLOW_UNVERSIONED_RECOVERY=1 n8n/bin/install-macstudio-stack.zsh` explicitly
persists `unversioned`; redeploy an exact tested release immediately afterward.
Alert-store and both AI LaunchAgents are stopped before their mutable files are
copied and remain stopped if installation fails.

The installer creates or updates:

- `$HOME/n8n-local`
- `$HOME/Documents/SOC Alerts` symlink
- `$HOME/n8n-local/onion-sentinel-dashboard`
- `$HOME/SOC Alerts Web`
- LaunchAgents under `~/Library/LaunchAgents`

It does not overwrite an existing `$HOME/n8n-local/.env`, and it never writes
to `$HOME/.hermes` or `$HOME/report_portal`. Those paths belong to the separate
Hermes LAN Portal project.

AC Hunter Deep Review is also disabled on first install. The installer seeds
only `$HOME/n8n-local/config/ac-hunter.json`, ensures the normalized cache
directory is owner-only, and installs the shared contract and dashboard
client. It never creates or reads
`$HOME/n8n-local/config/ac-hunter-credentials.json`, never generates its
dedicated SSH key, and never enables the Relay. Follow
`../docs/ac-hunter-deep-review.md` to establish and validate that trust path.

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

The custom investigation harness is installed but intentionally disabled by
the committed policy. When an operator later enables shadow mode, it observes
the existing analysis runner without changing selected results or production
authorization. Its owner-only SQLite state records policy-bound job identity,
phase transitions, evidence provenance, requested and observed model identity,
bounded query activity, hypothesis and decision references, and memory
promotion decisions. Analysis submissions use an immutable owner-only spool;
eligible memory intent is response-bound and crash-recoverable, and cannot
cross into role/shared memory until alert-store returns a matching commit
receipt. Enforce mode is a separate production promotion and must not be
enabled until the replay, recovery, SLO, and soak gates in
`../docs/onion-sentinel-investigation-harness.md` pass.

Shadow observation never bypasses an explicit approval gate. A live endpoint
OSQuery dispatch, memory promotion, mutation, or other operational capability
denied for missing human approval remains blocked in both shadow and enforce
modes.

Per run, the policy must be enabled and both the assigned and second-opinion
routes must use ordinary Ollama or Codex CLI adapters. Selecting Hermes Agent
or OpenClaw for either route always bypasses the Onion Sentinel harness because
those providers already supply an agent harness and must not be nested.

Audit a copied or quiescent runtime trace database without contacting a model
or Security Onion:

```bash
python3 operations/evaluate-harness-traces.py \
  --db "$HOME/n8n-local/alert_store_data/investigation-harness.sqlite3" \
  --fail-on-invalid-chain
```

Daily recovery bundles include the harness SQLite database when it exists and
perform an independent logical restore check before publication. The hourly
maintenance LaunchAgent retains terminal traces for at most 30 days and 10,000
runs, applies a 2 GiB live-page budget, deletes at most 1,000 terminal runs per
pass, and never deletes an active trace. Retention is blocked unless a recent
hash-verified runtime bundle contains a restorable harness snapshot. Its
owner-only accounting report is
`logs/investigation-harness-maintenance.json`; run the helper without
`--apply` for a non-mutating preview.

Verify the complete five-agent memory contract after installation or prompt
maintenance:

```bash
$HOME/n8n-local/bin/verify-agent-memory.py
```

The command is read-only and exits nonzero if any prompt, individual memory,
shared memory, managed Markdown section, file permission, or retrieval path is
missing. This includes the primary and independent reviewer prompt for all five
roles. Agent filenames are defined once in `bin/agent_memory.py`; the query,
writeback, tests, and verifier all consume that same registry.

The active SOC Analyst reviewer is independently prompted and cannot see the
primary conclusion. After both structured responses are validated,
deterministic code compares material and advisory fields and writes reviewer
effectiveness telemetry to SQLite `ai_second_opinion_runs`. Reviewer memory is
promoted only after complete high-confidence agreement and the standard
grounding, redaction, deduplication, expiry, and size gates.

When that deterministic comparison finds a material disagreement, an optional
third route receives the two immutable positions, the exact disputed fields,
and the same bounded evidence contract. It must return one closed decision:
`primary_supported`, `reviewer_supported`, or `unresolved`. The runner permits
one response plus one schema-repair attempt, records the result in
`ai_disagreement_adjudication_runs`, and never asks the models to debate or
manufactures consensus. Adjudication is shadow-only: it cannot rewrite either
position, close or contain a case, tune a rule, or promote memory. The existing
human-review gate remains authoritative for every material disagreement.

The runner separates five verdict dimensions: event occurrence, detection
validity, activity disposition, handling, and duplicate identity. The legacy
Detection Outcome remains a deterministic compatibility projection of those
dimensions. Confidence is a numeric, calibrated score with evidence caps.
Rule-intent mismatches override an incompatible model verdict, block model-
proposed containment and suppress/drop controls, preserve the original model
claim for audit, and require human review where appropriate.

`config/detection_playbooks.json` is deployed on every install because it is
reviewed code-owned policy. `config/asset_inventory.json` is operator-owned and
is only seeded from the empty example when missing. Asset records require
offset-aware validity intervals so an address reused by another host is
resolved at the alert time. Repeating an `asset_id` with non-overlapping
validity intervals records identifier history without making old and new
addresses concurrently active. Overlapping intervals for the same asset are
rejected, overlapping claims by different assets are surfaced as conflicts,
and resolution output is capped with explicit truncation metadata. Registered
roles and expected services are context, never proof of authorization or
benignness. Owner aliases are removed from hosted/reviewer packages unless that
individual asset explicitly sets `share_with_hosted_models`.

`config/investigation_skills.json` is also deployed as reviewed code-owned
policy. The initial registry is fixed to shadow mode. Skills can advise the
model about required evidence, alternative hypotheses, confidence limits, and
bounded pivots, but cannot execute a query or activate a candidate change.
Every selected skill is projected into the prompt with registry and skill
SHA-256 digests. Candidate promotion requires replay evaluation, independent
review, and human approval.

Primary/reviewer material disagreement is persisted and shown as disputed.
Suppressing an alert or resolving an incident is blocked until an analyst
submits an append-only adjudication with outcome, confidence, rationale,
evidence gap, next action, reviewer, and (for resolution) a case-resolution
reason. The form also records the analyst-confirmed factored verdict fields;
legacy rows that lack those factors remain unlabeled rather than having labels
inferred from the compatibility outcome. Adjudication does not rewrite the
model artifact.

Run the sanitized checked-in regression suite without contacting any model or
network service:

```bash
python3 operations/evaluate-analysis-replays.py --fail-on-regression
```

On the Mac Studio, build a private production-shaped suite from the latest
append-only analyst decisions, then evaluate it from the repository:

```bash
$HOME/n8n-local/bin/export-adjudicated-analysis-replays.py
python3 operations/evaluate-analysis-replays.py \
  --fixtures "$HOME/n8n-local/soc-alerts/evaluations/adjudicated-replays.json"
```

That exported file contains live evidence, is written mode `0600`, and must
never be committed. The evaluator reports per-dimension confusion matrices,
precision/recall, dangerous dismissals, over-escalations, schema repair,
unsupported evidence references, reviewer gain, Brier score, and expected
calibration error. The checked-in BPFDoor case rebuilds deterministic
validation from a synthetic packet and deployed-rule fixture, so parser and
playbook regressions cannot pass behind a hard-coded validator result.

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
- `ENRICHMENT_CACHE_RAW_RESPONSE_MAX_BYTES=5242880` retains every provider body
  accepted by the 5 MiB bounded HTTP client. Cache rows record the response
  SHA-256, original byte count, and completeness flag.

The AI investigation loop also exposes a structured `enrichment` pivot. It
accepts only an exact public indicator already present in the alert or found in
provenance-validated investigation evidence. The harness first calls the
authenticated alert-store cache-only endpoint. It invokes the n8n
`onion-sentinel-investigation-enrichment` webhook only when one or more
configured provider entries are absent or stale. Alert-store repeats the cache
check, coalesces identical in-flight requests, and reserves each provider's
persisted rate-limit slot before outbound access. Full provider bodies remain
in the cache; model prompts receive a digest-bound bounded projection.
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

The parser traverses the complete local capture set. Zeek aggregates every
generated JSON record into bounded heavy-hitter summaries; TShark decodes every
packet in one streaming field pass per capture and retains a deterministic
representative sample instead of the first packets only. Each artifact records
file, record, packet, byte, decode, time-range, malformed-record, sampling, and
completion coverage so analysts can distinguish complete evidence from partial
parser output without loading a raw capture into memory.

That single TShark pass also builds bounded evidence summaries for every DNS
question/answer observed, every HTTP/1 or HTTP/2 User-Agent value, every TLS
handshake/supported/record version, and ICMP/ICMPv6 frames at or above the
configured abnormal-size threshold. Set `ICMP_ABNORMAL_MIN_FRAME_BYTES` only
when the environment requires a threshold other than the conservative 256-byte
default. An abnormal ICMP frame is a review signal for tunneling or C2; packet
size alone is never a malicious verdict.

Optional offline GeoIP context uses three local MaxMind `.mmdb` databases and
never sends indicators to a network service. Configure these keys in
`$HOME/n8n-local/config/ai_model_settings.json` or through the standalone
MaxMind section on the Settings page:

```text
maxmind_geoip_asn_db_path      ~/n8n-local/config/maxmind/GeoLite2-ASN.mmdb
maxmind_geoip_city_db_path     ~/n8n-local/config/maxmind/GeoLite2-City.mmdb
maxmind_geoip_country_db_path  ~/n8n-local/config/maxmind/GeoLite2-Country.mmdb
```

The legacy `maxmind_geoip_db_path` setting is accepted as a City database
during migration. Only globally routable IPs are looked up. Results are bounded
by `MAXMIND_GEOIP_MAX_LOOKUPS` (128 by default), combined into one compact
record per IP, and missing or unreadable databases remain explicit nonfatal
evidence gaps.
Install the Python reader into the private runtime directory with:

```bash
PYTHONPATH="$HOME/n8n-local/python" /usr/bin/python3 -m pip install \
  --target "$HOME/n8n-local/python" 'maxminddb>=2.6,<3'
```

Keep all `.mmdb` files out of Git. Upload or update the licensed databases only
under `$HOME/n8n-local/config/maxmind`, set the directory to `0750` and files to
`0640`, and use the Settings page to confirm all three live states. GeoIP is
approximate context and must not independently determine attribution, severity,
or blocking actions.

Zeek and TShark process packet captures as untrusted input. They run with a
stripped environment, child-only CPU/memory/file-descriptor/file-size limits,
bounded stdout/stderr, process-tree termination, and network denial through
macOS `sandbox-exec` when available. Packet-derived strings are sanitized for
control characters and remain evidence only; neither scripts nor models may
interpret them as instructions.

The investigation runtime can pivot against the private derived-evidence index
through `bin/pcap_evidence_query.py`. Each broker call accepts no more than four
requests, returns no more than 20 records per request, scans at most 4096
derived records per request, and has a 32 KiB total response budget. Supported
operations are `coverage`, `connections`, `dns`, `tls`, `http`, `files`,
`notices`, `weird`, `protocols`, `packet_facts`, `icmp_facts`, `user_agents`,
`tls_versions`, and `geoip`. The legacy names `packet_samples` and
`icmp_anomalies` remain equivalent payload-free views.

A request has this form:

```json
{
  "operation": "http",
  "filters": {
    "source_ip": "192.0.2.10",
    "destination_port": 443,
    "start_epoch": 1784916000,
    "end_epoch": 1784916300,
    "host": "service.example",
    "uri_prefix": "/api/"
  },
  "limit": 10
}
```

All comparisons are exact except the explicitly named `uri_prefix`. Common
flow filters are source, destination, or either endpoint IP; source,
destination, or either port; transport; protocol; and start/end epoch. DNS can
filter query, answer, answer type, query type, and response code. TLS can
filter SNI, version, cipher, and established state. HTTP can filter host, URI,
URI prefix, method, status, and User-Agent. File, notice, weird, packet-fact,
ICMP-fact, User-Agent, TLS-version, and GeoIP operations have similarly narrow
typed fields. `indicator` remains available only as a legacy exact scalar
match over an approved derived record.

Time-bounded queries fail closed for timeless aggregate rows. The private Zeek
index is a deterministic, bounded per-log record sample, while TShark keeps
bounded DNS, TLS, HTTP, and ICMP fact samples in addition to capture-wide
aggregates. Results identify the derived views scanned and whether either the
index scan or returned result was truncated. Every normalized request has a
SHA-256 query digest and a stable derived-evidence reference for report
citation. These samples are investigative leads and never proof of complete
capture coverage.

Unknown fields, paths, regular expressions, display/BPF filters, scripts,
parser arguments, shell text, and invalid types or ranges are rejected. The
broker never invokes Zeek, TShark, a shell, or the network. Output is projected
through operation-specific field allowlists; raw payloads and parser metadata
cannot be returned even if a private index is malformed. Hosted-model payloads
remove packet facts, follow-up results, local paths, tool metadata, and the
private query index before invocation.

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
- `ENRICHMENT_NEGATIVE_CACHE_TTL_SECONDS=21600`
- `ENRICHMENT_STALE_IF_ERROR_SECONDS=604800`
- `ENRICHMENT_VULN_STALE_IF_ERROR_SECONDS=2592000`
- `ENRICHMENT_CACHE_L1_MAX_ENTRIES=2048`
- `ENRICHMENT_CACHE_L1_TTL_SECONDS=300`
- `ENRICHMENT_CACHE_L1_MAX_BYTES=67108864`
- `ENRICHMENT_CACHE_MAX_ENTRIES=10000`
- `ENRICHMENT_CACHE_MAX_BYTES=268435456`
- `ENRICHMENT_CACHE_RAW_RESPONSE_MAX_BYTES=131072`
- `ENRICHMENT_CACHE_CLEANUP_INTERVAL_SECONDS=3600`
- `ENRICHMENT_TIMEOUT_MS=5000`
- `VIRUSTOTAL_MINIMUM_LEVEL=high`
- `URLSCAN_SUBMIT_ENABLED=false`

Provider-specific positive TTLs can be set without code changes using
`ENRICHMENT_CACHE_<SOURCE>_TTL_SECONDS`; non-alphanumeric source characters are
written as underscores. For example,
`ENRICHMENT_CACHE_VIRUSTOTAL_TTL_SECONDS=86400` and
`ENRICHMENT_CACHE_SHODAN_INTERNETDB_TTL_SECONDS=86400`.

Alert-store runtime model:

- `com.arron.soc.alert-store` runs the real Node.js alert-store on the Mac host.
- The Docker Compose `alert-store` service is only a TCP proxy so n8n workflows
  can keep using `http://alert-store:8787`.
- The host launcher parses `.env` as literal `KEY=VALUE` data and never sources
  it as shell code, so API keys containing shell metacharacters remain data.
- Do not run the SQLite-writing alert-store process inside Docker against the
  macOS bind-mounted DB. That path produced repeat `SQLITE_IOERR` and index
  corruption during summary rebuilds.
- The Onion Sentinel API sends acknowledge, suppress, and expose transitions to
  `http://127.0.0.1:8787/analyst-status`. Alert-store is the production owner
  of `analyst_alert_group_state` writes and automatically reopens an
  acknowledged group after its stored observation count increases.
- Manual PCAP requests are posted to `http://127.0.0.1:8787/pcap/request` so
  the web service does not become a second SQLite queue writer. Alert-store also
  serializes relay claim, completion, and operator requeue mutations.
- Enrichment uses a bounded in-process L1 cache in front of the durable SQLite
  L2 cache. Keys normalize provider, indicator type, domains, URLs, hashes,
  CVEs, and IPs so equivalent indicators share one record. Concurrent misses
  for the same provider and indicator are single-flight coalesced, preventing a
  burst of duplicate alerts from spending duplicate free-tier API calls.
- Only a real cache miss enters the provider queue and reserves a rate-limit
  slot. Provider rate limits and cache writes stay coherent, while unrelated
  providers run concurrently. Unknown zero-confidence responses use the shorter
  negative-result TTL so new intelligence is discovered without repeatedly
  querying providers during a burst.
- If a provider refresh fails, an expired result can be returned within the
  configured stale-on-error window. The source status and record are explicitly
  marked `stale_cache`; stale evidence never masquerades as fresh evidence.
  Provider raw responses, cache rows, total cache payload bytes, and the L1 are
  independently bounded and pruned on a timer so cache acceleration cannot
  become a disk or memory exhaustion path. The retention pass also compacts
  oversized raw responses left by older deployments while preserving their
  normalized verdict, confidence, tags, and observation timestamps. A
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
- keeps the newest 10 verified hourly backups by default, limiting the
  fast-growing SQLite snapshot tier while separate daily recovery bundles
  preserve longer disaster-recovery coverage;
- if corruption is detected, preserves the malformed DB and writes a recovered
  candidate with SQLite `.recover`;
- sends Telegram on failure and recovery transitions when
  `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are present in the runtime `.env`;
- uses the shared bounded notification helper so a Telegram timeout cannot
  execute malformed `.env` content or emit a Python traceback;
- creates a short-lived, current-user-owned web-maintenance hold during an
  authorized auto-recovery swap and uses an exit trap to restore every stopped
  runtime service if recovery is interrupted;
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

Alert-store atomically persists the latest authenticated relay broker state as
`pcap-workflow-state.json` beside its beacon files. A fresh
`capture_protection_hold` suppresses only stale *pending* queue warnings while
Security Onion capture telemetry is above threshold. It does not suppress stale
claimed work, an operational broker failure, or a silent relay; the dashboard
expires the exemption after three minutes. The operational SLO reports this as
degraded and pauses the production-soak clock without sending failure/recovery
alerts on every monitor cycle.

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

## Incident Response Evidence

Escalated cases are queued as durable `incident_response_analysis` jobs ahead
of ordinary alert analysis. Before the Incident Responder model runs,
`bin/collect-incident-evidence.py` resolves the complete duplicate group from
SQLite and sends only bounded observables and UTC windows through the dedicated
Mac-to-relay forced-command key. Runtime configuration is rendered from
`config/incident-evidence.example.json` to
`$HOME/n8n-local/config/incident-evidence.json`; collected artifacts live under
`$HOME/n8n-local/soc-alerts/incident-evidence` and are runtime data, not repo
content. New configurations use a 420-second outer transport timeout for four
sequential pivot queries plus positive and negative controls. Upgrades add that
default only when `timeout_seconds` is absent and preserve every existing
operator-selected value. The collector also carries the representative alert's
Elasticsearch backing index and document ID that the restricted alert exporter
stored outside the event `_source`. It never accepts an index or ID from model
output.

`incident-evidence.json` also selects the exact iterative-query wire contract.
An absent `investigation_query_contract` is v1. Every v1 selection validates
and atomically installs the checksum-pinned repository compatibility contract
and collector, replacing any modified or stale runtime copies, then installs
the current version-aware prompt builder and runner. The builder continues to
support blind manual reanalysis while projecting only fields accepted by v1.
V2 is installed only for the exact value
`onion-sentinel-investigation-pivots-v2`, and only after the matching Security
Onion forced-command wrapper has been installed and verified. An unknown value
aborts the Mac install; transport failures never cause an automatic downgrade.

The collector requests five immutable Elastic packs and seven immutable local
OSquery packs. Security Onion creates every baseline command; model output is
never interpreted as KQL, Query DSL, baseline OSquery SQL, an index name, a
field, a target, or a shell command. The prompt receives the bounded results
alongside the complete alert group, prior SOC analysis, enrichment, parsed
PCAP evidence, notes, and agent memories.

Every Incident Response report includes a **Security Onion Query Audit**. Each
entry must show:

1. `KQL (analyst-readable equivalent)` for quick review.
2. `Elasticsearch Query DSL (exact executed request)` for exact provenance.
3. `OSquery Command Audit` with the reviewed pack, exact SQL, target, status,
   query digest, and bounded result metadata.

Query DSL and OSquery SQL are the authoritative records of what the restricted
wrapper ran. KQL is an explanatory equivalent and is not a second executed
query. A v2 artifact additionally records the fixed per-pack index scope,
endpoint, shard metadata, execution-manifest digest, positive representative
alert control, contradictory negative filter control, and semantic-validity
state. `complete: true` is accepted only when both controls, every Elastic
query, and every fixed local OSquery pack pass; a transport success or zero-hit
response alone is insufficient.

An Incident Responder response may propose one optional live endpoint OSQuery
round. `bin/live_osquery_contract.py` validates the request before
`bin/live_osquery_client.py` crosses a dedicated forced-command relay path. The
same contract is revalidated on the relay and Security Onion. Exact endpoint
aliases, Fleet IDs, and authorization are operator controlled; wildcard
targets are forbidden. The final model call receives only bounded results plus
an auditable request/status record. See
`docs/incident-response-query-and-model-routing.md` for the exact baseline
queries, live allowlist, and enablement gates.

The lowest-level Mac collector requires a current, alias-scoped operator
approval before every live endpoint OSQuery transport, independent of the
selected provider or whether the custom harness is active. The harness also
records that decision when active. Missing, expired, or wrongly scoped approval
blocks dispatch in ordinary, shadow, enforce, Hermes, and OpenClaw paths.

The production Incident Responder route is `gpt-cli`, resolved to the local
Codex CLI with model `gpt-5.5` and `medium` reasoning. The runner searches the
configured path and standard user-local/Homebrew locations without executing
lookalike binaries. If the executable is unavailable, the case fails visibly;
it does not silently change providers or privacy boundaries.

The Settings roster exposes the fixed Codex CLI catalog `gpt-5.5`,
`gpt-5.6-sol`, `gpt-5.6-terra`, and `gpt-5.6-luna`. Each model has one
reasoning-effort selection and an independent enable switch. Only enabled exact
routes may be assigned to an agent.

Provider lanes are independent. All Ollama/local-model work shares one
host-wide inference lock; the Codex/GPT CLI worker does not acquire that lock
and can process one CLI job in parallel with one local-model job. Each durable
job keeps its assigned provider.

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

Operator escalation uses the same durable worker boundary. Alert-store accepts
`POST /incidents/escalate`, resolves the dashboard alias to the stable group,
upserts one `incident_response_cases` row, records an event, and enqueues an
`incident_response_analysis` job with role `incident-responder`. The worker
prioritizes these case jobs ahead of routine SOC analysis, renews the same
token-owned lease, and writes the result through `POST /analysis/result`.
Role-aware writeback updates the case without allowing the Incident Responder
result to replace the SOC Analyst outcome in the alerts table.

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
