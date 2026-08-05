# Disaster Recovery Runbook

Use this when the Pi SD card fails, the Mac Studio n8n stack breaks, or the Security Onion relay wrapper needs to be recreated.

## Assumptions

```text
Security Onion: aj@192.168.1.7
Pi relay: <relay_user>@10.88.8.8
Mac Studio: <mac_user>@10.77.7.225
Pi relay VLAN: 888 / 10.88.8.0/24
Pi relay IP: 10.88.8.8
```

## Recovery Priority

1. Restore network reachability.
2. Restore or upgrade the Security Onion export wrapper.
3. Restore or upgrade Mac Studio n8n and alert-store.
4. Restore Pi relay.
5. Run end-to-end tests.

The section numbers below group host-specific instructions; they do not change
that execution order. Deploy the Security Onion wrapper before Mac code because
the newer wrapper accepts legacy requests, while newer Mac query packs or
constraints may be rejected by an older wrapper. Roll back in the reverse
order: Mac first, then Security Onion.

## 1. Network Checklist

pfSense VLAN 888 should allow:

```text
admin Mac or admin network -> 10.88.8.8 TCP/22
10.88.8.8 -> 192.168.1.7 TCP/22
10.88.8.8 -> 10.77.7.225 TCP/22 for forced alert intake and artifact transport
10.88.8.8 -> 10.77.7.225 TCP/5678 for PCAP control metadata and emergency rollback
10.88.8.8 -> DNS TCP/UDP 53
10.88.8.8 -> NTP UDP/123, preferably to the VLAN-local firewall/NTP service
temporary: 10.88.8.8 -> Internet UDP/123 until VLAN-local NTP is ready
10.88.8.8 -> api.telegram.org TCP/443
```

Keep broad Internet access disabled except during update windows.

After restoring the relay, pin `systemd-timesyncd` to the VLAN-local NTP
service using `relay/systemd/onion-sentinel-relay-vlan-timesyncd.conf.example`.
If the VLAN-local NTP service is not ready, use
`relay/systemd/onion-sentinel-relay-internet-timesyncd.conf.example` as a
temporary drop-in and allow only `10.88.8.8` to reach Internet UDP/123.
Confirm `timedatectl status` reports `System clock synchronized: yes` and
`timedatectl timesync-status` shows `Packet count` greater than `0`.

## 2. Restore Mac Studio n8n

On the Mac Studio:

```bash
cd /path/to/OnionSentinel
release_id="$(git rev-parse --verify HEAD)"
ONION_SENTINEL_RELEASE_ID="$release_id" ./n8n/bin/install-macstudio-stack.zsh
```

The installer requires Homebrew Node.js 20.17 or newer and restores the
alert-store dependency tree with the committed `package-lock.json` via
`npm ci --omit=dev`. Treat a Node version-gate or lockfile failure as a blocked
restore; do not fall back to an unlocked `npm install`.

The explicit release ID is non-secret and is persisted as the dedicated
`ONION_SENTINEL_RELEASE_ID` entry in the live `.env` without rewriting any
other key. Incident reanalysis runs store that exact release so accuracy
changes can be compared to the code that produced them. A production
deployment without an exact release ID is incomplete. The installer validates
the release before changing the runtime or stopping services.

Only when a disaster-recovery checkout has no recoverable release identifier,
use the explicit escape hatch:

```bash
ALLOW_UNVERSIONED_RECOVERY=1 ./n8n/bin/install-macstudio-stack.zsh
```

That exact value persists `ONION_SENTINEL_RELEASE_ID=unversioned` and emits a
warning. No other missing-release bypass is accepted. Use it only to restore
service, then redeploy promptly with an exact tested release ID.

Before copying mutable alert-store or AI runtime code, the installer stops only
the alert-store and the Ollama and Codex AI LaunchAgents. Other LaunchAgents
remain undisturbed until the final reload phase. If validation, copying,
dependency installation, Docker startup, or LaunchAgent reload fails, those
three code consumers remain stopped; correct the failure and rerun the installer
successfully rather than starting a partially updated runtime.

Create the SOC report directory used by n8n and expose it through the
Obsidian-facing Documents path:

```bash
mkdir -p $HOME/n8n-local/soc-alerts
if [ -d "$HOME/Documents/SOC Alerts" ] && [ ! -L "$HOME/Documents/SOC Alerts" ] && [ -z "$(ls -A "$HOME/Documents/SOC Alerts")" ]; then
  rmdir "$HOME/Documents/SOC Alerts"
fi
if [ ! -e "$HOME/Documents/SOC Alerts" ]; then
  ln -s $HOME/n8n-local/soc-alerts "$HOME/Documents/SOC Alerts"
fi
```

This keeps Docker's bind mount inside `$HOME/n8n-local` while preserving the
operator-friendly `$HOME/Documents/SOC Alerts` path. Hermes does not read or
publish this corpus as part of Onion Sentinel.

Edit:

```text
$HOME/n8n-local/.env
```

Required values:

```text
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
```

After editing `.env`, restart the host-native alert-store and recreate the
Docker-network proxy:

```bash
cd $HOME/n8n-local
launchctl kickstart -k gui/$(id -u)/com.arron.soc.alert-store
/usr/local/bin/docker compose up -d --force-recreate alert-store
```

Validate both the host service and Docker-network proxy:

```bash
curl -fsS http://127.0.0.1:8787/health
/usr/local/bin/docker exec n8n node -e 'fetch("http://alert-store:8787/health").then(r=>r.text()).then(console.log)'
```

### Restore the durable alert commit boundary

Render and validate the portable workflow before importing it:

```bash
cd /path/to/OnionSentinel
python3 n8n/bin/sync-alert-intake-workflow.py
python3 n8n/bin/sync-alert-intake-workflow.py --check
```

Import and activate
`n8n/workflows/security-onion-configurable-scoring.workflow.json`. Confirm the
active workflow has both entry paths:

```text
Security Onion Alert Webhook -> ... -> Acknowledge Durable Alert Commit
Committed Alert Webhook -> Validate Committed Alert -> Write SOC Markdown Report
```

The first path is rollback compatibility and must not reach the Markdown
writer. The second path is the only report-writing path.

Create the n8n variable `RELAY_WEBHOOK_TOKEN`. Store the same value only in the
Mac runtime `.env` as `N8N_POST_COMMIT_TOKEN`; do not put it in Git, shell
history, workflow JSON, or command-line arguments. Configure:

```text
N8N_POST_COMMIT_URL=http://127.0.0.1:5678/webhook/onion-sentinel-committed-alert
N8N_POST_COMMIT_INTERVAL_MS=5000
N8N_POST_COMMIT_TIMEOUT_MS=30000
N8N_POST_COMMIT_MAX_ATTEMPTS=12
N8N_POST_COMMIT_BASE_RETRY_SECONDS=15
```

The installer places the forced wrapper at
`$HOME/n8n-local/bin/onion-sentinel-alert-intake.py`. Install the relay's
dedicated public key with:

```bash
ssh <relay_user>@10.88.8.8 \\
  'sudo cat /opt/so-alert-relay/keys/macstudio-alert-ingest_ed25519.pub' |
  "$HOME/n8n-local/bin/install-alert-intake-authorized-key.py"
```

The helper creates a mode-0600 backup, preserves unrelated entries, and writes
real newline-delimited records. Never build this file with escaped `\\n` shell
strings. Verify the source restriction is `10.88.8.8` and that shell, PTY, rc,
forwarding, and X11 access are denied.

On the relay, pin the verified Mac ED25519 host key in
`/opt/so-alert-relay/keys/macstudio_known_hosts` and enable `alert_ingest` in
`config.json`. Do not use blind trust-on-first-use or
`StrictHostKeyChecking=no`.

Qualify the path with a synthetic TEST-NET alert before live traffic:

1. Submit the same bounded batch twice and confirm one alert row and one report.
2. Stop n8n, submit another synthetic alert, and confirm the alert commits while
   `n8n_post_commit` remains pending.
3. Restart n8n and confirm the job completes and one deterministic report exists.
4. Submit one malformed and one valid item together; confirm only the malformed
   item is dead-lettered and the valid item is acknowledged.
5. Confirm `PRAGMA quick_check`, `/jobs/stats`, `/metrics`, and the relay timer.

Rollback is transport-only: disable `alert_ingest`, enable the legacy webhook,
and keep the active workflow's legacy branch ending at the acknowledgement
node. Never route both branches to the report writer.

The first host-native alert-store startup after restoring current source creates
the additive observable, AI-analysis-history, and correlation tables. It also
atomically indexes retained alerts that do not yet have observables. Confirm the
tables exist without printing live alert content:

```bash
sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" \
  "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('alert_observables','ai_analysis_runs','alert_correlations') ORDER BY name;"
```

If historical local-AI artifacts were restored, index their compact analysis
history through alert-store after the service is healthy:

```bash
$HOME/n8n-local/bin/backfill-ai-correlation-context.py --dry-run
$HOME/n8n-local/bin/backfill-ai-correlation-context.py
```

Do not import those artifacts with direct SQLite statements. The endpoint
resolves the trusted stable group identity, performs idempotent upserts, and
skips artifacts whose operational alert row has already aged out.

If `TELEGRAM_CHAT_ID=unset`, alert-store can be healthy and still skip
high/critical Telegram sends because it has no destination chat. Medium and low
alerts are still intentionally stored without Telegram under the default
`TELEGRAM_ALERT_LEVELS=critical,high` policy.

The installer also creates editable SOC Analyst, Incident Responder, SIEM
Engineer, Cyber Threat Intel Analyst, and Threat Hunter system prompts plus the
AI model routing config only if they are missing:

```text
$HOME/n8n-local/config/soc_analyst_system_prompt.md
$HOME/n8n-local/config/incident_responder_system_prompt.md
$HOME/n8n-local/config/siem_engineer_system_prompt.md
$HOME/n8n-local/config/cyber_threat_intel_system_prompt.md
$HOME/n8n-local/config/threat_hunter_system_prompt.md
$HOME/n8n-local/config/ai_model_settings.json
```

The installer also seeds the five independent reviewer prompts only when they
are missing. Existing operator edits are never overwritten:

```text
$HOME/n8n-local/config/soc_analyst_second_opinion_prompt.md
$HOME/n8n-local/config/incident_responder_second_opinion_prompt.md
$HOME/n8n-local/config/siem_engineer_second_opinion_prompt.md
$HOME/n8n-local/config/cyber_threat_intel_second_opinion_prompt.md
$HOME/n8n-local/config/threat_hunter_second_opinion_prompt.md
```

Fresh installs seed the Incident Responder reviewer as
`codex-cli:gpt-5.6-sol:xhigh` and enable that exact Sol catalog entry. During an
upgrade, the installer changes `ai_model_settings.json` only when the complete
file is byte-for-byte identical to the approved former repository template
(Incident Responder reviewer `ollama:gemma4:31b`, Sol disabled at `medium`).
Any differing file is treated as operator-owned and left unchanged, including
an existing custom Sol route or reasoning effort. Review preserved routing in
Settings and make any desired change explicitly.

After deployment, `verify-agent-memory.py` verifies every primary/reviewer
prompt pair as well as each role memory and the shared memory file. A missing
reviewer prompt is a failed deployment verification, not a silent fallback to
the primary prompt.

The seeded Incident Responder production assignment is
`codex-cli:gpt-5.5:medium`. The fixed `codex_cli_models` catalog contains
`gpt-5.5`, `gpt-5.6-sol`, `gpt-5.6-terra`, and `gpt-5.6-luna`; each model has
one operator-selected reasoning effort and must be enabled individually before
an agent can use it. Install and authenticate Codex CLI for the Mac Studio
runtime user before enabling a route. Verify the executable and saved routing
without printing credentials:

```bash
command -v codex
codex --version
python3 -m json.tool "$HOME/n8n-local/config/ai_model_settings.json" >/dev/null
```

`run-local-ai-analysis.py` resolves an executable named exactly `codex` from
the configured path, the runtime user's `PATH`, `$HOME/.local/bin`, or standard
Homebrew locations. It does not execute arbitrary provider command strings. A
missing Codex binary fails the case visibly instead of silently switching the
model or privacy boundary.

The installer also seeds editable Cyber Security Agent Markdown memory files
only if they are missing:

```text
$HOME/n8n-local/soc-alerts/agent-memory/soc-analyst-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/incident-responder-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/siem-engineer-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/cyber-threat-intel-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/threat-hunter-memory.md
$HOME/n8n-local/soc-alerts/agent-memory/shared-agent-memory.md
```

Do not overwrite these files during normal DR redeploys if they have been tuned
or populated in production. The installer deploys `agent_memory.py` and
`manage-agent-memory.py`; it never replaces existing memory files. Managed
records are atomically updated inside delimited sections while operator notes
outside those sections remain intact. Include the runtime memory directory in
normal encrypted Mac Studio backups because Git contains templates only.

The prompts and model routing can be edited from:

```text
http://10.77.7.225:8766/settings.html
```

Open n8n:

```text
http://10.77.7.225:5678
```

Import:

```text
n8n/workflows/security-onion-configurable-scoring.workflow.json
n8n/workflows/onion-sentinel-pcap-broker.workflow.json
```

Replace:

```text
REPLACE_WITH_RELAY_TOKEN
REPLACE_WITH_PCAP_BROKER_TOKEN
```

Use one token for the alert-store-to-n8n post-commit report handoff and a
separate token for PCAP broker access. Create an n8n variable named
`RELAY_WEBHOOK_TOKEN`; store the same value only as `N8N_POST_COMMIT_TOKEN` in
the Mac runtime `.env`. The production Pi alert path does not hold this token.
The workflow reads `$vars.RELAY_WEBHOOK_TOKEN` so the live value is not stored
in workflow JSON, workflow history, or execution snapshots.
Create a second n8n variable named `PCAP_BROKER_TOKEN` with the same value as
the `pcap_broker.token` rendered into `/opt/so-alert-relay/app/config.json` on
the Pi. The PCAP broker workflow reads `$vars.PCAP_BROKER_TOKEN`, keeping that
live packet-evidence broker secret out of workflow JSON, workflow history, and
execution snapshots.

Activate both workflows. The PCAP broker workflow exposes relay-safe n8n proxy
routes and keeps alert-store reachable only on the Docker network:

```text
POST /webhook/pcap-requests
POST /webhook/pcap-claim
POST /webhook/pcap/progress
POST /webhook/pcap-complete
```

The workflow writes one Obsidian-compatible Markdown report for each newly
accepted alert. Duplicate alerts return `report_written=false` and do not
create repeated files.

The alert intake workflow intentionally treats public enrichment as best-effort.
If the dedicated `Enrich Alert` node cannot reach alert-store or an upstream
provider stalls, it marks the alert with an `external_intel.errors` record and
continues to storage. `Store Score And Filter Alert` uses a 30 second
alert-store timeout. Do not reduce that timeout below normal `/alert` write
latency plus burst headroom.

After restoring alert-store, verify the durable enrichment cache without
printing indicators or raw provider responses:

```bash
curl -fsS http://127.0.0.1:8787/health
curl -fsS http://127.0.0.1:8787/metrics
sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" \
  "SELECT COUNT(*) AS cache_rows, COALESCE(SUM(length(raw_response_json)),0) AS cache_bytes FROM enrichment_cache;"
```

`/health.enrichment_cache` reports process-local hit, miss, coalescing, stale
fallback, and bound counters. `/metrics.metrics.enrichment_cache` adds durable
row, freshness, and byte totals. Neither endpoint returns cached indicators,
provider payloads, or secrets. A cold L1 after restart is expected; valid SQLite
rows continue serving lookups without provider calls.

Install Mac Studio packet-analysis tooling before expecting PCAP evidence in AI
reports. Zeek/zeek-cut provide structured network logs; TShark provides
protocol hierarchy and packet-field corroboration. The restore script copies the
worker and creates runtime-only directories:

```bash
/opt/homebrew/bin/brew install zeek wireshark
```

```text
$HOME/n8n-local/bin/process-pcap-evidence.py
$HOME/n8n-local/pcap-evidence/artifacts
$HOME/n8n-local/soc-alerts/pcap-analysis
$HOME/Library/LaunchAgents/com.arron.soc.pcap-analysis.plist
```

The installer also creates `$HOME/n8n-local/python` and attempts to install the
bounded `maxminddb` reader there. A package-install failure does not disable
Zeek/TShark analysis; it leaves offline GeoIP unavailable until the reader is
installed. Verify it without reading any database contents:

```bash
PYTHONPATH="$HOME/n8n-local/python" /usr/bin/python3 -c 'import maxminddb; print(maxminddb.__version__)'
```

The default runtime database locations are:

```text
$HOME/n8n-local/config/maxmind/GeoLite2-ASN.mmdb
$HOME/n8n-local/config/maxmind/GeoLite2-City.mmdb
$HOME/n8n-local/config/maxmind/GeoLite2-Country.mmdb
```

Create `$HOME/n8n-local/config/maxmind` with mode `0750`, upload only the three
extracted `.mmdb` files, set each file to `0640`, and confirm the standalone
MaxMind section on the Settings page reports `Ready` for ASN, City, and Country.
To use other absolute or `$HOME`-relative files, set
`maxmind_geoip_asn_db_path`, `maxmind_geoip_city_db_path`, and
`maxmind_geoip_country_db_path` in
`$HOME/n8n-local/config/ai_model_settings.json` or save the paths through the
Settings page. The legacy `maxmind_geoip_db_path` key migrates to City only.
Never place a database or vendor archive in the repo, generated dashboard,
report corpus, backup bundle intended for Git, or Obsidian vault.

The TShark parser reviews every packet for DNS activity, HTTP User-Agent values,
TLS versions, and abnormal-size ICMP/ICMPv6 frames in the same bounded pass used
for packet samples. `ICMP_ABNORMAL_MIN_FRAME_BYTES=256` is the default. These
signals and offline GeoIP are contextual evidence only, not automatic malicious
classifications.

The `pcap_requests` table uses `created_at`, `claimed_at`, `completed_at`, and
`updated_at` to track broker lifecycle. If a restored database is older, restart
alert-store once after copying the current source so the additive schema
migration creates any missing lifecycle columns.

The dashboard can also queue packet evidence from the SOC Alerts table. The
`PCAP` row action calls the Onion Sentinel API, which writes or requeues a bounded
`pcap_requests` row and immediately returns `Queued` to the UI. The relay and
Security Onion wrapper still own capture fulfillment, so a dashboard/API
failure does not stop normal alert relay ingestion, and a relay/PCAP failure
does not stop analyst status changes or alert storage.

Alert-store also auto-queues PCAP requests for every newly stored,
non-suppressed alert with a known triage level by default through
`PCAP_AUTO_REQUEST_LEVELS=critical,high,medium,low,informational`. This is
server-side ingest policy, not dashboard JavaScript. Set the variable to an
empty value during maintenance if operators need manual-only PCAP requests.
Pending automatic requests coalesce by stable alert-group identity. Relay
selection is severity-first (`critical` through `informational`), then uses
capture-retention urgency and newest creation time within the same severity.

Set `ZEEK_BIN`, `ZEEK_CUT_BIN`, or `TSHARK_BIN` only if the tools are not on
the LaunchAgent `PATH`. Do not copy PCAP files or generated PCAP analysis
artifacts into the Git repo.

The Mac Studio also includes a conservative retention helper for runtime-only
packet evidence:

```bash
python3 $HOME/n8n-local/bin/maintain-pcap-evidence.py
python3 $HOME/n8n-local/bin/maintain-pcap-evidence.py --apply
python3 $HOME/n8n-local/bin/maintain-pcap-evidence.py --analyzed-only --apply
```

The parser deletes broker-managed raw artifacts immediately only after Zeek and
TShark both succeed and validated JSON/Markdown evidence is durable. Direct
manual PCAP inputs and partial analyses are retained. `--analyzed-only` applies
the same proof requirement to historical request directories. The helper
refuses cleanup paths outside `$HOME/n8n-local` so a bad argument cannot erase
an operator directory.

The LaunchAgent `com.arron.soc.pcap-retention` runs the helper every five
minutes with `--analyzed-only --apply`. Unanalyzed, failed, pending, and
partially parsed captures are outside this automatic delete set.

System Health includes compact PCAP broker/parser health. `No Packets` PCAP
failures are expected negative evidence and are counted separately. Stale
pending/claimed requests older than 20 minutes and non-no-packet failures are
reported as PCAP warnings. The System Health page also lists recent PCAP broker
requests with status, request id, group id, artifact size, update time, and
sanitized error text. If `pcap-analysis.err.log` shows an old traceback
but `launchctl` reports `last exit code = 0`, run the worker directly before
assuming the schedule is broken:

```bash
python3 $HOME/n8n-local/bin/process-pcap-evidence.py --limit 1 --stdout
```

Oversize PCAP requests are counted separately from active warnings. They mean
the capture matched packets but exceeded the older inline JSON artifact ingest
limit or the current configured artifact ceiling.

Current production PCAP transfer keeps n8n as the request/claim/complete
control plane and uses the relay as the data-plane bridge. Security Onion
streams one bounded tuple-filtered rotation at a time over restricted SSH;
the relay writes each stream directly into
`/mnt/onion-sentinel-pcap-spool/pcap` on the relay SSD, checkpoints it, builds
the compatible tar locally, then rsyncs it to
`$HOME/n8n-local/pcap-evidence/artifacts/<request_id>/` on the Mac Studio.
The relay verifies size and SHA256 before completion, and deletes the relay
spool copy only after alert-store durably acknowledges the fulfilled completion
callback. A failed transfer or callback preserves the relay copy for bounded
retry. Stream mode never creates an Onion Sentinel artifact on Security Onion.

The relay SSD should be mounted with:

```text
noatime,nosuid,nodev,noexec,nofail
```

Use a UUID-based `/etc/fstab` entry with
`x-systemd.device-timeout=30s`. Before enabling the broker, verify that
`findmnt /mnt/onion-sentinel-pcap-spool` resolves to the external SSD rather
than the SD-card root filesystem, and perform a write/read/delete test as the
`soalert` account. The production profile uses a 1 TB ext4 SSD, 128 GiB
per-artifact limit, 200 GiB free-space reserve, and 75 percent high-water mark.

The Mac alert-store independently rejects new `/alert` and `/enrich` writes
with HTTP 507 at 75 percent use, when a projected request would cross that
threshold, or when the 50 GiB reserve would be consumed. Relay heartbeats are
still accepted, and completion/cleanup metadata remains writable so queued
work can drain. The relay keeps rejected alerts in its durable batch evidence
for retry rather than dropping them.

Use `RELAY_PCAP_TIMEOUT_SECONDS=43200` for large captures. The systemd oneshot
also permits 12 hours while bounded per-chunk and rsync timeouts detect stalls.
Alert-store also
requeues stale `claimed` PCAP requests after `PCAP_CLAIM_LEASE_SECONDS`
defaults to 1800 seconds, so interrupted transfers do not need direct database
repair before the relay can retry them.

Alert filtering and suppression are controlled on Mac Studio in:

```text
$HOME/n8n-local/alert_store/config/scoring_rules.json
```

After changing `scoring_rules.json`, restart the host-native alert-store:

```bash
cd $HOME/n8n-local
launchctl kickstart -k gui/$(id -u)/com.arron.soc.alert-store
```

Then verify health:

```bash
/usr/local/bin/docker exec n8n node -e '(async()=>{const r=await fetch("http://alert-store:8787/health"); console.log(await r.text()); if(!r.ok) process.exit(1);})().catch(()=>process.exit(1))'
```

If the SOC Alerts dashboard count or grouped rows look stale after a restore,
manually rebuild the grouped summary table:

```bash
/usr/local/bin/docker exec n8n node -e '(async()=>{const r=await fetch("http://alert-store:8787/refresh-groups",{method:"POST"}); console.log(await r.text()); if(!r.ok) process.exit(1);})().catch(()=>process.exit(1))'
```

Report output:

```text
$HOME/Documents/SOC Alerts
```

Dashboard refresh:

```bash
python3 $HOME/n8n-local/bin/refresh-soc-dashboard.py
```

The refresh worker serializes builds behind its own lock and writes directly to
`$HOME/SOC Alerts Web`. The dedicated `com.arron.onion-sentinel.web`
LaunchAgent serves that tree and SOC APIs on port `8766`. No supported Onion
Sentinel job reads or writes `$HOME/.hermes` or `$HOME/report_portal`.

The Hermes LAN Portal is a separate project on port `8765`. It may provide an
ordinary external link to Onion Sentinel, but it must not iframe, proxy, copy,
rebuild, authenticate, delete, or otherwise manage Onion Sentinel content.
Hermes and OpenClaw availability cannot affect this dashboard runtime.

Dashboard URL:

```text
http://10.77.7.225:8766/
```

After alert-store starts, its additive schema migration creates the Incident
Response case/event tables and the AI-run role discriminator. Verify the
dedicated dashboard endpoints without exposing alert content:

```bash
curl -fsS http://127.0.0.1:8766/api/soc-incidents >/dev/null
curl -fsS http://127.0.0.1:8766/investigations.html >/dev/null
```

Escalations originate at `POST /api/soc-alerts/<dashboard-group-id>/escalate`,
are resolved to the stable group by alert-store, and enqueue a durable
`incident_response_analysis` job. Restore alert-store before the dashboard and
AI worker so case state and role-isolated analysis writeback are available.

Synthetic durable-intake test from the relay:

```bash
cat > /tmp/onion-sentinel-intake-test.json <<'JSON'
{
  "protocol": "onion-sentinel-alert-batch/v1",
  "messages": [{
    "delivery_id": "synthetic-dr-intake-check",
    "payload": {
      "alert_id": "synthetic-dr-intake-check",
      "timestamp": "2026-07-01  20:31:15Z",
      "rule_name": "Synthetic DR intake check",
      "event_dataset": "integration.test",
      "severity": 1,
      "severity_label": "low",
      "source": {"ip": "192.0.2.10", "port": 4444},
      "destination": {"ip": "198.51.100.20", "port": 443},
      "network": {"transport": "tcp"},
      "rule_category": "test"
    }
  }]
}
JSON

sudo -u soalert ssh \
  -i /opt/so-alert-relay/keys/macstudio-alert-ingest_ed25519 \
  -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/opt/so-alert-relay/keys/macstudio_known_hosts \
  -o GlobalKnownHostsFile=/dev/null -T \
  <mac_user>@10.77.7.225 onion-sentinel-alert-intake batch \
  < /tmp/onion-sentinel-intake-test.json
```

The response must contain one `ok: true` acknowledgement for
`synthetic-dr-intake-check`. Repeating the same batch must return a successful
idempotent result and must not create another alert row or report artifact.

The dashboard sidebar health tile depends on `n8n-beacon.json`. During normal
operation, new alerts and quiet-cycle relay heartbeats both update that file.
If the tile is red, check the newest beacon timestamp and the Pi timer logs:

```bash
ssh aj_lobster@10.77.7.225 'cat "$HOME/n8n-local/alert_store_data/n8n-beacon.json"'
ssh aj_lobster@10.77.7.225 'curl -fsS "http://127.0.0.1:8766/api/system-health/beacons?hours=24"'
ssh aj@10.88.8.8 'systemctl list-timers --all so-alert-poll.timer so-pcap-broker.timer --no-pager; sudo journalctl -u so-alert-poll.service -u so-pcap-broker.service -n 40 --no-pager'
```

The System Health page at `/system-health.html` uses
`n8n-beacon-history.json` to show the last 24 hours of relay/n8n beacon events,
unsuccessful recovery-marked events, and gaps longer than 10 minutes between
successful beacons. The history file is generated beside `n8n-beacon.json` and
is runtime telemetry; do not commit it.

If n8n logs show SQLite I/O errors, validate both SQLite stores before
troubleshooting the relay:

```bash
ssh aj_lobster@10.77.7.225 'sqlite3 "$HOME/n8n-local/n8n_data/database.sqlite" "PRAGMA quick_check;"'
ssh aj_lobster@10.77.7.225 'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "PRAGMA quick_check;"'
```

Alert-store SQLite maintenance:

```bash
ssh aj_lobster@10.77.7.225 'launchctl print gui/$(id -u)/com.arron.soc.alert-store-maintenance | grep -E "state =|last exit code|run interval|path ="'
ssh aj_lobster@10.77.7.225 '$HOME/n8n-local/bin/maintain-alert-store-sqlite.zsh'
ssh aj_lobster@10.77.7.225 'tail -80 "$HOME/n8n-local/logs/alert-store-sqlite-maintenance.log"'
ssh aj_lobster@10.77.7.225 'ls -lh "$HOME/n8n-local/alert_store_backups" | tail'
```

The maintenance job creates verified SQLite backups and recovered candidates
when corruption is detected. It also verifies that `alert_group_summary` matches
the raw `alerts` table and uses the local alert-store `/refresh-groups` endpoint
to repair stale grouped state. It sends Telegram on failure and recovery
transitions when the runtime `.env` contains Telegram credentials. It does not
replace the live DB unless `ALERT_STORE_AUTO_RECOVER=1` is explicitly set for
that run. Online backup operations wait up to 60 seconds for active writers and
retry a bounded number of times; a transient `database is locked` result is not
evidence of corruption. The hourly tier retains the newest 10 verified
`alerts.sqlite3.*.backup` snapshots; daily recovery bundles remain a separate
longer-lived DR tier.

During an authorized `ALERT_STORE_AUTO_RECOVER=1` swap, maintenance creates a
short-lived web guard hold and installs an exit trap before stopping services.
The trap restores the host alert store, Docker proxy, and dedicated Onion
Sentinel web LaunchAgent even if recovery is interrupted. The web guard can
bootstrap the exact current-user-owned
`com.arron.onion-sentinel.web.plist` when launchd has lost its registration;
it never bootstraps an arbitrary path or label. Telegram and local SLO probe
timeouts are bounded and logged without credential material or Python
tracebacks.

The daily runtime recovery bundle complements the hourly SQLite backups with
n8n PostgreSQL and encryption/configuration state:

```bash
ssh <mac_user>@<mac_studio_ip> 'python3 "$HOME/n8n-local/bin/backup-onion-sentinel-runtime.py"'
ssh <mac_user>@<mac_studio_ip> 'latest=$(find "$HOME/n8n-local/recovery_backups" -mindepth 1 -maxdepth 1 -type d ! -name ".*" | sort | tail -1); python3 -m json.tool "$latest/manifest.json"'
```

Each atomic bundle contains the quick-checked alert-store SQLite database and,
when it exists, the owner-only investigation-harness SQLite database. Both
snapshots are restored through SQLite's backup API, rechecked, and compared to
their manifest row counts before the bundle is published. The bundle also
contains the n8n PostgreSQL custom-format dump and, when the alert-store shadow
is enabled, a distinct alert-store PostgreSQL dump. Both are validated by
`pg_restore --list`. The bundle also contains a SHA-256 manifest and the
runtime `.env`, n8n encryption config,
prompts/settings, and agent memories needed for recovery. A missing harness
database remains a valid pre-harness recovery state. The bundle is mode `0700`
with files mode `0600`, retained for seven days, and must never enter Git.
Because it contains secrets and live operator state, any off-host copy must
use an operator-controlled encrypted backup target.

Qualify a bundle with a full isolated restore rather than relying only on dump
creation checks:

```bash
ssh <mac_user>@<mac_studio_ip> 'python3 "$HOME/n8n-local/bin/run-recovery-restore-drill.py"'
```

This uses a disposable PostgreSQL container with networking disabled and a
temporary data filesystem. It validates the restored n8n schema and workflow
records; restores and validates the optional alert-store PostgreSQL shadow
schema and durable-job rows; verifies the alert-store and optional investigation-harness SQLite
copies, foreign keys, schema version, and manifest row counts; checks all
bundle hashes; and confirms the archive contains the n8n encryption
configuration. The production containers, databases, keys, and workflows are
not modified.

### Mac Studio supervision readiness and restart quarantine

Run the non-mutating readiness check before and after a deployment or recovery:

```bash
python3 "$HOME/n8n-local/bin/check-onion-sentinel-readiness.py" --network
```

The check validates release configuration, read-only database integrity,
storage capacity, provider configuration, service identity, required launchd
registration, duplicate AI workers, web restart quarantine, and Relay TCP
reachability. It does not execute a Security Onion evidence query or a model
inference.

The web identity guard permits at most three automatic restart attempts within
15 minutes. When that budget is exhausted it records an owner-only quarantine
at `~/n8n-local/logs/onion-sentinel-web-restart-budget.json` and refuses further
automatic restarts. Do not simply erase the quarantine. First collect the web,
guard, monitor, and readiness logs; resolve any port conflict, invalid release,
or repeated process failure; then preserve the state for review before moving
it aside and starting the allowlisted launchd job:

```bash
mkdir -p "$HOME/n8n-local/logs/restart-budget-history"
mv "$HOME/n8n-local/logs/onion-sentinel-web-restart-budget.json" \
  "$HOME/n8n-local/logs/restart-budget-history/web-$(date -u +%Y%m%dT%H%M%SZ).json"
launchctl kickstart -k "gui/$(id -u)/com.arron.onion-sentinel.web"
python3 "$HOME/n8n-local/bin/check-onion-sentinel-readiness.py" --network
```

An unknown or duplicate listener remains a manual incident: the guard never
terminates an unrecognized process. Provider workers are scheduled jobs and
may legitimately be absent when idle, but more than one worker in the same
provider lane fails readiness. Their durable job and harness state must be
inspected before restarting a scheduler.

Harness trace retention is a separate hourly job. It preserves active runs,
deletes no more than 1,000 terminal traces per pass, and refuses every
destructive pass unless a hash-verified harness snapshot exists in a recovery
bundle no older than 26 hours:

```bash
ssh <mac_user>@<mac_studio_ip> \
  'python3 "$HOME/n8n-local/bin/maintain-investigation-harness.py"'
ssh <mac_user>@<mac_studio_ip> \
  'python3 -m json.tool "$HOME/n8n-local/logs/investigation-harness-maintenance.json"'
```

The first command is a dry run. The installed LaunchAgent supplies `--apply`.
Exit `1` means another bounded pass is required; exit `2` means the database,
lock, permissions, integrity check, or backup precondition blocked retention.

Alert-store SQLite should run with these durability defaults in the Mac Studio
runtime `.env` and repo compose template:

```text
ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS=30000
ALERT_STORE_SQLITE_JOURNAL_MODE=DELETE
ALERT_STORE_SQLITE_SYNCHRONOUS=FULL
ALERT_STORE_SQLITE_TEMP_STORE=DEFAULT
```

The host-native alert-store is the sole production writer for alert evidence,
analyst workflow state, grouped summaries, and PCAP request records. The
dedicated Onion Sentinel API service
proxies mutations to alert-store and opens SQLite read-only for dashboard
queries. On the current Docker Desktop bind-mounted runtime path, do not enable
WAL; use a named Docker volume or host-native service before reconsidering it.
If a recovered DB must be swapped in, stop alert-store and all readers,
including the Onion Sentinel web service, before replacing `alerts.sqlite3`.
The separate Hermes LAN Portal is not an alert database reader and must not be
stopped or restarted by this procedure. Remove stale
`alerts.sqlite3-journal`, `alerts.sqlite3-wal`, and `alerts.sqlite3-shm`
sidecars before restarting.

If `quick_check` reports index-only damage such as `wrong # of entries in
index ...`, or page cleanup issues that still allow reads, use a short
alert-store maintenance window. Keep all backups in the Mac Studio runtime
tree and never copy them into Git:

```bash
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose stop alert-store'
ssh aj_lobster@10.77.7.225 'launchctl bootout gui/$(id -u)/com.arron.soc.alert-store 2>/dev/null || true'
ssh aj_lobster@10.77.7.225 'launchctl bootout gui/$(id -u)/com.arron.onion-sentinel.web 2>/dev/null || true'
ssh aj_lobster@10.77.7.225 'ts=$(date +%Y%m%dT%H%M%S%z); cp -p "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "$HOME/n8n-local/alert_store_backups/alerts.sqlite3.pre-index-repair-$ts.bak"'
ssh aj_lobster@10.77.7.225 'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "REINDEX;"'
ssh aj_lobster@10.77.7.225 'ts=$(date +%Y%m%dT%H%M%S%z); out="$HOME/n8n-local/alert_store_data/alerts.repaired-$ts.sqlite3"; rm -f "$out"; sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "VACUUM INTO '\''$out'\'';"; sqlite3 "$out" "PRAGMA integrity_check;"; mv "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "$HOME/n8n-local/alert_store_data/alerts.sqlite3.pre-vacuum-replace-$ts.bak"; mv "$out" "$HOME/n8n-local/alert_store_data/alerts.sqlite3"; chmod 0644 "$HOME/n8n-local/alert_store_data/alerts.sqlite3"'
ssh aj_lobster@10.77.7.225 'launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.arron.soc.alert-store.plist" 2>/dev/null || launchctl kickstart -k gui/$(id -u)/com.arron.soc.alert-store'
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose up -d alert-store'
ssh aj_lobster@10.77.7.225 'launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.arron.onion-sentinel.web.plist" 2>/dev/null || launchctl kickstart -k gui/$(id -u)/com.arron.onion-sentinel.web'
ssh aj_lobster@10.77.7.225 'sqlite3 "$HOME/n8n-local/alert_store_data/alerts.sqlite3" "PRAGMA quick_check;"'
```

After the container is healthy, run one relay service cycle and confirm the
journal reports `alert_relay=ok pcap_broker=ok`.

If corruption is isolated to n8n execution history, stop n8n, back up the
database, recover or clear execution history, verify `PRAGMA quick_check;`,
then start n8n again. Do not copy the n8n runtime database into Git.

For high-volume relay webhooks, the repo compose template keeps bounded n8n
execution history in PostgreSQL and prunes old rows. Earlier SQLite-only
deployments used reduced execution persistence to limit write pressure, but the
PostgreSQL-backed deployment should keep successful and failed execution status
available for operational debugging.

If n8n continues to produce `SQLITE_IOERR` or `SQLITE_CORRUPT` during webhook
bursts after this tuning, migrate n8n from SQLite to PostgreSQL. The repo
compose template includes a PostgreSQL service for n8n metadata/execution state
only. Keep alert-store SQLite separate; it remains the operational alert
database.

SQLite-to-PostgreSQL migration outline:

```bash
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && ts=$(date +%Y%m%dT%H%M%S%z) && mkdir -p "n8n_data/migration-exports/$ts/entities" && /usr/local/bin/docker compose stop n8n && /usr/local/bin/docker compose run --rm --entrypoint n8n n8n export:entities --outputDir="/home/node/.n8n/migration-exports/$ts/entities" && printf "%s\n" "$ts" > n8n_data/migration-exports/latest-postgres-migration.txt'
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose stop n8n'
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose up -d postgres'
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose run --rm --entrypoint n8n n8n import:entities --inputDir="/home/node/.n8n/migration-exports/<timestamp>/entities" --truncateTables'
ssh aj_lobster@10.77.7.225 'cd "$HOME/n8n-local" && /usr/local/bin/docker compose up -d n8n'
```

Use a runtime-only `N8N_POSTGRES_PASSWORD` in `$HOME/n8n-local/.env`. Do not
commit the migration export, PostgreSQL data directory, n8n runtime DB, or any
credential export.

## 3. Restore Security Onion Wrapper

Copy this repo to Security Onion or clone it there, then run:

```bash
cd /path/to/OnionSentinel
sudo ./security-onion/bin/install-security-onion-wrapper.sh
```

Create the forced-command authorized key:

```bash
sudo install -o so-ai-relay -g so-ai-relay -m 0700 -d /home/so-ai-relay/.ssh
sudo cp security-onion/ssh/authorized_keys.example /home/so-ai-relay/.ssh/authorized_keys
sudo nano /home/so-ai-relay/.ssh/authorized_keys
sudo chown so-ai-relay:so-ai-relay /home/so-ai-relay/.ssh/authorized_keys
sudo chmod 0600 /home/so-ai-relay/.ssh/authorized_keys
```

Replace:

```text
REPLACE_WITH_PUBLIC_KEY
```

with the Pi relay public key.

Test locally:

```bash
sudo -u so-ai-relay sudo -n /usr/local/sbin/export-recent-alerts | jq '.alerts | length'
```

For PCAP fulfillment, install a separate forced-command public key using
`security-onion/ssh/authorized_keys.pcap.example`. The associated wrapper is:

```text
/usr/local/sbin/export-pcap-window
```

It accepts a bounded JSON request on stdin. `stream_manifest` returns source
metadata; `stream_chunk` writes one filtered PCAP to SSH stdout. The relay writes
stdout directly to its external SSD. Do not install or enable the former
`so-ai-relay-pcap-rsync` account: the production design stages zero bytes under
`/nsm`. The staged implementation and rollback switch are absent from the
current source tree.

For Incident Response evidence, install a third dedicated forced-command key
using `security-onion/ssh/authorized_keys.incident-query.example`. The
associated wrapper is:

```text
/usr/local/sbin/export-incident-evidence
```

The relay side uses
`relay/config/authorized_keys.incident-evidence.example` and
`relay/app/incident_evidence_broker.py`. The Mac runtime configuration is
rendered from `n8n/config/incident-evidence.example.json`; never commit the
private keys or live rendered file.

This baseline path accepts only validated observables and a bounded UTC window.
Security Onion constructs five fixed Elastic packs and seven fixed local
OSquery packs. The caller cannot supply KQL, Query DSL, OSquery SQL, an index,
target, path, or command. Reports retain analyst-readable KQL, exact executed
Query DSL, and exact executed OSquery SQL with pack, target, status, digest,
and bounded row metadata.

Live endpoint OSQuery is a separate, optional Incident Responder follow-up. Its
Mac, relay, and Security Onion configurations are disabled by default. Recover
the fixed evidence path first. Then follow
`docs/incident-response-query-and-model-routing.md` to install two dedicated
forced-command keys, pin both host keys, configure identical operator aliases,
map each alias to one exact Fleet agent ID on Security Onion, install the
trusted Kibana CA and least-privilege authorization, and validate the
fail-closed state before enabling each node. Never configure wildcard or
all-endpoint aliases.

Validate the full chain with a disposable alert-store fixture whose selected
alert contains only reserved TEST-NET observables. The collector accepts an
alert ID, reads that alert's exact group from SQLite, and writes the artifact
path to stdout; it intentionally does not accept caller-supplied observables or
queries:

```bash
TEST_ALERT_ID='<synthetic-alert-id>'
TEST_DB='/path/to/disposable-test-alerts.sqlite3'
ARTIFACT="$(
  $HOME/n8n-local/bin/collect-incident-evidence.py \
    --alert-id "$TEST_ALERT_ID" \
    --db "$TEST_DB" \
    --out-dir /tmp/onion-sentinel-incident-evidence-test \
    --size 10
)"

python3 - "$ARTIFACT" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
response = data["security_onion_response"]
assert data["schema"] == "onion-sentinel-incident-evidence-v2"
assert response["ok"] is True
assert response["read_only"] is True
assert response["complete"] is True
assert len(response["results"]) == len(data["request"]["packs"]) * len(data["request"]["windows"])
assert all(item["status"] == "ok" for item in response["results"])
assert all(item.get("kql_equivalent") for item in response["results"])
assert all(item.get("query_dsl") and item.get("query_digest") for item in response["results"])
assert len(response["osquery_results"]) == 7
assert all(item["status"] == "ok" for item in response["osquery_results"])
assert all(item.get("query") and item.get("query_digest") for item in response["osquery_results"])
print("incident evidence contract passed")
PY

rm -f "$ARTIFACT"
rmdir /tmp/onion-sentinel-incident-evidence-test 2>/dev/null || true
```

Use only reserved TEST-NET observables for this test. Do not print returned
rows, which may contain local host context.

The installer creates `/etc/onion-sentinel/pcap-stream-token.key` as a root-only
32-byte signing key. Manifest chunks bind the exact source inode, initial size,
request window, and BPF variant. This lets `stream_chunk` validate a prior
manifest after normal capture rotation without rescanning the directory. Treat
the key as a runtime secret: never print, copy to the relay, or commit it.

Security Onion captures on tagged VLAN interfaces in this deployment, so the
PCAP wrapper combines VLAN-aware and plain flow filters into one BPF expression
and scans each candidate rotation once. Requests should also carry
`suricata.capture_file` when Security
Onion provided it in the raw alert. The wrapper validates that capture path is
under `/nsm/suripcap`, prefers that file first, and otherwise selects rotations
whose capture epochs overlap the bounded window. This keeps requests anchored to the actual
capture file that produced the detection instead of relying only on broad
timestamp searches.

Fulfilled PCAP broker metadata is not enough for LLM analysis by itself. The
preferred path is the relay artifact data plane: the relay requests bounded
stream metadata from the Security Onion forced-command wrapper, captures each
SSH stream on the relay SSD with a durable checkpoint, builds and verifies the
tar on the relay, and rsyncs it to
the Mac Studio, and verifies the Mac copy before reporting fulfillment. n8n is
only the request/claim/complete control plane; PCAP tar bytes do not move
through n8n, alert-store HTTP bodies, or inline chunk payloads.

```text
$HOME/n8n-local/pcap-evidence/artifacts/<request_id>/
```

The Mac Studio parser then runs:

```bash
$HOME/n8n-local/bin/process-pcap-evidence.py --request-id <request_id>
```

and writes bounded Zeek/TShark summaries to
`$HOME/n8n-local/soc-alerts/pcap-analysis`. The SOC Analyst prompt builder
automatically includes those summaries for matching alerts.

The production parser must scan the complete capture set while retaining only
bounded state. Zeek aggregates every generated JSON record; TShark performs one
streaming field pass over every packet and retains a deterministic
representative sample. Confirm the resulting JSON contains `coverage.complete`
and parser-specific file/record/packet/byte/time coverage before treating the
evidence as complete. A failed or incomplete parser pass preserves the raw Mac
artifact for investigation and must not be silently reported as analyzed.

The parser process boundary is part of the security recovery baseline. Restore
`pcap_analysis_core.py`, `pcap_tool_runtime.py`, and
`pcap_evidence_query.py` with `process-pcap-evidence.py`. Parser children use a
stripped environment, process and output ceilings, and macOS network denial
when `sandbox-exec` is available. The SOC Analyst follow-up interface queries
only sanitized derived evidence through fixed operations; it never accepts a
path, shell command, regular expression, display filter, or parser argument.
Hosted model invocations must not contain raw payloads, packet samples, local
query results, tool paths, or the private derived-evidence index.

When parsed PCAP evidence is newer than an existing SOC Analyst report, the AI
scheduler considers that grouped detection stale and rebuilds the prompt before
calling the local model again. The dashboard's lazy detail endpoint also
appends current parsed PCAP evidence even when the static detail fragment was
built before the PCAP parser finished.

If Security Onion returns a valid negative result, such as no packets matching
the requested flow/window, the dashboard shows `No Packets` instead of a
generic failure. Operators should treat that as useful evidence about capture
coverage or tuple/window selection, not as a broken broker.

`export-pcap-window` evaluates a validated `capture_file` first, then selects
time-overlapping Security Onion rotations before applying its candidate limit.
Each source is limited to 1.1 GiB, at most 12 are considered, and one stream runs
at a time. Security Onion disk utilization is telemetry only and never blocks
the read-only stream. If matching packets exist but no
packets are returned, inspect the bounded completion diagnostics (candidate
count, candidate basenames, BPF variants, and requested window) before
widening the request. The wrapper uses destination port by default for BPF flow filtering. Use
`require_source_port: true` only for controlled validation or rare cases where
the source port is intentionally the discriminator.

## 4. Restore Pi Relay

On the Pi:

```bash
sudo apt update
sudo apt install -y python3 openssh-client netcat-openbsd jq
cd /path/to/OnionSentinel
sudo ./relay/bin/install-relay.sh
```

Install the Security Onion SSH private key:

```bash
sudo install -o soalert -g soalert -m 0700 -d /opt/so-alert-relay/keys
sudo cp /path/to/so-ai-relay_ed25519 /opt/so-alert-relay/keys/so-ai-relay_ed25519
sudo chown soalert:soalert /opt/so-alert-relay/keys/so-ai-relay_ed25519
sudo chmod 0600 /opt/so-alert-relay/keys/so-ai-relay_ed25519
```

Edit:

```text
/etc/so-alert-relay/relay.env
```

Required values:

```text
RELAY_WEBHOOK_URL
RELAY_WEBHOOK_TOKEN
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
```

Test pull-only:

```bash
sudo -u soalert /usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --pull-once
```

PCAP fulfillment remains disabled until the n8n broker/proxy URL, separate
broker token, and path map are configured in
`/opt/so-alert-relay/app/config.json`. Configure the dedicated Security Onion
stream key under the top-level `security_onion` object:

```json
"security_onion": {
  "host": "192.168.1.7",
  "ssh_user": "so-ai-relay",
  "ssh_key": "/opt/so-alert-relay/keys/so-ai-relay_ed25519",
  "pcap_ssh_key": "/opt/so-alert-relay/keys/so-ai-relay-pcap_ed25519"
}
```

The default n8n proxy configuration is:

```json
"pcap_broker": {
  "enabled": true,
  "url": "http://10.77.7.225:5678/webhook",
  "token": "REPLACE_WITH_PCAP_BROKER_TOKEN",
  "requests_method": "POST",
  "paths": {
    "requests": "/pcap-requests",
    "claim": "/pcap-claim",
    "progress": "/pcap/progress",
    "complete": "/pcap-complete"
  },
  "upload_artifact": true,
  "artifact_upload_mode": "streamed_chunks",
  "artifact_spool_dir": "/mnt/onion-sentinel-pcap-spool/pcap",
  "artifact_spool_require_mount": true,
  "artifact_spool_max_bytes": 137438953472,
  "artifact_spool_min_free_bytes": 214748364800,
  "artifact_spool_max_used_percent": 75,
  "artifact_spool_delete_after_upload": true,
  "artifact_spool_partial_ttl_seconds": 86400,
  "artifact_spool_completed_ttl_seconds": 3600,
  "security_onion_storage_telemetry": true,
  "capture_protection_enabled": true,
  "capture_protection_require_telemetry": true,
  "capture_loss_threshold_percent": 1.0,
  "capture_loss_freshness_seconds": 900,
  "stream_chunk_idle_timeout_seconds": 300,
  "mac_transfer": {
    "host": "10.77.7.225",
    "user": "__MAC_STUDIO_SSH_USER__",
    "ssh_key": "/opt/so-alert-relay/keys/macstudio-pcap-transfer_ed25519",
    "artifact_dir": "n8n-local/pcap-evidence/artifacts",
    "connect_timeout_seconds": 20,
    "rsync_timeout_seconds": 1800,
    "minimum_bytes_per_second": 2097152
  },
  "lock_path": "/tmp/onion-sentinel-pcap-broker.lock",
  "timeout_seconds": 20,
  "limit": 1
}
```

When enabled, it uses a separate Security Onion forced-command key and this
relay mode:

```bash
sudo -u soalert /usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --process-pcap-requests
```

The relay filters the broker response and processes only `pending` requests.
That keeps fulfillment correct even if a proxy returns recent request history
alongside pending work. A request that reaches Security Onion and returns
`no matching packets found` is valid negative packet evidence, not a relay
transport failure.

Relay SSD cleanup is intentionally conservative. The final `.tar` in the relay
spool is deleted only after the Mac Studio artifact has been copied and
verified by size and SHA256. Interrupted `.tar.part` files are pruned during
the next broker run by default. Set `artifact_spool_partial_ttl_seconds` higher
than `0` to keep partials for a short retry window, or `-1` to disable partial
cleanup during troubleshooting.

Use `artifact_upload_mode: "streamed_chunks"` after importing and activating
the metadata-only n8n workflow. Keep `lock_path` enabled so only one relay
worker runs. The wrapper's separate stream lock permits only one Security Onion
read at a time, caps source reads at 4 MiB/s, caps relay-to-Mac rsync at 4 MiB/s,
and combines tagged and untagged
filters into one scan. The broker handles one request per run and the timer
waits one minute after completion before another run. The worker remains
single-flight, bandwidth-capped, and capture-loss gated; the shorter idle
interval lets a healthy broker recover a burst backlog without concurrent
Security Onion reads. The old n8n inline
upload and Security Onion tar-staging paths are absent.

Keep capture protection enabled. The relay must receive a fresh latest-interval
Zeek capture-loss sample before claiming work and uses a 1.0 percent default
threshold unless the reviewed live configuration says otherwise. The separate
Zeek and Suricata packet-loss threshold remains 0.1 percent. A protected
deferral is an intentional degraded state: it must not consume a retry attempt
or be reported as a stack failure. Confirm the relay posts a `pcap_broker`
heartbeat each minute and that the Mac has a fresh
`alert_store_data/pcap-workflow-state.json`; state older than three minutes is
treated as stale and cannot suppress a real backlog warning.

Do not install the obsolete Security Onion PCAP output retention timer. The
production wrapper is read-only, stages zero bytes, and leaves native capture
retention to Security Onion. A healthy production stream creates no Onion
Sentinel directory or packet artifact under `/nsm`.

Test service:

```bash
sudo systemctl start so-alert-poll.service
sudo journalctl -u so-alert-poll.service -n 30 --no-pager
systemctl list-timers --all so-alert-poll.timer so-pcap-broker.timer --no-pager
```

The Pi should not own normal rule filtering. Its live config should keep:

```json
"filters": {
  "drop_alerts": []
}
```

The Pi still deduplicates exact alert IDs locally to avoid retry storms, but
drop rules, suppression windows, routing, reports, and notifications belong to
Mac Studio alert-store/n8n.

Preferred alert delivery settings live in
`/opt/so-alert-relay/app/config.json`:

```json
"alert_ingest": {
  "enabled": true,
  "mode": "ssh_batch",
  "host": "10.77.7.225",
  "user": "__MAC_STUDIO_SSH_USER__",
  "ssh_key": "/opt/so-alert-relay/keys/macstudio-alert-ingest_ed25519",
  "known_hosts": "/opt/so-alert-relay/keys/macstudio_known_hosts",
  "remote_command": "onion-sentinel-alert-intake batch",
  "batch_max_items": 100,
  "batch_max_bytes": 8388608,
  "connect_timeout_seconds": 20,
  "request_timeout_seconds": 180
}
```

The relay persists each fetched alert in its SQLite outbox before delivery.
Each forced SSH batch returns one acknowledgement per delivery ID. Missing or
retryable acknowledgements remain pending for the next timer run; permanent
per-item rejects move only that message to the dead-letter table. Alert-store
uses `alert_id` as an idempotency key, so replay after a lost connection is safe.

The direct alert path does not require a shared application token on the Pi and
does not depend on n8n availability. Authentication and authorization come from
the dedicated key, verified Mac host key, source-restricted `authorized_keys`
entry, forced command, and loopback-only alert-store endpoint.

### Emergency HTTP rollback only

If direct intake cannot be restored, the legacy n8n webhook may be enabled for
a controlled rollback. In that mode, the relay must fail closed on workflow
rejects even when n8n returns HTTP 200: `relay.py` inspects the JSON body and
treats `ok: false` or `status: rejected` as failure.

The n8n validation node should use:

```javascript
const expectedToken = $vars.RELAY_WEBHOOK_TOKEN || 'REPLACE_WITH_RELAY_TOKEN';
```

Do not enable broad Code-node environment-variable access just for this token.

When debugging rollback mode, confirm the relay env and config token sources
are not drifting. Do not print token values:

```bash
ssh <relay_user>@10.88.8.8 'sudo python3 - <<'"'"'PY'"'"'
import hashlib, json
from pathlib import Path
cfg=json.loads(Path("/opt/so-alert-relay/app/config.json").read_text())
env={}
for line in Path("/etc/so-alert-relay/relay.env").read_text().splitlines():
    if line.strip() and not line.startswith("#") and "=" in line:
        k,v=line.split("=",1)
        env[k]=v.strip().strip("\"").strip("'")
for label, token in [("config", cfg.get("webhook",{}).get("token") or ""), ("env", env.get("RELAY_WEBHOOK_TOKEN") or "")]:
    print(label, "len", len(token), "sha256_12", hashlib.sha256(token.encode()).hexdigest()[:12])
PY'
```

For high-volume bursts, the wrapper must have enough time to commit each bounded
alert batch. Keep these timeout controls in
`/etc/so-alert-relay/relay.env`:

```bash
RELAY_COMMAND_TIMEOUT_SECONDS=300
RELAY_PCAP_TIMEOUT_SECONDS=43200
RELAY_FAILURE_NOTIFY_THRESHOLD=3
```

Do not pass `RELAY_WEBHOOK_TOKEN` on the command line. It is unused in preferred
SSH mode. If rollback mode is enabled, `relay.py` reads it from
`/etc/so-alert-relay/relay.env` so process listings do not expose token material.

## 5. Harden Pi SSH

Apply this only after confirming at least one admin public key exists in:

```text
/home/aj/.ssh/authorized_keys
```

Install the key-only SSH drop-in:

```bash
sudo cp relay/ssh/99-key-only-admin.conf /etc/ssh/sshd_config.d/99-key-only-admin.conf
sudo chmod 0644 /etc/ssh/sshd_config.d/99-key-only-admin.conf
sudo sshd -t
sudo systemctl reload ssh
```

Expected effective settings:

```bash
sudo sshd -T | egrep '^(port|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitrootlogin) '
```

```text
port 22
permitrootlogin no
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
```

Verify from an admin workstation:

```bash
ssh -o BatchMode=yes \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o PreferredAuthentications=publickey \
  <relay_user>@10.88.8.8 'echo key_auth_ok'
```

Live hardening applied on 2026-07-01:

```text
Drop-in: /etc/ssh/sshd_config.d/99-key-only-admin.conf
Backup:  /etc/ssh/sshd_config.backup-before-key-only-20260701-202624Z
Result:  public-key login verified, password auth disabled, port 22 still open
```

## 6. Verify From Admin Mac

From this repo on the admin Mac:

```bash
PI_HOST=<relay_user>@10.88.8.8 \
SO_HOST=<security_onion_user>@192.168.1.7 \
MAC_HOST=<mac_user>@10.77.7.225 \
./operations/verify-stack.zsh
```

### Non-Destructive SQLite Restore Drill

Run this after storage, maintenance, or alert-store ownership changes. It uses
SQLite's online backup API, validates the copy independently, and deletes the
temporary drill artifact. It does not stop services or modify production data.

```bash
ssh <mac_user>@10.77.7.225 'bash -s' <<'REMOTE'
set -euo pipefail
db="$HOME/n8n-local/alert_store_data/alerts.sqlite3"
tmp="$(mktemp /tmp/onion-sentinel-dr-XXXXXX.sqlite3)"
trap 'rm -f "$tmp"' EXIT
test "$(sqlite3 "$db" "PRAGMA quick_check;")" = ok
sqlite3 "$db" ".backup '$tmp'"
test "$(sqlite3 "$tmp" "PRAGMA quick_check;")" = ok
test "$(sqlite3 "$tmp" "SELECT count(*) > 0 FROM sqlite_master WHERE type IN ('table','view');")" = 1
test -s "$tmp"
REMOTE
```

Also verify that `$HOME/n8n-local/alert_store_backups` contains recent
`alerts.sqlite3.*.backup` files and open the newest backup with
`PRAGMA quick_check`. Never copy those runtime backups into this repository.

### Post-Deployment Acceptance

Before declaring recovery complete, confirm all of the following:

- n8n and Onion Sentinel `/healthz` endpoints return success;
- alert-store production SQLite and the newest maintenance backup pass
  `PRAGMA quick_check`;
- both `so-alert-poll.timer` and `so-pcap-broker.timer` are active, their last
  service results are successful, and the dedicated PCAP spool is below its
  75 percent high-water mark with at least 200 GiB free;
- alert-store `/metrics` reports no sustained ingest errors or stale durable
  AI/enrichment/PCAP work, its `pipeline` stages expose bounded queue age and
  throughput, and known backlog does not project Mac disk use to 75 percent;
- Security Onion's restricted read-only export wrapper is enabled, the obsolete
  Onion Sentinel retention timer is disabled, no Onion Sentinel packet artifact
  exists under `/nsm`, and the latest Zeek capture-loss interval remains below
  the configured protection threshold during a controlled export;
- System Health records recent successful beacons and exposes historical gaps;
- desktop and mobile SOC Alerts can sort, expand details, reload without stale
  row expansion, and open the suppression modal without viewport zoom.

## SD Card Failure Note

The Pi previously dropped into recovery shell after reboot and recovered with:

```bash
e2fsck -f -y /dev/mmcblk0p7
sync
reboot -f
```

If this repeats, replace or reimage the SD card before trusting the Pi as the production relay.
