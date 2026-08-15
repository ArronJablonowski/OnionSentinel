# Onion Sentinel Application Logging

Onion Sentinel writes structured, timestamped JSON Lines records for the web
application, alert-store, and investigation harness. LaunchAgent stdout/stderr
files remain available for boot failures, but the JSONL files are the primary
troubleshooting record.

## Owned inventory and policy

`application_log_contract.py` is the machine-readable inventory used by the
maintenance job, the authenticated API, and the Logs page. Every entry names
its purpose, owner, path class, format, active-file maximum, rotation,
compression, retention, and disk-pressure behavior. The two admitted path
classes are:

- `runtime`: owner-controlled regular files below `~/n8n-local/logs`;
- `analysis-audit`: the AI transcript audit below
  `~/n8n-local/soc-alerts/llm-analysis-logs`.

The complete structured inventory is:

| Owner / purpose | File | Format | Active maximum | Rotation and retention |
|---|---|---|---:|---|
| Onion Sentinel web service / HTTP and audited application events | `logs/onion-sentinel-application.jsonl` | JSONL | 10 MiB | Producer rotation; current plus 5 numbered files |
| Alert Store / lifecycle, API, and persistence events | `logs/alert-store-application.jsonl` | JSONL | 10 MiB default | Producer rotation; configured size 1 MiB–1 GiB and 1–20 numbered files |
| Investigation harness / execution and outcome events | `logs/investigation-harness.jsonl` | JSONL | 10 MiB | Producer rotation; current plus 5 numbered files |
| Software Inventory / collection events | `logs/software-inventory.jsonl` | JSONL | 10 MiB | Producer rotation; current plus 5 numbered files |
| Endpoint Software Inventory / scheduled endpoint retry and preflight events | `logs/endpoint-software-inventory.jsonl` | JSONL | 10 MiB | Producer rotation; current plus 5 numbered files |
| DHCP discovery / collection events | `logs/dhcp-asset-discovery.jsonl` | JSONL | 10 MiB | Producer rotation; current plus 5 numbered files |
| DHCP review / operator decisions | `logs/dhcp-asset-review.jsonl` | JSONL | 10 MiB | Producer rotation; current plus 5 numbered files |
| Security Onion query client / redacted query lifecycle | `logs/security-onion-query.jsonl` | JSONL | 10 MiB | Producer rotation; current plus 5 numbered files |
| Operational SLO evaluator / bounded health snapshots | `logs/operational-slo-history.jsonl` | JSONL | 64 MiB safety ceiling | Producer rewrites the latest 4,032 samples, approximately 14 days |
| AI analysis workers / transcript audit | `soc-alerts/llm-analysis-logs/llm-analysis-log.jsonl` | JSONL | 50 MiB | Maintenance copy-truncate; current plus 10 gzip files, maximum 30 days |

Every installed LaunchAgent has both a `runtime` text stdout file and a text
stderr file. The names are `<stem>.out.log` and `<stem>.err.log`; each is owned
by the named job, rotates at 10 MiB, retains five gzip generations for at most
30 days, and is pruned oldest-first under disk pressure:

| Stem | Owner / purpose |
|---|---|
| `launchd-ensure-stack` | Stack ensure scheduler |
| `launchd-monitor-stack` | Stack monitor |
| `harness-maintenance` | Harness database maintenance |
| `evaluation-artifact-maintenance` | Evaluation artifact retention and capacity monitoring |
| `runtime-backup` | Runtime backup |
| `onion-sentinel-web-guard` | Web recovery supervisor |
| `onion-sentinel-web` | Web service bootstrap output |
| `ac-hunter` | AC Hunter collector |
| `ai-analysis-cli` | Interactive AI worker |
| `ai-analysis` | Scheduled AI worker |
| `alert-store-maintenance` | Alert Store database maintenance |
| `alert-store-host` | Alert Store service bootstrap output |
| `daily-rollup` | Daily SOC rollup |
| `dashboard-refresh` | Static dashboard refresh |
| `dhcp-asset-discovery` | DHCP collector bootstrap output |
| `endpoint-software-inventory` | Endpoint Software Inventory collector |
| `pcap-analysis` | PCAP worker |
| `pcap-retention` | Local PCAP evidence retention |
| `software-inventory` | General Software Inventory collector |
| `application-log-maintenance` | This bounded rotation/cleanup job |

Two additional `runtime` text families are cataloged. Alert Store SQLite
maintenance output (`alert-store-sqlite-maintenance.log`) follows the same
10 MiB / five-gzip / 30-day maintenance policy. Timestamped
`ensure-n8n-stack-*.log` run files are owned by the stack ensure scheduler,
have a documented 10 MiB per-file ceiling, and are deleted after 30 days by the
ensure job. The authoritative harness ledger is not a log-page file; it remains
the owner-only hash-chained SQLite database at
`~/n8n-local/alert_store_data/investigation-harness.sqlite3`.

Every JSONL record contains:

- `timestamp`: UTC ISO 8601 with millisecond precision and timezone;
- `timestamp_epoch_ms`: numeric time for sorting and correlation;
- `level`, `service`, `process_id`, and `event`;
- request, release, run, stage, sequence, and correlation fields when relevant;
- elapsed request duration where applicable.

HTTP logs include only the normalized path, not the query string or body.
Harness JSONL records mirror committed event metadata and hashes, not prompts,
raw evidence, model responses, or tool output. The SQLite harness ledger
remains the authoritative hash-chained audit record.

## Security controls

- Files and rotation locks are owner-only mode `0600`.
- Parent log directories are owner-only when newly created.
- Keys containing password, token, cookie, authorization, API key, secret, or
  credential are recursively replaced with `[REDACTED]`.
- Secret-looking `key=value` fragments in text are also redacted.
- Strings, arrays, objects, and nesting depth are bounded.
- Logger failures never terminate the alert-store, web service, or committed
  harness work.
- Alert-store and web access logs never record request bodies or authorization
  headers.

Structured application logs rotate at 10 MiB with five retained generations
by default. The alert-store limits can be changed with
`ALERT_STORE_APPLICATION_LOG_MAX_BYTES` and
`ALERT_STORE_APPLICATION_LOG_BACKUPS`.

The hourly `com.arron.onion-sentinel.application-log-maintenance` LaunchAgent
owns files not rotated by their producers. It uses a non-overlapping owner-only
lock, fixed allowlisted basenames, `O_NOFOLLOW` regular-file checks, gzip
archives written and fsynced before publication, and copy-truncate for active
LaunchAgent streams. Each admitted current file is hardened to mode `0600` on
an applying pass. A rotation archives only the newest configured active-file
maximum, so an unexpectedly oversized file cannot create an unbounded archive.
Archives older than their policy are deleted. At 75% filesystem use, older gzip
generations are pruned first while the current file and newest archive remain.
The job emits only log IDs, byte counts, actions, and safe errors—not file
contents, credentials, or raw evidence.

Preview log-file actions without mutating any log, or apply the exact policy
(both modes take the owner-only non-overlap lock):

```bash
/usr/bin/python3 "$HOME/n8n-local/bin/maintain-application-logs.py" \
  --stack-dir "$HOME/n8n-local"
/usr/bin/python3 "$HOME/n8n-local/bin/maintain-application-logs.py" \
  --stack-dir "$HOME/n8n-local" --apply
```

The Logs page reads only fixed IDs and fixed current/archive members. It offers
bounded 100/200/500-line backward pages, decompresses gzip members under each
entry's expansion ceiling, redacts credential patterns, and never accepts a
filesystem path. Relay journald, Security Onion logs, and Docker engine logs
remain separate operational sources: the page neither ingests nor mutates
them, and Onion Sentinel never applies this retention policy to those systems.

## Common troubleshooting commands

```bash
tail -n 100 "$HOME/n8n-local/logs/alert-store-application.jsonl"
tail -n 100 "$HOME/n8n-local/logs/onion-sentinel-application.jsonl"
tail -n 100 "$HOME/n8n-local/logs/investigation-harness.jsonl"
```

Filter one harness run:

```bash
jq -c 'select(.run_id == "RUN_ID")' \
  "$HOME/n8n-local/logs/investigation-harness.jsonl"
```

Filter errors across application logs:

```bash
jq -c 'select(.level == "error" or .level == "critical")' \
  "$HOME/n8n-local/logs/"*-application.jsonl
```

Do not copy production logs into Git, evaluation packages, model prompts, or
support tickets without reviewing them for alert identifiers, IP addresses,
hostnames, and other environment-specific security data.
