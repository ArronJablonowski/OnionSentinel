# Onion Sentinel Application Logging

Onion Sentinel writes structured, timestamped JSON Lines records for the web
application, alert-store, and investigation harness. LaunchAgent stdout/stderr
files remain available for boot failures, but the JSONL files are the primary
troubleshooting record.

## Runtime files

| Component | File |
|---|---|
| Web application | `~/n8n-local/logs/onion-sentinel-application.jsonl` |
| Alert-store | `~/n8n-local/logs/alert-store-application.jsonl` |
| Investigation harness | `~/n8n-local/logs/investigation-harness.jsonl` |
| Authoritative harness audit ledger | `~/n8n-local/alert_store_data/investigation-harness.sqlite3` |

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

Application logs rotate at 10 MiB with five retained generations by default.
The alert-store limits can be changed with
`ALERT_STORE_APPLICATION_LOG_MAX_BYTES` and
`ALERT_STORE_APPLICATION_LOG_BACKUPS`.

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
