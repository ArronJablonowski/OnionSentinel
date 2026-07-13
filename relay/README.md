# Raspberry Pi Relay Node

The relay is intentionally dumb and reliable. It pulls alerts from Security Onion through restricted SSH and POSTs new alerts to the Mac Studio n8n webhook. If a timer run has no new alerts, it sends a small heartbeat payload instead so Onion Sentinel can prove the relay and n8n path are still alive. Filtering, scoring, suppression, AI analysis, reporting, and Telegram notification decisions belong to n8n/alert-store on the Mac Studio.

## Files

| File | Destination | Purpose |
| --- | --- | --- |
| `app/relay.py` | `/opt/so-alert-relay/app/relay.py` | Pulls alert JSON and posts new alerts or quiet-cycle heartbeats. |
| `app/relay_health_wrapper.py` | `/opt/so-alert-relay/app/relay_health_wrapper.py` | Adds failure/recovery notification thresholding. |
| `config/config.example.json` | `/opt/so-alert-relay/app/config.json` | Non-secret relay config. |
| `config/relay.example.env` | `/etc/so-alert-relay/relay.env` | Secret-bearing env template. Do not commit live copy. |
| `systemd/so-alert-relay.service` | `/etc/systemd/system/so-alert-relay.service` | One relay execution. |
| `systemd/so-alert-relay.timer` | `/etc/systemd/system/so-alert-relay.timer` | Runs relay every 5 minutes. |
| `ssh/99-key-only-admin.conf` | `/etc/ssh/sshd_config.d/99-key-only-admin.conf` | Optional SSH hardening after deployment is confirmed. |

## Install

```bash
cd /path/to/OnionSentinel
sudo relay/bin/install-pi-relay.sh
```

Then install the Security Onion private key:

```bash
sudo install -o soalert -g soalert -m 0600 /path/to/so-ai-relay_ed25519 /opt/so-alert-relay/keys/so-ai-relay_ed25519
```

If PCAP fulfillment is enabled later, install a separate forced-command key for
that path:

```bash
sudo install -o soalert -g soalert -m 0600 /path/to/so-ai-relay-pcap_ed25519 /opt/so-alert-relay/keys/so-ai-relay-pcap_ed25519
```

Install a third dedicated read-only artifact transfer key for rsyncing prepared
PCAP tar files from Security Onion to the relay SSD spool:

```bash
sudo install -o soalert -g soalert -m 0600 /path/to/so-ai-relay-pcap-rsync_ed25519 /opt/so-alert-relay/keys/so-ai-relay-pcap-rsync_ed25519
```

Edit the live env file:

```bash
sudo nano /etc/so-alert-relay/relay.env
sudo chmod 0640 /etc/so-alert-relay/relay.env
sudo chown root:soalert /etc/so-alert-relay/relay.env
```

Required live values:

- `RELAY_WEBHOOK_URL`
- `RELAY_WEBHOOK_TOKEN`
- `TELEGRAM_BOT_TOKEN` for relay health notifications
- `TELEGRAM_CHAT_ID` for relay health notifications

## Validate

```bash
sudo -u soalert /usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --pull-once
sudo systemctl start so-alert-relay.service
sudo journalctl -u so-alert-relay.service -n 50 --no-pager
sudo systemctl enable --now so-alert-relay.timer
```

Quiet timer cycles should log `posted_webhook_heartbeat: true`. Alert cycles
should log `posted_webhook_alerts` greater than zero. Either path updates the
Mac Studio `n8n-beacon.json` used by dashboard health.

## Webhook Retry Behavior

The relay retries transient webhook failures before giving the timer run back to
systemd. Defaults live in `config/config.example.json`:

```json
"retry_attempts": 3,
"retry_backoff_seconds": 1.5,
"retry_max_backoff_seconds": 10
```

HTTP `408`, `409`, `425`, `429`, and `5xx` responses are retried. Client/auth
errors such as `400`, `401`, and `403` fail immediately because another retry
would repeat the same bad request. Each alert is marked seen only after its own
successful POST, so a partial-batch failure resumes with the remaining unposted
alerts on the next timer run.

## PCAP Broker

PCAP fulfillment is disabled by default in `config/config.example.json`:

```json
"pcap_broker": {
  "enabled": false,
  "url": "http://10.77.7.225:5678/webhook",
  "requests_method": "POST",
  "upload_artifact": true,
  "artifact_upload_mode": "spooled_rsync",
  "artifact_spool_dir": "/mnt/onion-sentinel-pcap-spool/pcap",
  "artifact_spool_max_bytes": 8589934592,
  "artifact_spool_min_free_bytes": 3221225472,
  "artifact_spool_delete_after_upload": true,
  "artifact_spool_partial_ttl_seconds": 86400,
  "artifact_spool_completed_ttl_seconds": 3600,
  "mac_transfer": {
    "host": "10.77.7.225",
    "user": "__MAC_STUDIO_SSH_USER__",
    "ssh_key": "/opt/so-alert-relay/keys/macstudio-pcap-transfer_ed25519",
    "artifact_dir": "n8n-local/pcap-evidence/artifacts",
    "connect_timeout_seconds": 20,
    "rsync_timeout_seconds": 1800
  },
  "lock_path": "/tmp/onion-sentinel-pcap-broker.lock",
  "completion_retry_attempts": 3,
  "completion_retry_delay_seconds": 2,
  "paths": {
    "requests": "/pcap-requests",
    "claim": "/pcap-claim",
    "complete": "/pcap-complete"
  }
}
```

The matching `security_onion` config must include the dedicated artifact
transfer key:

```json
"security_onion": {
  "host": "192.168.1.7",
  "ssh_user": "so-ai-relay",
  "ssh_key": "/opt/so-alert-relay/keys/so-ai-relay_ed25519",
  "pcap_ssh_key": "/opt/so-alert-relay/keys/so-ai-relay-pcap_ed25519",
  "pcap_artifact_transfer": {
    "host": "192.168.1.7",
    "ssh_user": "so-ai-relay-pcap-rsync",
    "ssh_key": "/opt/so-alert-relay/keys/so-ai-relay-pcap-rsync_ed25519",
    "rsync_timeout_seconds": 1800
  }
}
```

When enabled, the relay polls a relay-safe n8n broker/proxy endpoint for pending
requests, claims one request at a time, sends the bounded JSON request to the
Security Onion forced-command PCAP key, pulls the exported artifact onto the
relay SSD spool with the dedicated read-only rsync key, and transfers the tar
to the Mac Studio with restricted SSH and `rsync`. The relay verifies artifact
size and SHA256 on both the relay spool and the Mac Studio before it reports
the request as fulfilled.

The relay SSD spool should be mounted outside the Pi SD card. The current
portable target is `/mnt/onion-sentinel-pcap-spool/pcap`, mounted with
`noatime,nosuid,nodev,noexec`. The default repo limit allows artifacts up to
8 GiB while keeping 3 GiB free. A 16 GiB SSD is sufficient for current
multi-hundred-MB captures, but the project should watch average and maximum
artifact sizes and upgrade the spool disk if captures regularly approach the
limit.

Successful relay-spooled `.tar` artifacts are deleted immediately after the
Mac Studio copy has been verified by size and SHA256. A checksum-valid artifact
is reused when the same request is retried after a Mac upload failure.
Interrupted `.tar.part` files are retained for 24 hours so rsync can resume
them with `--append-verify`. Completed artifacts abandoned by failed or lost
broker state are removed after one hour while the broker lock is held. Set the
corresponding TTL to `-1` only during controlled troubleshooting.

The `spooled_rsync` mode is the preferred data plane for large captures. n8n
remains the control plane for request, claim, and completion state, while SSH
and rsync move raw artifact bytes. The older n8n inline artifact upload route
and Security Onion chunk pull path have been removed because they are
fragile for large captures and can pressure workflow memory, HTTP body limits,
proxy timeouts, and relay memory.

Packet artifacts remain runtime evidence, not repo content. Use a separate
broker token from the alert ingestion token and store it only in the live relay
config and live n8n workflow.

The relay defensively filters broker responses to process only requests whose
status is `pending`. This keeps the PCAP broker safe if an n8n proxy returns a
mixed request history instead of a strict pending-only list. Legacy rows without
a status are treated as pending for compatibility.

Alert-store requeues stale `claimed` PCAP requests after the claim lease expires
so interrupted relay runs do not strand work forever. Tune the lease with
`PCAP_CLAIM_LEASE_SECONDS` on Mac Studio when very large captures need a longer
exclusive window.

PCAP export and artifact upload are tracked separately. If Security Onion
returns bounded capture metadata but artifact upload is temporarily unavailable,
the relay logs `pcap_artifact_upload_failed`, marks that PCAP request failed
with a retryable artifact upload error, and continues processing other requests.
After the Mac Studio confirms artifact ingest and the completion callback
succeeds, the relay asks the restricted Security Onion wrapper to delete only
that request id's temporary tar and work directory. Cleanup failures are logged
as `pcap_artifact_cleanup_failed` but do not convert an already-ingested request
back to failed.
Alert relay delivery and PCAP broker delivery are also isolated by the health
wrapper so one path does not mask the other.

The relay does not parse packet captures or call LLMs. After a fulfilled capture
is ingested into the Mac Studio runtime evidence directory, the Mac Studio
`process-pcap-evidence.py` worker runs Zeek and TShark and writes bounded
summaries for the SOC Analyst prompt package.

`relay_health_wrapper.py` runs alert delivery and PCAP fulfillment as separate
sub-steps on every timer cycle. A downstream alert webhook failure must not
skip PCAP broker processing, and a PCAP broker failure must not block normal
alert delivery. The wrapper exits nonzero if either sub-step fails so systemd,
journald, and relay health state still show degraded service.

The relay also validates n8n's webhook response body. n8n can return HTTP 200
for a workflow execution that rejected the payload inside the validation node,
such as a stale `X-Relay-Token`. If the response JSON contains `ok: false` or a
`rejected` status, the relay treats the run as failed so the wrapper can trigger
Telegram failure/recovery notifications. When both `/opt/so-alert-relay/app/config.json`
and `/etc/so-alert-relay/relay.env` contain webhook tokens, the wrapper checks
that they match before polling Security Onion.

High-volume bursts can take longer than a quiet heartbeat because n8n processes
each alert workflow before returning the webhook response. Large PCAP exports
also take longer than alert polling because the Security Onion wrapper validates
and serves artifacts in bounded chunks. Tune these in
`/etc/so-alert-relay/relay.env` when needed:

```bash
RELAY_COMMAND_TIMEOUT_SECONDS=300
RELAY_PCAP_TIMEOUT_SECONDS=1800
RELAY_FAILURE_NOTIFY_THRESHOLD=3
```

Do not pass the relay webhook token on the command line. The systemd wrapper
passes only the webhook URL; `relay.py` reads `RELAY_WEBHOOK_TOKEN` from the
service environment so process listings do not expose token material.

PCAP SSH runs under the service account used for the broker command. If the
broker is invoked with `sudo`, make sure the Security Onion host key is present
in that account's `known_hosts`; otherwise PCAP export will fail before the
forced-command wrapper receives the request.

## Firewall Needs

From relay `10.88.8.8`:

- to Security Onion `192.168.1.7:22/tcp`
- to Mac Studio `10.77.7.225:5678/tcp`
- to DNS `53/tcp,udp`
- to `api.telegram.org:443/tcp` if relay health notifications are enabled
