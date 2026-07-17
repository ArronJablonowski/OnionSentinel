# Raspberry Pi Relay Node

The relay is intentionally dumb and reliable. It pulls alerts from Security
Onion through restricted SSH, commits them to its local outbox, and delivers
bounded batches through a second forced-command SSH key to the host-native Mac
Studio alert-store. If a timer run has no new alerts, it sends a small heartbeat
through the same durable path. Filtering, scoring, suppression, AI analysis,
reporting, and Telegram notification decisions remain on the Mac Studio.

n8n is deliberately after the alert-store commit boundary. A committed alert
queues a durable `n8n_post_commit` job; n8n writes the Markdown report later.
An n8n outage therefore cannot roll back alert persistence or make the relay
replay a safely committed alert.

## Files

| File | Destination | Purpose |
| --- | --- | --- |
| `app/relay.py` | `/opt/so-alert-relay/app/relay.py` | Pulls alert JSON and submits new alerts or quiet-cycle heartbeats. |
| `app/alert_outbox.py` | `/opt/so-alert-relay/app/alert_outbox.py` | Durable, idempotent SQLite delivery outbox and poison-message dead letter. |
| `app/alert_delivery.py` | `/opt/so-alert-relay/app/alert_delivery.py` | Bounded SSH batch transport with strict host-key pinning and per-item acknowledgements. |
| `app/relay_health_wrapper.py` | `/opt/so-alert-relay/app/relay_health_wrapper.py` | Adds failure/recovery notification thresholding. |
| `config/config.example.json` | `/opt/so-alert-relay/app/config.json` | Non-secret relay config. |
| `config/relay.example.env` | `/etc/so-alert-relay/relay.env` | Secret-bearing env template. Do not commit live copy. |
| `systemd/so-alert-poll.service` | `/etc/systemd/system/so-alert-poll.service` | One alert poll/outbox/heartbeat execution. |
| `systemd/so-alert-poll.timer` | `/etc/systemd/system/so-alert-poll.timer` | Runs alert polling every 5 minutes. |
| `systemd/so-pcap-broker.service` | `/etc/systemd/system/so-pcap-broker.service` | One independent PCAP broker execution. |
| `systemd/so-pcap-broker.timer` | `/etc/systemd/system/so-pcap-broker.timer` | Runs PCAP work every minute. |
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

Do not install the former Security Onion staged-artifact rsync key. The current
forced-command PCAP key streams directly into the relay SSD.

Edit the live env file:

```bash
sudo nano /etc/so-alert-relay/relay.env
sudo chmod 0640 /etc/so-alert-relay/relay.env
sudo chown root:soalert /etc/so-alert-relay/relay.env
```

Required live values:

- `TELEGRAM_BOT_TOKEN` for relay health notifications
- `TELEGRAM_CHAT_ID` for relay health notifications

`RELAY_WEBHOOK_URL` and `RELAY_WEBHOOK_TOKEN` are needed only while the legacy
HTTP rollback transport is enabled. The preferred SSH intake carries no shared
application token on the Pi.

Create a dedicated key for alert intake. Do not reuse the admin, Security Onion
alert-export, PCAP-export, or PCAP-transfer keys:

```bash
sudo -u soalert ssh-keygen -t ed25519 -N '' \
  -f /opt/so-alert-relay/keys/macstudio-alert-ingest_ed25519 \
  -C onion-sentinel-alert-intake@relay
```

Pin the Mac Studio ED25519 host key in
`/opt/so-alert-relay/keys/macstudio_known_hosts`. Compare the fingerprint from
`ssh-keyscan` on the Pi with `/etc/ssh/ssh_host_ed25519_key.pub` through an
already trusted Mac admin session before installing it. Never use
`StrictHostKeyChecking=no` for this path.

Install the dedicated public key on the Mac Studio with the repo's backup-first
helper:

```bash
ssh <relay_user>@10.88.8.8 \\
  'sudo cat /opt/so-alert-relay/keys/macstudio-alert-ingest_ed25519.pub' |
  "$HOME/n8n-local/bin/install-alert-intake-authorized-key.py"
```

Do not append escaped `\\n` strings to `authorized_keys`. The installer
preserves existing records, replaces only the managed alert-intake entry,
creates a mode-0600 backup, and writes one real newline-delimited record per
key. The entry restricts the source to `10.88.8.8`, forces the intake wrapper,
and denies shells, PTYs, user rc files, X11, agent forwarding, and port
forwarding.

Enable the preferred transport in the live `config.json` only after that key
and host pin are verified:

```json
"alert_ingest": {
  "enabled": true,
  "mode": "ssh_batch",
  "host": "10.77.7.225",
  "user": "__MAC_STUDIO_SSH_USER__",
  "ssh_key": "/opt/so-alert-relay/keys/macstudio-alert-ingest_ed25519",
  "known_hosts": "/opt/so-alert-relay/keys/macstudio_known_hosts",
  "remote_command": "onion-sentinel-alert-intake batch",
  "connect_timeout_seconds": 20,
  "request_timeout_seconds": 180,
  "batch_max_items": 100,
  "batch_max_bytes": 8388608
}
```

## Validate

```bash
sudo -u soalert /usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --pull-once
sudo systemctl start so-alert-poll.service
sudo journalctl -u so-alert-poll.service -n 50 --no-pager
sudo systemctl enable --now so-alert-poll.timer so-pcap-broker.timer
```

Quiet timer cycles should report a successfully acknowledged heartbeat. Alert
cycles should report delivered outbox items with no new dead letters. Either
path updates the Mac Studio `n8n-beacon.json` used by dashboard health.
The installer disables the legacy combined `so-alert-relay.timer`; alert and
PCAP failures therefore cannot block one another's schedule.

## Durable Alert Delivery

The relay records every alert before attempting network delivery. The preferred
transport splits due outbox rows by both item count and encoded bytes, opens a
non-interactive SSH session, and requires one acknowledgement for every
delivery ID. Missing acknowledgements, connection loss, timeout, and Mac
`408`, `425`, `429`, `5xx`, or `507` responses stay retryable. Permanent
validation failures move only that item to the dead-letter table so a poison
message cannot block the rest of the queue.

The legacy HTTP webhook remains disabled but intact for controlled rollback.
Its bounded retry defaults live in `config/config.example.json`:

```json
"retry_attempts": 3,
"retry_backoff_seconds": 1.5,
"retry_max_backoff_seconds": 10
```

HTTP `408`, `409`, `425`, `429`, and `5xx` responses are retried. Client/auth
errors such as `400`, `401`, and `403` fail immediately. Expired delivery
leases are requeued after a crash. `alert_id` is the outbox idempotency key, so
a partial-batch failure resumes only undelivered alerts.

## PCAP Broker

PCAP fulfillment is disabled by default in `config/config.example.json`:

```json
"pcap_broker": {
  "enabled": false,
  "url": "http://10.77.7.225:5678/webhook",
  "requests_method": "POST",
  "upload_artifact": true,
  "artifact_upload_mode": "streamed_chunks",
  "artifact_spool_dir": "/mnt/onion-sentinel-pcap-spool/pcap",
  "artifact_spool_require_mount": true,
  "artifact_spool_max_bytes": 137438953472,
  "artifact_spool_min_free_bytes": 214748364800,
  "artifact_spool_max_used_percent": 75,
  "artifact_spool_delete_after_upload": true,
  "artifact_spool_partial_ttl_seconds": 86400,
  "artifact_spool_completed_ttl_seconds": 86400,
  "transfer_retry_base_seconds": 30,
  "transfer_retry_max_seconds": 1800,
  "security_onion_storage_telemetry": true,
  "capture_protection_enabled": true,
  "capture_protection_require_telemetry": true,
  "capture_loss_threshold_percent": 0.1,
  "sensor_packet_loss_threshold_percent": 0.1,
  "capture_loss_freshness_seconds": 900,
  "stream_chunk_idle_timeout_seconds": 300,
  "mac_transfer": {
    "host": "10.77.7.225",
    "user": "__MAC_STUDIO_SSH_USER__",
    "ssh_key": "/opt/so-alert-relay/keys/macstudio-pcap-transfer_ed25519",
    "artifact_dir": "n8n-local/pcap-evidence/artifacts",
    "connect_timeout_seconds": 20,
    "rsync_timeout_seconds": 1800,
    "minimum_bytes_per_second": 2097152,
    "max_bytes_per_second": 4194304
  },
  "lock_path": "/tmp/onion-sentinel-pcap-broker.lock",
  "limit": 1,
  "completion_retry_attempts": 3,
  "completion_retry_delay_seconds": 2,
  "paths": {
    "requests": "/pcap-requests",
    "claim": "/pcap-claim",
    "progress": "/pcap/progress",
    "retry": "/pcap-retry",
    "complete": "/pcap-complete"
  }
}
```

The matching `security_onion` config needs only the separate forced-command
PCAP stream key:

```json
"security_onion": {
  "host": "192.168.1.7",
  "ssh_user": "so-ai-relay",
  "ssh_key": "/opt/so-alert-relay/keys/so-ai-relay_ed25519",
  "pcap_ssh_key": "/opt/so-alert-relay/keys/so-ai-relay-pcap_ed25519"
}
```

When enabled, the relay polls a relay-safe n8n broker/proxy endpoint for pending
requests, claims one request at a time, sends the bounded JSON request to the
Security Onion forced-command PCAP key, and requests one filtered rotation
stream at a time. SSH stdout is written directly to the external relay SSD.
Manifest entries carry Security Onion-signed chunk capabilities, so capture
directory rotation between the manifest and a later chunk does not force a
rescan or invalidate an otherwise available source file. The relay cannot alter
the authorized source inode, request window, or BPF variant without rejection.
Completed chunks are hashed and checkpointed, so an interrupted request resumes
without rebuilding prior chunks. The relay assembles the compatible tar on its
SSD, then transfers it to the Mac Studio with restricted SSH and resumable
`rsync`. Security Onion stages zero bytes. The relay and Mac verify size and
SHA256 before the request is reported fulfilled.

The relay SSD spool should be mounted outside the Pi SD card. The current
portable target is `/mnt/onion-sentinel-pcap-spool/pcap`, mounted with
`noatime,nosuid,nodev,noexec`. The current production profile uses a 1 TB ext4
SSD. The zero-staging profile permits a 128 GiB relay artifact, reserves
at least 200 GiB free, and stops projected usage at 75 percent. Security Onion
itself never stores this artifact. The wrapper considers at most 12 source
rotations bounded to 1.1 GiB each, so the practical stream input remains below
the Mac parser's 40 GiB expanded-data limit. Keep watching average and maximum
capture size before changing any bound.

Mount by filesystem UUID so USB enumeration changes cannot redirect the spool
onto the SD card. Replace the placeholder with `blkid` output for the installed
SSD:

```text
UUID=REPLACE_WITH_SPOOL_UUID /mnt/onion-sentinel-pcap-spool ext4 defaults,noatime,nosuid,nodev,noexec,nofail,x-systemd.device-timeout=30s 0 2
```

The PCAP worker has an explicit `RequiresMountsFor` dependency on the spool,
but the alert poller does not. A missing or slow USB SSD can therefore delay or
fail PCAP work without delaying alert delivery. The installer also retains a
size-capped 14 days of journald data so reboot, USB, and mount failures remain
available after a hard power cycle.

The production Sabrent USB bridge may take about 30 seconds to enumerate after
power-on. This is acceptable with the current three-minute PCAP worker startup
delay. Repeated UAS resets, I/O errors, or a need for hard power cycles are not
normal; capture the previous boot before changing USB transport behavior:

```bash
sudo journalctl -b -1 -k --no-pager | grep -Ei 'usb|uas|scsi|sd[a-z]|I/O error|reset|under.?voltage'
vcgencmd get_throttled
systemd-analyze time
```

Install and enable SMART monitoring when the relay VLAN has controlled package
repository access. Auto-detection works for the current NVMe SSD through its
Sabrent USB bridge; do not force an ATA device mode unless auto-detection fails:

```bash
sudo apt-get install smartmontools
sudo systemctl enable --now smartmontools.service
sudo smartctl -H /dev/sda
sudo smartctl -a -j /dev/sda
```

Treat a failed health assessment, media errors, rising critical warnings, or
unexpected unsafe shutdown counts as a maintenance condition. SMART is an
additional signal and does not replace the relay's mount, capacity, checksum,
and write-path checks.

The installer enables `so-storage-health.timer` for an independent five-minute
check. It verifies the root SD-card reserve, confirms that the spool resolves
to an external block device rather than the SD card, enforces capacity and temperature thresholds, and reads SMART
through one exact passwordless sudo command. Storage failures and recoveries
use the existing stateful Telegram health path without affecting alert polling
or PCAP broker scheduling. Portable defaults are:

```text
RELAY_ROOT_MIN_FREE_BYTES=2147483648
RELAY_ROOT_WARN_USED_PERCENT=75
RELAY_ROOT_HARD_USED_PERCENT=80
RELAY_SSD_MIN_FREE_BYTES=214748364800
RELAY_SSD_MAX_USED_PERCENT=75
RELAY_SSD_MAX_TEMPERATURE_C=70
RELAY_SSD_MAX_UNSAFE_SHUTDOWNS=0
```

If an SSD already has a known nonzero unsafe-shutdown baseline, set the last
value to that audited count. A later increase will then trigger the monitor.
Do not increase the baseline merely to clear an unexplained alarm.

Relay-owned batch and per-alert JSON evidence is retained for seven days by
default. Every alert and PCAP worker run prunes older files before checking the
root filesystem admission guard. New relay writes stop at 75 percent so the SD
card cannot cross the 80 percent hard ceiling during normal operation.

```bash
sudo mkdir -p /mnt/onion-sentinel-pcap-spool
sudo mount /mnt/onion-sentinel-pcap-spool
sudo chown root:soalert /mnt/onion-sentinel-pcap-spool
sudo chmod 0750 /mnt/onion-sentinel-pcap-spool
sudo install -d -o soalert -g soalert -m 0750 /mnt/onion-sentinel-pcap-spool/pcap
sudo systemctl daemon-reload
sudo systemctl enable --now so-storage-health.timer
sudo systemctl start so-storage-health.service
sudo systemctl status so-storage-health.service --no-pager
sudo findmnt --verify
```

Do not start `so-pcap-broker.timer` unless `findmnt` confirms the spool source
is the intended external disk and a write/read/delete test succeeds as
`soalert`. This prevents an absent USB disk from sending large writes to the SD
card through an empty fallback mount directory.

Successful relay-spooled `.tar` artifacts are deleted only after the Mac Studio
copy passes size/SHA256 verification and alert-store durably acknowledges the
fulfilled completion callback. A checksum-valid artifact is reused when the
same request is retried after a Mac upload or callback failure. If the Mac
rejects the copied bytes, the relay uses the restricted intake wrapper to
remove only that request directory and performs one checksum-forced clean
retry. It never weakens the size or SHA256 gate.
Interrupted `.tar.part` files are retained for 24 hours so rsync can resume
them with `--append-verify`. Completed artifacts abandoned by failed or lost
broker state are removed after 24 hours while the broker lock is held. Set the
corresponding TTL to `-1` only during controlled troubleshooting.

Transient export, SSH, rsync, timeout, and checksum failures are returned to
alert-store through `/pcap-retry`. Alert-store preserves transfer stage and byte
progress, applies bounded exponential backoff, and permits five attempts by
default. No-packets, expired, oversize, and rejected outcomes remain terminal.
The relay never deletes a retryable spool artifact merely because one attempt
or completion callback failed.

The `streamed_chunks` mode is the required data plane. n8n remains the control
plane for request, claim, progress, and completion state. Restricted SSH moves
one bounded filtered rotation from Security Onion to the relay SSD; rsync moves
the completed relay artifact to the Mac. The older n8n inline route and Security
Onion tar-staging path are disabled because they can pressure workflow memory,
HTTP limits, relay memory, and most importantly Security Onion `/nsm` capacity.

The Security Onion wrapper combines tagged and untagged tuple filters into one
scan, caps source reads at 4 MiB/s, uses idle I/O priority, and allows one stream.
Before claiming work and between chunks, the relay requires fresh latest-interval
Zeek capture-loss telemetry plus local Zeek and Suricata packet-loss telemetry.
It returns a healthy protected deferral when the sample is missing, stale, or
above its threshold. The completed relay artifact is rsynced to the Mac at no
more than 4 MiB/s by default, with an 8 MiB/s code-enforced maximum. This
second ceiling is mandatory because the
relay-to-Mac VLAN flow is visible to the Security Onion mirror; an uncapped
cached artifact can otherwise saturate a 1 Gb/s SPAN destination even though
the earlier Security Onion read was throttled. The PCAP timer waits one minute
after each oneshot exits and the broker processes at most one request per run.
The shorter idle interval improves burst recovery while the single-flight
lock, bandwidth ceilings, and capture-loss gate prevent concurrent or unsafe
source reads.

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

The relay posts a metadata-only progress heartbeat every 30 seconds while an
export, rsync leg, or checksum verification is active. The heartbeat renews the
claim lease and lets System Health distinguish a live large-file transfer from
a stalled request. Packet bytes never traverse n8n.

PCAP streaming and Mac artifact upload are tracked separately. If a chunk stream
or Mac upload is interrupted, the relay retains its hashed checkpoint on the
external SSD and retries without creating source-side recovery state. After the
Mac confirms artifact ingest, the relay removes its tar and stream sidecar. No
Security Onion cleanup callback is needed because the production path writes no
Security Onion artifact.

`stream_chunk_idle_timeout_seconds` is a no-progress threshold, not a maximum
transfer duration. Every increase in the relay partial-file size resets it, so
a healthy Security Onion read continues until the available capture is read.
Alert relay delivery and PCAP broker delivery are also isolated by the health
wrapper so one path does not mask the other.

The relay does not parse packet captures or call LLMs. After a fulfilled capture
is ingested into the Mac Studio runtime evidence directory, the Mac Studio
`process-pcap-evidence.py` worker runs Zeek and TShark and writes bounded
summaries for the SOC Analyst prompt package.

`relay_health_wrapper.py` runs alert delivery and PCAP fulfillment as separate
sub-steps on every timer cycle. A Mac forced-intake failure must not skip PCAP
broker processing, and a PCAP broker failure must not block normal alert
delivery. The wrapper exits nonzero if either sub-step fails so systemd,
journald, and relay health state still show degraded service.

For PCAP broker failures, the wrapper preserves both the bounded outcome
counters and the final structured transport error emitted by `relay.py`. This
lets operators distinguish an SSH, rsync, checksum, or Mac intake failure
without logging credentials or packet content. Historical `transport_failed`
events created before this behavior retain only their outcome counter.

The preferred alert path validates a protocol response containing exactly one
acknowledgement for every submitted delivery ID. Missing acknowledgements or a
lost SSH connection leave the corresponding outbox rows retryable. A permanent
per-item rejection moves only that item to the dead-letter queue, so malformed
input cannot block healthy alerts behind it.

The old HTTP transport still validates n8n's JSON response in addition to its
HTTP status, but it is rollback-only. Token drift checks run only in that mode.

High-volume bursts can take longer than a quiet heartbeat because alert-store
must commit each bounded item before acknowledging it. Large PCAP exports also
take longer than alert polling because the Security Onion wrapper validates and
serves artifacts in bounded chunks. Tune these in
`/etc/so-alert-relay/relay.env` when needed:

```bash
RELAY_COMMAND_TIMEOUT_SECONDS=300
RELAY_PCAP_TIMEOUT_SECONDS=43200
RELAY_FAILURE_NOTIFY_THRESHOLD=3
```

Do not pass the rollback webhook token on the command line. If emergency HTTP
rollback is enabled, `relay.py` reads `RELAY_WEBHOOK_TOKEN` from the service
environment so process listings do not expose token material.

PCAP SSH runs under the service account used for the broker command. If the
broker is invoked with `sudo`, make sure the Security Onion host key is present
in that account's `known_hosts`; otherwise PCAP export will fail before the
forced-command wrapper receives the request.

## Firewall Needs

From relay `10.88.8.8`:

- to Security Onion `192.168.1.7:22/tcp`
- to Mac Studio `10.77.7.225:22/tcp` for durable alert intake and artifact transport
- to Mac Studio `10.77.7.225:5678/tcp` for PCAP control metadata and emergency rollback
- to DNS `53/tcp,udp`
- to `api.telegram.org:443/tcp` if relay health notifications are enabled
