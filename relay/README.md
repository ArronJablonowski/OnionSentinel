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
| `app/relay_readiness.py` | `/opt/so-alert-relay/app/relay_readiness.py` | Bounded local-only power, thermal, kernel, storage, service, route, SSH-metadata, and broker-config readiness. |
| `config/config.example.json` | `/opt/so-alert-relay/app/config.json` | Runtime relay config seeded only on first install and preserved across upgrades. |
| `config/relay.example.env` | `/etc/so-alert-relay/relay.env` | Secret-bearing env template. Do not commit live copy. |
| `systemd/so-alert-poll.service` | `/etc/systemd/system/so-alert-poll.service` | One alert poll/outbox/heartbeat execution. |
| `systemd/so-alert-poll.timer` | `/etc/systemd/system/so-alert-poll.timer` | Runs alert polling every 5 minutes. |
| `systemd/so-pcap-broker.service` | `/etc/systemd/system/so-pcap-broker.service` | One independent PCAP broker execution. |
| `systemd/so-pcap-broker.timer` | `/etc/systemd/system/so-pcap-broker.timer` | Runs PCAP work every minute. |
| `ssh/99-key-only-admin.conf` | `/etc/ssh/sshd_config.d/99-key-only-admin.conf` | Optional SSH hardening after deployment is confirmed. |
| `app/live_osquery_broker.py` | `/opt/so-alert-relay/app/live_osquery_broker.py` | Disabled-by-default validator and broker for bounded Incident Responder endpoint OSQuery. |
| `bin/run-live-osquery-broker` | `/usr/local/sbin/run-live-osquery-broker` | Root-owned, SSH-traversable pre-sudo forced-command guard that rejects caller-supplied SSH commands. |
| `config/live-osquery.example.json` | `/etc/so-alert-relay/live-osquery.json` | Exact alias roster and dedicated Security Onion SSH transport settings; must be `root:soalert 0640`. |
| `sudoers/so-live-osquery` | `/etc/sudoers.d/92-so-alert-relay-live-osquery` | Installer-rendered rule that lets only the relay administrator execute the broker as `soalert`. |
| `app/ac_hunter_broker.py` | `/usr/local/libexec/onion-sentinel/ac_hunter_broker.py` | Stateless named-operation HTTPS broker for the fixed, TLS-pinned AC Hunter upstream. |
| `bin/run-ac-hunter-broker` | `/usr/local/sbin/run-ac-hunter-broker` | Root-owned pre-sudo forced-command guard for the dedicated Mac AC Hunter key. |
| `config/ac-hunter.example.json` | `/etc/so-alert-relay/ac-hunter.json` | Disabled fixed-upstream configuration and certificate pin; must be `root:soalert 0640`. |
| `config/authorized_keys.ac-hunter.example` | Relay administrator `authorized_keys` | Source-restricted forced-command template for the dedicated Mac AC Hunter public key. |
| `sudoers/so-ac-hunter` | `/etc/sudoers.d/93-so-alert-relay-ac-hunter` | Installer-rendered rule allowing only the AC Hunter broker as `soalert`. |

## Install

```bash
cd /path/to/OnionSentinel
sudo relay/bin/install-pi-relay.sh
```

The installer renders `__RELAY_ADMIN_USER__` from `SUDO_USER`. When installing
from a direct root shell, set `ONION_SENTINEL_RELAY_ADMIN_USER` to the existing
administrative account. The rendered rule permits only the forced live-OSQuery
broker command to run as `soalert`.

The installer never replaces an existing regular
`/opt/so-alert-relay/app/config.json`. It rejects a symlink or non-regular
object, preserves the live file across repair and upgrade installs, and
normalizes it to `soalert:soalert 0600` because enabled broker sections may
contain runtime tokens.

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

Live endpoint OSQuery uses its own Mac-to-relay key and the forced command in
`relay/config/authorized_keys.live-osquery.example`. The root-owned launcher
is installed at `/usr/local/sbin/run-live-osquery-broker`, outside the
intentionally private `/opt/so-alert-relay` tree so the SSH account can execute
it before sudo. It rejects `SSH_ORIGINAL_COMMAND` before `sudo` can discard it,
then uses the narrow sudoers rule to run only `live_osquery_broker.py` as
`soalert`. Keep `/opt/so-alert-relay` exactly `soalert:soalert 0700`; do not
make the private runtime tree traversable to solve forced-command execution.
Configure exact endpoint aliases in `/etc/so-alert-relay/live-osquery.json`,
keep that file exactly `root:soalert 0640`,
install a separate relay-to-Security Onion key, and prove the disabled
fail-closed response before enabling it. The relay never receives a Fleet
agent ID or Kibana credential. Full limits are documented in
`docs/incident-response-query-and-model-routing.md`.

DHCP asset discovery reuses the existing incident-evidence key pair on both
SSH hops. `incident_evidence_broker.py` revalidates the exact DHCP contract
before forwarding it through the existing pinned Security Onion host and
incident-query key. Security Onion's existing `export-incident-evidence`
forced command routes that exact contract to the fixed read-only DHCP helper.
It cannot accept arbitrary Elasticsearch DSL. This contract is independent
from alert polling, PCAP, and live OSQuery.

The Mac-side `query-security-onion.py dhcp` command uses this same contract for
interactive diagnostics. It does not set `SSH_ORIGINAL_COMMAND`, request a
shell, or bypass the broker. Manual queries can run while the scheduled DHCP
collector is disabled; both use the same pinned hosts and existing
incident-evidence key. Query details are returned only after the Mac validates
the response contract and fixed query audit.

Software Inventory uses the same existing key pair and broker without adding a
route, account, or credential. The broker recognizes only the exact
`onion-sentinel-software-inventory-v1` request, revalidates its source, bounded
window, page size, cursor, record provenance, timestamps, pagination, fixed
index/dataset audit, and pseudonymous endpoint reference, and then forwards it
to the co-located fixed helper on Security Onion. The scheduled Mac collector
retains a cursor only in memory while proving a complete snapshot; it never
persists or logs the transient OSQuery hostname cursor.

AC Hunter Deep Review is an independent, disabled-by-default Mac-to-Relay
transport. Its root-owned launcher rejects caller-supplied commands before
sudo, and its root-owned broker accepts only the shared named-operation
contract. The broker can connect only to `192.168.1.12:443`, requires the
operator-installed CA and exact leaf certificate digest, rejects redirects,
and bounds every request and response. AC Hunter credentials, Flask session
cookies, and JWTs are held by the Mac client; they transit the broker only in
memory and are never stored or logged on the Relay. Do not put any AC Hunter
credential in `/etc/so-alert-relay`.

The installer seeds `/etc/so-alert-relay/ac-hunter.json` with
`"enabled": false` and does not install a CA or edit `authorized_keys`.
Complete the certificate, dedicated-key, host-pin, fail-closed, and rollback
procedure in `docs/ac-hunter-deep-review.md` before enabling the transport.

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
  "capture_loss_threshold_percent": 5.0,
  "sensor_packet_loss_threshold_percent": 0.1,
  "capture_loss_freshness_seconds": 900,
  "stream_chunk_idle_timeout_seconds": 300,
  "mac_transfer": {
    "host": "10.77.7.225",
    "user": "__MAC_STUDIO_SSH_USER__",
    "ssh_key": "/opt/so-alert-relay/keys/macstudio-pcap-transfer_ed25519",
    "known_hosts": "/opt/so-alert-relay/keys/macstudio_known_hosts",
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
above its threshold. The broker response supplies the current Settings-page
capture-loss threshold over the authenticated control plane; the relay config's
5 percent value is the fail-safe default. When no PCAP request is pending, the
relay does not query Security Onion capture telemetry. The completed relay
artifact is rsynced to the Mac at no
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

Every broker timer run also posts a bounded `pcap_broker` status heartbeat.
When capture telemetry exceeds its safety threshold, the heartbeat reports a
`capture_protection_hold` with the observed metric and threshold. This is an
intentional degraded state, not a transport failure: pending requests remain
durable, no retry is consumed, and the Mac Studio can distinguish the hold from
a silent relay. Command lines, credentials, paths, and packet evidence are not
included in this status event.

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

## Read-only Relay readiness

The storage timer runs `relay_readiness.py` through the existing debounced
health wrapper every five minutes. The probe covers Pi power and thermal state,
current-boot filesystem/media warnings, root and external storage, the three
systemd timers, local route-table resolution, credential-file metadata, and
broker configuration. It never starts SSH, ping, HTTP, or broker traffic and
never reads credential content. Output is restricted to eight fixed check IDs,
pass/fail status, and allowlisted categorical reason codes.

```bash
sudo -u soalert /usr/bin/python3 /opt/so-alert-relay/app/relay_readiness.py \
  --config /opt/so-alert-relay/app/config.json
```

PCAP SSH runs under the service account used for the broker command. Before
enabling it, independently verify the Mac Studio host fingerprint and write the
pin to `/opt/so-alert-relay/keys/macstudio_known_hosts` as an owner-only regular
file. Relay-to-Mac SSH uses `StrictHostKeyChecking=yes` with only that configured
file; it never accepts a first-seen key. The unified readiness probe rejects an
enabled PCAP transfer whose key or host-pin metadata is absent or permissive.
The field defaults to that same path for an older live config, so an upgrade can
preprovision the pin without rewriting the rest of `config.json`.

## Incident Evidence Relay

Incident Response evidence uses a control plane separate from alert delivery
and PCAP transport. The Mac Studio connects with a dedicated key whose relay
authorized-key entry is rendered from
`relay/config/authorized_keys.incident-evidence.example`. That forced command
runs only `relay/app/incident_evidence_broker.py`; it does not accept an SSH
command, forwarding request, PTY, path, or query text.

The broker validates a bounded JSON request and relays it over a second
dedicated key to Security Onion. Runtime settings belong in
`/etc/so-alert-relay/incident-evidence.json`, rendered from the sanitized
example. The relay's 400-second inner timeout accommodates a bounded
four-query pivot batch plus two semantic controls; the Mac caller uses a
slightly longer 420-second outer timeout. The broker caps request, response,
stderr, connection, and total runtime sizes on both hops. Security Onion independently rebuilds every query
from fixed allowlisted packs, so neither the dashboard nor either model can
turn incident reasoning into an arbitrary Elasticsearch or shell operation.

Each successful Elastic query result carries two audit forms:

- `kql_equivalent`: a readable equivalent for analyst review.
- `query_dsl`: the exact read-only Elasticsearch request that was executed.

The DSL is authoritative. The KQL is displayed to make the search intent easy
to inspect and must never be treated as proof that a separate KQL request ran.

The same request also invokes only the fixed OSquery packs compiled into the
Security Onion wrapper. Each result records the reviewed pack name, exact
read-only SQL, local Security Onion target, execution status, digest, and
bounded row metadata. The relay cannot accept or forward caller-authored SQL.
This provides host context from Security Onion itself and bounded historical
osquery/endpoint evidence without granting the model an interactive shell or
general endpoint-query channel.

## Firewall Needs

From relay `10.88.8.8`:

- to Security Onion `192.168.1.7:22/tcp`
- to Mac Studio `10.77.7.225:22/tcp` for durable alert intake and artifact transport
- to Mac Studio `10.77.7.225:5678/tcp` for PCAP control metadata and emergency rollback
- to DNS `53/tcp,udp`
- to `api.telegram.org:443/tcp` if relay health notifications are enabled
