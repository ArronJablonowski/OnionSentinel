# Security Onion Node

This directory contains the Security Onion-side pieces for Onion Sentinel.

## Files

| File | Destination | Purpose |
| --- | --- | --- |
| `bin/export-recent-alerts` | `/usr/local/sbin/export-recent-alerts` | Restricted wrapper that exports recent alerts as JSON. |
| `bin/export-pcap-window` | `/usr/local/sbin/export-pcap-window` | Restricted wrapper that exports bounded PCAP artifacts from validated JSON requests. |
| `bin/onion-sentinel-rsync-pcapout` | `/usr/local/sbin/onion-sentinel-rsync-pcapout` | Read-only forced-command wrapper for rsyncing prepared PCAP artifacts to the relay SSD spool. |
| `bin/prune-onion-sentinel-pcapout` | `/usr/local/sbin/prune-onion-sentinel-pcapout` | Safety-net cleanup for stale Onion Sentinel PCAP export artifacts. |
| `systemd/onion-sentinel-pcapout-retention.service` | `/etc/systemd/system/onion-sentinel-pcapout-retention.service` | One-shot Security Onion PCAP export retention cleanup. |
| `systemd/onion-sentinel-pcapout-retention.timer` | `/etc/systemd/system/onion-sentinel-pcapout-retention.timer` | Hourly timer for stale PCAP export cleanup. |
| `sudoers/90-so-ai-relay-export` | `/etc/sudoers.d/90-so-ai-relay-export` | Allows only the wrapper to run passwordless for `so-ai-relay`. |
| `ssh/authorized_keys.example` | `/home/so-ai-relay/.ssh/authorized_keys` | Forced-command SSH template restricted to the relay source IP. |
| `ssh/authorized_keys.pcap.example` | `/home/so-ai-relay/.ssh/authorized_keys` | Separate forced-command SSH template for PCAP fulfillment. |
| `ssh/authorized_keys.pcap-rsync.example` | `/home/so-ai-relay-pcap-rsync/.ssh/authorized_keys` | Separate read-only rsync template for PCAP artifact transfer. |
| `ssh/99-onion-sentinel-pcap-rsync.conf` | `/etc/ssh/sshd_config.d/99-onion-sentinel-pcap-rsync.conf` | Disables the SSH banner only for the rsync transfer account so rsync protocol negotiation is clean. |
| `bin/install-security-onion-wrapper.sh` | run with `sudo` on Security Onion | Installs wrapper, sudoers, and service account scaffolding. |

## Install

```bash
cd /path/to/OnionSentinel
sudo security-onion/bin/install-security-onion-wrapper.sh
```

Then create the forced-command authorized key:

```bash
sudo install -o so-ai-relay -g so-ai-relay -m 0700 -d /home/so-ai-relay/.ssh
sudo cp security-onion/ssh/authorized_keys.example /home/so-ai-relay/.ssh/authorized_keys
sudo nano /home/so-ai-relay/.ssh/authorized_keys
sudo chown so-ai-relay:so-ai-relay /home/so-ai-relay/.ssh/authorized_keys
sudo chmod 0600 /home/so-ai-relay/.ssh/authorized_keys
```

Replace `REPLACE_WITH_PUBLIC_KEY` with the Raspberry Pi relay public key. Keep the `from="10.88.8.8"` restriction unless the relay address changes.

PCAP fulfillment should use a separate key entry based on
`security-onion/ssh/authorized_keys.pcap.example`. The wrapper reads a bounded
JSON request from stdin and writes artifacts only under
`/nsm/pcapout/onion-sentinel`.

PCAP artifact transfer should use a third, read-only key based on
`security-onion/ssh/authorized_keys.pcap-rsync.example`. Install
`security-onion/bin/onion-sentinel-rsync-pcapout` to
`/usr/local/sbin/onion-sentinel-rsync-pcapout` and force that command for the
transfer key. This key does not run the export wrapper and cannot open a shell;
it only permits rsync sender mode for existing tar files under
`/nsm/pcapout/onion-sentinel`.

If Security Onion has a global SSH banner, install
`security-onion/ssh/99-onion-sentinel-pcap-rsync.conf` and reload `sshd`. rsync
requires a clean protocol stream, so the banner must be disabled for only the
dedicated rsync account.

The export wrapper grants the transfer group read/traverse access to
`/nsm/pcapout/onion-sentinel` and generated tar artifacts. The default group is
`so-ai-relay-pcap-rsync`; set `ONION_SENTINEL_PCAP_TRANSFER_GROUP` before the
forced command if you choose a different transfer account/group.

`export-pcap-window` treats a validated `capture_file` as a preferred hint,
then ranks bounded candidates by the capture epoch nearest the alert window.
This prevents historical requests from accidentally searching only the newest
captures. The wrapper defaults to using the destination service port as the
BPF port discriminator; request JSON may set `require_source_port: true` for
controlled validation or rare cases where an ephemeral source port is the only
safe discriminator. `ONION_SENTINEL_PCAP_MAX_ARTIFACT_BYTES` defaults to 32 GiB
and is applied to `tcpdump` itself, so an unusually dense flow cannot fill the
Security Onion export directory before the relay SSD limit is enforced. Keep
this bound below available Security Onion and Mac Studio capacity; the live
1 TB relay spool reserves 100 GiB and stops accepting work at 80 percent used.

After a relay upload has been accepted by the Mac Studio and the PCAP broker
completion callback succeeds, the relay calls `export-pcap-window` with
`mode: artifact_cleanup`. That restricted mode accepts only a request id and
removes only `/nsm/pcapout/onion-sentinel/<request_id>.tar` plus the matching
work directory.

Install the retention timer as a safety net for artifacts that survive relay
cleanup, for example during interrupted transfers or node outages:

```bash
sudo install -o root -g root -m 0755 security-onion/bin/prune-onion-sentinel-pcapout /usr/local/sbin/prune-onion-sentinel-pcapout
sudo install -o root -g root -m 0644 security-onion/systemd/onion-sentinel-pcapout-retention.service /etc/systemd/system/onion-sentinel-pcapout-retention.service
sudo install -o root -g root -m 0644 security-onion/systemd/onion-sentinel-pcapout-retention.timer /etc/systemd/system/onion-sentinel-pcapout-retention.timer
sudo systemctl daemon-reload
sudo systemctl enable --now onion-sentinel-pcapout-retention.timer
```

The prune helper defaults to dry-run when run manually. The systemd service runs
it with `--apply` and removes only top-level tar files or request directories
older than 24 hours under `/nsm/pcapout/onion-sentinel`.

## Validate

```bash
sudo visudo -cf /etc/sudoers.d/90-so-ai-relay-export
sudo -u so-ai-relay sudo -n /usr/local/sbin/export-recent-alerts | jq '.alerts | length'
```

Expected result: JSON prints without prompting for a password.
