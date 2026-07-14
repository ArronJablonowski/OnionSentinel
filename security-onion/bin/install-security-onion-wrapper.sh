#!/bin/bash
set -euo pipefail

# Run this locally on Security Onion after cloning/copying the DR repo there.
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run on Security Onion with sudo: sudo $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

install -o root -g root -m 0755 "$REPO_DIR/security-onion/bin/export-recent-alerts" /usr/local/sbin/export-recent-alerts
install -o root -g root -m 0755 "$REPO_DIR/security-onion/bin/export-pcap-window" /usr/local/sbin/export-pcap-window
install -o root -g root -m 0755 "$REPO_DIR/security-onion/bin/onion-sentinel-rsync-pcapout" /usr/local/sbin/onion-sentinel-rsync-pcapout
install -o root -g root -m 0755 "$REPO_DIR/security-onion/bin/prune-onion-sentinel-pcapout" /usr/local/sbin/prune-onion-sentinel-pcapout
install -o root -g root -m 0440 "$REPO_DIR/security-onion/sudoers/90-so-ai-relay-export" /etc/sudoers.d/90-so-ai-relay-export
# Always validate sudoers before relying on passwordless wrapper execution.
visudo -cf /etc/sudoers.d/90-so-ai-relay-export

if ! id so-ai-relay >/dev/null 2>&1; then
  # This account should not be interactive. SSH authorized_keys forces one
  # wrapper command, and sudoers permits only that wrapper.
  useradd --system --create-home --shell /usr/sbin/nologin so-ai-relay
fi

install -o so-ai-relay -g so-ai-relay -m 0700 -d /home/so-ai-relay/.ssh

if ! id so-ai-relay-pcap-rsync >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin so-ai-relay-pcap-rsync
fi
install -o so-ai-relay-pcap-rsync -g so-ai-relay-pcap-rsync -m 0700 -d /home/so-ai-relay-pcap-rsync/.ssh

install -o root -g root -m 0644 "$REPO_DIR/security-onion/ssh/99-onion-sentinel-pcap-rsync.conf" /etc/ssh/sshd_config.d/99-onion-sentinel-pcap-rsync.conf
sshd -t

install -o root -g root -m 0644 "$REPO_DIR/security-onion/systemd/onion-sentinel-pcapout-retention.service" /etc/systemd/system/onion-sentinel-pcapout-retention.service
install -o root -g root -m 0644 "$REPO_DIR/security-onion/systemd/onion-sentinel-pcapout-retention.timer" /etc/systemd/system/onion-sentinel-pcapout-retention.timer
systemctl daemon-reload
systemctl enable --now onion-sentinel-pcapout-retention.timer

cat <<'MSG'

Security Onion wrapper installed.

Next manual step:
1. Generate or choose the Pi relay public key.
2. Create /home/so-ai-relay/.ssh/authorized_keys from security-onion/ssh/authorized_keys.example.
3. Replace REPLACE_WITH_PUBLIC_KEY with the real public key.
4. Keep the from="10.88.8.8" source restriction unless the Pi address changes.
5. Create the dedicated rsync account authorized_keys from
   security-onion/ssh/authorized_keys.pcap-rsync.example using the Pi's
   separate public key. Never reuse the command/export key.

Test:
  sudo -u so-ai-relay sudo -n /usr/local/sbin/export-recent-alerts | jq '.alerts | length'

MSG
