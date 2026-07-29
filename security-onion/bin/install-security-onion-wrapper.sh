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
install -o root -g root -m 0755 "$REPO_DIR/security-onion/bin/export-incident-evidence" /usr/local/sbin/export-incident-evidence
install -o root -g root -m 0755 "$REPO_DIR/security-onion/bin/export-dhcp-observations" /usr/local/sbin/export-dhcp-observations
install -o root -g root -m 0755 "$REPO_DIR/security-onion/bin/run-live-osquery" /usr/local/sbin/run-live-osquery
install -o root -g root -m 0755 -d /usr/local/lib/onion-sentinel
install -o root -g root -m 0644 "$REPO_DIR/n8n/bin/live_osquery_contract.py" /usr/local/lib/onion-sentinel/live_osquery_contract.py
install -o root -g root -m 0440 "$REPO_DIR/security-onion/sudoers/90-so-ai-relay-export" /etc/sudoers.d/90-so-ai-relay-export
# Always validate sudoers before relying on passwordless wrapper execution.
visudo -cf /etc/sudoers.d/90-so-ai-relay-export

if ! id so-ai-relay >/dev/null 2>&1; then
  # This account should not be interactive. SSH authorized_keys forces one
  # wrapper command, and sudoers permits only that wrapper.
  useradd --system --create-home --shell /usr/sbin/nologin so-ai-relay
fi

install -o so-ai-relay -g so-ai-relay -m 0700 -d /home/so-ai-relay/.ssh

# The current PCAP path streams directly through the forced-command wrapper.
# Ensure a prior staged-rsync deployment cannot be reactivated accidentally.
rm -f /usr/local/sbin/onion-sentinel-rsync-pcapout
rm -f /etc/ssh/sshd_config.d/99-onion-sentinel-pcap-rsync.conf
rm -f /etc/onion-sentinel/pcapout-rsync.conf
if id so-ai-relay-pcap-rsync >/dev/null 2>&1; then
  install -o root -g root -m 0700 -d /root/onion-sentinel-disabled-keys
  if [[ -f /home/so-ai-relay-pcap-rsync/.ssh/authorized_keys ]]; then
    mv -f /home/so-ai-relay-pcap-rsync/.ssh/authorized_keys \
      /root/onion-sentinel-disabled-keys/so-ai-relay-pcap-rsync.authorized_keys.disabled
    chown root:root /root/onion-sentinel-disabled-keys/so-ai-relay-pcap-rsync.authorized_keys.disabled
    chmod 0600 /root/onion-sentinel-disabled-keys/so-ai-relay-pcap-rsync.authorized_keys.disabled
  fi
  usermod --lock --shell /usr/sbin/nologin so-ai-relay-pcap-rsync
fi

# Sign manifest chunks on Security Onion so normal capture rotation cannot
# invalidate an in-flight transfer or let the relay substitute another source.
install -o root -g root -m 0700 -d /etc/onion-sentinel
if [[ ! -f /etc/onion-sentinel/live-osquery.json ]]; then
  install -o root -g root -m 0600 \
    "$REPO_DIR/security-onion/config/live-osquery.example.json" \
    /etc/onion-sentinel/live-osquery.json
  echo "Created disabled /etc/onion-sentinel/live-osquery.json example." >&2
fi
if [[ ! -s /etc/onion-sentinel/pcap-stream-token.key ]]; then
  umask 077
  head -c 32 /dev/urandom > /etc/onion-sentinel/pcap-stream-token.key
fi
chown root:root /etc/onion-sentinel/pcap-stream-token.key
chmod 0600 /etc/onion-sentinel/pcap-stream-token.key

sshd -t

# Production PCAP export is read-only and stages zero bytes on Security Onion.
# Erase obsolete writer-side components from earlier deployments so a rebuild
# cannot silently restore the retired /nsm staging data plane. The rmdir is
# deliberately non-recursive: unexpected contents require operator review.
systemctl disable --now onion-sentinel-pcapout-retention.timer >/dev/null 2>&1 || true
rm -f \
  /etc/systemd/system/onion-sentinel-pcapout-retention.service \
  /etc/systemd/system/onion-sentinel-pcapout-retention.timer \
  /var/lib/systemd/timers/stamp-onion-sentinel-pcapout-retention.timer \
  /usr/local/sbin/__pycache__/onion-sentinel-rsync-pcapoutcpython-39.pyc \
  /usr/local/sbin/__pycache__/prune-onion-sentinel-pcapoutcpython-39.pyc
rmdir /nsm/pcapout/onion-sentinel >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl reset-failed onion-sentinel-pcapout-retention.service >/dev/null 2>&1 || true

cat <<'MSG'

Security Onion wrapper installed.

Next manual step:
1. Generate or choose the Pi relay public key.
2. Create /home/so-ai-relay/.ssh/authorized_keys from security-onion/ssh/authorized_keys.example.
3. Replace REPLACE_WITH_PUBLIC_KEY with the real public key.
4. Keep the from="10.88.8.8" source restriction unless the Pi address changes.
5. Do not create the deprecated staged-rsync account or key. PCAP bytes stream
   through the dedicated forced-command key from authorized_keys.pcap.example.
6. Endpoint live OSQuery requires a third dedicated key, exact endpoint aliases,
   a root-only authorization file, and explicit enablement. It is not part of
   the default read-only alert and PCAP data plane.
7. DHCP asset discovery requires its own forced-command key from
   authorized_keys.dhcp-asset-discovery.example. It accepts only the fixed,
   bounded zeek.dhcp DSL contract and never accepts caller-supplied DSL.

Test:
  sudo -u so-ai-relay sudo -n /usr/local/sbin/export-recent-alerts | jq '.alerts | length'

MSG
