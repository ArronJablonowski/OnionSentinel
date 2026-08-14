#!/bin/bash
set -euo pipefail

# Run this locally on the Pi after cloning/copying the DR repo there.
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run on the Pi with sudo: sudo $0" >&2
  exit 1
fi

RELAY_ADMIN_USER="${ONION_SENTINEL_RELAY_ADMIN_USER:-${SUDO_USER:-}}"
if [[ -z "$RELAY_ADMIN_USER" || "$RELAY_ADMIN_USER" == "root" ]]; then
  echo "Unable to identify the relay administrator. Re-run with sudo or set ONION_SENTINEL_RELAY_ADMIN_USER." >&2
  exit 1
fi
if [[ ! "$RELAY_ADMIN_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || ! id "$RELAY_ADMIN_USER" >/dev/null 2>&1; then
  echo "Invalid relay administrator account: $RELAY_ADMIN_USER" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

if ! id soalert >/dev/null 2>&1; then
  # Dedicated service account owns runtime files but cannot log in.
  useradd --system --home-dir /opt/so-alert-relay --shell /usr/sbin/nologin soalert
fi

# Install directories with restrictive permissions. The key and env directories
# are intentionally not world-readable.
install -o soalert -g soalert -m 0700 -d /opt/so-alert-relay
install -o soalert -g soalert -m 0750 -d /opt/so-alert-relay/app
install -o root -g root -m 0755 -d /usr/local/libexec
install -o root -g root -m 0755 -d /usr/local/libexec/onion-sentinel
install -o root -g root -m 0755 -d /usr/local/sbin
install -o soalert -g soalert -m 0750 -d /opt/so-alert-relay/keys
install -o soalert -g soalert -m 0750 -d /opt/so-alert-relay/state
install -o soalert -g soalert -m 0750 -d /opt/so-alert-relay/state/batches
install -o soalert -g soalert -m 0750 -d /opt/so-alert-relay/state/new-alerts
install -o root -g soalert -m 0750 -d /etc/so-alert-relay

install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_core.py" /opt/so-alert-relay/app/relay_core.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_pcap_spool_policy.py" /opt/so-alert-relay/app/relay_pcap_spool_policy.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_pcap_capture_policy.py" /opt/so-alert-relay/app/relay_pcap_capture_policy.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_pcap_streaming.py" /opt/so-alert-relay/app/relay_pcap_streaming.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_pcap_transport.py" /opt/so-alert-relay/app/relay_pcap_transport.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_pcap_delivery.py" /opt/so-alert-relay/app/relay_pcap_delivery.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_pcap_service.py" /opt/so-alert-relay/app/relay_pcap_service.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_application.py" /opt/so-alert-relay/app/relay_application.py
install -o soalert -g soalert -m 0755 "$REPO_DIR/relay/app/relay.py" /opt/so-alert-relay/app/relay.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/alert_outbox.py" /opt/so-alert-relay/app/alert_outbox.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/alert_delivery.py" /opt/so-alert-relay/app/alert_delivery.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/process_io.py" /opt/so-alert-relay/app/process_io.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/incident_evidence_dhcp.py" /opt/so-alert-relay/app/incident_evidence_dhcp.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/incident_evidence_software.py" /opt/so-alert-relay/app/incident_evidence_software.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/incident_evidence_transport.py" /opt/so-alert-relay/app/incident_evidence_transport.py
install -o soalert -g soalert -m 0755 "$REPO_DIR/relay/app/incident_evidence_broker.py" /opt/so-alert-relay/app/incident_evidence_broker.py
install -o soalert -g soalert -m 0755 "$REPO_DIR/relay/app/live_osquery_broker.py" /opt/so-alert-relay/app/live_osquery_broker.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/n8n/bin/live_osquery_contract_schema.py" /opt/so-alert-relay/app/live_osquery_contract_schema.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/n8n/bin/live_osquery_contract_query.py" /opt/so-alert-relay/app/live_osquery_contract_query.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/n8n/bin/live_osquery_contract_request.py" /opt/so-alert-relay/app/live_osquery_contract_request.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/n8n/bin/live_osquery_contract_result.py" /opt/so-alert-relay/app/live_osquery_contract_result.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/n8n/bin/live_osquery_contract.py" /opt/so-alert-relay/app/live_osquery_contract.py
install -o root -g root -m 0755 "$REPO_DIR/relay/bin/run-live-osquery-broker" /usr/local/sbin/run-live-osquery-broker
install -o root -g root -m 0755 \
  "$REPO_DIR/relay/app/ac_hunter_broker.py" \
  /usr/local/libexec/onion-sentinel/ac_hunter_broker.py
install -o root -g root -m 0644 \
  "$REPO_DIR/n8n/bin/ac_hunter_contract.py" \
  /usr/local/libexec/onion-sentinel/ac_hunter_contract.py
install -o root -g root -m 0755 \
  "$REPO_DIR/relay/bin/run-ac-hunter-broker" \
  /usr/local/sbin/run-ac-hunter-broker
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_health_contract.py" /opt/so-alert-relay/app/relay_health_contract.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_health_sanitization.py" /opt/so-alert-relay/app/relay_health_sanitization.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/app/relay_health_application.py" /opt/so-alert-relay/app/relay_health_application.py
install -o soalert -g soalert -m 0755 "$REPO_DIR/relay/app/relay_health_wrapper.py" /opt/so-alert-relay/app/relay_health_wrapper.py
install -o soalert -g soalert -m 0755 "$REPO_DIR/relay/app/storage_health.py" /opt/so-alert-relay/app/storage_health.py
install -o soalert -g soalert -m 0644 "$REPO_DIR/relay/config/config.example.json" /opt/so-alert-relay/app/config.json

if [[ ! -f /etc/so-alert-relay/relay.env ]]; then
  # Do not overwrite live secrets during a repair install.
  install -o root -g soalert -m 0640 "$REPO_DIR/relay/config/relay.example.env" /etc/so-alert-relay/relay.env
  echo "Created /etc/so-alert-relay/relay.env from example. Edit it before enabling live forwarding." >&2
fi

if [[ ! -f /etc/so-alert-relay/live-osquery.json ]]; then
  # This path remains inert until operators configure exact endpoint aliases
  # and provision its two dedicated forced-command SSH keys.
  install -o root -g soalert -m 0640 \
    "$REPO_DIR/relay/config/live-osquery.example.json" \
    /etc/so-alert-relay/live-osquery.json
  echo "Created disabled /etc/so-alert-relay/live-osquery.json example." >&2
fi

if [[ ! -f /etc/so-alert-relay/incident-evidence.json ]]; then
  install -o root -g soalert -m 0640 \
    "$REPO_DIR/relay/config/incident-evidence.example.json" \
    /etc/so-alert-relay/incident-evidence.json
  echo "Created /etc/so-alert-relay/incident-evidence.json example." >&2
fi

AC_HUNTER_CONFIG=/etc/so-alert-relay/ac-hunter.json
if [[ -L "$AC_HUNTER_CONFIG" ]] \
  || [[ -e "$AC_HUNTER_CONFIG" && ! -f "$AC_HUNTER_CONFIG" ]]; then
  echo "Refusing install: AC Hunter relay config must be a regular file." >&2
  exit 1
fi
if [[ ! -f "$AC_HUNTER_CONFIG" ]]; then
  # The example is pinned to one upstream and remains inert until the operator
  # installs the verified CA, records the leaf fingerprint, and enables it.
  install -o root -g soalert -m 0640 \
    "$REPO_DIR/relay/config/ac-hunter.example.json" \
    "$AC_HUNTER_CONFIG"
  echo "Created disabled $AC_HUNTER_CONFIG example." >&2
else
  chown root:soalert "$AC_HUNTER_CONFIG"
  chmod 0640 "$AC_HUNTER_CONFIG"
fi


install -o root -g root -m 0644 "$REPO_DIR/relay/systemd/so-alert-relay.service" /etc/systemd/system/so-alert-relay.service
install -o root -g root -m 0644 "$REPO_DIR/relay/systemd/so-alert-relay.timer" /etc/systemd/system/so-alert-relay.timer
install -o root -g root -m 0644 "$REPO_DIR/relay/systemd/so-alert-poll.service" /etc/systemd/system/so-alert-poll.service
install -o root -g root -m 0644 "$REPO_DIR/relay/systemd/so-alert-poll.timer" /etc/systemd/system/so-alert-poll.timer
install -o root -g root -m 0644 "$REPO_DIR/relay/systemd/so-pcap-broker.service" /etc/systemd/system/so-pcap-broker.service
install -o root -g root -m 0644 "$REPO_DIR/relay/systemd/so-pcap-broker.timer" /etc/systemd/system/so-pcap-broker.timer
install -o root -g root -m 0644 "$REPO_DIR/relay/systemd/so-storage-health.service" /etc/systemd/system/so-storage-health.service
install -o root -g root -m 0644 "$REPO_DIR/relay/systemd/so-storage-health.timer" /etc/systemd/system/so-storage-health.timer
install -o root -g root -m 0440 "$REPO_DIR/relay/sudoers/so-storage-health" /etc/sudoers.d/91-so-alert-relay-storage-health
visudo -cf /etc/sudoers.d/91-so-alert-relay-storage-health
LIVE_OSQUERY_SUDOERS_TMP="$(mktemp)"
trap 'rm -f "$LIVE_OSQUERY_SUDOERS_TMP"' EXIT
sed "s/__RELAY_ADMIN_USER__/${RELAY_ADMIN_USER}/g" \
  "$REPO_DIR/relay/sudoers/so-live-osquery" > "$LIVE_OSQUERY_SUDOERS_TMP"
if grep -q "__RELAY_ADMIN_USER__" "$LIVE_OSQUERY_SUDOERS_TMP"; then
  echo "Failed to render the live OSQuery sudoers rule." >&2
  exit 1
fi
install -o root -g root -m 0440 "$LIVE_OSQUERY_SUDOERS_TMP" /etc/sudoers.d/92-so-alert-relay-live-osquery
visudo -cf /etc/sudoers.d/92-so-alert-relay-live-osquery
rm -f "$LIVE_OSQUERY_SUDOERS_TMP"
trap - EXIT
AC_HUNTER_SUDOERS_TMP="$(mktemp)"
trap 'rm -f "$AC_HUNTER_SUDOERS_TMP"' EXIT
sed "s/__RELAY_ADMIN_USER__/${RELAY_ADMIN_USER}/g" \
  "$REPO_DIR/relay/sudoers/so-ac-hunter" > "$AC_HUNTER_SUDOERS_TMP"
if grep -q "__RELAY_ADMIN_USER__" "$AC_HUNTER_SUDOERS_TMP"; then
  echo "Failed to render the AC Hunter sudoers rule." >&2
  exit 1
fi
chmod 0440 "$AC_HUNTER_SUDOERS_TMP"
visudo -cf "$AC_HUNTER_SUDOERS_TMP"
install -o root -g root -m 0440 \
  "$AC_HUNTER_SUDOERS_TMP" \
  /etc/sudoers.d/93-so-alert-relay-ac-hunter
visudo -cf /etc/sudoers.d/93-so-alert-relay-ac-hunter
rm -f "$AC_HUNTER_SUDOERS_TMP"
trap - EXIT
install -o root -g root -m 0755 -d /etc/systemd/journald.conf.d
install -o root -g root -m 0644 "$REPO_DIR/relay/systemd/onion-sentinel-journald.conf" /etc/systemd/journald.conf.d/onion-sentinel.conf
install -o root -g systemd-journal -m 2755 -d /var/log/journal

systemctl daemon-reload
systemctl restart systemd-journald
# NetworkManager-wait-online may not exist on every OS image; tolerate that.
systemctl enable NetworkManager-wait-online.service >/dev/null 2>&1 || true
systemctl disable --now so-alert-relay.timer >/dev/null 2>&1 || true
systemctl enable so-alert-poll.timer so-pcap-broker.timer so-storage-health.timer

cat <<'MSG'

Pi relay installed.

Required manual steps:
1. Put the Security Onion private key at /opt/so-alert-relay/keys/so-ai-relay_ed25519.
2. chown soalert:soalert /opt/so-alert-relay/keys/so-ai-relay_ed25519
3. chmod 0600 /opt/so-alert-relay/keys/so-ai-relay_ed25519
4. Create the dedicated Mac alert-intake key and verified macstudio_known_hosts pin.
5. Install its forced-command public key on the Mac Studio.
6. Edit /etc/so-alert-relay/relay.env and replace placeholder tokens.
7. Verify /opt/so-alert-relay/app/config.json host/path values, then enable alert_ingest.
8. Live endpoint OSQuery uses a separate key and remains disabled until
   /etc/so-alert-relay/live-osquery.json contains exact operator aliases.
9. DHCP discovery reuses the existing read-only incident-evidence key pair.
   Install the updated incident broker and validate its exact DHCP contract.
10. AC Hunter Deep Review remains disabled. Install and verify the AC Hunter
    CA at /etc/so-alert-relay/ac-hunter-ca.pem, record the exact leaf
    fingerprint in /etc/so-alert-relay/ac-hunter.json, and install the
    source-restricted dedicated public key from
    relay/config/authorized_keys.ac-hunter.example before enabling it.

Test:
  sudo -u soalert /usr/bin/python3 /opt/so-alert-relay/app/relay.py --config /opt/so-alert-relay/app/config.json --pull-once
  sudo systemctl start so-alert-relay.service
  sudo journalctl -u so-alert-relay.service -n 30 --no-pager

MSG
