# AC Hunter Deep Review Deployment

AC Hunter Deep Review is a read-only behavioral-triage integration. It does
not classify a host as malicious from an AC Hunter score alone. Onion Sentinel
normalizes the bounded AC Hunter results, applies explainable triage rules, and
presents evidence for an analyst to investigate.

Collection is schedule-owned rather than request-owned. The Mac Studio
LaunchAgent `com.arron.soc.ac-hunter` runs once an hour at minute `35`. Public
dashboard requests read PostgreSQL only and cannot trigger AC Hunter or Relay
activity.

The only supported network path is:

```text
Onion Sentinel 10.77.7.225
  -> forced SSH request to Relay 10.88.8.8
  -> pinned HTTPS request to AC Hunter 192.168.1.12:443
```

Onion Sentinel cannot supply a URL, host, HTTP method, redirect, proxy, or TLS
setting. The shared contract accepts only named AC Hunter operations and
bounded typed parameters. The Relay compiles those operations into requests
for the fixed `security-onion-rolling` dataset. The Relay has no AC Hunter
credential file and does not persist session cookies, JWTs, request bodies, or
responses.

## Trust and secret boundaries

- A dedicated AC Hunter service identity is required. Do not reuse an
  administrator's account.
- Its credential file exists only on the Mac Studio at
  `$HOME/n8n-local/config/ac-hunter-credentials.json`, is a regular owner-only
  `0600` file, and has this schema:

  ```json
  {
    "schema": "onion-sentinel-ac-hunter-credentials-v1",
    "email": "DEDICATED_SERVICE_ACCOUNT_EMAIL",
    "password": "DEDICATED_SERVICE_ACCOUNT_PASSWORD"
  }
  ```

- The Mac retains the Flask session cookie and five-minute JWT only in process
  memory. They are streamed to the forced SSH process over an anonymous pipe;
  they are not staged in a temporary file and are never written to the
  normalized cache or application logs.
- PostgreSQL is authoritative for normalized AC Hunter findings. The
  `onion_sentinel_ac_hunter` schema retains distinct snapshots and pull-run
  history for 24 hours. The current snapshot is immutable and content
  addressed: an identical hourly pull updates only poll state and does not
  rewrite or insert the cached dataset.
- The former owner-only JSON cache is migration input only. The WebUI and
  dashboard API do not read it after the PostgreSQL cutover.
- The Relay trusts one root-owned CA certificate and the exact SHA-256 digest
  of the AC Hunter leaf certificate. It does not disable certificate-chain
  verification. The current appliance certificate has no subjectAltName, so
  the broker connects only to the fixed IP, sends the fixed `localhost` SNI,
  validates the chain against the pinned certificate, and separately enforces
  the exact leaf fingerprint. Replace that appliance certificate with an
  internal-CA certificate containing an appropriate SAN when practical.
- Use a dedicated Mac-to-Relay Ed25519 key. Do not reuse the alert-ingest,
  incident-evidence, live-OSQuery, PCAP, Security Onion, or administrator key.
- This integration requires no Security Onion account, wrapper, script, key,
  or configuration change.

## Relay installation

Run the repository installer on the Relay. The AC Hunter transport remains
disabled and cannot be reached over SSH until the operator performs the trust
steps below.

```bash
cd /path/to/OnionSentinel
sudo relay/bin/install-pi-relay.sh
```

The installer:

- installs the broker and shared request contract under
  `/usr/local/libexec/onion-sentinel/`;
- installs the root-owned pre-sudo guard at
  `/usr/local/sbin/run-ac-hunter-broker`;
- seeds `/etc/so-alert-relay/ac-hunter.json` only when absent, with
  `"enabled": false`;
- renders and validates
  `/etc/sudoers.d/93-so-alert-relay-ac-hunter`; and
- never creates a key, edits `authorized_keys`, installs a CA, or enables the
  transport.

Transfer the AC Hunter public certificate to the Relay through an already
trusted administrative path, verify it out of band, and install it:

```bash
sudo install -o root -g soalert -m 0640 \
  /trusted/staging/ac-hunter-public.crt \
  /etc/so-alert-relay/ac-hunter-ca.pem
```

Calculate the exact DER leaf digest on AC Hunter and independently on the
Relay. Both values must match:

```bash
openssl x509 -in /etc/AC-Hunter/public.crt -outform DER |
  openssl dgst -sha256

openssl x509 -in /etc/so-alert-relay/ac-hunter-ca.pem -outform DER |
  openssl dgst -sha256
```

Set that lowercase 64-character digest in
`/etc/so-alert-relay/ac-hunter.json`. Keep the fixed upstream address,
port, TLS name, paths, and limits unchanged. Leave `"enabled": false` until
the Mac forced key and host pin have been validated.

## Dedicated forced SSH key

Generate the integration-specific key on the Mac Studio:

```bash
ssh-keygen -t ed25519 -N '' \
  -f "$HOME/.ssh/onion-sentinel-ac-hunter_ed25519" \
  -C onion-sentinel-ac-hunter@mac-studio
chmod 0600 "$HOME/.ssh/onion-sentinel-ac-hunter_ed25519"
```

Starting from `relay/config/authorized_keys.ac-hunter.example`, replace only
the public-key placeholder and install the resulting single line in the Relay
administrator's `authorized_keys`. Preserve its source restriction to
`10.77.7.225`, forced command, and all forwarding, PTY, X11, agent, and user-rc
denials. Confirm that the selected SSH user matches `relay_user` in the Mac
config and the administrator used to render the Relay sudoers rule.

Pin the Relay's Ed25519 host key in
`$HOME/n8n-local/config/ac-hunter-relay-known-hosts`. Compare its fingerprint
with `/etc/ssh/ssh_host_ed25519_key.pub` through an existing trusted Relay
session. Never use `StrictHostKeyChecking=no`.

Before enabling AC Hunter, prove that the forced key:

1. returns the disabled, fail-closed response for an empty stdin request;
2. rejects any caller-supplied SSH command;
3. cannot open a shell or allocate a PTY; and
4. cannot forward a TCP connection.

## Mac Studio installation

The Mac stack installer copies the shared contract, scheduled collector,
PostgreSQL schema/store, dashboard client, and the minute-35 LaunchAgent. It
seeds
`$HOME/n8n-local/config/ac-hunter.json` only when absent:

```bash
cd /path/to/OnionSentinel
ONION_SENTINEL_RELEASE_ID=<tested-release-id> \
  n8n/bin/install-macstudio-stack.zsh
```

The installer refuses a symlink or non-regular AC Hunter config or credential
path. It never creates, replaces, or reads the credential file. Create that
file separately with the credential schema above, make it `0600`, and verify
that only the Mac runtime user owns it.

Review the disabled client config, dedicated key, known-host pin, credential
file, and owner-only `.env`. PostgreSQL AC Hunter storage follows
`ASSET_POSTGRES_ENABLED` unless `AC_HUNTER_POSTGRES_ENABLED` is explicitly set.
Enable `/etc/so-alert-relay/ac-hunter.json` first and then
`$HOME/n8n-local/config/ac-hunter.json`. That order ensures the scheduled
collector continues to fail closed until the Relay trust boundary is ready.

## Validation and rollback

Run the collector once for cutover validation, then read the local database API:

```bash
launchctl kickstart -k \
  "gui/$(id -u)/com.arron.soc.ac-hunter"

curl --fail --silent --show-error \
  http://127.0.0.1:8766/api/ac-hunter/deep-review
```

Validate that the response identifies `security-onion-rolling`, reports
`storage_backend: postgresql`, has a bounded dataset time range, and contains
normalized findings rather than cookies, authorization headers, passwords, or
raw login HTML. Dashboard GET and reload requests must never produce SSH or AC
Hunter activity.

Verify two identical collector runs. The second run must return
`changed: false`, retain the same `dataset_digest`, leave the stored snapshot
unchanged, and add only the bounded pull-state/audit observation. A change to
any analyst-visible dataset field must produce `changed: true` and a new
content-addressed snapshot. Snapshots and pull history older than 24 hours are
pruned, except that the current snapshot is retained until replaced so an
unchanged dataset does not disappear.

The page rechecks PostgreSQL every 60 seconds for reactive display. Its
“Reload stored snapshot” button also reads PostgreSQL only. The sole automatic
pull schedule is:

```text
Every hour at HH:35 in the Mac Studio's configured timezone
```

The installed contract requests page `1` for bounded list operations. On the
deployed AC Hunter release, page `0` ignores `size` for beacon endpoints and
can return the entire dataset; page `1` honors the 100-row limit. This is a
compatibility guard, not an attempt to skip the first page.

Rollback is immediate and does not affect alert ingestion or Security Onion:

1. unload `com.arron.soc.ac-hunter`;
2. set `"enabled": false` in the Mac client config;
3. set `"enabled": false` in the Relay config; and
4. remove only the dedicated AC Hunter public-key entry if the transport is
   being retired.

Preserve the PostgreSQL schema and latest normalized snapshot for analyst
continuity unless incident handling requires removal. Never copy the live
credential file, private key, session cookie, JWT, CA trust decision, or cached
findings into Git.
