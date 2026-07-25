# Security Onion Node

This directory contains the Security Onion-side pieces for Onion Sentinel.

## Files

| File | Destination | Purpose |
| --- | --- | --- |
| `bin/export-recent-alerts` | `/usr/local/sbin/export-recent-alerts` | Restricted wrapper that exports recent alerts as JSON. |
| `bin/export-pcap-window` | `/usr/local/sbin/export-pcap-window` | Restricted wrapper that streams one bounded, filtered rotation directly to the relay SSD without Security Onion staging. |
| `bin/export-incident-evidence` | `/usr/local/sbin/export-incident-evidence` | Restricted read-only incident evidence wrapper with fixed Elasticsearch query packs. |
| `bin/run-live-osquery` | `/usr/local/sbin/run-live-osquery` | Disabled-by-default live endpoint OSQuery wrapper with exact alias mapping and bounded Osquery Manager calls. |
| `sudoers/90-so-ai-relay-export` | `/etc/sudoers.d/90-so-ai-relay-export` | Allows only the wrapper to run passwordless for `so-ai-relay`. |
| `ssh/authorized_keys.example` | `/home/so-ai-relay/.ssh/authorized_keys` | Forced-command SSH template restricted to the relay source IP. |
| `ssh/authorized_keys.pcap.example` | `/home/so-ai-relay/.ssh/authorized_keys` | Separate forced-command SSH template for PCAP fulfillment. |
| `ssh/authorized_keys.incident-query.example` | `/home/so-ai-relay/.ssh/authorized_keys` | Separate forced-command SSH template for bounded incident evidence queries. |
| `ssh/authorized_keys.live-osquery.example` | `/home/so-ai-relay/.ssh/authorized_keys` | Separate forced-command SSH template for bounded endpoint OSQuery. |
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

Incident Response evidence collection uses another dedicated key entry based on
`security-onion/ssh/authorized_keys.incident-query.example`. That key can invoke
only `export-incident-evidence`; forwarding, PTY allocation, user rc files, and
arbitrary commands remain disabled.

The incident wrapper accepts validated observables and bounded UTC windows,
then executes five built-in Elastic packs and seven built-in OSquery packs.
Elastic covers alert context, network flow, DNS activity, host telemetry, and a
cross-sensor timeline. OSquery covers Security Onion system inventory,
logged-in users, listening ports, processes, packages, scheduled tasks, and
startup items. A separate fixed history pack searches retained Security Onion
Elastic osquery/endpoint events for the bounded incident window.

The caller cannot supply an index, field list, KQL expression, Query DSL
object, OSquery SQL, host target, path, or shell command. Every Elastic result
records the analyst-readable KQL equivalent and exact Query DSL submitted
through `so-elasticsearch-query`, plus the fixed per-pack index scope, exact
endpoint, shard result, and execution-manifest digest. The wrapper rejects
Elasticsearch root errors, timeouts, failed or zero shards, malformed hit
metadata, and hits outside the reviewed scope instead of interpreting them as
empty results.

The collector may supply only one representative alert backing index/document
ID produced by the restricted alert exporter. The incident wrapper validates
that index against the fixed alert scope, confirms the exact document is
retrievable once, and runs a contradictory ID-filter negative control. Both
controls, every Elastic pack, and every local OSquery pack must pass before the
response can set `complete: true`. An older anchorless request remains bounded
and readable but is always returned as a semantically unverified partial
result. Every OSquery result records the reviewed pack, exact SQL, local target,
status, query digest, bounded result metadata, and any explicit error. Query
DSL and OSquery SQL are the authoritative command audits; KQL is explanatory
and is not independently executed.

Live endpoint OSQuery is a separate Incident Responder capability based on
`security-onion/ssh/authorized_keys.live-osquery.example`. It remains disabled
until `/etc/onion-sentinel/live-osquery.json` maps each operator alias to one
exact Fleet agent ID and references a trusted Kibana CA plus a root-only
authorization file. The wrapper independently rejects wildcard targets,
non-SELECT SQL, comments, mutations, CTEs, compound queries, subqueries,
unknown tables, excessive rows, oversized output, and excessive runtime. It
uses the Kibana Osquery Manager API; neither the Mac nor relay receives the
Fleet IDs or credential. See
`docs/incident-response-query-and-model-routing.md` for the complete allowlist
and recovery gates.

PCAP fulfillment should use a separate key entry based on
`security-onion/ssh/authorized_keys.pcap.example`. The wrapper reads a bounded
JSON request from stdin. `stream_manifest` returns only validated source
metadata. `stream_chunk` runs a low-priority tuple-filtered `tcpdump` against one
bounded Security Onion rotation and writes the PCAP stream to SSH stdout. The
relay writes stdout directly to its external SSD and checkpoints each completed
chunk. No Onion Sentinel tar, filtered PCAP, or work directory is created under
`/nsm`.

Each manifest chunk is authorized by a Security Onion-local HMAC key at
`/etc/onion-sentinel/pcap-stream-token.key` (root-owned, mode `0600`). The later
`stream_chunk` call validates that signed source inode, initial size, request
window, and BPF variant directly. It does not rebuild the manifest from the
live capture directory, so normal Security Onion rotation cannot invalidate a
long transfer. Never copy this runtime key into the repository or relay.

The former staged-artifact and Security Onion rsync path is removed from the
production data plane. The relay rejects every non-stream transfer mode, and
the installer removes prior retention units and an empty Onion Sentinel staging
directory. The live restricted rsync account must remain locked or absent.

`install-security-onion-wrapper.sh` removes the deprecated rsync wrapper and
SSH match configuration, locks any existing legacy account, and moves its
authorized key to a root-only disabled-key directory. A DR rebuild therefore
cannot silently restore the disk-staging data plane.

`export-pcap-window` treats a validated `capture_file` as a preferred hint and
otherwise selects only rotations whose capture epochs overlap the bounded alert
window. Each source rotation must be at most 1.1 GiB by default, no more than 12
rotations are considered, and only one Onion Sentinel stream may run at once.
Tagged and untagged tuple filters are combined into one BPF expression so each
rotation is scanned only once. Source reads are capped at 4 MiB/s by default;
`ionice -c3` plus a positive niceness keeps the optional read behind Security
Onion's primary work. `/nsm` utilization is exposed as telemetry but never
blocks a read-only export. Fresh Zeek capture-loss telemetry is returned to the
relay, which defers new PCAP work when the latest worker interval exceeds 1%.
Security Onion owns native retention and capacity.
There is no total wall-clock cutoff for an active read; relay-side progress
monitoring ends only a stream that stops producing bytes.
The relay independently reserves 200 GiB on its 1 TB SSD and refuses projected
usage above 75 percent.

The destination service port is the normal BPF discriminator; request JSON may
set `require_source_port: true` only when an ephemeral source port is required.
Both VLAN-aware and plain BPF variants are attempted because capture
encapsulation differs by sensor.

Onion Sentinel does not run a retention writer on Security Onion. The stream
path reads native rotating captures through the restricted wrapper, writes no
archive under `/nsm`, and leaves native capture lifecycle management entirely
to Security Onion. The installer erases obsolete retention units from older
staged deployments. Runtime writes are limited to an advisory lock under
`/run`; the signing key is provisioned by the installer and the restricted
runtime wrapper cannot create or repair persistent files.

## Validate

```bash
sudo visudo -cf /etc/sudoers.d/90-so-ai-relay-export
sudo -u so-ai-relay sudo -n /usr/local/sbin/export-recent-alerts | jq '.alerts | length'
```

Expected result: JSON prints without prompting for a password.

The alert query uses `@timestamp` plus Elasticsearch's supported
`_shard_doc` tiebreaker with a fixed search preference. Do not change the
tiebreaker back to `_id`: current Security Onion Elasticsearch releases disable
`_id` fielddata, and sorting on it causes the active alert shard to fail. The
wrapper rejects top-level errors, partial shard failures, and malformed hit
responses instead of reporting a false successful zero-alert poll.

If relay heartbeats remain current but alert ingestion unexpectedly stops,
compare the wrapper's `.query` metadata with a metadata-only Elasticsearch
count. A wrapper failure must produce a nonzero relay poll result; a successful
empty batch is valid only when every queried shard succeeded.
