# Incident Responder Case Audit — Newest 15 Cases

Date: 2026-07-29  
Scope: the 15 most recently escalated Incident Responder cases at audit start  
Investigation path: Mac Studio → forced-command SSH → Relay → read-only Security Onion

Mac release containing the audit and PCAP-provenance fixes:
`63b8d526760f2aa42fb6405dafd4410e1522b183`.
The Mac remains intentionally pinned to compatibility-v1 until the restricted
Security Onion wrapper is upgraded and verified; case reanalysis must wait for
the coordinated v2 cutover.

## Executive result

The current reports are appropriately cautious about the absence of endpoint
process attribution, but their factored detection verdicts are materially
understated. Replaying the deployed Suricata rule predicates against the stored
Security Onion event data with the corrected deterministic validator produced:

- 15 of 15 selected events observed;
- 15 of 15 deployed rule intents matched;
- 14 cases with audited model-requested pivots, but zero successful dynamic
  pivot results;
- five primary reports that used `authorized_benign` without a structured
  operator authorization record;
- two exact-flow PCAPs completed during the audit, for one APT case and the
  Python SimpleHTTP case, and 13 exact-flow PCAP requests were still awaiting
  Relay fulfillment at the time this report was written.

`matched_intent` means the observed event satisfies the deployed detection
logic. It does not mean the activity is malicious. The activity disposition
and response decision must remain separate.

## Method and repeatability

For each case, the audit:

1. selected the case by `incident_response_cases.escalated_at DESC`;
2. reviewed the representative alert, complete grouped raw-alert rows,
   enrichment, prior analysis, primary Incident Responder response, independent
   second opinion, fixed Security Onion evidence artifact, query audit, and
   evidence gaps;
3. reran the checked-in deterministic Suricata parser against stored
   `network.data.decoded`/`payload_printable` application projections;
4. collected a fresh fixed incident-evidence artifact through the Relay using
   the representative alert, exact bounded observables, and fixed packs;
5. requested an exact alert-bound PCAP using both endpoints, both ports when
   available, the alert timestamp, a 300-second maximum window, and
   `require_source_port=true`;
6. treated every failed, rejected, truncated, or pending query as a limitation,
   never as negative evidence;
7. independently factored the conclusion into event observation, detection
   validity, activity disposition, authorization, and response handling.

The fixed Security Onion path completed for all 15 cases. Its exact
Elasticsearch Query DSL and query digest are authoritative execution records.
Its KQL is a readable equivalent only. The OQL request form is a restricted
analyst proposal that the wrapper compiles into fixed Query DSL; it is not a
second Security Onion Hunt execution. Fixed OSQuery snapshots describe the
Security Onion appliance. `osquery_history` is an Elastic search of indexed
history, not a live OSQuery command against an endpoint.

## Grading rubric

Each stored case was graded out of 100:

- 20: selected event and deployed rule intent;
- 25: fidelity to available application/network evidence;
- 20: successful, scoped, auditable pivots;
- 20: supported activity, authorization, and response labels;
- 15: complete limitations and repeatable query provenance.

Scores grade the stored Onion Sentinel case, not the quality of the underlying
Suricata rule.

## Case-by-case findings

| Case | Detection validity | Independent activity finding | Stored-case discrepancy | Grade |
|---|---|---|---|---:|
| `ir-7cf7aea2cc183d57` | `matched_intent` | Debian APT HTTP activity to Ubuntu/Canonical infrastructure is strongly consistent with package management; authorization not established | Stored `unknown` detection validity missed the exact `Debian APT-HTTP/1.3 (2.4.14)` User-Agent and Ubuntu `InRelease` request. Dynamic pivots: 0 successful | 58 |
| `ir-e3e00a86d1652a15` | `matched_intent` | Likely benign connectivity testing; exact HTTP data identifies `/connecttest.txt`, `www.msftconnecttest.com`, and GlobalProtect 6.1.1 on Linux. Authorization not established | Primary `authorized_benign` is unsupported. Stored report said exact HTTP metadata was absent even though it existed in the selected Suricata event | 47 |
| `ir-56ae78c97f626d68` | `matched_intent` | Strongly consistent with normal Ubuntu APT traffic; authorization not established | Primary `authorized_benign` is unsupported; exact APT User-Agent/host/request evidence was missed; 0 successful pivots | 44 |
| `ir-fc8db3aa9902402a` | `matched_intent` | Exact PCAP shows `Debian APT-HTTP/1.3 (2.4.14)` requesting `/ubuntu/dists/jammy-security/InRelease` from `security.ubuntu.com`, receiving HTTP 200 and a text response. This is normal Ubuntu APT traffic; formal authorization is still not established | Primary `authorized_benign` is unsupported; exact application evidence was missed; reviewer correctly reduced authorization certainty | 51 |
| `ir-cbbc240155dd8c00` | `matched_intent` | Exact PCAP shows Firefox on `192.168.100.14` requested `GET /reports.html` from `10.77.7.225:8766`; Python SimpleHTTP returned HTTP 404 and a 469-byte HTML body. Likely expected Onion Sentinel UI access, but formal authorization is not present | Stored report said banner/HTTP/PCAP evidence was missing. The selected Suricata event already contained `Server: SimpleHTTP/0.6 Python/3.9.6`; exact PCAP later independently corroborated the flow | 54 |
| `ir-b193e7b4ea0dbccc` | `matched_intent` | Valid RFC 5389 STUN binding request to Google on high port 19305; likely NAT traversal, but owning process and authorization are unknown | Primary `authorized_benign` is unsupported. Exact STUN framing existed in the selected event; dynamic Zeek pivot failed | 48 |
| `ir-fe8fdea2b7eac6f4` | `matched_intent` | Valid STUN binding request to Google on 3478, paired with responses; likely benign NAT traversal, with process attribution still required | Stored `unknown` validity understates deterministic protocol proof; 0 successful pivots | 54 |
| `ir-ae2675dbfbc0136a` | `matched_intent` | Exact TLS ClientHello contains `dns.google`. DoH is real; benignness is policy- and process-dependent | Primary `benign` is too strong without endpoint process or approved DoH policy. Stored report missed decisive SNI in the Suricata application projection | 46 |
| `ir-7f9c63d2a41f212f` | `matched_intent` | Exact TLS ClientHello contains `cloudflare-dns.com`. Activity is policy-relevant and remains unattributed | Stored `unknown` validity missed exact SNI. No successful exact Zeek/process pivot | 50 |
| `ir-c207dc9a18306e51` | `matched_intent` | Exact TLS ClientHello contains `dns.google`. Activity is policy-relevant and remains unattributed | Stored report explicitly said exact SNI was not independently validated, but selected-event evidence validates the deployed signature predicate | 50 |
| `ir-8ce3879de8bec697` | `matched_intent` | Exact TLS ClientHello contains `cloudflare-dns.com`. Activity is policy-relevant and remains unattributed | Stored report said exact SNI was unavailable despite its presence in the selected Suricata event | 50 |
| `ir-c7aa2cc288e3f4cf` | `matched_intent` | Exact TLS ClientHello contains `cdn.discordapp.com`, corroborated by nearby DNS. Use is policy-dependent; endpoint process is unknown | Primary `benign` is premature and stored validity is understated. Reviewer correctly moved activity to unknown | 47 |
| `ir-b1ffcf0e28f21268` | `matched_intent` | Exact TLS ClientHello contains `vscode.download.prss.microsoft.com`; likely normal VSCode download/update traffic | Stored report claimed trusted exact SNI was unavailable. It was present in the selected Suricata application projection | 52 |
| `ir-e3c6ea1c603ab983` | `matched_intent` | Exact DNS message queries `vscode.download.prss.microsoft.com`; paired TLS detection makes normal VSCode traffic likely | Stored report said the exact Zeek body/answer was missing, which is a fair Zeek limitation, but it incorrectly left deployed rule intent unknown despite the selected Suricata DNS evidence | 53 |
| `ir-c7844a5653322a04` | `matched_intent` | Valid paired STUN binding response from Google to the same workstation/flow; likely NAT traversal, but process and authorization remain unknown | Primary `authorized_benign` and suppression implication are unsupported. Reviewer correctly required more data; stored validity still missed exact STUN semantics | 47 |

## Cross-case truthfulness findings

### Decisive application evidence was present but not used

The original Suricata events retained bounded decoded application projections:

- HTTP method, URI, Host, User-Agent, server banner, and status;
- TLS SNI in ClientHello;
- DNS query name;
- STUN message type, magic cookie, and binding semantics.

The old validator looked primarily at packet-copy transport payload features.
That caused the reports to call deployed rule intent `unknown` while the exact
application predicate was present in the same trusted selected event.

### Dynamic pivot execution was not evidence-producing

Fourteen cases contained admitted iterative requests. None produced a
successful read-only pivot result. The recurring remote error was:

```text
investigation pivot query contract is unsupported
```

Other rejected requests used malformed observable structures, requested
untrusted observables, or exceeded the authorized time envelope. The reports
usually disclosed these failures, but the investigation workflow still
advanced to a conclusion without resolving its named discriminator.

### Authorization was inferred rather than proven

`authorized_benign` appeared in five primary responses without a structured
change record, owner assertion, approved software/service record, or analyst
decision supporting authorization. Vendor ownership, recurrence, an asset
inventory expectation, or a plausible benign application may support
`benign`, but none alone establishes `authorized_benign`.

### Second opinions were materially useful but not conservatively merged

The independent reviewer materially disagreed in 11 of 15 cases, commonly
reducing `authorized_benign` to `benign`/`unknown` and changing `no_action` to
monitor/investigate. The durable top-level response did not consistently
become disputed/inconclusive after those material disagreements.

### Exact PCAP requests used mutable rollup timestamps

The representative alert row can retain the immutable original `timestamp`
while `first_seen`/`last_seen` move forward after replay or rollup. The audit
requests were tied to the exact alert ID and returned the correct alert
capture, but their request metadata displayed the later rollup time. The
parser's Zeek/TShark coverage timestamps and exact alert ID establish the
completed captures' actual packet times. Future exact-alert PCAP requests now
bind both window endpoints to the database-owned event `timestamp`.

### Query-language labels

No reviewed case was found to have truthfully executed KQL while falsely
calling it OSQuery. The recurring labels were generally correct:

- exact `query_dsl`: executed Elasticsearch request;
- `kql_equivalent`: explanatory filter equivalent, not separately executed;
- OQL: restricted proposal compiled to fixed Query DSL;
- fixed OSQuery: local Security Onion appliance only;
- `osquery_history`: Elasticsearch search over historical indexed events;
- live endpoint OSQuery: disabled and not executed.

## Harness corrections implemented from the audit

1. The deterministic Suricata validator now evaluates bounded HTTP, DNS, TLS,
   and STUN application projections without exposing raw payloads to a model.
2. HTTP content modifiers, application sticky buffers, TLS dot-prefix
   semantics, and RFC 5389 STUN framing are handled deterministically.
3. Incident Responders receive a repeatable protocol-first pivot plan derived
   only from the collector-authorized alert tuple:
   - fixed pack selection by deployed protocol;
   - exact ±5-minute UTC window;
   - fixed `size=100`;
   - exact authorized IPs;
   - `network.community_id` correlation when crossing Suricata/Zeek roles;
   - no model-supplied KQL, OQL, DSL, SQL, fields, indices, or shell text.
4. The response audit records deterministic query IDs and a canonical plan
   digest, allowing the same evidence package to reproduce the same plan.
5. PCAP selection now distinguishes exact-alert captures from historical
   stable-group captures. Historical group captures can inform prevalence but
   cannot be claimed as proof of the selected alert.
6. `authorized_benign` now requires structured trusted authorization evidence.
   Unsupported values are reduced to `benign`, response handling becomes at
   least `monitor`, and suppression/drop tuning becomes `needs_more_data`.
7. A material primary/reviewer disagreement now forces a conservative disputed
   top-level state for human review.
8. Prompt instructions now state the exact KQL/OQL/DSL/OSQuery execution
   distinctions.
9. Exact-alert PCAP requests now use the immutable selected-event timestamp
   instead of mutable ingestion `first_seen`/`last_seen` rollup values.

## Remaining blockers

1. **Restricted wrapper contract mismatch:** the installed Security Onion
   companion rejects `onion-sentinel-investigation-pivots-v2`. Install and
   verify the reviewed v2 Security Onion wrapper and matching Relay broker
   documented in the Desktop restricted-node handoff.
2. **Endpoint attribution:** live endpoint OSQuery remains intentionally
   disabled. Do not claim process, user, or authorization findings until an
   approved endpoint telemetry path exists.
3. **PCAP queue latency:** 15 exact PCAP requests were submitted. Two completed
   during the audit and 13 remained pending/claimed. Final case grades should
   be amended when those exact captures complete.
4. **Asset authorization:** inventory relationships help name systems but are
   not authorization records. Add a separate structured, time-bounded
   authorization source if the operator wants `authorized_benign` outcomes.
5. **Capture coverage:** preserve Zeek capture-loss telemetry in every evidence
   handoff so missing Zeek metadata is not interpreted as traffic absence.

## Independent disposition summary

No case contains evidence of confirmed compromise. All 15 detections are valid
matches to their deployed informational rules. APT and VSCode cases are
strongly consistent with expected software traffic; the SimpleHTTP case is
corroborated as a browser request to the known Onion Sentinel service; STUN
cases are strongly consistent with NAT traversal; and DoH/Discord cases are
real domain uses whose acceptability depends on endpoint process attribution
and local policy. None of those contextual conclusions proves operator
authorization.
