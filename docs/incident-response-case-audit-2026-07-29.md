# Incident Responder Case Audit — Newest 15 Cases

Date: 2026-07-29  
Scope: the 15 most recently escalated Incident Responder cases at audit start  
Investigation path: Mac Studio → forced-command SSH → Relay → read-only Security Onion

Pre-v2 Mac release containing the original audit and PCAP-provenance fixes:
`63b8d526760f2aa42fb6405dafd4410e1522b183`.

Cutover update at 2026-07-29 18:23 MDT: the restricted Security Onion wrapper
now accepts `onion-sentinel-investigation-pivots-v2`. A production
Mac → Relay → Security Onion probe returned a complete, semantically valid
`zeek_http` event with valid positive/negative controls. Two identical probes
produced the same executed-query digest
`00ec985db7eb8c9cb50fa72002be1e4cbab5d551bb63d9bb53609aba9eaa6d48`.
The Mac was explicitly cut over to v2. Blind reanalysis of the 15 audited
cases was then restarted on release
`79a1a8ac16837dbbf1f242f1c0a870349cdbbeb7`, which requires an independent
second opinion for every manual Incident Responder rerun.

## Executive result

The original stored reports were appropriately cautious about missing endpoint
process attribution, but their factored detection verdicts were materially
understated. Replaying the deployed Suricata rule predicates against stored
Security Onion data with the corrected deterministic validator produced:

- 15 of 15 selected events observed;
- 15 of 15 deployed rule intents matched;
- 42 successful read-only v2 Security Onion queries in the blind rerun;
- zero broker/query errors, timeouts, or partial results;
- four fail-closed model-proposal rejections, all caused by the same malformed
  `observables` container;
- 15 completed independent second opinions: two full agreements, five partial
  disagreements, and eight material disagreements;
- six fulfilled exact-flow PCAP requests, five failed closed with
  `no matching packets found`, one claimed, and three pending at the cohort
  checkpoint.

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

The grades below are for the pre-v2 stored reports that triggered this audit.
They are retained as the baseline against which the corrected blind rerun is
measured.

| Case | Detection validity | Independent activity finding | Stored-case discrepancy | Grade |
|---|---|---|---|---:|
| `ir-7cf7aea2cc183d57` | `matched_intent` | Debian APT HTTP activity to Ubuntu/Canonical infrastructure is strongly consistent with package management; authorization not established | Stored `unknown` detection validity missed the exact `Debian APT-HTTP/1.3 (2.4.14)` User-Agent and Ubuntu `InRelease` request. Dynamic pivots: 0 successful | 58 |
| `ir-e3e00a86d1652a15` | `matched_intent` | Likely benign connectivity testing; exact HTTP data identifies `/connecttest.txt`, `www.msftconnecttest.com`, and GlobalProtect 6.1.1 on Linux. An exact-flow PCAP now independently corroborates the HTTP 200 transaction. Authorization not established | Primary `authorized_benign` is unsupported. Stored report said exact HTTP metadata was absent even though it existed in the selected Suricata event | 47 |
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

## Blind v2 rerun checkpoint

All 15 cases completed on release
`79a1a8ac16837dbbf1f242f1c0a870349cdbbeb7` using
`onion-sentinel-investigation-pivots-v2`. Every case used the primary
`codex-cli:gpt-5.5:high` route and the independent
`codex-cli:gpt-5.6-sol:xhigh` reviewer route.

| Case | Canonical v2 result | Successful / rejected pivots | Reviewer |
|---|---|---:|---|
| `ir-56ae78c97f626d68` | `matched_intent`; benign; no action; not authorized | 3 / 0 | partial disagreement |
| `ir-7cf7aea2cc183d57` | `matched_intent`; benign; no action; not authorized | 2 / 1 | partial disagreement |
| `ir-7f9c63d2a41f212f` | `matched_intent`; unknown; monitor; disputed | 3 / 1 | material disagreement |
| `ir-8ce3879de8bec697` | `matched_intent`; unknown; monitor; disputed | 2 / 0 | material disagreement |
| `ir-ae2675dbfbc0136a` | `matched_intent`; benign; no action; not authorized | 4 / 0 | partial disagreement |
| `ir-b193e7b4ea0dbccc` | `matched_intent`; unknown; monitor; disputed | 3 / 1 | material disagreement |
| `ir-b1ffcf0e28f21268` | `matched_intent`; benign; no action; not authorized | 4 / 0 | partial disagreement |
| `ir-c207dc9a18306e51` | `matched_intent`; unknown; monitor; disputed | 4 / 0 | material disagreement |
| `ir-c7844a5653322a04` | `matched_intent`; unknown; monitor; disputed | 2 / 0 | material disagreement |
| `ir-c7aa2cc288e3f4cf` | `matched_intent`; benign; no action; not authorized | 3 / 1 | partial disagreement |
| `ir-cbbc240155dd8c00` | `matched_intent`; benign; no action; not authorized | 2 / 0 | agreement |
| `ir-e3c6ea1c603ab983` | `matched_intent`; unknown; monitor; disputed | 4 / 0 | material disagreement |
| `ir-e3e00a86d1652a15` | `matched_intent`; unknown; monitor; disputed | 2 / 0 | material disagreement |
| `ir-fc8db3aa9902402a` | `matched_intent`; unknown; monitor; disputed | 2 / 0 | material disagreement |
| `ir-fe8fdea2b7eac6f4` | `matched_intent`; benign; no action; not authorized | 2 / 0 | agreement |

The execution ledger identifies every trusted dynamic query as dialect
`elastic` with execution backend `so-elasticsearch-query`. KQL and OQL are
retained only as readable equivalents. The fixed OSQuery snapshots target
`security-onion-local-host`; live endpoint OSQuery remained disabled and no
endpoint command was executed.

This checkpoint exposed two repeatable harness defects:

1. Four otherwise bounded model proposals encoded `observables` as a list.
   The harness correctly rejected the non-contract shape, but could not
   schedule its one bounded planning-repair round.
2. In five cases an exact selected-alert PCAP was available, but prompt-budget
   compaction could retain an older stable-group capture because direct PCAP
   artifacts were not deterministically ordered. The count still reported
   exact evidence, creating a contradiction between metadata and the one
   retained parsed capture.

Both defects are corrected in the next reviewed Mac release. A smaller
post-deployment validation cohort will rerun every malformed-proposal case and
every case with a fulfilled exact PCAP.

## Release 494 targeted validation

Release `494b75eeb72aea695b4bbb6b1fb2b10ebc935351` was validated with
nine blind Incident Responder reruns: the union of the four cases that had
previously emitted malformed observable containers and the six cases with
fulfilled exact-alert PCAP. The cohort completed with:

- nine completed cases, zero failed or skipped;
- nine durable independent second-opinion runs;
- 23 successful, read-only Security Onion queries;
- zero query execution errors, timeouts, or partial results;
- four fail-closed proposal rejections in three cases;
- three reviewer agreements, three partial disagreements, and three material
  disagreements.

| Case | Post-fix canonical result | Successful / rejected pivots | Reviewer | Post-fix grade |
|---|---|---:|---|---:|
| `ir-7cf7aea2cc183d57` | `matched_intent`; benign APT activity; no action; not authorized | 3 / 1 | partial disagreement | 92 |
| `ir-7f9c63d2a41f212f` | `matched_intent`; suspicious DoH; investigate; not authorized | 4 / 0 | partial disagreement | 96 |
| `ir-b193e7b4ea0dbccc` | `matched_intent`; benign STUN; no action; not authorized | 2 / 0 | agreement | 96 |
| `ir-c7844a5653322a04` | `matched_intent`; benign STUN; no action; not authorized | 2 / 0 | agreement | 96 |
| `ir-c7aa2cc288e3f4cf` | `matched_intent`; unknown Discord policy disposition; disputed | 4 / 0 | material disagreement | 94 |
| `ir-cbbc240155dd8c00` | `matched_intent`; benign SimpleHTTP access; no action; not authorized | 2 / 2 | material disagreement limited to tuning | 88 |
| `ir-e3e00a86d1652a15` | `matched_intent`; benign connectivity test; no action; not authorized | 2 / 0 | agreement | 97 |
| `ir-fc8db3aa9902402a` | `matched_intent`; benign APT activity; no action; not authorized | 2 / 0 | partial disagreement | 97 |
| `ir-fe8fdea2b7eac6f4` | `matched_intent`; benign STUN; no action; not authorized | 2 / 1 | material disagreement limited to tuning | 91 |

The exact-alert PCAP ordering correction materially changed the truthfulness of
four reports:

- `ir-c7844a5653322a04` and `ir-b193e7b4ea0dbccc` now cite exact,
  bidirectional STUN framing instead of remaining unknown;
- `ir-e3e00a86d1652a15` now cites the exact
  `www.msftconnecttest.com/connecttest.txt` HTTP 200 transaction and the
  GlobalProtect User-Agent;
- `ir-fc8db3aa9902402a` now cites the exact Ubuntu security `InRelease`
  request, Debian APT User-Agent, HTTP 200 response, and returned metadata
  file;
- `ir-cbbc240155dd8c00` now cites the exact Firefox `GET /reports.html`
  request and Python SimpleHTTP 404 response.

The reviewer-disagreement gate also behaved as intended. A real case
disposition dispute (`ir-c7aa2cc288e3f4cf`) remained conservative and pending
human adjudication. Disputes limited to tuning
(`ir-cbbc240155dd8c00` and `ir-fe8fdea2b7eac6f4`) preserved the agreed benign
case verdict while blocking tuning, memory writeback, and consequential
automation.

The remaining four rejections revealed one narrower repair defect:

- two list-shaped `observables` proposals could not be repaired when the list
  contained no recoverable scalar, even though a valid alert event tuple was
  present;
- two proposals supplied a contract-shaped `observables` object whose four
  lists were all empty, so the deployed repair path did not treat the object
  as malformed.

The follow-up Mac-only correction treats empty observable objects as invalid
and can derive a repair scope from the alert event tuple only when every
non-empty tuple IP maps uniquely to the collector-owned permitted IP catalog.
A partly trusted tuple, unknown value, ambiguous value, new query text, or
wider window remains rejected.

### Release f596 repair validation

Release `f596c6485aeb8e43a6c5aa37685b02d80777a0b9` reran the three
cases that retained proposal rejections. All three completed with independent
second opinions:

- `ir-fe8fdea2b7eac6f4` emitted a valid request directly and completed with two
  successful pivots and no rejection;
- `ir-cbbc240155dd8c00` produced a valid
  `trusted_event_tuple_intersection` repair candidate, but the model returned
  final synthesis instead of the requested repaired query;
- `ir-7cf7aea2cc183d57` produced the same trusted repair candidate, but the
  model restated it with a changed event tuple and the non-widening validator
  correctly rejected it.

This proved that repair-scope derivation was correct but still depended on a
second model response. The final correction removes that dependency. Once a
repair scope is normalized against collector-owned authorization, the harness
reconstructs and executes that exact scope in the single repair round. It
does not ask a model to restate, narrow, or modify the query. The audit retains
the original failed attempt and records deterministic scope execution. If the
same query ID later succeeds, the failed attempt is marked as a resolved retry
rather than an unresolved evidence gap.

Concurrent validation workers also exposed a scheduler observability defect.
When two workers selected the same pending job, the compare-and-set lease
correctly allowed only one owner, but the losing worker logged the group as
failed and consumed its bounded work allowance. The corrected scheduler logs
normal `claim contention`, performs no failure transition, does not invoke
analysis, and continues to another eligible group.

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
10. Manual Incident Responder reanalysis now deterministically requires the
    configured independent second-opinion route, even when a confident primary
    would not otherwise request review.
11. The Mac installer now stops exact orphaned AI scheduler/runner processes
    after unloading their LaunchAgents, preventing a pre-cutover process from
    finishing with stale in-memory query-contract code.
12. A malformed observable container can enter the single planning-repair
    round only when its scalar values map unambiguously to the collector-owned
    permitted-observable catalog. Unknown or ambiguous values still fail
    closed; model-provided syntax never gains authority.
13. Parsed PCAP evidence is now ordered with exact selected-alert captures
    before stable-group historical context, and package-budget counts are
    recomputed after truncation.
14. A material disagreement limited to suppression/drop tuning now preserves
    the primary/reviewer-agreed case verdict while blocking tuning and
    automation. A material disagreement in the case disposition still
    publishes the conservative `unknown`/monitor-or-investigate state.
15. Empty or non-object observable containers can use the single bounded
    planning-repair round only when all non-empty alert event-tuple IPs map
    uniquely to the trusted permitted-observable catalog. Partly trusted
    tuples fail closed.
16. A valid non-widenable repair scope is executed deterministically without a
    second model call. The original failed attempt remains visible, while a
    later successful execution of the same query ID is recorded as a resolved
    retry and no longer creates a false evidence-completeness gap.
17. A lost durable-job compare-and-set claim is classified as normal worker
    contention, not an analysis failure, and does not consume the losing
    worker's bounded analysis allowance.

## Remaining blockers

1. **Endpoint attribution:** live endpoint OSQuery remains intentionally
   disabled. Do not claim process, user, or authorization findings until an
   approved endpoint telemetry path exists.
2. **PCAP queue latency:** 15 exact PCAP requests were submitted. At the final
   audit checkpoint, six were fulfilled, seven had failed closed with
   `no matching packets found`, and two remained pending. A failed, pending,
   or in-transfer capture is an evidence gap, not negative evidence.
3. **Asset authorization:** inventory relationships help name systems but are
   not authorization records. Add a separate structured, time-bounded
   authorization source if the operator wants `authorized_benign` outcomes.
4. **Capture coverage:** preserve Zeek capture-loss telemetry in every evidence
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
