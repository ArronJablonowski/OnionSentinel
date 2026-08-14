# ARR-19: Protocol and data-source skill packs

Status: non-production seed plan

## Pack strategy

Build small skills around a discriminating question, not one large “investigate
everything” prompt. Packs may recommend pivots, but every query is compiled by
a typed broker using the deployed field catalog and fixed target scope.

| Pack | Minimum evidence | Useful pivots | Important alternative |
| --- | --- | --- | --- |
| Alert/group context | exact selected event, trusted timestamp, group dimensions and member identities | exact anchor, bounded group drilldown, per-member tuple and rule attribution | newest group member differs from earlier/later observations or broad grouping combines unrelated events |
| Flow/window expansion | trusted anchor, role-safe tuple, bounded authorization envelope | narrow flow anchor, then bounded cross-sensor windows with unchanged filters | monitoring, maintenance, retention gaps, asymmetric routing |
| DNS | alert/flow time, client, resolver, qname/qtype when present | Zeek DNS, Suricata DNS, answer history, NXDOMAIN ratio, related TLS/HTTP | normal discovery, CDN, update, security tooling |
| TLS | five-tuple/time, SNI/cert/JA3 when present | Zeek SSL, cert chain, DNS history, flow duration/bytes, CTI | shared CDN/VPS, interception, normal client diversity |
| HTTP | flow/time, host/URI/method/user agent | Zeek HTTP, DNS, TLS upgrade, file metadata, bounded body metadata | updates, telemetry, automation, scanners |
| SSH | endpoints/time/direction | Zeek SSH/conn, duration/bytes, auth telemetry if available | administration, backup, automation |
| ICMP | type/code/direction/size/frequency | Suricata rule version, flow/PCAP-derived summary, peer history | monitoring, diagnostics, network appliances |
| Scanning | trusted actor/target and bounded window | peer/port breadth, outcomes, direction, asset authorization | vulnerability scanning, discovery, health checks, retry storms |
| DoH | attributable HTTPS flow and client | TLS/QUIC identity, visible HTTP metadata, conventional DNS baseline | approved secure DNS, privacy/security software, shared resolver infrastructure |
| STUN | exact STUN event/flow and role semantics | method/class, NAT addresses, flow duration/bytes, application context | conferencing, WebRTC, gaming, VPN or support software |
| Beaconing | attributable peer and multiple covered windows | timestamp/volume series, cross-sensor application context | updates, telemetry, messaging, VPN keepalives |
| Long connection | connection anchor, duration/state/bytes | peer/application ownership and bounded timeline | VPN, administration, replication, messaging, incomplete capture |
| Suricata intent | exact SID/revision and event | active rule metadata, upstream documentation, matching fields, flow context | signature is syntactically true but benign in environment |
| Zeek correlation | UID/community ID/five-tuple/time | conn then protocol log, files, notices, weirds | parser/retention/asymmetric-routing gaps |
| Elastic/OQL | normalized identity and bounded time | exact field catalog and read-only language-specific query | field drift, index/sensor/retention gaps |
| Historical OSQuery | host identity and collection time | approved pack results for processes, users, sockets, software | stale collection or host mismatch |
| Live OSQuery | explicit host approval and pack | narrow approved query only | endpoint cost, sensitive output, transient state |
| Derived PCAP | existing capture digest and bounds | Zeek/TShark summaries, packet loss/snaplen/parser metadata | partial/asymmetric/encrypted capture |
| CTI/AC Hunter | normalized indicator/behavior and freshness | provenance-rich reputation and cross-module behavior | shared infrastructure, circular/stale reporting |

## Required result semantics

Every pack reports successful/failed/rejected/partial/unavailable status,
validated scope, row and byte bounds, truncation, telemetry gaps, evidence
references, alternative hypotheses, and the smallest useful next pivot. Empty
results are never generalized beyond their exact successful scope.

Each pack separately defines `positive_evidence`, `negative_evidence`, and
`escalation_pivots`. Positive evidence is an admitted observation that supports
the scoped hypothesis. Negative evidence must come from a successful,
complete, non-truncated observation over the exact declared target, tuple, and
time window; unavailable, unverified, failed, partial, or mapping-drifted data
remains a gap and cannot be used as a negative. Escalation pivots are bounded
discriminators, not authority: the broker still owns capability intersection,
target and time bounds, query compilation, approval, and execution.

## Delivery sequence

1. Promote DNS, TLS, HTTP, SSH, ICMP, Suricata intent, and Zeek correlation
   through offline replay.
2. Add Elastic Query DSL, KQL, and OQL as separate language-specific skills.
3. Add historical OSQuery and existing derived PCAP skills.
4. Keep live OSQuery and remote PCAP creation separate and approval-gated.
5. Add CTI and AC Hunter only as contextual sources, never verdict authorities.

## Offline replay checkpoint

The seven first-wave candidates now have a synthetic, non-production replay
corpus at
`n8n/config/investigation-skills-v2-candidates/offline-replay-fixtures.json`.
Run the deterministic identity-routing and expected-field contract check with:

```bash
python3 n8n/bin/evaluate-investigation-skills-v2.py
```

The evaluator executes no query and cannot activate a candidate. It satisfies
promotion attestations only in an in-memory copy and exercises the same
identity-only resolver used by the framework. Security Onion, Elastic, Zeek,
Suricata, and historical OSQuery template fields are checked against the exact
allowlisted field projections in
`security-onion/bin/export-incident-evidence`. Derived-PCAP fields come from
`pcap_evidence_query_policy.py`, and AC Hunter fields come from the stable
top-level return projection in `ac_hunter_collection_projection.py`; fixture
catalog fields cannot mask drift in any of those governed sources. The replay
also includes an adversarial capability-expansion case. A passing offline
replay is only the start of verification. It does not replace deployed-version
mapping comparison, representative sanitized result replay, independent query
review, shadow measurement, or human approval.

All candidate manifests pin the output fact-state set to `observed`,
`inferred`, `unverified`, and `unavailable`. This keeps absent or inaccessible
telemetry distinct from a confirmed negative observation across every protocol
and data-source pack.

Two foundational candidates cover the pre-protocol investigation boundary.
Alert/group validation treats the exact selected alert separately from grouped
history; a grouped view's newest member is never projected onto other members.
Flow/window expansion begins at the trusted anchor and widens only inside the
broker-owned authorization envelope, without changing observable or tuple
meaning. Both candidates use the governed `alert_context`, `network_flow`, and
`cross_sensor_timeline` projections and remain inactive and unpromotable.

Five behavioral network candidates cover scanning, DoH, STUN, beaconing, and
long connections. They require attributable bounded observations and competing
benign explanations: breadth, encryption, periodicity, STUN use, or duration
alone never establishes malicious intent. The STUN pack is pinned to Security
Onion's bundled Zeek analyzer; the DoH pack follows RFC 8484 and reports
encrypted DNS content as unavailable unless separately observable.

Three language-specific candidates preserve the deployed query provenance
boundary. The Query DSL pack validates the canonical broker-generated request
as the exact execution record. The KQL pack validates only the
analyst-readable filter equivalent and explicitly records that KQL was not
executed. The Security Onion OQL pack validates the release-pinned Hunt OQL
representation and its independent compilation to the fixed Query DSL path; it
does not claim that the SOC Hunt API executed the OQL text. All three accept
only typed broker parameters, use governed wrapper field projections, and
remain inactive and unpromotable.

Three direct-source candidates preserve their distinct authority and freshness
semantics. Historical OSQuery searches only already-indexed endpoint and
Osquery Manager streams through the governed `osquery_history` pack; it cannot
dispatch SQL or select a live endpoint. Derived PCAP reads only an already
admitted sanitized artifact through fixed coverage, connection, and packet-fact
operations; it cannot carve a new stream, return raw packets, or invoke a
parser, shell, filesystem path, or network call. AC Hunter reads only the
normalized local snapshot through `reports.read`; its scores and correlations
prioritize review and never prove malware, compromise, or malicious intent.
All remain inactive and unpromotable.

The same offline corpus includes sanitized evidence-state cases for common
benign CDN DNS, approved SSH administration, conferencing STUN, periodic
telemetry, and long-lived VPN traffic, plus injection-like evidence,
malformed rows, partial/truncated results, mapping drift, failed sources,
unsupported sources, and a complete exact-scope empty result. The evaluator
projects only case identity, category, fact state, and negative-evidence
eligibility; it never echoes fixture rows or consumes their text as guidance.
Only the successful, complete, non-truncated, evidence-referenced empty case
permits scoped negative evidence. Every other gap remains `unverified` or
`unavailable`, while interpretation cases remain explicitly `inferred`.

`skill-packs/dns-triage-v2.example.json` demonstrates the v2 boundary. Its
verification flags are deliberately false because this package has not passed
the required replay, review, or human promotion gates. It is structurally
schema-valid but the registry must reject it for shadow or active promotion.
