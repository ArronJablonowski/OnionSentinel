# ARR-19: Protocol and data-source skill packs

Status: non-production seed plan

## Pack strategy

Build small skills around a discriminating question, not one large “investigate
everything” prompt. Packs may recommend pivots, but every query is compiled by
a typed broker using the deployed field catalog and fixed target scope.

| Pack | Minimum evidence | Useful pivots | Important alternative |
| --- | --- | --- | --- |
| DNS | alert/flow time, client, resolver, qname/qtype when present | Zeek DNS, Suricata DNS, answer history, NXDOMAIN ratio, related TLS/HTTP | normal discovery, CDN, update, security tooling |
| TLS | five-tuple/time, SNI/cert/JA3 when present | Zeek SSL, cert chain, DNS history, flow duration/bytes, CTI | shared CDN/VPS, interception, normal client diversity |
| HTTP | flow/time, host/URI/method/user agent | Zeek HTTP, DNS, TLS upgrade, file metadata, bounded body metadata | updates, telemetry, automation, scanners |
| SSH | endpoints/time/direction | Zeek SSH/conn, duration/bytes, auth telemetry if available | administration, backup, automation |
| ICMP | type/code/direction/size/frequency | Suricata rule version, flow/PCAP-derived summary, peer history | monitoring, diagnostics, network appliances |
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
promotion attestations only in an in-memory copy, exercises the same
identity-only resolver used by the framework, checks each selected template's
expected fields against the frozen fixture catalog, and includes an
adversarial capability-expansion case. A passing synthetic replay is only the
start of verification. It does not replace version-pinned Security Onion,
Elastic, Zeek, Suricata, or PCAP field review; representative sanitized result
replay; independent query review; shadow measurement; or human approval.

`skill-packs/dns-triage-v2.example.json` demonstrates the v2 boundary. Its
verification flags are deliberately false because this package has not passed
the required replay, review, or human promotion gates. It is structurally
schema-valid but the registry must reject it for shadow or active promotion.
