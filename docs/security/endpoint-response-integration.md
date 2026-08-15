# Isolated Endpoint-Response Integration

Status: design qualified, execution disabled

Owner: Onion Sentinel security architecture and incident-response operators

Tracked by: ARR-38, related to ARR-70

## Decision

Onion Sentinel may evaluate an endpoint-response integration only as an
isolated brokered capability. The investigation system and every model remain
recommendation-only. No model, prompt, report, alert, query result, or evidence
field can approve an action, select a target, obtain a reusable privileged
credential, or invoke the response broker directly.

The repository contract is
`operations/security/endpoint-response-governance.json`. It deliberately
records both review gates as unapproved and response execution as disabled.
`operations/validate-endpoint-response-governance.py` rejects any source change
that enables the capability or weakens the minimum boundary. The contract is a
security design and release gate, not an endpoint agent, transport, credential,
deployment plan, or authorization to run a proof of concept.

## Authority Separation

```text
untrusted telemetry -> read-only investigation broker -> evidence and recommendation
                                                        |
                                                        v
                                            durable approval request
                                                        |
                               two distinct trusted human approvers
                                                        |
                                                        v
                     disabled isolated response broker -> one typed target-bound action
                                                        |
                          independent verification -> receipt or rollback
```

The two capability tiers must use different service identities, credential
scopes, and route scopes:

| Tier | Allowed authority | Forbidden authority |
| --- | --- | --- |
| `investigation_read_only` | Existing bounded, attributable collection and query operations | State change, response credential use, response-broker invocation |
| `response_mutation` | Eventually, one approved typed action through a separate broker | Investigation queries, arbitrary commands, shell, interactive or unrestricted SSH, target discovery, approval |

The current read-only query and PCAP paths do not become a response transport.
The Relay and Security Onion remain read-only. A future response service must
be separately installed, identified, routed, reviewed, and operated; it cannot
reuse the investigation broker, Relay identity, or Security Onion credential.

## Request And Approval Contract

A future request envelope must be created by trusted code and bind all of the
following into a canonical digest:

- one request identifier and one-use nonce;
- one allowlisted action identifier;
- one exact operator-inventory asset identifier and target identity digest;
- one closed, typed parameter object and its digest;
- the pre-action evidence seal and provenance references;
- expiry no more than five minutes after approval;
- the action timeout and idempotency key;
- the required postcondition and rollback checks; and
- the requesting investigation and recommendation provenance.

Two distinct human principals from an operator-controlled trust store must
approve the exact same digest. Both must be distinct from the requester. A
model identity, service identity, free-text answer, chat acknowledgement,
prompt edit, UI click without a signed digest, or previously used approval can
never authorize execution. Changing the target, action, parameters, evidence,
expiry, or nonce invalidates every approval and creates a new request.

Approval is necessary but not sufficient. The broker independently revalidates
the action and target allowlists, target identity, inventory authority, nonce,
expiry, idempotency state, approvals, pre-action evidence seal, credential
scope, and current safety policy immediately before adapter selection.

## Action And Target Scope

The initial guarded proof-of-concept candidate is
`endpoint_network_isolation`, with the code-owned rollback operation
`endpoint_network_restore`. This is a design identifier only; no executable
adapter is present. It has one typed `isolation_profile_id` parameter, a
120-second maximum timeout, mandatory pre-action evidence, and mandatory
independent postcondition verification.

The initial proof of concept must refuse:

- process execution, package installation, file retrieval or modification,
  account changes, reboot, destructive collection, or evidence deletion;
- any non-reversible or partially specified action;
- arbitrary command text, scripts, shell fragments, SSH command lines, query
  languages, URLs, paths, environment variables, or provider-native payloads;
- wildcards, ranges, broadcast groups, model-selected targets, discovered
  targets, or a target absent from the operator-managed inventory;
- an endpoint identity that differs from the independently observed hardware
  and response-agent binding; and
- a destination outside the broker's exact egress allowlist.

Adding an action is a security-boundary change. It requires red
characterization, threat-model review, rollback and out-of-band recovery proof,
bounded adapter tests, and explicit approval separate from the approval of an
individual action request.

## Credential And Transport Boundary

No reusable root, administrator, SSH, API, or endpoint credential may enter a
model context, prompt, report, evidence object, source file, Linear comment,
request envelope, approval record, audit receipt, command line, inherited
environment, or general-purpose investigation service.

A future broker may obtain only a short-lived capability from an
operator-controlled issuer after all admission checks pass. That capability
must be bound to one action, target identity, request digest, nonce, and expiry;
it must not permit discovery, lateral movement, interactive login, or a second
action. Failure to mint or attest the exact capability is a refusal, never a
fallback to a broader credential or transport.

The adapter must be code-owned and positively project typed parameters into a
provider-specific request. Endpoint or model text cannot select an adapter,
route, credential, destination, executable, or provider operation. The broker
has no general shell and no unrestricted SSH client.

## Evidence, Audit, And Recovery

Before mutation, the system seals the relevant evidence and request provenance
outside the target's control. The action receipt is appended to an independent
store and contains only bounded identifiers, digests, timestamps, result state,
postcondition proof, and rollback receipt binding. It excludes raw endpoint
output and all secret values.

The endpoint's self-report is never sufficient proof of success. An independent
observer must verify the exact postcondition. Missing, ambiguous, late, or
digest-mismatched verification produces a failed or indeterminate result and
initiates the reviewed rollback path. Rollback uses a separately typed,
idempotent operation and is independently verified. If rollback cannot be
proven, the broker stops further actions, preserves all receipts and evidence,
and escalates to out-of-band recovery.

Retries reuse the same idempotency identity and must return the prior terminal
receipt or safely resume the same bounded operation. A retry never consumes a
new approval to widen action or target scope. Crash recovery treats an action
without a terminal independently verified receipt as indeterminate, not
successful.

## Threat Model

| Threat | Required controls | Fail-closed result |
| --- | --- | --- |
| Compromised endpoint | Operator-owned inventory binding, pre-action evidence seal, independent identity and postcondition observation | Reject an unverifiable target or state; never trust endpoint self-report alone |
| Command injection | Closed action and parameter schemas, code-owned adapter, unknown-field rejection, no shell/SSH/arbitrary command surface | Reject before adapter or credential selection |
| Credential theft | Broker-held short-lived target/action capability, isolated service identity, secret-free requests and receipts | Refuse if exact ephemeral authority cannot be minted and attested |
| Lateral movement | Exact target binding, broker egress allowlist, no discovery or wildcard scope, no shared investigation identity | Reject a model-selected, inventory-mismatched, or non-allowlisted destination |
| Evidence tampering | Pre-action provenance seal, independent append-only receipt, independent postcondition and rollback verification | Preserve disputed evidence and refuse a success claim when proof is absent |

Additional abuse cases include approval replay, confused deputy behavior,
request races, duplicate execution, clock skew, partial response, broker crash,
provider ambiguity, compromised approver accounts, and malicious evidence that
claims to be an instruction. Nonces, digest-bound short approvals,
requester/approver separation, idempotency, closed schemas, independent state,
and conservative indeterminate outcomes address those cases. Compromise of the
operator trust store or the independent observer remains an out-of-band
incident and blocks the proof of concept.

## Guarded Proof-Of-Concept Gate

Implementation and deployment remain prohibited until a new reviewed change
provides all of this evidence:

1. An approved security review names the provider, endpoint agent, issuer,
   independent observer, audit store, network path, owners, and rollback owner.
2. A separately approved POC plan selects non-production synthetic endpoints
   with out-of-band console recovery and no access to Security Onion or the
   Relay.
3. The broker, issuer, adapter, and observer use separate least-privilege
   identities and exact egress controls; a model cannot address any of them.
4. Red tests prove rejection of unknown fields/actions, command injection,
   wildcard or swapped targets, model approval, reused/expired approvals,
   duplicate execution, stolen or overbroad authority, missing evidence,
   verification disagreement, timeout, crash, and failed rollback.
5. The reversible isolation action and restore operation pass repeated
   production-shaped tests, including process interruption between every
   durable transition.
6. Audit receipts are append-only, independently retained, secret-free, and
   reconcile exactly with request, approvals, target state, result, and rollback.
7. Operators approve an explicit go/no-go record, rollback point, monitoring
   window, and stop conditions. No source flag, configuration value, or partial
   test result substitutes for this approval.

Until every item is proven, the only valid repository state is `disabled`,
both review gates remain false, and no endpoint-response runtime, credential,
network route, installer, or service is introduced.

## Validation

Run the source-only gate on both supported Python runtimes:

```bash
/usr/bin/python3 operations/validate-endpoint-response-governance.py
python3 operations/validate-endpoint-response-governance.py
/usr/bin/python3 -m unittest tests.test_endpoint_response_governance
python3 -m unittest tests.test_endpoint_response_governance
```

The validator reads only the repository contract and source anchors. It never
opens runtime configuration, credentials, databases, logs, evidence, network
connections, Security Onion, the Relay, or an endpoint. A successful result
means the disabled design satisfies the minimum static boundary; it does not
approve a POC, enable execution, or prove any future provider implementation.
