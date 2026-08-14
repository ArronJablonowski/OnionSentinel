# ARR-18: Versioned investigation skill framework v2

Status: governed source implementation; v1 remains authoritative in production
until an independently reviewed, signed registry is explicitly activated.

## Purpose

Turn investigation guidance into governed, reviewable skill packs without
allowing a skill or model to expand authority. A skill is declarative advice
plus typed broker templates. It is not executable code, a credential holder,
an arbitrary query, or a permission grant.

## Registry model

Each immutable manifest conforms to
`n8n/config/investigation-skills-v2-candidates/investigation-skill-manifest-v2.schema.json`
and is content-addressed.
The artifact digest is SHA-256 of canonical JSON after replacing the
`artifact_digest` value with 64 ASCII zeroes; this avoids a self-referential
digest while keeping the entire remaining manifest bound.
The registry separately records lifecycle state: `candidate`, `shadow`,
`active`, `deprecated`, or `revoked`. Changing content creates a new semantic
version and digest; it never edits an active artifact in place.

Structural validity is not promotion. Candidate manifests may honestly record
incomplete verification. The registry's activation validator requires every
verification flag to be true, at least one replay case, a non-placeholder
reviewer, a matching artifact digest, compatibility, and explicit human
approval before `active` status is possible.

Required lineage includes skill ID, semantic version, predecessor digest,
compatible harness/policy/evidence-contract versions, source revision,
maintainer, review record, and promotion evidence. Registry and selected-skill
digests are pinned into every job envelope and trace.

`n8n/bin/investigation_skill_registry_v2.py` owns immutable registry revisions.
Every shadow or active record also carries a signed, digest-bound evaluation
attestation. It binds the exact manifest and source revision to the independent
reviewer, distinct human approver, evaluation-report digest, test/replay counts,
review and adversarial-test outcomes, and timezone-aware evaluation time. A
boolean promotion claim without this evidence cannot enter a signed active
registry.

## Selection

Selection is deterministic and collector-owned:

1. Match normalized role, task, telemetry, protocol, alert family, and data
   source using exact registered values.
2. Check preconditions and backend availability.
3. Intersect requested capabilities with the envelope's permitted set.
4. Resolve dependencies, conflicts, and maximum selected-skill budget.
5. Return selected IDs/versions/digests plus rejection reasons.

Model text, evidence text, memory, and skills cannot activate a skill or alter
selection. Candidate, deprecated, revoked, incompatible, unsigned (when
signing is enforced), or digest-mismatched skills are unavailable.

## Execution boundary

- `query_templates` contain typed parameters, never shell, HTTP, credentials,
  target addresses, index wildcards, or query-language fallback.
- The broker compiles and validates templates using its deployed field catalog.
- Every skill declares read capabilities, sensitivity, active-operation flag,
  row/byte/time budgets, expected result schema, coverage semantics, and safe
  stop conditions.
- A live OSQuery skill is approval-gated and distinct from a historical-results
  skill. Remote PCAP creation is not a derived-PCAP read skill.
- Failure, unavailable telemetry, partial capture, truncation, and field drift
  become explicit gaps.

## Result contract

A skill result contains execution status, selected manifest digest, validated
request/result digests, evidence references, coverage, truncation, findings,
contradictions, gaps, confidence limiters, and next discriminators. Skills do
not emit a final malware verdict or perform persistence. The harness reconciles
skill outputs into its evidence and hypothesis ledgers.

Every v2 candidate pins the complete fact-state vocabulary in its output
contract. `observed` requires direct admitted evidence; `inferred` requires an
evidence-linked interpretation; `unverified` preserves a claim that lacks
enough support; and `unavailable` records a source, mapping, retention, or
collection gap. Packs may not collapse unverified or unavailable evidence into
negative evidence, and consumers must retain the state with each projected
fact.

Every candidate also declares three distinct bounded guidance sets.
`positive_evidence` identifies admitted observations that would support the
pack's hypothesis. `negative_evidence` identifies observations that weigh
against it, but only when the underlying query completed successfully over its
exact declared scope with complete coverage. A failed, partial, truncated,
mapping-incompatible, unavailable, or unverified observation is a visible gap,
never negative evidence. `escalation_pivots` lists the smallest bounded next
steps that could discriminate among remaining hypotheses. Those pivots are
advice only: they cannot grant a capability, widen target or time scope, select
an executor, or bypass broker authorization and approval.

## Promotion and rollback

Promotion requires schema validation, unit tests, replay corpus results,
independent query review, false-positive analysis, adversarial evidence tests,
documentation citations pinned to product/release versions, and human approval.
Start candidate-only, then shadow. Active use requires measured improvement
without safety or resource regression. Rollback revokes the exact digest and
pins the previous approved registry; existing traces retain their original
artifact identities.

The lifecycle implementation is deliberately separate from selection:

- `investigation_skill_signing_v2.py` invokes the installed OpenSSL Ed25519
  primitive and admits only exact owner-controlled private/trusted-public key
  files. Private bytes are never returned or logged.
- `investigation_skill_lifecycle_v2.py` validates the signature before any
  write, stores immutable digest-named snapshots under an owner-only directory,
  serializes mutations with an exclusive lock, and atomically replaces only
  `current.json` after a compare-and-swap predecessor check.
- `manage-investigation-skill-registry-v2.py` exposes `validate`, `activate`,
  `status`, and `rollback`. Its JSON receipts contain only registry identity,
  mode, revision, record count, and predecessor identity—never manifests,
  guidance, templates, evidence, or keys.
- `investigation_skill_runtime_v2.py` loads the verified active snapshot and
  returns the identity-only selector result. It has no query, model, network,
  credential, prompt, or persistence authority.

An operator must supply an externally signed snapshot, a protected public trust
key, the exact expected current digest, provider identity, capability set, and
job budget. There is no shipped active registry, trust key, feature flag, or
implicit v1-to-v2 cutover. A typical validation and activation sequence is:

```bash
python3 n8n/bin/manage-investigation-skill-registry-v2.py \
  --root /owner-controlled/registry \
  --public-key /owner-controlled/trust/operator-release-key.pem \
  --key-id operator-release-key \
  validate --snapshot /owner-controlled/candidate/signed-registry.json

python3 n8n/bin/manage-investigation-skill-registry-v2.py \
  --root /owner-controlled/registry \
  --public-key /owner-controlled/trust/operator-release-key.pem \
  --key-id operator-release-key \
  activate --snapshot /owner-controlled/candidate/signed-registry.json \
  --expected-current-digest PREVIOUS_DIGEST_OR_EMPTY
```

Rollback uses the exact currently observed digest and restores only its signed,
verified predecessor:

```bash
python3 n8n/bin/manage-investigation-skill-registry-v2.py \
  --root /owner-controlled/registry \
  --public-key /owner-controlled/trust/operator-release-key.pem \
  --key-id operator-release-key \
  rollback --expected-current-digest CURRENT_DIGEST
```

Activation still does not change prompt composition. A separate controlled
configuration change must select the v2 runtime adapter, and the resulting v2
decision must match the assigned native provider before the harness admits the
job. Provider incompatibility, lifecycle rejection, revocation, dependency or
conflict failure, and aggregate-budget rejection remain visible in the durable
job attestation and `onion-sentinel-harness-execution-contract-v2`.

## Initial pack boundaries (ARR-19)

- Network protocols: DNS, TLS, HTTP, SSH, SMTP, SMB, RDP, ICMP.
- Security Onion sources: Suricata alert/flow, Zeek conn/dns/http/ssl/files,
  Elastic event search, OQL.
- Endpoint: historical OSQuery results first; separately approved live packs.
- Artifacts: existing bounded PCAP/Zeek derivations only.
- Context: CTI lookups and AC Hunter are behavioral context, not proof.

## Acceptance criteria

- Schema and digest validation is fail closed.
- Exact deterministic selection and explainable rejection tests.
- Capability intersection prevents self-expansion.
- No arbitrary query-language, target, or executor fallback.
- Compatibility, dependency, conflict, budget, and revocation tests.
- Replay demonstrates citation precision and outcome improvement by skill.
- Adversarial evidence cannot select, modify, or authorize a skill.
