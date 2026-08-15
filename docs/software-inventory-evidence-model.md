# Software Inventory evidence model

Onion Sentinel stores observable software claims as evidence, not as an
authoritative list of what is currently installed. The PostgreSQL backend uses
`onion_sentinel_software.snapshots` for atomic snapshot lifecycle and
`onion_sentinel_software.inventory_records` for bounded provenance records.
The compatibility backend projects the same public API from an owner-controlled
state file.

## Evidence tiers

- `installed` means a successful endpoint OSQuery Apps result reported the
  package at observation time. It does not prove a complete or current endpoint
  inventory.
- `observed` means network metadata presented a named product or version on
  monitored traffic. Passive absence is never evidence of absence.
- `inferred` means a user-agent, fingerprint, service, or related clue supports
  a hypothesis. It is not installed-software truth.

Every record preserves a stable `evidence_id`, source and source dataset,
asset-reference type and value, product and full version, operating-system type
and full version, first and last seen timestamps, observation count, evidence
tier, confidence, and provenance. HTTP/browser evidence also projects the
original `observed_user_agent` or the equivalent version field retained by the
source record.

## Snapshot and deduplication rules

Imports are written as staging snapshots. Activation verifies the exact expected
record count, retires the previous active snapshot, and activates the new one in
one PostgreSQL transaction. One active and two retired snapshots are retained.
The `(snapshot_id, evidence_id)` key deduplicates retry writes without merging
different observations or silently choosing an authoritative value.

Conflicting evidence stays visible. Two non-empty versions are marked
`simultaneous-version-disagreement` when they have the same snapshot, asset
reference type and value, case-insensitive product, and exact `last_seen`
timestamp. The rule is evaluated across the complete active snapshot/window,
not only the current page. Every conflicting row is retained, counted, and
displayed; Onion Sentinel does not select either version as authoritative.
The PostgreSQL lookup uses a bounded product digest index and then confirms the
full case-insensitive product value, preserving correctness even if digests
collide while avoiding a page-local or quadratic scan.

## Asset and operating-system uncertainty

Raw host identity is represented by a bounded host reference or an IP reference.
A friendly asset label and operating-system association are added only when a
complete Asset Inventory provides a unique hostname-to-static-IP match. Missing,
ambiguous, or incomplete mappings remain explicit host-resolution uncertainty;
they are never guessed. Endpoint OS evidence retains its own source, confidence,
observation timestamp, and freshness independently of software evidence.

## Freshness and expiry

Evidence is `current` within 24 hours and `recent` within seven days. Passive
`observed` and `inferred` evidence may remain `historical` through 30 days.
Everything outside its trusted window is `expired`. Expiry changes how a record
may support a conclusion; it does not delete provenance or imply that software
is absent. Source completeness and last-good collection status remain visible.

## Analyst presentation and compatibility

The API and responsive Software Inventory page expose evidence identity,
conflict state, full values, provenance, OS association, freshness, and
confidence. Long product names wrap within their column. PostgreSQL sort
indexes use bounded product/version prefix keys and full-value tie-breakers, so
the documented maximum values remain writable without changing lexical order.
Endpoint-only,
network-only, unresolved-host, expired, duplicate, and conflicting fixtures are
covered by the repository test suite. PostgreSQL and local-state projections
use the same conflict label and summary count so storage selection does not
change analyst conclusions.
