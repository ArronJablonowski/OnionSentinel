# Service Identity And Credential Lifecycle

Onion Sentinel keeps credential material only in owner-controlled runtime
stores. The repository catalog at
`operations/security/credential-governance.json` records logical identities,
not values, hashes, public keys, fingerprints, paths from a live host, or
provider responses. Every entry names its purpose, owner, storage class,
allowed actions, enablement condition, creation evidence, expiry, rotation,
revocation, and rollback policy.

## Runtime inventory

Operators maintain a separate owner-only `0600` lifecycle inventory from
`operations/security/service-identity-inventory.example.json`. It contains only
logical catalog IDs, integer generations, state, UTC lifecycle timestamps,
storage-class names, allowed-action names, and predecessor generation numbers.
It must never contain a token, password, key, digest, endpoint, account name,
public-key text, host fingerprint, or credential-file path.

`required_ids` is the explicit enablement manifest. It must contain every
catalog ID used by the deployment and must not contain duplicates. The
validator requires one active, conforming record for each enabled ID. An empty
template is intentionally not startup-ready. Provision the private inventory
before a controlled deployment; the installer deploys the source catalog and
validator but never creates, copies, or overwrites this operator-owned file.

Validate the source catalog during every release:

```bash
python3 operations/validate-credential-governance.py
```

Validate an owner-only runtime inventory and the identities required by the
enabled deployment without printing its contents:

```bash
python3 operations/validate-credential-governance.py \
  --inventory "$HOME/n8n-local/config/service-identity-inventory.json" \
  --required-id api.post-commit-relay \
  --required-id ssh.relay-mac-alert
```

The result contains only schema, status, catalog-entry count, and categorical
failures. Unknown fields fail closed, which prevents secret material from being
projected through this tool. A missing required active record, duplicate active
or generation record, expired credential, overdue rotation, mismatched storage
class/action set, or broken rollback lineage fails validation.

## Rotation and rollback

1. Stop new work for the affected allowlisted action and let in-flight work
   drain. Do not broaden the route during maintenance.
2. Create generation `N+1` in its designated runtime store. Record its creation,
   expiry, rotation due time, and predecessor generation in the private
   metadata inventory without copying credential material.
3. Keep generation `N` disabled as `rollback` for one bounded cutover window.
   The validator accepts exactly one active and one unexpired rollback
   generation only when their lineage matches.
4. Run the component's positive smoke test and its negative authorization,
   wrong-source, wrong-route, and redaction tests. For shared secrets, prove all
   peers use the same new generation before resuming work.
5. If validation fails, disable `N+1`, restore `N`, repeat the smoke/denial
   tests, and record only the categorical outcome. If it succeeds, revoke `N`
   at the provider or authorized-key boundary and mark it `revoked`.

The alert-store host wrapper runs the deployed validator before Node starts and
exits with a fixed, secret-free configuration error if validation fails. The
production readiness snapshot independently reports only
`lifecycle_inventory_valid` or `credential_governance_failed`. Neither boundary
prints the inventory, catalog paths, credential values, or validator failures.

Ephemeral evaluation, lease, capability, and browser-session secrets do not
permit rollback. They are destroyed and regenerated. Provider refresh tokens
rotate only inside their dedicated isolated store and are atomically persisted;
transport-only nodes and model prompts never receive them.

## Revocation evidence

Linear and Git may record the logical credential ID, generation number, UTC
event time, test names/results, and whether revocation succeeded. They must not
record secret values, digests usable as offline verifiers, public keys, host
fingerprints, live paths, account names, or provider response bodies.
