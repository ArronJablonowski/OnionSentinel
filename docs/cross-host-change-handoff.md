# Cross-Host Change Handoff And Drift Control

This process coordinates reviewed Onion Sentinel application changes across the
Mac Studio, Raspberry Pi Relay, and Security Onion. The handoff validator is a
read-only decision gate. It never connects to a remote host, applies a file,
creates an account or key, reloads a service, or opens runtime configuration.

Security Onion remains read-only by default. A Security Onion write requires a
separate approved change whose handoff sets `target_system` to
`security_onion`, sets `write_authorized` to `true`, and names only the reviewed
idempotent operations. Standing application-development authorization does not
turn a read-only investigation request into a Security Onion write.

## Required Request

Every request is an exact, secret-free JSON document with:

- a unique `change_id` and schema version;
- target system, accountable owner, purpose, prerequisites, risk, validation,
  rollback, exact source revision, exact rollback revision, and UTC request
  time;
- an explicit boolean write decision and a bounded list of idempotent managed
  operations;
- each managed source/destination pair, its desired Git-blob SHA-256, the
  reviewed expected current SHA-256, and an independently observed current
  SHA-256.

Use `null` for both current hashes only after proving the managed destination is
absent. Never use `null` to bypass an unknown or unreadable current state. Hash
collection must emit only the digest and exit status, never file content.

The validator resolves the exact Git commit and hashes every requested source
blob itself. An incorrect desired hash fails before any apply decision. If the
observed current hash differs from the reviewed expected current hash, the
decision is `drift_review_required`, even when writes were authorized. Reconcile
that drift deliberately under a new `change_id`; do not edit and replay an
already identified request.

Allowed operations are intentionally declarative:

- `replace_managed_artifact`
- `reconcile_managed_account`
- `reconcile_managed_public_key`
- `reconcile_managed_service`
- `reload_managed_service`

Each reconcile operation must inspect current state first and become a no-op
when the requested state already exists. The handoff cannot authorize writes to
runtime secrets, host configuration, databases, logs, evidence, state, agent
memory, private keys, Relay key/state trees, Security Onion capture storage, or
other protected destinations.

## Pre-Deployment Gate

Start from the secret-free example, replace its metadata and hashes, and keep
the working handoff outside production runtime trees:

```bash
python3 operations/validate-cross-host-handoff.py \
  --repo-root "$(pwd)" \
  --handoff /path/to/change-handoff.json
```

The command prints metadata only: identity, target, source revision, request
digest, acknowledgement status, decision, idempotent-replay flag, and artifact
counts. It never prints purpose text, prerequisites, paths, remote content, or
verification output.

Decision meanings:

| Decision | Exit | Required action |
| --- | ---: | --- |
| `apply_authorized` | 0 | Expected and observed state match; apply only the named operations and artifacts. |
| `noop_current_match` | 0 | Every observed artifact already has the desired hash; do not run an installer. |
| `approval_required` | 1 | No write was authorized; preserve read-only state. |
| `drift_review_required` | 1 | Current or acknowledged state differs; stop and reconcile under review. |
| `verification_review_required` | 1 | Applied hashes may match, but at least one verification did not pass. |
| `noop_already_applied` | 0 | A digest-bound applied acknowledgement and all verification receipts match. |
| rejected or rolled-back decision | 1 | Preserve the recorded terminal state; create a new request for new work. |

Contract, JSON, Git, path, identity-collision, or sensitive-content failures
exit 2. Run the validator before invoking a Mac, Relay, or Security Onion
installer. A decision is permission for the exact manifest only; it is not a
general remote shell or configuration authorization.

## Applied Acknowledgement

After an authorized apply, add one `acknowledgement` object containing:

- `status`: `applied`, `already_applied`, `rejected`, or `rolled_back`;
- the exact `request_sha256` printed by the pending gate;
- exact applied version, UTC apply time, and the request's rollback commit;
- destination plus observed post-apply SHA-256 for every managed artifact;
- one or more categorical verification receipts with an identifier, `pass`,
  `warn`, or `fail`, and SHA-256 of the owner-only evidence artifact.

Do not paste command output, hostnames, credentials, keys, response bodies,
runtime paths outside the public managed destinations, or raw evidence into the
handoff. Store detailed evidence owner-only and record only its digest. An
applied acknowledgement without write authorization, with a different source
revision or rollback point, or without exact request-digest binding fails.

Rerun the gate with the acknowledgement. Only `noop_already_applied` proves the
post-apply hashes and all verification receipts pass.

## Idempotent Replay

When processing a repeated request, provide the previously admitted document:

```bash
python3 operations/validate-cross-host-handoff.py \
  --repo-root "$(pwd)" \
  --handoff /path/to/change-handoff.json \
  --prior-handoff /path/to/prior-change-handoff.json
```

The same `change_id` and canonical request digest yields
`idempotent_replay: true`. The same identity with any changed request content is
an identity collision and exits 2. An exact replay never justifies recreating
an account, key, wrapper, artifact, or service.

## Reconciliation And Rollback

For intentional drift, preserve the old request and its receipt, review the
observed hash, then create a new change identity whose expected current hash is
that reviewed observation. Record the prior exact source commit as the rollback
revision. Apply only after the new gate returns `apply_authorized`.

Rollback is a new, explicitly authorized handoff whose desired revision is the
recorded rollback point. After rollback, attach fresh sanitized hash and
verification receipts and require `noop_already_applied`. Mac Studio releases
also retain the byte-exact `reconcile-macstudio-release.py` post-deploy gate.
