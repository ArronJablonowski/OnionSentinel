# Security Onion API And OSQuery Roadmap

## Purpose

This roadmap preserves the current restricted-SSH deployment while preparing
Onion Sentinel to adopt supported Security Onion APIs and tightly controlled
host telemetry. The repository remains the source of truth; credentials and
environment-specific access grants remain only on their destination hosts.

## Current Production Boundary

- Alert export and PCAP capture use separate restricted SSH identities and
  forced-command wrappers.
- The Raspberry Pi is the only bridge between Security Onion and the Mac Studio.
- The Mac Studio has no direct route to Security Onion.
- SSH remains the supported production transport until API access is licensed,
  documented, tested, and explicitly enabled.
- Onion Sentinel does not run arbitrary OSQuery or shell commands on Security
  Onion or monitored endpoints.

## Security Onion API Adoption

Introduce an adapter boundary rather than replacing the existing transport in
place. Both adapters must return the same normalized alert and PCAP request
contracts so storage, AI analysis, and the dashboard remain transport-agnostic.

### Phases

1. Obtain supported API access and authoritative vendor documentation.
2. Create a development-only service account with read-only alert and packet
   retrieval scopes. Do not reuse administrator credentials.
3. Implement `ssh` and `api` adapters behind an explicit feature flag whose
   default remains `ssh`.
4. Add contract tests using synthetic alerts and packet metadata. Never record
   live API responses in Git fixtures.
5. Run shadow comparisons for counts, timestamps, grouping fields, and packet
   coverage without allowing the API adapter to mutate production state.
6. Complete a security review covering authentication storage, TLS validation,
   audit logs, request bounds, rate limits, and token rotation.
7. Promote the API adapter only after rollback to restricted SSH has been
   exercised successfully.

### Required Controls

- Store tokens in the Mac Studio runtime secret store or root-owned environment
  file, never in n8n exports, generated reports, dashboard HTML, or Git.
- Validate the Security Onion server certificate; do not disable TLS checks.
- Use least-privilege read scopes and separate development and production
  identities.
- Bound query windows, row counts, PCAP sizes, retries, and concurrency.
- Record request outcome and correlation IDs without logging tokens or packet
  payloads.
- Fail closed on malformed responses and keep alert ingestion independent from
  PCAP retrieval failures.

## OSQuery Investigation Architecture

OSQuery execution belongs on a dedicated incident-response host or managed
endpoint service, not in the alert relay and not as unrestricted SSH access to
Security Onion. The SOC Analyst may recommend a query, but execution must pass
through a policy broker.

### Policy Broker Contract

- Accept only versioned, reviewed query-pack IDs and typed parameters.
- Reject arbitrary SQL, shell fragments, path traversal, and unknown hosts.
- Require analyst approval for queries outside a preapproved low-risk pack.
- Enforce target allowlists, read-only queries, row and byte limits, and short
  execution deadlines.
- Sign requests, authenticate the caller, and write an immutable audit record of
  requester, target, pack, parameters, timestamps, and outcome.
- Redact secrets and bound output before it is stored or supplied to a local LLM.
- Keep the broker unavailable from the public Internet and use a dedicated
  credential that cannot collect PCAP or administer Security Onion.

### Initial Query Packs

Start with read-only host context needed during triage: operating-system and
hardware inventory, logged-in users, listening sockets, process metadata,
installed packages, scheduled tasks, and bounded persistence indicators. Each
pack needs an owner, rationale, supported platforms, timeout, expected output,
and rollback/removal procedure.

## Acceptance Gates

- Synthetic contract and authorization tests pass.
- A denied query cannot be transformed into an allowed query by parameters.
- API or OSQuery failure cannot interrupt relay heartbeats or alert ingestion.
- Credentials never appear in logs, reports, browser responses, backups, or Git.
- Disaster recovery restores the adapters disabled by default.
- Operators can revert to restricted SSH without data loss or duplicate alert
  state transitions.
