# Application Access Control

## Scope and invariants

This contract governs human access to the Onion Sentinel dashboard and its
browser-facing APIs. It does not replace the existing service-identity catalog,
restricted SSH commands, alert-store bearer tokens, provider credentials, or
controlled-evaluation capabilities. A service identity can never be presented
as a browser session, and a human session can never authorize a service route.

Authentication proves a principal. Authorization evaluates one explicit
permission for that principal. Same-origin and CSRF checks prove request intent.
All three checks are required before an unsafe browser request is parsed deeply
or reaches a persistence, process, notification, query, or integration side
effect. Unknown roles, permissions, routes, session records, and enforcement
modes fail closed.

## Human roles and permissions

Roles are monotonic: Administrator includes Analyst, and Analyst includes
Viewer. No role grants Security Onion, Relay, shell, arbitrary query, or direct
database authority.

| Role | Permissions |
| --- | --- |
| Viewer | View dashboard evidence and end its own session. |
| Analyst | Viewer plus acknowledge, escalate, and adjudicate alerts; adjudicate or change incident status; request governed PCAP evidence; and reanalyze an alert, one incident, or the bounded eligible incident set. |
| Administrator | Analyst plus manage asset inventory, CTI configuration, model/prompt settings, integrations and allowlisted services, Resource Library metadata/actions, and explicitly confirmed privileged Administration actions. |

The canonical machine-readable names and route mapping live in
`onion-sentinel-dashboard/portal_access_policy.py`. Adding an unsafe route
without adding exactly one permission mapping is a release-gate failure.

## Browser session contract

The existing owner-managed PBKDF2 password record remains the initial login
credential. A successful login creates a random opaque session ID; only its
digest is stored server-side. The target session record adds a schema version,
immutable principal ID, role, issued time, absolute expiry, idle expiry, last
activity time, and a digest of a per-session CSRF secret. Raw session and CSRF
values exist only in the browser cookie/form boundary and are never logged.

Session cookies are `HttpOnly`, `SameSite=Strict`, and `Path=/`. `Secure` is
mandatory when TLS terminates at Onion Sentinel or a trusted local proxy; a
deployment may not advertise a secure remote origin while issuing a non-Secure
cookie. Login rotates the session identifier. Logout, expiry, password reset,
role change, recovery, and enforcement-mode rollback revoke affected sessions.
Absolute and idle timeouts are enforced server-side; client clocks are not
trusted.

## CSRF and unsafe-request contract

Every form or JSON mutation requires all of the following before dispatch:

1. the exact allowlisted method and normalized path;
2. an authenticated human session, except the login credential boundary;
3. the permission mapped to the route;
4. a same-origin `Origin`/`Host` decision (with the existing controlled local
   no-Origin compatibility handled only by the phased rollout below);
5. `Sec-Fetch-Site` absent or `same-origin`;
6. the expected content type and the existing bounded body size;
7. a constant-time match against the session-bound CSRF token.

The existing persisted Administration form token is transitional. It must not
be treated as a user identity or retained as the final CSRF mechanism. JSON
requests continue to require `X-Onion-Sentinel-Request: dashboard`; that header
is defense in depth, not authentication.

Authorization occurs before body parsing and before settings normalization.
After authorization, settings saves retain their current JSON schema,
validation messages, atomic-write behavior, response status/body, cache
invalidation, and rollback semantics. Introducing authentication must not
silently transform, partially apply, or discard a valid settings request.

## Administrative audit contract

Every allowed or denied unsafe request produces one bounded metadata-only audit
event. Events contain schema version, sequence, UTC time, request ID, a
pseudonymous principal/session fingerprint, role, permission, action, bounded
target type and identifier digest, outcome, HTTP status, reason code, previous
event digest, and event digest. They never contain credentials, cookies, CSRF
tokens, request bodies, prompts, evidence, report text, provider responses,
database rows, filenames outside an allowlisted public identifier, or raw IP
addresses.

Events are appended atomically to an owner-only ledger. The event digest is a
keyed chain over canonical event metadata and the previous digest. Its signing
key is an operator-managed service credential distinct from the admin password,
browser session, and application-log files. The logical identity is
`dashboard.admin-audit-signing`; its value remains only in the owner-managed
runtime file represented by `file:mac-admin-audit-signing-key`. Startup verifies the complete
retained chain and fails closed for enforcement if the ledger is malformed or
the head cannot be verified. Rotation creates an explicit signed key-transition
event. Retention exports preserve a verified head receipt before pruning.

## Service identities

The logical identities in
`operations/security/credential-governance.json` keep their current narrowly
allowlisted actions and storage classes. Browser cookies are rejected on their
routes. Service credentials are rejected on human routes. Provider/model text,
alert evidence, Relay responses, and Security Onion data can never supply a
role, permission, CSRF decision, or audit outcome.

## Phased deployment and recovery

Deployment uses explicit, validated modes; an unknown value is a startup error.
The source runtime reads `ONION_SENTINEL_ACCESS_MODE`; an absent value is
`legacy`. The current qualified implementation admits only `legacy` and
`observe`. Configuring `admin-enforce` or `rbac-enforce` fails startup until the
corresponding session, UI, denial-response, and recovery gates are implemented
and separately accepted.

1. `legacy`: current behavior only, used solely as the pre-migration rollback
   point. Policy coverage and audit code may run offline, but no claim of access
   enforcement is made.
2. `observe`: authenticate sessions where available, compute same-origin/CSRF
   and role decisions, and emit metadata-only would-allow/would-deny events
   without changing the existing response or mutation behavior.
3. `admin-enforce`: require an Administrator session and session-bound CSRF for
   all settings, integration, asset, CTI, Resource Library, and privileged
   writes. Analyst workflow writes remain observed until UI and API denial
   handling qualify.
4. `rbac-enforce`: enforce the canonical role mapping for every unsafe browser
   route. No legacy unauthenticated mutation remains.

Observe mode requires the operator-created file
`$HOME/n8n-local/config/onion-sentinel-admin-audit-signing.key` to be a regular,
owner-owned `0600` file containing exactly 64 lowercase hexadecimal characters
and one optional final newline. The decoded 32-byte key is never printed or
copied by the installer. The verified ledger is
`$HOME/n8n-local/logs/onion-sentinel-admin-audit.jsonl`; an existing ledger must
be owner-owned `0600` beneath an owner-owned `0700` directory. The installer
deploys code only and never creates, replaces, parses, or removes either
operator-owned object.

Promotion requires owner-only configuration validation, an active
Administrator session smoke test, negative cross-origin/CSRF/role tests,
settings-save parity, audit-chain verification, logout/absolute/idle expiry,
service-identity separation, rollback rehearsal, readiness, and a new healthy
production soak. Each mode change revokes sessions to prevent authority from
crossing policy generations.

Recovery is local and operator-controlled: stop the dashboard write listener,
run the owner-only password/role recovery command, verify runtime file modes,
revoke all sessions, and restart into the previously qualified mode. There is
no network recovery token, query parameter bypass, universal service token, or
fail-open environment value. Rollback restores the prior qualified source and
mode through the guarded installer without replacing the password record,
audit key/ledger, service credentials, configuration, databases, or evidence.
