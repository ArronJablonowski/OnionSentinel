# PostgreSQL Alert-Store Queue Migration

## Decision

SQLite remains the production source of truth for alerts, analyst state, PCAP
requests, and durable jobs until a shadow migration proves transaction and
recovery equivalence. The current single-writer design commits an alert and its
work intent in one SQLite transaction. Moving only `durable_jobs` to PostgreSQL
without an outbox would introduce a dual-write window where an alert could be
stored without its enrichment, reporting, PCAP, or AI job.

The target PostgreSQL contract is staged in:

```text
n8n/postgres/alert-store-queue-schema.sql
operations/verify-postgres-queue-schema.zsh
```

The transactional shadow foundation is implemented but disabled by default:

```text
n8n/alert_store/lib/postgres_shadow_outbox.js
n8n/alert_store/lib/postgres_shadow_projector.js
n8n/docker-compose.yml  # alert-store-shadow profile
```

SQLite triggers create or advance one revisioned outbox marker in the same
transaction as every `durable_jobs` insert or update. The projector reads the
current row snapshot, calls PostgreSQL's idempotent
`apply_shadow_durable_job`, and acknowledges only the exact SQLite revision it
observed. A concurrent SQLite update therefore remains dirty even if an older
projection finishes afterward.

The schema uses JSONB payloads, typed timestamps, unique idempotency keys,
lease recovery, coalesced reruns, and `FOR UPDATE SKIP LOCKED` claims. This
allows multiple future workers to claim jobs without duplicate processing or a
global SQLite write gate.

## Security Boundary

- Use a dedicated database and least-privilege role; never reuse the n8n owner.
- Bind any host-accessible PostgreSQL listener to `127.0.0.1` only.
- Keep the password in the Mac Studio runtime `.env`, never in Git or Markdown.
- Do not publish PostgreSQL to the LAN, relay VLAN, or Internet.
- Back up and restore-qualify PostgreSQL before it becomes authoritative.
- Queue payloads contain alert context and remain runtime data.

## Deployment Phases

1. **Schema qualification:** run the isolated verifier. It starts the pinned
   PostgreSQL image with `--network none`, mounts no live data, checks enqueue,
   atomic claim, rerun latching, and completion, then deletes the container.
2. **Shadow projection:** retain SQLite authority. After each committed SQLite
   transaction, an outbox projector mirrors queue state to PostgreSQL. Compare
   aggregate depth, status, age, and dedupe-key hashes; never copy output into
   Git.
3. **Read-only worker canary:** allow one non-destructive canary consumer to
   claim copied synthetic jobs in a separate namespace. Production workers
   continue claiming SQLite jobs.
4. **Transactional cutover:** either migrate the full alert-store transaction
   boundary to PostgreSQL or keep a SQLite transactional outbox whose projector
   is the only PostgreSQL writer. Enable one job type at a time behind a runtime
   feature flag.
5. **Rollback window:** keep SQLite queue rows and project completion states
   back during the canary. A rollback disables PostgreSQL claims, releases
   leases, and resumes SQLite workers without replaying completed idempotency
   keys.
6. **Qualification:** run burst, worker-crash, lease-expiry, database-restart,
   disk-pressure, backup, and restore drills before PostgreSQL becomes the
   durable authority.

## Enabling the shadow

Do not enable this during a controlled harness evaluation. First:

```bash
operations/verify-postgres-queue-schema.zsh
```

Generate a unique alert-store PostgreSQL password and place it only in the Mac
runtime `.env`. Do not reuse the n8n password. Then start the opt-in database:

```bash
cd "$HOME/n8n-local"
docker compose --profile alert-store-shadow up -d alert-store-postgres
```

Apply the schema explicitly on an existing data volume because PostgreSQL's
`docker-entrypoint-initdb.d` directory runs only when the data directory is
first created:

```bash
docker exec -i onion-sentinel-alert-store-postgres \
  sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < "$HOME/n8n-local/postgres/alert-store-queue-schema.sql"
```

Verify the schema and take the first PostgreSQL backup before setting:

```text
ALERT_STORE_POSTGRES_SHADOW_ENABLED=1
```

Restart only the host-native alert-store after changing that flag. Confirm
`postgres_shadow_outbox.pending` trends toward zero in `/health` and `/metrics`.
The shadow table is deliberately separate from the claimable PostgreSQL queue;
no production worker can consume shadow rows.

To stop projection without affecting SQLite authority, set the flag back to
`0` and restart alert-store. The outbox retains every newer revision and safely
resumes later.

## Go/No-Go Gates

- Zero missing or duplicate dedupe keys throughout a 48-hour shadow run.
- Queue depth and terminal-state counts match after every reconciliation.
- Worker crash recovery stays within the configured lease period.
- Alert ingest remains successful when PostgreSQL is intentionally unavailable;
  the SQLite outbox must retain projection work.
- PostgreSQL backup and isolated restore complete successfully.
- Secret scan and alert-data scan remain clean.

Do not perform a direct queue-only dual write. The shadow/outbox phase is a
correctness requirement, not an optional optimization.
