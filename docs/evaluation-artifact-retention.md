# Evaluation Artifact Retention and Cleanup

Evaluation outputs can contain sensitive investigation metadata and can grow
much faster than ordinary application logs. They remain runtime-only,
owner-controlled artifacts; none belong in Git, Linear, prompts, or general
support bundles.

## Owned artifact classes

| Class | Runtime location | Bound | Cleanup owner |
|---|---|---|---|
| Hash-chained harness traces | `alert_store_data/investigation-harness.sqlite3` | 30 days, 10,000 terminal runs, 2 GiB live pages; at most 1,000 deletions per pass | Hourly harness maintenance, gated by a recent verified recovery snapshot |
| Controlled cohort/replay runtimes | `harness-evaluations/<run>` | 30 days, 40 run directories, 200 GiB aggregate; preserve the newest 5 and remove at most 2 sealed runs per pass | Hourly evaluation artifact maintenance |
| Temporary provider/test state | `tmp`, `__pycache__`, and `.pytest_cache` directly below a controlled run | Removed only after the run has a valid retention seal | Hourly evaluation artifact maintenance |
| Production soak reports | `logs/soak-reports` | 14 days and at most 4,032 files; at most 256 report deletions per pass | Hourly evaluation artifact maintenance |
| Isolated restore-drill reports | `logs/restore-drills` | 30 days and at most 90 files; at most 256 report deletions per pass | Hourly evaluation artifact maintenance |
| Application and worker logs | Fixed paths in `application_log_contract.py` | 10 or 50 MiB active files, fixed gzip generations, maximum 30 days | Hourly application-log maintenance |

An unsealed run is never deleted. An expired unsealed run, an invalid seal, an
unsafe path, or run-count/byte pressure is an explicit maintenance failure,
not permission to guess which evidence may be discarded.

## Integrity seal and cleanup ordering

After an evaluation has finished and its review has identified the exact final
outputs, create one owner-only seal using absolute paths:

```bash
python3 "$HOME/n8n-local/bin/seal-evaluation-artifacts.py" \
  --run-dir "$HOME/n8n-local/harness-evaluations/RUN" \
  --output "$HOME/n8n-local/harness-evaluations/RUN/final-result.json" \
  --output "$HOME/n8n-local/harness-evaluations/RUN/final-report.md"
```

The seal records the terminal timestamp, exact relative output paths, byte
counts, SHA-256 digests, and a digest of the seal itself. Seal publication is
atomic and mode `0600`. Maintenance revalidates the complete seal and every
output immediately before mutation. Only then may it remove known temporary
directories. Final outputs remain intact until the entire sealed run reaches a
retention/count/byte bound. Whole-run deletion is oldest-first, bounded to two
runs per pass, and never removes one of the newest five runs.

Preview or apply the same policy manually:

```bash
python3 "$HOME/n8n-local/bin/maintain-evaluation-artifacts.py" \
  --stack-dir "$HOME/n8n-local"
python3 "$HOME/n8n-local/bin/maintain-evaluation-artifacts.py" \
  --stack-dir "$HOME/n8n-local" --apply
```

The installed hourly LaunchAgent uses `--apply`, an owner-only non-overlap
lock, and an atomic owner-only report at
`logs/evaluation-artifact-maintenance.json`. It reads artifact metadata and
explicit seals; it never parses prompts, transcripts, evidence rows, or model
responses.

## Capacity thresholds and encrypted copies

Local evaluation storage warns at 65% filesystem use and fails at 75%, ahead
of the existing 80% hard capacity boundary. The global operational SLO uses
the same 75% no-new-work gate. The evaluation report separately identifies
artifact count and byte pressure so a large unsealed tree cannot hide behind
otherwise adequate free space.

If evaluation artifacts are replicated, the destination must be an
operator-controlled encrypted volume with an owner-only root. Pass that root
to maintenance with `--encrypted-storage-root`. Its independent capacity
threshold warns at 70% and fails at 85%. The path is configuration, not source:
the repository and installer never create, select, mount, or overwrite an
encrypted destination. A configured destination that is missing, symlinked,
or not owner-only fails closed. Encryption/key custody remains the operator's
responsibility and must be verified before the path is configured.

Neither this policy nor its LaunchAgent touches Security Onion or the Relay.
