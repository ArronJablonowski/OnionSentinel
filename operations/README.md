# Operations

Cross-node checks and operator workflows live here.

## Module Quality Gate

```bash
python3 operations/check-module-quality.py
```

The gate enforces the modularization policy in `quality/` without adding a
runtime dependency. Existing oversized modules and functions are recorded in a
ratcheting baseline: they may shrink but may not grow. New production modules,
new functions, complexity regressions, import cycles, and forbidden dependency
directions fail. Human-readable output reports the warning count; use `--json`
for detailed measurements.

After a reviewed refactor reduces existing debt, update the baseline with:

```bash
python3 operations/check-module-quality.py --update-baseline
```

The update refuses to run if any current measurement exceeds its existing
allowance. Review the baseline diff before commit. Do not use the baseline to
approve new debt; exceptions require the architecture review described in
`../docs/architecture/modularization-adr.md`.

## Release Content Reconciliation

`reconcile-macstudio-release.py` compares the exact application payload from a
Git commit with the running Mac Studio filesystem using SHA-256. The guarded
installer is the explicit mapping source of truth. Direct file copies, the
alert-store module trees, the complete `onion_sentinel` package, dashboard
assets, and the selected investigation-query compatibility bundle are covered.

Run it after readiness succeeds, using the release reported by `/healthz`:

```bash
release_id="$(git rev-parse --verify HEAD^{commit})"
python3 operations/reconcile-macstudio-release.py \
  --repo-root "$(pwd)" \
  --stack-dir "$HOME/n8n-local" \
  --source-revision "$release_id" \
  --expected-release-id "$release_id" \
  --summary-only
```

The command is read-only. It obtains the live release identifier from the
loopback health endpoint and reads only allowlisted application paths. It does
not enumerate or open `.env`, runtime configuration, prompts, model settings,
databases, logs, evidence, transcripts, caches, agent memory, or host LaunchAgent
files. Symlinks and non-regular runtime paths fail closed. A successful summary
records the exact source/live release, match counts, selected query contract,
and deterministic manifest digest without copying runtime content into Git.

Before deployment, run the normal test, module-quality, dependency, and secret
gates and record the rollback tag or commit. After deployment, require both
readiness and this byte-exact reconciliation. For rollback, install the recorded
commit through `install-macstudio-stack.zsh`, then rerun reconciliation with that
commit as both `--source-revision` and `--expected-release-id`.

## Verify Stack

```bash
operations/verify-stack.zsh
```

The script checks:

- Pi reachability.
- Pi access to Security Onion SSH.
- Pi access to Mac Studio n8n.
- DNS and Telegram reachability.
- n8n health.
- Docker Compose status on the Mac Studio.

## Secret Scan

```bash
operations/secret-scan.zsh
```

Run before every commit and before every push.

The scanner checks ordinary tracked and untracked source while pruning known
dependency and generated-test directories such as `.venv`, `node_modules`,
`__pycache__`, Playwright output, and pytest caches. Those trees may contain
third-party certificates or binary fixtures and are not repository content.
Use `git status --ignored` separately when auditing whether local dependency or
test-output directories remain correctly ignored.

The sole local-workspace exception is `.codex/config.toml`, and only when it is
untracked, Git-ignored, a regular non-symlink file, and mode `0600`. The scanner
still checks that exact ignored file for high-confidence secret patterns and
reports only a matching filename, never the matching credential text. A tracked,
unignored, symlinked, non-owner-only, or differently named `.codex` file remains
forbidden. This exception does not apply to production runtime configuration.

## Frontend UI QA

The Playwright chaos/regression suites are documented in
`../docs/frontend-ui-qa-runbook.md` and live in `qa/`. The live track is
read-only; the mutation track builds a temporary zero-data dashboard and uses
TEST-NET fixtures on a loopback server.

## Local Model Cybersecurity Benchmark

`benchmark-ollama-cybersecurity.py` compares installed Ollama models across a
fixed matrix of synthetic SOC triage, evidence-provenance, PCAP interpretation,
correlation, incident response, threat hunting, and SIEM safety decisions.
The tool never reads the live alert database, report corpus, or credentials.
The executable retains the synthetic decision fixture catalog and stable CLI.
Exact installed-model discovery and bounded POST transport live in
`benchmark_ollama_discovery.py`; deterministic prompt/retry execution lives in
`benchmark_ollama_execution.py`; generated-query fixtures live in
`benchmark_ollama_query_cases.py`; safety scoring and report aggregation live in
`benchmark_ollama_scoring.py` and `benchmark_ollama_reporting.py`. Dependencies
flow from the executable into those leaf modules without cycles.

Run it on the Ollama host and write generated results outside the repository:

```bash
python3 operations/benchmark-ollama-cybersecurity.py \
  --models devstral:latest qwen3:30b gemma4:31b \
  --yield-seconds 180 \
  --output /tmp/onion-sentinel-model-benchmark.json
```

Each model receives seven bounded requests containing 42 total cases: six
decision-category batches with 36 cases plus one six-case generated-query
batch. The JSON artifact contains case-level evidence-discipline results and
timing data; a Markdown summary is written beside it. `--yield-seconds` leaves
an interval between models for the production AI worker on a shared Ollama host.

## Incident Responder harness cohort

`run-incident-harness-cohort.py` provides a reproducible control plane for a
small Incident Responder evaluation. It selects through the local SQLite
summary and stable-alias tables using a read-only connection, refuses groups
that already have queued or running work, and writes owner-only,
digest-protected manifests. It never contacts Security Onion.

If the cohort was already selected, import the exact owner-only JSON array
instead of selecting again:

```bash
python3 operations/run-incident-harness-cohort.py freeze-from-rows \
  --db ~/n8n-local/alert_store_data/alerts.sqlite3 \
  --source-rows /path/to/private/frozen-rows.json \
  --manifest /path/to/private/cohort.json \
  --cohort-id newest-20-harness-evaluation \
  --reason "Evaluate the Incident Responder harness against a frozen cohort." \
  --expected-count 20 \
  --expected-assigned-route codex-cli:gpt-5.5:high \
  --expected-reviewer-route codex-cli:gpt-5.6-sol:xhigh \
  --evaluation-profile onion-sentinel-gpt55-high-gpt56-sol-xhigh-v1
```

The optional named profile pins this campaign to GPT-5.5 High as primary and
GPT-5.6 Sol XHigh as the required independent reviewer. Omitting the profile
keeps the reusable cohort tool route-agnostic, while still requiring two
enabled canonical Codex routes with different provider/model identities.

The import preserves source order and validates every dashboard group, stable
group, representative alert, supplied case state, and inactive queue state
against SQLite. Use `freeze --count 20` only when a new selection is intended.
The default role is `incident-responder`. To produce a separate SOC Analyst
manifest from the same source array, choose a different manifest path and add
`--agent-role soc-analyst`. That variant freezes the complete set of prior SOC
analysis IDs, dispatches only `/api/soc-alerts/{group}/analyze`, and identifies
the result by an exact one-ID set difference.

Validate without HTTP, then enqueue each exact member through the loopback
single-case dashboard routes:

```bash
python3 operations/run-incident-harness-cohort.py queue \
  --db ~/n8n-local/alert_store_data/alerts.sqlite3 \
  --manifest /path/to/private/cohort.json \
  --dry-run

python3 operations/run-incident-harness-cohort.py queue \
  --db ~/n8n-local/alert_store_data/alerts.sqlite3 \
  --manifest /path/to/private/cohort.json
```

The tool records a dispatching intent before each request. An ambiguous
response or interrupted dispatch is never retried automatically. It never
calls the bulk `reanalyze-all` route.

Monitor and export exact run/result metadata:

```bash
python3 operations/run-incident-harness-cohort.py monitor \
  --db ~/n8n-local/alert_store_data/alerts.sqlite3 \
  --manifest /path/to/private/cohort.json \
  --timeout 7200

python3 operations/run-incident-harness-cohort.py export \
  --db ~/n8n-local/alert_store_data/alerts.sqlite3 \
  --manifest /path/to/private/cohort.json \
  --harness-db ~/n8n-local/alert_store_data/investigation-harness.sqlite3 \
  --output /path/to/private/cohort-results.json
```

The export includes identities, execution routing, result classifications,
query-pack status/count/digests, response hashes, and one bounded proof for
each exact harness trace. Export fails unless every member completed freshly
after its one accepted dispatch. The proof binds the selected route, agent
role, reanalysis task kind, shadow policy mode, terminal hash chain and ledger
manifest, collector-owned memory-freeze attestation, and absence of
non-read-only tool calls. Every SOC Analyst and Incident Responder result must
also have at least one successful, explicitly read-only tool call in that
terminal-bound ledger; a zero-query or rejected-only trace is not gradeable.
Where the stored response includes collector-owned query-audit metadata, its
bounded digest and counts are bound into the execution proof. Incident
Responder results additionally require at least one explicitly read-only
Security Onion query in that collector audit. The export excludes raw alerts,
prompts, model responses, query text/results, job payloads, and credentials.

Accuracy grading is fail closed: provide both the SOC Analyst and Incident
Responder exports made from the same source-row file. The offline evaluator
refuses to score either role unless all 40 results pass their machine gates,
the two exports have the same full execution contract, source SHA-256, and
ordered identities, and every
independent adjudication is bound to the exact fresh analysis ID. The final
dual-role gate may claim read-only query ledgers only after all 40 results meet
the positive successful-tool requirement above. For the pinned GPT-5.5 High /
GPT-5.6 Sol XHigh campaign, pass
`--required-evaluation-profile onion-sentinel-gpt55-high-gpt56-sol-xhigh-v1`
to `evaluate-investigation-cohort.py`; generic grading may omit that optional
selector.
