# Operations

Cross-node checks and operator workflows live here.

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

Run it on the Ollama host and write generated results outside the repository:

```bash
python3 operations/benchmark-ollama-cybersecurity.py \
  --models devstral:latest qwen3:30b gemma4:31b \
  --yield-seconds 180 \
  --output /tmp/onion-sentinel-model-benchmark.json
```

Each model receives six bounded requests containing 36 total cases. The JSON
artifact contains case-level evidence-discipline results and timing data; a
Markdown summary is written beside it. `--yield-seconds` leaves an interval
between models for the production AI worker on a shared Ollama host.
