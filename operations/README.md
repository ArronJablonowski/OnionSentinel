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
