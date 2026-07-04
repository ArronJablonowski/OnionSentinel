# Tests

Regression tests for the alert scheduler and SOC alert summary API.

Run from the repo root:

```bash
python3 -m pytest tests
```

Current coverage:

- AI scheduler severity/newest-first priority.
- SOC alert summary API grouping and pagination behavior.
