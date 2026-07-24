# Local Ollama Cybersecurity Model Benchmark

This benchmark compares locally installed Ollama models for Onion Sentinel
alert triage and investigation work. It uses synthetic evidence only: reserved
TEST-NET addresses, example domains, and invented alert facts. It does not read
the live alert database, generated reports, credentials, or runtime settings.

## Test Matrix

Version 2 contains 36 deterministic decision cases split evenly across six
domains:

- evidence provenance and prompt-injection resistance
- SOC triage and detection-outcome classification
- PCAP, Zeek, TShark, DNS, TLS, and user-agent interpretation
- cross-alert correlation and threat-intelligence reasoning
- incident response and threat hunting
- safe SIEM tuning and bounded automation

It also contains six generated-query tasks: two Elastic KQL, two exact
Elasticsearch Query DSL, and two OSquery tasks. Query scoring checks syntax,
required fields and predicates, time bounds, read-only behavior, and whether
the query stays within the requested scope. All fixtures use reserved TEST-NET
addresses and example domains.

## Results

The benchmark ran on the Mac Studio on 2026-07-23 against 13 viable local
models. Times include all decision and query-generation tasks.

| Rank | Model | Overall | Query generation | Wall time | Median task | Eval rate |
| ---: | :--- | ---: | ---: | ---: | ---: | ---: |
| 1 | `devstral-small-2:24b-instruct-2512-q4_K_M` | 97.14% | 100.00% | 138.7s | 14.6s | 29.36 tok/s |
| 2 | `qwen3-coder:30b-a3b-q8_0` | 96.67% | 93.33% | 66.8s | 8.1s | 75.90 tok/s |
| 3 | `qwen2.5-coder:14b-instruct-q4_K_M` | 95.71% | 90.00% | 127.8s | n/a | n/a |
| 4 | `gemma4:31b` | 95.24% | 80.00% | 182.7s | n/a | n/a |
| 5 | `gemma4:26b-mlx` | 95.24% | 86.67% | 78.7s | n/a | n/a |
| 6 | `qwen3:30b` | 91.90% | n/a | n/a | n/a | n/a |
| 7 | `deepseek-r1:14b` | 91.43% | n/a | n/a | n/a | n/a |
| 8 | `devstral:latest` | 90.00% | n/a | n/a | n/a | n/a |
| 9 | `magistral:latest` | 89.05% | n/a | n/a | n/a | n/a |
| 10 | `mistral-small:latest` | 88.57% | n/a | n/a | n/a | n/a |
| 11 | `qwen2.5-coder:7b-instruct-q4_K_M` | 87.62% | n/a | n/a | n/a | n/a |
| 12 | `cogito:14b` | 80.95% | n/a | n/a | n/a | n/a |
| 13 | `gemma4:12b-it-q4_K_M` | 78.10% | n/a | n/a | n/a | n/a |

## Recommendation

`devstral-small-2:24b-instruct-2512-q4_K_M` is the strongest local Incident
Responder candidate. It had the highest overall score and was the only model
to score 100% across the generated KQL, exact Query DSL, and OSquery tasks. Its
slower runtime is acceptable for evidence-heavy case analysis where query
correctness and defensible classification matter more than raw throughput.

`qwen3-coder:30b-a3b-q8_0` is the best high-throughput alternative. It finished
roughly twice as fast while remaining within half a percentage point overall,
but its query-generation score was lower. It is a good canary candidate for
high-volume bounded tasks, not the first choice for authoritative incident
reports.

The production Incident Responder remains assigned to the Codex CLI route
`gpt-5.5` with `medium` reasoning. The local benchmark is advisory and does not
change that assignment.

## Safety Limits

No model is allowed to send generated KQL, Query DSL, OSquery SQL, shell text,
paths, or parser arguments to Security Onion. Production Incident Response uses
fixed reviewed query packs assembled by the trusted wrapper. The report shows
the analyst-readable KQL, exact executed Query DSL, and exact executed OSquery
SQL with digests and status. Model quality supplements these deterministic
controls; it does not replace them.

Small score differences are directional rather than statistically conclusive.
Re-run finalists after model or prompt upgrades and compare both accuracy and
variance before changing production routing.

## Reproducing The Benchmark

Run the benchmark only while production AI work is idle and keep generated
responses outside the repository:

```bash
python3 operations/benchmark-ollama-cybersecurity.py \
  --models devstral-small-2:24b-instruct-2512-q4_K_M \
    qwen3-coder:30b-a3b-q8_0 \
    qwen2.5-coder:14b-instruct-q4_K_M \
    gemma4:31b \
    gemma4:26b-mlx \
  --output /tmp/onion-sentinel-model-benchmark-v2.json
```
