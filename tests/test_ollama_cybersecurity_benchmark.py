from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "operations" / "benchmark-ollama-cybersecurity.py"
SPEC = importlib.util.spec_from_file_location("ollama_cybersecurity_benchmark", MODULE_PATH)
BENCHMARK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCHMARK
SPEC.loader.exec_module(BENCHMARK)


class OllamaCybersecurityBenchmarkTests(unittest.TestCase):
    def test_installed_models_preserves_exact_order_and_bounds_the_tags_response(self) -> None:
        payload = json.dumps({
            "models": [
                {"name": "qwen3:30b"},
                {"name": " devstral:latest "},
                {"name": ""},
                {},
            ]
        }).encode("utf-8")

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, size):
                self.requested_size = size
                return payload

        response = Response()
        with mock.patch.object(BENCHMARK.urllib.request, "urlopen", return_value=response) as opener:
            models = BENCHMARK.installed_models("http://127.0.0.1:11434/", timeout=7)

        self.assertEqual(models, ["qwen3:30b", "devstral:latest"])
        request = opener.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/tags")
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(opener.call_args.kwargs, {"timeout": 7})
        self.assertEqual(response.requested_size, BENCHMARK.MAX_RESPONSE_BYTES + 1)

    def test_run_batch_retries_with_exact_bounded_chat_contract(self) -> None:
        cases = list(BENCHMARK.benchmark_cases()[:1])
        success = {
            "message": {"content": '{"results":[]}'},
            "eval_count": 12,
            "eval_duration": 3_000_000_000,
        }
        with (
            mock.patch.object(
                BENCHMARK,
                "_bounded_json_request",
                side_effect=[TimeoutError("first"), success],
            ) as request,
            mock.patch.object(BENCHMARK.time, "sleep") as sleep,
            mock.patch.object(BENCHMARK.time, "monotonic", side_effect=[1.0, 2.0, 4.0]),
        ):
            result = BENCHMARK.run_batch(
                "http://127.0.0.1:11434/",
                "model:exact-tag",
                cases,
                repetition=2,
                timeout=17,
                retries=1,
                temperature=0.25,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["attempt"], 2)
        self.assertEqual(result["wall_seconds"], 2.0)
        self.assertEqual(request.call_count, 2)
        url, request_payload, timeout = request.call_args.args
        self.assertEqual(url, "http://127.0.0.1:11434/api/chat")
        self.assertEqual(timeout, 17)
        self.assertEqual(request_payload["model"], "model:exact-tag")
        self.assertEqual(request_payload["options"], {"temperature": 0.25, "num_predict": 3072})
        self.assertEqual(request_payload["keep_alive"], "10m")
        self.assertFalse(request_payload["stream"])
        self.assertFalse(request_payload["think"])
        sleep.assert_called_once_with(1.0)

    def test_main_filters_models_in_requested_order_and_persists_each_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "benchmark.json"
            results = [
                {"model": "model-b", "percent": 90.0, "wall_seconds_total": 1.0},
                {"model": "model-a", "percent": 80.0, "wall_seconds_total": 2.0},
            ]
            with (
                mock.patch.object(
                    BENCHMARK,
                    "installed_models",
                    return_value=["model-a", "model-b", "unrequested"],
                ),
                mock.patch.object(BENCHMARK, "benchmark_model", side_effect=results) as benchmark,
                mock.patch.object(BENCHMARK, "write_markdown") as markdown,
                mock.patch.object(sys, "stdout", new_callable=io.StringIO),
                mock.patch.object(sys, "stderr", new_callable=io.StringIO) as stderr,
            ):
                status = BENCHMARK.main([
                    "--models", "model-b", "missing", "model-a",
                    "--output", str(output),
                ])

            self.assertEqual(status, 0)
            self.assertEqual([call.args[0] for call in benchmark.call_args_list], ["model-b", "model-a"])
            self.assertEqual(markdown.call_count, 2)
            persisted = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(persisted["requested_models"], ["model-b", "missing", "model-a"])
            self.assertEqual(persisted["skipped_models"], ["missing"])
            self.assertEqual([item["model"] for item in persisted["models"]], ["model-b", "model-a"])
            self.assertIn("Skipping unavailable model(s): missing", stderr.getvalue())

    def test_matrix_has_six_balanced_domains_and_unique_ids(self) -> None:
        cases = BENCHMARK.benchmark_cases()
        self.assertEqual(len(cases), 36)
        self.assertEqual(len({case.case_id for case in cases}), 36)
        self.assertEqual(
            Counter(case.category for case in cases),
            {
                "provenance": 6,
                "triage": 6,
                "network_pcap": 6,
                "correlation_cti": 6,
                "ir_hunting": 6,
                "siem_safety": 6,
            },
        )

    def test_query_matrix_covers_kql_dsl_and_osquery(self) -> None:
        cases = BENCHMARK.query_benchmark_cases()
        self.assertEqual(len(cases), 6)
        self.assertEqual(len({case.case_id for case in cases}), 6)
        self.assertEqual(
            Counter(case.language for case in cases),
            {"kql": 2, "elasticsearch_dsl": 2, "osquery": 2},
        )

    def test_fixtures_are_synthetic_and_contain_no_live_addresses(self) -> None:
        serialized = "\n".join(
            value
            for case in BENCHMARK.benchmark_cases()
            for value in (*case.evidence, case.question, *case.choices)
        )
        self.assertNotIn("10.77.7.", serialized)
        self.assertNotIn("10.88.8.", serialized)
        self.assertNotIn("192.168.1.", serialized)
        self.assertNotIn("192.168.100.", serialized)
        for token in ("192.0.2.", "198.51.100.", "203.0.113.", ".example", ".test"):
            self.assertIn(token, serialized)

    def test_perfect_structured_response_scores_one_hundred_percent(self) -> None:
        cases = list(BENCHMARK.benchmark_cases()[:6])
        response = {
            "ok": True,
            "response": {
                "results": [
                    {
                        "id": case.case_id,
                        "answer": case.expected_answer,
                        "evidence": list(case.required_evidence),
                        "rationale": "Evidence supports the selected answer.",
                    }
                    for case in cases
                ]
            },
        }
        score = BENCHMARK.score_batch(cases, response)
        self.assertEqual(score["points"], score["possible"])
        self.assertFalse(score["missing_ids"])
        self.assertFalse(score["duplicate_ids"])

    def test_wrong_answer_and_cross_case_citation_reduce_score(self) -> None:
        case = BENCHMARK.benchmark_cases()[0]
        response = {
            "ok": True,
            "response": {
                "results": [{
                    "id": case.case_id,
                    "answer": "B",
                    "evidence": [*case.required_evidence, "OTHER-E1"],
                    "rationale": "Incorrect provenance decision.",
                }]
            },
        }
        detail = BENCHMARK.score_batch([case], response)["details"][0]
        self.assertFalse(detail["answer_ok"])
        self.assertFalse(detail["evidence_scope_ok"])
        self.assertEqual(detail["points"], 2)

    def test_json_extractor_labels_exact_and_fenced_responses(self) -> None:
        parsed, mode = BENCHMARK._extract_json('{"results": []}')
        self.assertEqual(parsed, {"results": []})
        self.assertEqual(mode, "exact")
        parsed, mode = BENCHMARK._extract_json('```json\n{"results": []}\n```')
        self.assertEqual(parsed, {"results": []})
        self.assertEqual(mode, "fenced")

    def test_generated_queries_require_valid_bounded_read_only_syntax(self) -> None:
        cases = BENCHMARK.query_benchmark_cases()
        queries = {
            "QK01": (
                'source.ip : "198.51.100.42" and destination.ip : '
                '"203.0.113.10" and destination.port : 443 and '
                "@timestamp >= now-30m"
            ),
            "QK02": (
                'event.category : "authentication" and event.outcome : '
                '"failure" and user.name : "analyst-test" and source.ip : '
                '"192.0.2.77" and @timestamp >= now-1h'
            ),
            "QD01": (
                '{"size":100,"_source":["@timestamp","source.ip",'
                '"destination.ip","destination.port","network.transport",'
                '"event.dataset"],"query":{"bool":{"filter":['
                '{"term":{"source.ip":"198.51.100.42"}},'
                '{"term":{"destination.ip":"203.0.113.10"}},'
                '{"term":{"destination.port":443}},'
                '{"range":{"@timestamp":{"gte":"now-30m"}}}]}},'
                '"sort":[{"@timestamp":"asc"}]}'
            ),
            "QD02": (
                '{"size":50,"_source":["@timestamp","rule.id","event.id",'
                '"source.ip","destination.ip"],"query":{"bool":{"filter":['
                '{"term":{"rule.id":"TEST-1001"}},'
                '{"range":{"@timestamp":{"gte":"2026-01-01T00:00:00Z",'
                '"lte":"2026-01-01T01:00:00Z"}}}]}},'
                '"sort":[{"@timestamp":"asc"}]}'
            ),
            "QO01": (
                "SELECT pid, name, path, cmdline FROM processes "
                "WHERE name = 'sshd' LIMIT 100;"
            ),
            "QO02": (
                "SELECT lp.address, lp.port, lp.protocol, p.name, p.path "
                "FROM listening_ports AS lp LEFT JOIN processes AS p "
                "ON lp.pid = p.pid WHERE lp.port = 22 LIMIT 100;"
            ),
        }
        response = {
            "ok": True,
            "response": {
                "results": [
                    {
                        "id": case.case_id,
                        "language": case.language,
                        "query": queries[case.case_id],
                        "rationale": "Bounded read-only investigation query.",
                    }
                    for case in cases
                ]
            },
        }
        score = BENCHMARK.score_query_batch(cases, response)
        self.assertEqual(score["points"], score["possible"])

    def test_generated_osquery_rejects_unbounded_or_destructive_sql(self) -> None:
        case = next(
            item for item in BENCHMARK.query_benchmark_cases()
            if item.case_id == "QO01"
        )
        response = {
            "ok": True,
            "response": {
                "results": [{
                    "id": case.case_id,
                    "language": case.language,
                    "query": "DELETE FROM processes WHERE name = 'sshd';",
                    "rationale": "Unsafe.",
                }]
            },
        }
        detail = BENCHMARK.score_query_batch((case,), response)["details"][0]
        self.assertFalse(detail["safe_read_only_ok"])
        self.assertFalse(detail["syntax_ok"])
        self.assertFalse(detail["bounded_ok"])

    def test_markdown_writer_sorts_models_by_accuracy(self) -> None:
        payload = {
            "generated_at": "2026-07-22T00:00:00+00:00",
            "case_count": 36,
            "repetitions": 1,
            "models": [
                {
                    "model": "lower",
                    "percent": 80.0,
                    "wall_seconds_total": 10.0,
                    "generation_tokens_per_second": 20.0,
                    "category_scores": {"triage": {"percent": 80.0}},
                },
                {
                    "model": "higher",
                    "percent": 90.0,
                    "wall_seconds_total": 20.0,
                    "generation_tokens_per_second": 10.0,
                    "category_scores": {"triage": {"percent": 90.0}},
                },
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "summary.md"
            BENCHMARK.write_markdown(output, payload)
            rendered = output.read_text(encoding="utf-8")
        self.assertLess(rendered.index("higher"), rendered.index("lower"))


if __name__ == "__main__":
    unittest.main()
