#!/usr/bin/env python3
"""Cross-boundary adversarial release contracts for untrusted telemetry."""
from __future__ import annotations

from types import SimpleNamespace
import html
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
SCRIPTS = DASHBOARD / "scripts"
N8N = ROOT / "n8n"
for path in (DASHBOARD, SCRIPTS, N8N):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import onion_sentinel_server as server  # noqa: E402
import portal_incident_read_runtime as incident_runtime  # noqa: E402
from portal_incident_report_renderer import (  # noqa: E402
    IncidentReportRenderCallbacks,
    render_incident_response_report,
)
from portal_json_body import parse_json_body  # noqa: E402
from portal_post_intake import prepare_post_intake  # noqa: E402
from portal_request_routes import classify_post_route  # noqa: E402
import dashboard_alert_detail_ai as dashboard_ai  # noqa: E402
from dashboard_alert_detail_markdown import markdown_to_html  # noqa: E402
from dashboard_untrusted_text import normalize_untrusted_text as dashboard_text  # noqa: E402
from portal_untrusted_text import normalize_untrusted_text as portal_text  # noqa: E402
from onion_sentinel.analysis.evidence import hosted_projection  # noqa: E402
from onion_sentinel.analysis.providers import ollama, openclaw  # noqa: E402
from onion_sentinel.analysis.query import request as query_request  # noqa: E402


FIXTURE = ROOT / "operations" / "fixtures" / "untrusted-telemetry-adversarial.json"


class QueryContractError(ValueError):
    pass


QUERY_POLICY = query_request.Policy(
    backends=frozenset({"elastic"}),
    parameter_keys={"elastic": frozenset({"pack"})},
)


def _query_dependencies() -> query_request.Dependencies:
    def normalize_parameters(backend, parameters, purpose, envelope, context):
        return parameters, {}

    return query_request.Dependencies(normalize_parameters=normalize_parameters)


def _html_text(value: object, fallback: str = "n/a") -> str:
    runtime = SimpleNamespace(html=html)
    return incident_runtime.incident_html_text(runtime, value, fallback)


def _html_list(value: object, fallback: str = "No findings were recorded.") -> str:
    runtime = SimpleNamespace(html=html, json=json)
    return incident_runtime.incident_html_list(runtime, value, fallback)


def _report_section(title: str, body: str) -> str:
    return f"<section><h4>{html.escape(title)}</h4>{body}</section>"


class UntrustedTelemetryAdversarialGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.cases = payload["cases"]

    def test_prompt_injection_remains_nested_user_evidence(self) -> None:
        injection = self.cases["prompt_injection"]
        prompt_package = {"alert": {"message": injection}}
        task = ollama.analysis_task(prompt_package, False)
        body = json.loads(ollama._chat_body(
            "fixture-model", "trusted-system", task, prompt_package,
            SimpleNamespace(temperature=0, max_predict_tokens=128),
        ))

        self.assertEqual(body["messages"][0], {
            "role": "system", "content": "trusted-system"
        })
        user = json.loads(body["messages"][1]["content"])
        self.assertEqual(user["prompt_package"]["alert"]["message"], injection)
        self.assertIn("untrusted attacker-controlled evidence", user["task"])

    def test_model_text_cannot_supply_executable_query_fields(self) -> None:
        with self.assertRaisesRegex(QueryContractError, "query fields"):
            query_request.normalize(
                self.cases["query_injection"], round_number=1, position=1,
                time_envelope={}, authorization_context={}, policy=QUERY_POLICY,
                dependencies=_query_dependencies(), error_type=QueryContractError,
            )
        parameter_injection = dict(self.cases["query_injection"])
        parameter_injection.pop("command")
        with self.assertRaisesRegex(QueryContractError, "elastic parameters"):
            query_request.normalize(
                parameter_injection, round_number=1, position=1,
                time_envelope={}, authorization_context={}, policy=QUERY_POLICY,
                dependencies=_query_dependencies(), error_type=QueryContractError,
            )

    def test_request_size_and_traversal_fail_before_read_or_file_access(self) -> None:
        route = classify_post_route(
            "/api/soc-alerts/status", cti_program_path="/api/cti",
            prompt_paths=frozenset(),
        )
        result = prepare_post_intake(
            route, self.cases["oversized_content_length"],
            cti_file_bytes=1024, admin_authenticated=lambda: False,
        )
        self.assertEqual(result.status, 400)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index.html").write_text("fixture", encoding="utf-8")
            self.assertIsNone(server.resolve_dashboard_target(
                root, self.cases["path_traversal"]
            ))

    def test_hosted_projection_redacts_sensitive_evidence(self) -> None:
        policy = hosted_projection.Policy(
            provenance_schema="columnar-v1",
            columns=("evidence_ref_or_empty",),
            maximum_queries=12,
            list_path_sentinel=object(),
        )
        projected = hosted_projection.prune_empty(hosted_projection.sanitize(
            self.cases["secret_disclosure"], policy=policy
        ))
        encoded = json.dumps(projected, sort_keys=True)
        self.assertNotIn("fixture-value-not-a-secret", encoded)
        self.assertNotIn("/Users/fixture", encoded)

    def test_non_loopback_model_egress_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "loopback Ollama"):
            openclaw.validate_route(
                "ollama/fixture", {"ollama_url": self.cases["unsafe_egress"]},
                model_pattern=re.compile(r"^[a-z]+/[a-z]+$"),
                uses_ollama_runtime=lambda _model: True,
                provider_prefix="ollama/",
                supported_urls=frozenset({"http://127.0.0.1:11434"}),
                default_url="http://127.0.0.1:11434",
            )

    def test_malicious_json_encoding_cannot_break_report_publication(self) -> None:
        parsed = parse_json_body(json.dumps({
            "value": self.cases["malicious_encoding"]
        }))
        self.assertTrue(parsed.is_object)
        malicious = parsed.value["value"]
        callbacks = IncidentReportRenderCallbacks(
            html_text=_html_text,
            nonnegative_int=lambda value: max(0, int(value or 0)),
            linked_finding=lambda _report, _digest: "",
            html_list=_html_list,
            report_section=_report_section,
            investigation_audit=lambda _response, _report: ("", 0),
            review_panel=lambda _review, **_kwargs: "",
        )
        rendered, _ = render_incident_response_report(
            {"case_id": "fixture"},
            {"incident_response_report": {
                "executive_bluf": malicious,
                "confidence": "low",
            }},
            {}, None, callbacks,
        )
        encoded = rendered.encode("utf-8")
        self.assertNotIn(b"<script", encoded.lower())
        self.assertNotIn("\x00", rendered)
        self.assertIn("\N{REPLACEMENT CHARACTER}", rendered)

        markdown = dashboard_ai.ai_analysis_report_markdown({
            "response": {
                "bluf": self.cases["prompt_injection"],
                "summary": malicious,
                "claim_evidence_graph": {
                    "claims": [{"statement": malicious}],
                },
            }
        })
        dashboard_html = markdown_to_html(markdown)
        dashboard_encoded = dashboard_html.encode("utf-8")
        self.assertNotIn(b"<script", dashboard_encoded.lower())
        self.assertNotIn("\x00", dashboard_html)
        self.assertIn("\N{REPLACEMENT CHARACTER}", dashboard_html)

    def test_text_boundaries_share_exact_control_and_bound_semantics(self) -> None:
        malicious = self.cases["malicious_encoding"]
        portal_value = portal_text(malicious)
        dashboard_value = dashboard_text(malicious)
        self.assertEqual(portal_value, dashboard_value)
        self.assertEqual(portal_value.encode("utf-8").decode("utf-8"), portal_value)
        for forbidden in ("\ud800", "\x00", "\u202e"):
            self.assertNotIn(forbidden, portal_value)
        self.assertEqual(portal_text("abcdef", max_characters=4), "abc…")

    def test_valid_unicode_and_large_existing_reports_are_unchanged(self) -> None:
        valid = "Evidence Café — 例 🧅\n" + ("bounded-existing-report " * 12_000)
        self.assertEqual(portal_text(valid), valid)
        self.assertEqual(dashboard_text(valid), valid)

    def test_gate_and_boundary_modules_are_in_the_production_contract(self) -> None:
        installer = (ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh").read_text(
            encoding="utf-8"
        )
        self.assertEqual(installer.count("portal_untrusted_text.py"), 2)
        self.assertEqual(installer.count("dashboard_untrusted_text.py"), 2)
        deployment = (ROOT / "docs" / "product-deployment-requirements.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("run-untrusted-telemetry-gate.py", deployment)


if __name__ == "__main__":
    unittest.main()
