from __future__ import annotations

from installer_source_fixture import read_installer_source

from incident_evidence_contract_fixtures import (
    BIN_DIR,
    BUILDER_PATH,
    CONTRACT_PATH,
    Path,
    REPO_ROOT,
    copy,
    digest,
    elastic_result,
    evidence_artifact,
    execution_digest,
    hashlib,
    importlib,
    json,
    load_builder_module,
    load_contract_module,
    shutil,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class IncidentEvidenceContractTestsAnchorlessV2RequestIsAcceptedOnlyAsSemanticallyPartialCases:
    def test_anchorless_v2_request_is_accepted_only_as_semantically_partial(self) -> None:
        artifact = evidence_artifact()
        response = artifact["security_onion_response"]
        artifact["request"]["anchor"] = None
        response["controls"] = {
            "anchor": None,
            "positive_anchor": {
                "status": "not_requested",
                "passed": False,
                "semantic_valid": False,
                "error": "A representative Security Onion alert anchor was not supplied",
            },
            "negative_filter": {
                "status": "not_requested",
                "passed": False,
                "semantic_valid": False,
                "error": "A representative Security Onion alert anchor was not supplied",
            },
        }
        response["semantic_validity"]["controls_valid"] = False
        response["semantic_validity"]["semantic_valid"] = False
        response["semantic_validity"]["reasons"] = [
            "representative alert controls did not both pass",
        ]
        response["complete"] = False
        response["partial"] = True

        validated = self.contract.validate_incident_evidence_artifact(artifact)

        self.assertFalse(validated["security_onion_response"]["complete"])


    def test_rejects_complete_claim_when_anchor_control_failed(self) -> None:
        artifact = evidence_artifact()
        response = artifact["security_onion_response"]
        positive = response["controls"]["positive_anchor"]
        positive["hits"] = []
        positive["returned_hits"] = 0
        positive["total_hits"] = 0
        positive["passed"] = False

        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "semantic validity controls_valid flag is inconsistent",
        ):
            self.contract.validate_incident_evidence_artifact(artifact)


    def test_rejects_query_endpoint_scope_tampering(self) -> None:
        artifact = evidence_artifact()
        result = artifact["security_onion_response"]["results"][0]
        result["query_endpoint"] = "/_search"

        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "outside its reviewed index scope",
        ):
            self.contract.validate_incident_evidence_artifact(artifact)


    def test_rejects_unreviewed_or_modified_osquery_sql(self) -> None:
        artifact = evidence_artifact()
        artifact["security_onion_response"]["osquery_results"][0]["query"] = (
            "SELECT * FROM processes;"
        )

        with self.assertRaisesRegex(
            self.contract.IncidentEvidenceContractError,
            "does not match its reviewed pack",
        ):
            self.contract.validate_incident_evidence_artifact(artifact)


    def test_accepts_legacy_v1_artifact_without_live_osquery(self) -> None:
        artifact = evidence_artifact()
        artifact["schema"] = "onion-sentinel-incident-evidence-v1"
        artifact["security_onion_response"]["query_contract"] = (
            "onion-sentinel-incident-evidence-v1"
        )
        artifact["request"].pop("osquery_packs")
        artifact["security_onion_response"].pop("osquery_results")

        validated = self.contract.validate_incident_evidence_artifact(artifact)

        self.assertIs(validated, artifact)


    def test_incident_prompt_builder_has_no_empty_evidence_fallback(self) -> None:
        builder = (BIN_DIR / "build-ai-investigation-prompt.py").read_text(
            encoding="utf-8"
        )
        assembler = (BIN_DIR / "prompt_package_view_model.py").read_text(
            encoding="utf-8"
        )
        orchestrator = (BIN_DIR / "prompt_package_orchestrator.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("build_prepared_prompt_package(", builder)
        self.assertIn("assemble_prepared_prompt_package(", orchestrator)
        self.assertIn("assemble_prompt_package(", assembler)
        self.assertIn("requires validated restricted Security Onion evidence", assembler)
        self.assertNotIn(
            '"security_onion_response": {"complete": False, "partial": True, "results": []}',
            builder + orchestrator + assembler,
        )


    def test_mac_installer_deploys_incident_evidence_runtime_dependencies(self) -> None:
        installer = read_installer_source(BIN_DIR / "install-macstudio-stack.zsh")
        example = json.loads(
            (REPO_ROOT / "n8n" / "config" / "incident-evidence.example.json").read_text(
                encoding="utf-8"
            )
        )
        collector = (BIN_DIR / "collect-incident-evidence.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("incident_evidence_contract.py", installer)
        for name in (
            "incident_evidence_validation.py",
            "incident_evidence_primitives.py",
            "incident_evidence_search_contract.py",
            "incident_evidence_osquery_contract.py",
            "incident_evidence_control_contract.py",
            "incident_evidence_artifact_contract.py",
        ):
            self.assertIn(
                f'cp "$REPO_DIR/n8n/bin/{name}" "$STACK_DIR/bin/{name}"',
                installer,
            )
        self.assertIn("collect-incident-evidence.py", installer)
        self.assertIn("incident-evidence.example.json", installer)
        self.assertIn('if "timeout_seconds" not in config:', installer)
        self.assertIn('config["timeout_seconds"] = 420', installer)
        self.assertEqual(example["timeout_seconds"], 420)
        self.assertIn('config.get("timeout_seconds", 420)', collector)


    def test_incident_evidence_facade_imports_from_an_isolated_flat_bin(self) -> None:
        names = (
            "incident_evidence_validation.py",
            "incident_evidence_primitives.py",
            "incident_evidence_search_contract.py",
            "incident_evidence_osquery_contract.py",
            "incident_evidence_control_contract.py",
            "incident_evidence_artifact_contract.py",
            "incident_evidence_contract.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            for name in names:
                shutil.copy2(BIN_DIR / name, runtime / name)
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(runtime / "incident_evidence_contract.py"),
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_incident_responder_prompt_requires_framework_and_query_audits(self) -> None:
        prompt = (
            REPO_ROOT / "n8n" / "config" / "incident_responder_system_prompt.md"
        ).read_text(encoding="utf-8")

        self.assertIn("SIEM Detection Outcome Classification", prompt)
        self.assertIn("True Positive - Malicious", prompt)
        self.assertIn("False Negative", prompt)
        self.assertIn("exact OSQuery SQL", prompt)
        self.assertIn("query digest", prompt)


