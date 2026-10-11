from __future__ import annotations

from installer_source_fixture import read_installer_source

from modularization_contracts_fixtures import (
    CONTRACT_PATH,
    INSTALLER_PATH,
    Optional,
    Path,
    QUERY_RUNTIME_INSTALLER_PATH,
    ROOT,
    _ReferenceContextVisitor,
    ast,
    builtins,
    importlib,
    json,
    load_contract,
    subprocess,
    symtable,
    sys,
    top_level_function,
    top_level_function_names,
    top_level_symbols,
    undefined_global_names,
    unittest,
)

class ModularizationCompatibilityContractTestsUndefinedGlobalAnalysisIgnoresOnlyPostponedAnnotationsCases:
    def test_undefined_global_analysis_ignores_only_postponed_annotations(
        self,
    ) -> None:
        source = """\
from __future__ import annotations

def build(value: AnnotationOnly) -> AnnotationOnly:
    return value
"""
        self.assertEqual(undefined_global_names(source, "postponed.py"), set())


    def test_undefined_global_analysis_keeps_executable_references(self) -> None:
        source = """\
from __future__ import annotations

def build(value: UsedAsAnnotation) -> UsedAsAnnotation:
    return UsedAsAnnotation(value)
"""
        self.assertEqual(
            undefined_global_names(source, "runtime.py"),
            {"UsedAsAnnotation"},
        )


    def test_undefined_global_analysis_keeps_eager_annotations(self) -> None:
        source = """\
def build(value: MissingAtDefinition) -> MissingAtDefinition:
    return value
"""
        self.assertEqual(
            undefined_global_names(source, "eager.py"),
            {"MissingAtDefinition"},
        )


    def test_relay_supports_isolated_file_loader_import(self) -> None:
        relay = ROOT / "relay" / "app" / "relay.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(relay)!r};"
            "s=importlib.util.spec_from_file_location('isolated_relay',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert m.PcapProgressReporter and m.WebhookPostError;"
            "assert callable(m.main) and callable(m.process_pcap_requests)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_relay_module_tree_is_fully_installed(self) -> None:
        installer = (ROOT / "relay" / "bin" / "install-pi-relay.sh").read_text(
            encoding="utf-8"
        )
        for path in sorted((ROOT / "relay" / "app").glob("relay_*.py")):
            with self.subTest(path=path.name):
                self.assertIn(
                    f'$REPO_DIR/relay/app/{path.name}',
                    installer,
                )


    def test_relay_pcap_spool_policy_owns_storage_contract(self) -> None:
        policy = ROOT / "relay" / "app" / "relay_pcap_spool_policy.py"
        transport = ROOT / "relay" / "app" / "relay_pcap_transport.py"
        installer = (ROOT / "relay" / "bin" / "install-pi-relay.sh").read_text(
            encoding="utf-8"
        )
        expected = {
            "atomic_json_write",
            "cleanup_stale_spool_artifacts",
            "cleanup_stale_spool_partials",
            "load_json_file",
            "pcap_spool_dir",
            "require_spool_capacity",
            "sha256_file",
            "spool_mount_ready",
            "spool_usage",
        }

        self.assertTrue(policy.is_file())
        self.assertTrue(expected <= top_level_symbols(policy))
        self.assertTrue(expected.isdisjoint(top_level_function_names(transport)))
        self.assertEqual(
            undefined_global_names(policy.read_text(encoding="utf-8"), str(policy)),
            set(),
        )
        self.assertLess(
            installer.index("relay_pcap_spool_policy.py"),
            installer.index("relay_pcap_transport.py"),
        )

        script = (
            f"import sys;sys.path.insert(0,{str(policy.parent)!r});"
            "import relay_pcap_spool_policy as p,relay_pcap_transport as t;"
            "names=" + repr(sorted(expected)) + ";"
            "assert all(getattr(t,n) is getattr(p,n) for n in names)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_relay_pcap_capture_policy_owns_telemetry_admission(self) -> None:
        policy = ROOT / "relay" / "app" / "relay_pcap_capture_policy.py"
        transport = ROOT / "relay" / "app" / "relay_pcap_transport.py"
        installer = (ROOT / "relay" / "bin" / "install-pi-relay.sh").read_text(
            encoding="utf-8"
        )
        expected = {
            "capture_protection_decision",
            "require_capture_safe",
            "security_onion_storage_status",
        }

        self.assertTrue(policy.is_file())
        self.assertTrue(expected <= top_level_symbols(policy))
        self.assertTrue(expected.isdisjoint(top_level_function_names(transport)))
        self.assertEqual(
            undefined_global_names(policy.read_text(encoding="utf-8"), str(policy)),
            set(),
        )
        self.assertLess(
            installer.index("relay_pcap_capture_policy.py"),
            installer.index("relay_pcap_transport.py"),
        )

        script = (
            f"import sys;sys.path.insert(0,{str(policy.parent)!r});"
            "import relay as r,relay_pcap_capture_policy as p;"
            "import relay_pcap_transport as t;"
            "names=" + repr(sorted(expected)) + ";"
            "assert p in r._MODULES;"
            "assert all(getattr(t,n) is getattr(p,n) for n in names);"
            "assert all(r._CANONICAL[n] is getattr(p,n) for n in names)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_relay_pcap_streaming_owns_chunk_and_artifact_workflow(self) -> None:
        streaming = ROOT / "relay" / "app" / "relay_pcap_streaming.py"
        transport = ROOT / "relay" / "app" / "relay_pcap_transport.py"
        installer = (ROOT / "relay" / "bin" / "install-pi-relay.sh").read_text(
            encoding="utf-8"
        )
        expected = {
            "stream_chunk_idle_timeout",
            "stream_one_security_onion_chunk",
            "streamed_spool_artifact",
            "wait_for_stream_progress",
        }

        self.assertTrue(streaming.is_file())
        self.assertTrue(expected <= top_level_symbols(streaming))
        self.assertTrue(expected.isdisjoint(top_level_function_names(transport)))
        self.assertEqual(
            undefined_global_names(
                streaming.read_text(encoding="utf-8"),
                str(streaming),
            ),
            set(),
        )
        self.assertLess(
            installer.index("relay_pcap_streaming.py"),
            installer.index("relay_pcap_transport.py"),
        )

        script = (
            f"import sys;sys.path.insert(0,{str(streaming.parent)!r});"
            "import relay as r,relay_pcap_streaming as s;"
            "import relay_pcap_transport as t;"
            "names=" + repr(sorted(expected)) + ";"
            "assert s in r._MODULES;"
            "assert all(getattr(t,n) is getattr(s,n) for n in names);"
            "assert all(r._CANONICAL[n] is getattr(s,n) for n in names)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_relay_pcap_service_has_bounded_state_machine_phases(self) -> None:
        service = ROOT / "relay" / "app" / "relay_pcap_service.py"
        expected = {
            "_pcap_poll_context",
            "_process_claimed_pcap_request",
            "_schedule_pcap_retry",
            "_pcap_run_summary",
        }

        self.assertTrue(expected <= top_level_function_names(service))
        unlocked = top_level_function(service, "_process_pcap_requests_unlocked")
        self.assertLessEqual(
            (unlocked.end_lineno or unlocked.lineno) - unlocked.lineno + 1,
            50,
        )


    def test_relay_application_has_bounded_lifecycle_phases(self) -> None:
        application = ROOT / "relay" / "app" / "relay_application.py"
        expected = {
            "_drain_ssh_alert_outbox",
            "_drain_webhook_alert_outbox",
            "_parse_relay_args",
            "_run_pull_cycle",
            "_pull_cycle_result",
        }

        self.assertTrue(expected <= top_level_function_names(application))
        for name in ("drain_alert_outbox", "main"):
            function = top_level_function(application, name)
            with self.subTest(name=name):
                self.assertLessEqual(
                    (function.end_lineno or function.lineno)
                    - function.lineno
                    + 1,
                    50,
                )


    def test_relay_core_has_bounded_policy_phases(self) -> None:
        core = ROOT / "relay" / "app" / "relay_core.py"
        expected = {
            "_prune_runtime_evidence_directory",
            "_relay_root_capacity_policy",
            "_webhook_failure_payload",
        }

        self.assertTrue(expected <= top_level_function_names(core))


    def test_relay_alert_delivery_has_bounded_transport_phases(self) -> None:
        delivery = ROOT / "relay" / "app" / "alert_delivery.py"
        expected = {
            "_ssh_intake_identity",
            "_ssh_intake_command",
            "_run_ssh_alert_batch",
            "_validate_ssh_batch_response",
        }

        self.assertTrue(expected <= top_level_function_names(delivery))
        for name in ("_ssh_command", "deliver_ssh_batch"):
            function = top_level_function(delivery, name)
            with self.subTest(name=name):
                self.assertLessEqual(
                    (function.end_lineno or function.lineno)
                    - function.lineno
                    + 1,
                    50,
                )


    def test_relay_process_io_has_bounded_lifecycle_phases(self) -> None:
        process_io = ROOT / "relay" / "app" / "process_io.py"
        expected = {
            "_start_bounded_process",
            "_register_process_control_channels",
            "_drain_process_control_channels",
            "_terminate_process_group",
            "_close_process_control_channels",
        }

        self.assertTrue(expected <= top_level_function_names(process_io))
        function = top_level_function(process_io, "run_bounded_command")
        self.assertLessEqual(
            (function.end_lineno or function.lineno) - function.lineno + 1,
            50,
        )


    def test_ac_hunter_broker_has_bounded_config_admission_phases(self) -> None:
        broker = ROOT / "relay" / "app" / "ac_hunter_broker.py"
        expected = {
            "_read_config_snapshot",
            "_validate_config_shape",
            "_validate_upstream_identity",
            "_validated_ca_bundle",
            "_validate_config_limits",
            "_validated_lock_file",
        }

        self.assertTrue(expected <= top_level_function_names(broker))
        function = top_level_function(broker, "_load_config")
        self.assertLessEqual(
            (function.end_lineno or function.lineno) - function.lineno + 1,
            50,
        )


    def test_live_osquery_broker_has_bounded_config_and_lifecycle_phases(self) -> None:
        broker = ROOT / "relay" / "app" / "live_osquery_broker.py"
        expected = {
            "_config_snapshot",
            "_validate_config_file",
            "_decode_config",
            "_validate_config",
            "_config_path",
            "_validated_request",
            "_ssh_command",
            "_run_query",
            "_validated_response",
            "_execute_request",
            "_emit_failure",
        }

        self.assertTrue(expected <= top_level_function_names(broker))
        for name in ("_load_config", "main"):
            function = top_level_function(broker, name)
            with self.subTest(name=name):
                self.assertLessEqual(
                    (function.end_lineno or function.lineno)
                    - function.lineno
                    + 1,
                    50,
                )


    def test_ac_hunter_broker_has_bounded_response_lifecycle_phases(self) -> None:
        broker = ROOT / "relay" / "app" / "ac_hunter_broker.py"
        expected = {
            "_safe_location",
            "_safe_cookies",
            "_validate_declared_length",
            "_read_bounded_body",
            "_decode_response_body",
            "_admit_request_bytes",
            "_candidate_request_id",
            "_execute_request",
            "_emit_success",
            "_emit_invalid_request",
            "_emit_broker_failure",
            "_emit_internal_failure",
        }

        self.assertTrue(expected <= top_level_function_names(broker))
        for name in ("_response_headers", "_read_response", "main"):
            function = top_level_function(broker, name)
            with self.subTest(name=name):
                self.assertLessEqual(
                    (function.end_lineno or function.lineno)
                    - function.lineno
                    + 1,
                    50,
                )


    def test_relay_health_contract_has_bounded_diagnostic_phases(self) -> None:
        contract = ROOT / "relay" / "app" / "relay_health_contract.py"
        expected = {
            "_validated_child_diagnostic",
            "_classified_diagnostic_category",
            "_diagnostic_projection",
        }

        self.assertTrue(expected <= top_level_function_names(contract))
        function = top_level_function(contract, "classify_child_diagnostic")
        self.assertLessEqual(
            (function.end_lineno or function.lineno) - function.lineno + 1,
            50,
        )


    def test_relay_health_sanitization_has_bounded_projection_phases(self) -> None:
        sanitization = ROOT / "relay" / "app" / "relay_health_sanitization.py"
        expected = {
            "_base_health_state",
            "_optional_health_timestamps",
            "_optional_health_summaries",
            "_optional_health_returncode",
            "_health_http_status",
            "_optional_pcap_failure_state",
            "_sanitize_pcap_scalar_fields",
            "_pcap_detail_projection",
            "_sanitize_storage_section",
            "_sanitize_smart_summary",
            "_storage_failure_categories",
            "_child_fallback_diagnostic",
            "_safe_child_stderr",
        }

        self.assertTrue(expected <= top_level_function_names(sanitization))
        for name in (
            "sanitize_pcap_summary",
            "sanitize_storage_summary",
            "sanitized_child_result",
            "sanitize_health_state",
        ):
            function = top_level_function(sanitization, name)
            with self.subTest(name=name):
                self.assertLessEqual(
                    (function.end_lineno or function.lineno)
                    - function.lineno
                    + 1,
                    50,
                )


    def test_relay_storage_health_has_bounded_probe_phases(self) -> None:
        storage_health = ROOT / "relay" / "app" / "storage_health.py"
        expected = {
            "_root_storage_health",
            "_mount_source",
            "_ssd_storage_health",
            "_smart_summary",
            "_smart_health",
        }

        self.assertTrue(expected <= top_level_function_names(storage_health))
        function = top_level_function(storage_health, "main")
        self.assertLessEqual(
            (function.end_lineno or function.lineno) - function.lineno + 1,
            50,
        )


    def test_relay_health_application_has_bounded_lifecycle_phases(self) -> None:
        application = ROOT / "relay" / "app" / "relay_health_application.py"
        expected = {
            "_pcap_status_summaries",
            "_pcap_status_counters",
            "_pcap_workflow_state",
            "_pcap_workflow",
            "_pcap_recovery_summary",
            "_pcap_recovery_has_invalid_fields",
            "_pcap_recovery_contract_valid",
            "_parse_component",
            "_run_alert_component",
            "_run_pcap_component",
            "_run_storage_component",
            "_run_components",
            "_component_outcome",
            "_prior_pcap_failure",
            "_update_pcap_failure_latch",
            "_complete_success",
            "_complete_failure",
        }

        self.assertTrue(expected <= top_level_function_names(application))
        for name in (
            "build_pcap_status_event",
            "pcap_result_proves_broker_recovery",
            "main",
        ):
            function = top_level_function(application, name)
            with self.subTest(name=name):
                self.assertLessEqual(
                    (function.end_lineno or function.lineno)
                    - function.lineno
                    + 1,
                    50,
                )


    def test_incident_evidence_broker_has_bounded_contract_phases(self) -> None:
        broker = ROOT / "relay" / "app" / "incident_evidence_broker.py"
        dhcp = ROOT / "relay" / "app" / "incident_evidence_dhcp.py"
        software = ROOT / "relay" / "app" / "incident_evidence_software.py"
        transport = ROOT / "relay" / "app" / "incident_evidence_transport.py"
        broker_phases = {
            "_receipt_identity",
            "_validate_receipt_accounting",
            "_admit_transport_request",
            "_request_kinds",
            "_validate_special_request",
            "_load_broker_config",
            "_upstream_command",
            "_run_upstream",
            "_decode_upstream_response",
            "_validate_upstream_response",
        }
        transport_phases = {
            "_audited_transport_fields",
            "_transport_payload_size",
            "_receipt_fields",
            "_receipt_contract_matches",
            "_receipt_terminal_matches",
            "transport_envelope",
            "receipt_identity",
        }
        dhcp_phases = {
            "_request_fields",
            "_validate_operation",
            "_request_window",
            "_validate_window",
            "_validate_size",
        }
        software_phases = {
            "_validate_record_identity",
            "_validate_asset_reference",
            "_validate_operating_system_fields",
            "_validate_endpoint_operating_system",
            "_validate_passive_operating_system",
            "_validate_operating_system",
            "_validate_record_observations",
            "_validate_response_identity",
            "_response_records",
            "_validate_pagination_state",
            "_validate_response_cursor",
            "_validate_response_records",
            "_validate_response_page",
            "_validate_query_audit",
        }

        self.assertTrue(broker_phases <= top_level_function_names(broker))
        self.assertTrue(transport_phases <= top_level_function_names(transport))
        self.assertTrue(dhcp_phases <= top_level_function_names(dhcp))
        self.assertTrue(software.is_file())
        self.assertTrue(software_phases <= top_level_function_names(software))
        for path, name in (
            (broker, "_transport_envelope"),
            (broker, "_receipt_identity"),
            (broker, "_validate_receipt"),
            (broker, "main"),
            (dhcp, "validate_dhcp_request"),
            (software, "_validate_operating_system"),
            (software, "_validate_response_page"),
            (software, "_validate_software_record"),
            (software, "validate_software_response"),
        ):
            function = top_level_function(path, name)
            with self.subTest(path=path.name, name=name):
                self.assertLessEqual(
                    (function.end_lineno or function.lineno)
                    - function.lineno
                    + 1,
                    50,
                )

        installer = (
            ROOT / "relay" / "bin" / "install-pi-relay.sh"
        ).read_text()
        self.assertLess(
            installer.index("incident_evidence_dhcp.py"),
            installer.index("incident_evidence_broker.py"),
        )
        self.assertLess(
            installer.index("incident_evidence_software.py"),
            installer.index("incident_evidence_broker.py"),
        )
        self.assertLess(
            installer.index("incident_evidence_transport.py"),
            installer.index("incident_evidence_broker.py"),
        )


    def test_relay_health_wrapper_supports_isolated_file_loader_import(self) -> None:
        wrapper = ROOT / "relay" / "app" / "relay_health_wrapper.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(wrapper)!r};"
            "s=importlib.util.spec_from_file_location('isolated_relay_health',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert callable(m.main) and callable(m.run_pcap_broker);"
            "assert callable(m.sanitize_health_state)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_pi_relay_python_installer_and_contract_are_complete(self) -> None:
        installer = (
            ROOT / "relay" / "bin" / "install-pi-relay.sh"
        ).read_text(encoding="utf-8")
        marker = '"$REPO_DIR/'
        installed = {}
        for line in installer.replace("\\\n", " ").splitlines():
            if marker not in line or ".py" not in line:
                continue
            source_path = line.split(marker, 1)[1].split('"', 1)[0]
            installed[source_path] = line.split()[-1]
        contracted = {
            entry["path"]: entry["runtime_path"]
            for entry in load_contract()["python_entry_points"]
            if entry["deployment"] == "relay-direct-copy"
        }

        self.assertEqual(contracted, installed)


    def test_extracted_harness_modules_have_no_undefined_globals(self) -> None:
        for path in sorted((ROOT / "n8n" / "bin").glob("harness_*.py")):
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertEqual(sorted(undefined_global_names(source, str(path))), [])


    def test_harness_supports_isolated_file_loader_import(self) -> None:
        harness = ROOT / "n8n" / "bin" / "onion_sentinel_harness.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(harness)!r};"
            "s=importlib.util.spec_from_file_location('isolated_harness',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert m.HarnessPolicy and m.HarnessStore and m.HarnessRun;"
            "assert callable(m.start_harness_run)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_scheduler_supports_isolated_late_bound_composition(self) -> None:
        scheduler = ROOT / "n8n" / "bin" / "auto-run-ai-analysis.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(scheduler)!r};"
            "s=importlib.util.spec_from_file_location('isolated_scheduler',p);"
            "m=importlib.util.module_from_spec(s);"
            "s.loader.exec_module(m);"
            "replacement=lambda *a,**k:None;"
            "m.run_analysis=replacement;"
            "assert m.scheduler_execution_sources().run_analysis is replacement;"
            "assert callable(m.main) and callable(m.parse_args)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_scheduler_runtime_module_tree_is_fully_installed(self) -> None:
        installer = read_installer_source(INSTALLER_PATH)
        for path in sorted((ROOT / "n8n" / "bin").glob("scheduler_*.py")):
            with self.subTest(path=path.name):
                self.assertIn(
                    f'$REPO_DIR/n8n/bin/{path.name}',
                    installer,
                )


    def test_harness_job_envelope_has_one_dataclass_boundary(self) -> None:
        contracts = ROOT / "n8n" / "bin" / "harness_contracts.py"
        tree = ast.parse(
            contracts.read_text(encoding="utf-8"), filename=str(contracts)
        )
        envelope = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "JobEnvelope"
        )
        self.assertEqual(len(envelope.decorator_list), 1)

        policy_owners = {
            "PolicyDecision": ROOT / "n8n" / "bin" / "harness_policy_capabilities.py",
            "HarnessPolicy": ROOT / "n8n" / "bin" / "harness_policy_document.py",
        }
        for name, policy_path in policy_owners.items():
            with self.subTest(name=name):
                policy_tree = ast.parse(
                    policy_path.read_text(encoding="utf-8"), filename=str(policy_path)
                )
                policy_classes = {
                    node.name: node
                    for node in policy_tree.body
                    if isinstance(node, ast.ClassDef)
                }
                self.assertEqual(len(policy_classes[name].decorator_list), 1)


    def test_software_inventory_supports_isolated_file_loader_import(self) -> None:
        inventory = ROOT / "onion-sentinel-dashboard" / "software_inventory.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(inventory)!r};"
            "s=importlib.util.spec_from_file_location('isolated_software_inventory',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert callable(m.build_response) and callable(m.load_state)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_report_portal_supports_isolated_file_loader_import(self) -> None:
        portal = ROOT / "onion-sentinel-dashboard" / "report_portal.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(portal)!r};"
            "s=importlib.util.spec_from_file_location('isolated_report_portal',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert m.PortalHandler and callable(m.main)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
