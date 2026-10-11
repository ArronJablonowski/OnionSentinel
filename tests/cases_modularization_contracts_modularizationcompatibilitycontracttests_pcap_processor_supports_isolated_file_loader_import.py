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

class ModularizationCompatibilityContractTestsPcapProcessorSupportsIsolatedFileLoaderImportCases:
    def test_pcap_processor_supports_isolated_file_loader_import(self) -> None:
        processor = ROOT / "n8n" / "bin" / "process-pcap-evidence.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(processor)!r};"
            "s=importlib.util.spec_from_file_location('isolated_pcap_processor',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert callable(m.process_one) and callable(m.run_zeek);"
            "assert callable(m.run_tshark) and callable(m.main)"
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


    def test_detection_validation_supports_isolated_file_loader_import(self) -> None:
        validator = ROOT / "n8n" / "bin" / "detection_validation.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(validator)!r};"
            "s=importlib.util.spec_from_file_location('isolated_detection_validation',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert callable(m.parse_suricata_rule);"
            "assert callable(m.extract_group_packet_features);"
            "assert callable(m.build_detection_validation)"
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


    def test_software_inventory_collector_supports_isolated_file_loader_import(self) -> None:
        collector = ROOT / "n8n" / "bin" / "collect-software-inventory.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(collector)!r};"
            "s=importlib.util.spec_from_file_location('isolated_software_collector',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert callable(m.collect_snapshot);"
            "assert callable(m.validate_state);"
            "assert callable(m.main)"
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


    def test_ac_hunter_review_supports_isolated_file_loader_import(self) -> None:
        review = ROOT / "onion-sentinel-dashboard" / "ac_hunter_review.py"
        script = (
            "import importlib.util,sys;"
            f"p={str(review)!r};"
            "s=importlib.util.spec_from_file_location('isolated_ac_hunter_review',p);"
            "m=importlib.util.module_from_spec(s);"
            "sys.modules[s.name]=m;"
            "s.loader.exec_module(m);"
            "assert m.AcHunterReviewService;"
            "assert callable(m.normalize_collection);"
            "assert callable(m.database_review_response)"
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


    def test_contract_is_versioned_and_bound_to_a_full_release(self) -> None:
        contract = load_contract()
        self.assertEqual(
            contract["schema"],
            "onion-sentinel-modularization-contracts-v1",
        )
        release = contract["baseline_release"]
        self.assertEqual(len(release), 40)
        self.assertTrue(all(character in "0123456789abcdef" for character in release))


    def test_legacy_python_entry_points_retain_required_symbols(self) -> None:
        for entry in load_contract()["python_entry_points"]:
            with self.subTest(path=entry["path"]):
                path = ROOT / entry["path"]
                self.assertTrue(path.is_file())
                symbols = top_level_symbols(path)
                self.assertEqual(
                    sorted(set(entry["required_symbols"]) - symbols),
                    [],
                )


    def test_direct_copy_entry_points_are_present_in_production_installer(self) -> None:
        installer = read_installer_source(INSTALLER_PATH)
        for entry in load_contract()["python_entry_points"]:
            if entry["deployment"] not in {
                "direct-copy",
                "dashboard-direct-copy",
            }:
                continue
            source = entry["path"]
            runtime = entry["runtime_path"]
            with self.subTest(path=source):
                self.assertIn(f'$REPO_DIR/{source}', installer)
                self.assertIn(runtime, installer)


    def test_versioned_prompt_builder_remains_in_query_runtime_installer(self) -> None:
        installer = QUERY_RUNTIME_INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'HARDENED_BUILDER = "build-ai-investigation-prompt.py"',
            installer,
        )
        self.assertIn("validate_hardened_builder", installer)
        self.assertIn("_atomic_install", installer)


    def test_python_package_tree_is_complete_importable_and_installed(self) -> None:
        contract = load_contract()
        installer = read_installer_source(INSTALLER_PATH)
        original_path = list(sys.path)
        try:
            sys.path.insert(0, str(ROOT / "n8n"))
            for tree in contract["python_package_trees"]:
                self.assertTrue((ROOT / tree["path"] / "__init__.py").is_file())
                self.assertIn(f'$REPO_DIR/{tree["path"]}', installer)
                self.assertIn(tree["runtime_path"], installer)
                self.assertIn(f'$REPO_DIR/{tree["installer"]}', installer)
                for module in tree["required_modules"]:
                    imported = importlib.import_module(module)
                    self.assertIsNotNone(imported)
        finally:
            sys.path[:] = original_path


    def test_ai_runner_delegates_through_package_composition_root(self) -> None:
        runner = (ROOT / "n8n/bin/run-local-ai-analysis.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "from onion_sentinel.composition import invoke_legacy_entrypoint",
            runner,
        )
        self.assertIn("invoke_legacy_entrypoint(globals())", runner)
        package_sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "n8n/onion_sentinel").rglob("*.py")
        )
        self.assertNotIn("run-local-ai-analysis", package_sources)


    def test_ai_runner_query_entry_point_is_a_bounded_runtime_delegate(self) -> None:
        runner_path = ROOT / "n8n/bin/run-local-ai-analysis.py"
        function = top_level_function(
            runner_path,
            "apply_investigation_query_loop",
        )
        self.assertLessEqual(function.end_lineno - function.lineno + 1, 100)
        self.assertFalse(
            any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(function))
        )
        calls = {
            f"{node.func.value.id}.{node.func.attr}"
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
        }
        self.assertIn("module.run", calls)


    def test_ai_runner_query_execution_is_a_bounded_runtime_delegate(self) -> None:
        function = top_level_function(
            ROOT / "n8n/bin/run-local-ai-analysis.py",
            "execute_investigation_query_batch",
        )
        self.assertLessEqual(function.end_lineno - function.lineno + 1, 40)
        self.assertFalse(
            any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(function))
        )
        attributes = {
            node.func.attr for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertIn("execute_batch", attributes)


    def test_node_entry_point_matches_package_and_production_installer(self) -> None:
        installer = read_installer_source(INSTALLER_PATH)
        for entry in load_contract()["node_entry_points"]:
            with self.subTest(path=entry["path"]):
                package = json.loads(
                    (ROOT / entry["package"]).read_text(encoding="utf-8")
                )
                self.assertEqual(package["main"], entry["package_main"])
                self.assertEqual(package["scripts"]["start"], entry["package_start"])
                self.assertIn(f'$REPO_DIR/{entry["path"]}', installer)
                self.assertIn(entry["runtime_path"], installer)


    def test_alert_store_module_trees_are_staged_before_consumers_stop(self) -> None:
        installer = read_installer_source(INSTALLER_PATH)
        self.assertLess(
            installer.index("\nprepare_alert_store_stage\n"),
            installer.index("\ncritical_launch_agents_down\n"),
        )
        for tree in (
            "lib",
            "routes",
            "services",
            "repositories",
            "jobs",
            "composition",
        ):
            self.assertIn(f"n8n/alert_store/$tree", installer)
            self.assertIn(f'ALERT_STORE_STAGE_DIR/$tree', installer)
        self.assertIn("node --check", installer)
        self.assertIn("/usr/bin/rsync -a --delete", installer)
        self.assertIn("Refusing incomplete staged alert-store module tree", installer)


    def test_security_and_compatibility_invariants_are_explicit(self) -> None:
        invariants = "\n".join(load_contract()["stable_service_contracts"])
        self.assertIn("read-only", invariants)
        self.assertIn("HTTP route", invariants)
        self.assertIn("launchd", invariants)
        self.assertIn("versioned migrations", invariants)
