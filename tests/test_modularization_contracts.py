"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

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

from modularization_contracts_fixtures_modularizationcompatibilitycontracttests import ModularizationCompatibilityContractTestsFixtures
from cases_modularization_contracts_modularizationcompatibilitycontracttests_undefined_global_analysis_ignores_only_postponed_annotations import ModularizationCompatibilityContractTestsUndefinedGlobalAnalysisIgnoresOnlyPostponedAnnotationsCases
from cases_modularization_contracts_modularizationcompatibilitycontracttests_pcap_processor_supports_isolated_file_loader_import import ModularizationCompatibilityContractTestsPcapProcessorSupportsIsolatedFileLoaderImportCases


class ModularizationCompatibilityContractTests(
    ModularizationCompatibilityContractTestsUndefinedGlobalAnalysisIgnoresOnlyPostponedAnnotationsCases,
    ModularizationCompatibilityContractTestsPcapProcessorSupportsIsolatedFileLoaderImportCases,
    ModularizationCompatibilityContractTestsFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
