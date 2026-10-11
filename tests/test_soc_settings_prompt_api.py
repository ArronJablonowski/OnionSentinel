"""Discover focused contract suites; preserve historical test identities."""
from __future__ import annotations

import unittest
import sys
from pathlib import Path

_test_directory = str(Path(__file__).resolve().parent)
if _test_directory not in sys.path:
    sys.path.insert(0, _test_directory)

from soc_settings_prompt_api_fixtures import (
    PORTAL_PATH,
    Path,
    REPO_ROOT,
    SettingsPostRequest,
    importlib,
    io,
    json,
    load_portal,
    mock,
    sys,
    tempfile,
    unittest,
)

from soc_settings_prompt_api_fixtures_socsettingspromptapitest import SocSettingsPromptApiTestFixtures
from cases_soc_settings_prompt_api_socsettingspromptapitest_incident_responder_prompt_save_and_read import SocSettingsPromptApiTestIncidentResponderPromptSaveAndReadCases
from cases_soc_settings_prompt_api_socsettingspromptapitest_retired_hybrid_policy_is_ignored_and_not_persisted import SocSettingsPromptApiTestRetiredHybridPolicyIsIgnoredAndNotPersistedCases


class SocSettingsPromptApiTest(
    SocSettingsPromptApiTestIncidentResponderPromptSaveAndReadCases,
    SocSettingsPromptApiTestRetiredHybridPolicyIsIgnoredAndNotPersistedCases,
    SocSettingsPromptApiTestFixtures,
):
    """Compose independently maintained behavior contracts with shared fixtures."""


if __name__ == "__main__":
    unittest.main()
