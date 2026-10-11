from __future__ import annotations

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

class SocSettingsPromptApiTestFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.portal = load_portal()
        self.prompt_path = Path(self.tmp.name) / "config" / "incident_responder_system_prompt.md"
        self.portal.INCIDENT_RESPONDER_PROMPT_FILE = self.prompt_path
        prompt_dir = self.prompt_path.parent
        prompt_specs = {
            "/api/soc-settings/analyst-prompt": ("SOC Analyst", "soc_analyst_system_prompt.md"),
            "/api/soc-settings/analyst-second-opinion-prompt": ("SOC Analyst second-opinion", "soc_analyst_second_opinion_prompt.md"),
            "/api/soc-settings/incident-responder-prompt": ("Incident Responder", "incident_responder_system_prompt.md"),
            "/api/soc-settings/incident-responder-second-opinion-prompt": ("Incident Responder second-opinion", "incident_responder_second_opinion_prompt.md"),
            "/api/soc-settings/siem-engineer-prompt": ("SIEM Engineer", "siem_engineer_system_prompt.md"),
            "/api/soc-settings/siem-engineer-second-opinion-prompt": ("SIEM Engineer second-opinion", "siem_engineer_second_opinion_prompt.md"),
            "/api/soc-settings/cyber-threat-intel-prompt": ("Cyber Threat Intel", "cyber_threat_intel_system_prompt.md"),
            "/api/soc-settings/cyber-threat-intel-second-opinion-prompt": ("Cyber Threat Intel second-opinion", "cyber_threat_intel_second_opinion_prompt.md"),
            "/api/soc-settings/threat-hunter-prompt": ("Threat Hunter", "threat_hunter_system_prompt.md"),
            "/api/soc-settings/threat-hunter-second-opinion-prompt": ("Threat Hunter second-opinion", "threat_hunter_second_opinion_prompt.md"),
        }
        self.portal.SOC_SETTINGS_PROMPT_FILES = {
            route: (label, prompt_dir / filename)
            for route, (label, filename) in prompt_specs.items()
        }
        self.portal.SOC_SETTINGS_PROMPT_API_PATHS = frozenset(self.portal.SOC_SETTINGS_PROMPT_FILES)
        self.memory_dir = Path(self.tmp.name) / "agent-memory"
        self.memory_dir.mkdir()
        self.portal.AGENT_MEMORY_DIR = self.memory_dir
        self.portal.SOC_ANALYST_MEMORY_FILE = self.memory_dir / "soc-analyst-memory.md"
        self.portal.SHARED_AGENT_MEMORY_FILE = self.memory_dir / "shared-agent-memory.md"
        self.portal.SOC_AI_SETTINGS_FILE = Path(self.tmp.name) / "config" / "ai_model_settings.json"


    def tearDown(self) -> None:
        self.tmp.cleanup()
