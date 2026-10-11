from __future__ import annotations

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

class IncidentEvidenceContractTestsFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract_module()
        cls.builder = load_builder_module()
