import json
from pathlib import Path


WORKFLOW_PATH = (
    Path(__file__).resolve().parents[1]
    / "n8n"
    / "workflows"
    / "security-onion-configurable-scoring.workflow.json"
)


def _node_code(workflow, node_name):
    for node in workflow["nodes"]:
        if node["name"] == node_name:
            return node["parameters"]["jsCode"]
    raise AssertionError(f"Missing workflow node: {node_name}")


def test_store_node_uses_alert_store_timeout_with_headroom():
    workflow = json.loads(WORKFLOW_PATH.read_text())
    code = _node_code(workflow, "Store Score And Filter Alert")

    assert "timeout: 30000" in code
    assert "SQLite alert-store unavailable" not in code
    assert "const alertForStore = $json.alert || {};" in code


def test_enrichment_passthrough_marks_alert_as_enrichment_attempted():
    workflow = json.loads(WORKFLOW_PATH.read_text())
    code = _node_code(workflow, "Enrich Alert")

    assert "enrichment_status: 'error_passthrough'" in code
    assert "external_intel" in code
    assert "errors: [{source: 'alert-store'" in code
