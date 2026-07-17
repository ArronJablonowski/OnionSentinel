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


def test_enrichment_stage_is_a_fast_durable_queue_handoff():
    workflow = json.loads(WORKFLOW_PATH.read_text())
    code = _node_code(workflow, "Enrich Alert")

    assert "enrichment_status: 'queued_by_alert_store'" in code
    assert "http.request" not in code
    assert "public APIs" in code


def test_post_commit_path_is_the_only_markdown_writer_path():
    workflow = json.loads(WORKFLOW_PATH.read_text())
    connections = workflow["connections"]

    assert connections["Route Report Decision"]["main"][0][0]["node"] == (
        "Acknowledge Durable Alert Commit"
    )
    assert connections["Committed Alert Webhook"]["main"][0][0]["node"] == (
        "Validate Committed Alert"
    )
    assert connections["Validate Committed Alert"]["main"][0][0]["node"] == (
        "Write SOC Markdown Report"
    )


def test_post_commit_validation_and_report_write_are_replay_safe():
    workflow = json.loads(WORKFLOW_PATH.read_text())
    validate = _node_code(workflow, "Validate Committed Alert")
    writer = _node_code(workflow, "Write SOC Markdown Report")

    assert "RELAY_WEBHOOK_TOKEN" in validate
    assert "missing report_job_id" in validate
    assert "missing committed_at" in validate
    assert "stableReportPart" in writer
    assert "item.committed_at" in writer
    assert "fs.renameSync(temporaryPath, fullPath)" in writer
