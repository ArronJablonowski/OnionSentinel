#!/usr/bin/env python3
"""Render maintainable node source into the portable n8n workflow export."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / "n8n/workflows/security-onion-configurable-scoring.workflow.json"
CODE_DIR = REPO_ROOT / "n8n/workflows/code"

CODE_SOURCES = {
    "Validate Committed Alert": CODE_DIR / "validate-committed-alert.js",
    "Acknowledge Durable Alert Commit": CODE_DIR / "acknowledge-durable-alert.js",
    "Write SOC Markdown Report": CODE_DIR / "write-soc-markdown-report.js",
}

REQUIRED_NODES = (
    {
        "parameters": {
            "httpMethod": "POST",
            "path": "onion-sentinel-committed-alert",
            "responseMode": "lastNode",
            "options": {},
        },
        "id": "onion-sentinel-committed-alert-webhook",
        "name": "Committed Alert Webhook",
        "type": "n8n-nodes-base.webhook",
        "typeVersion": 2,
        "position": [800, 520],
        "webhookId": "onion-sentinel-committed-alert",
    },
    {
        "parameters": {"jsCode": ""},
        "id": "validate-committed-alert",
        "name": "Validate Committed Alert",
        "type": "n8n-nodes-base.code",
        "typeVersion": 2,
        "position": [1080, 520],
    },
    {
        "parameters": {"jsCode": ""},
        "id": "acknowledge-durable-alert-commit",
        "name": "Acknowledge Durable Alert Commit",
        "type": "n8n-nodes-base.code",
        "typeVersion": 2,
        "position": [1360, 360],
    },
)


def rendered_workflow() -> str:
    workflow = json.loads(WORKFLOW.read_text(encoding="utf-8"))
    nodes = {node["name"]: node for node in workflow["nodes"]}
    for required in REQUIRED_NODES:
        if required["name"] not in nodes:
            workflow["nodes"].append(required)
            nodes[required["name"]] = required
    for name, source in CODE_SOURCES.items():
        nodes[name]["parameters"]["jsCode"] = source.read_text(encoding="utf-8").rstrip()

    workflow["connections"]["Route Report Decision"] = {
        "main": [[{"node": "Acknowledge Durable Alert Commit", "type": "main", "index": 0}]]
    }
    workflow["connections"]["Committed Alert Webhook"] = {
        "main": [[{"node": "Validate Committed Alert", "type": "main", "index": 0}]]
    }
    workflow["connections"]["Validate Committed Alert"] = {
        "main": [[{"node": "Write SOC Markdown Report", "type": "main", "index": 0}]]
    }
    workflow["connections"].pop("Acknowledge Durable Alert Commit", None)
    return json.dumps(workflow, indent=2, ensure_ascii=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail when the export differs")
    args = parser.parse_args()
    rendered = rendered_workflow()
    current = WORKFLOW.read_text(encoding="utf-8")
    if args.check:
        if current != rendered:
            raise SystemExit("workflow export is out of sync; run sync-alert-intake-workflow.py")
        return 0
    WORKFLOW.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
