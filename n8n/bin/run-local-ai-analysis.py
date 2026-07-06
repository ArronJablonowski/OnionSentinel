#!/usr/bin/env python3
"""Run local AI analysis for a curated Security Onion prompt package.

This script is the bridge between deterministic alert handling and model-based
analysis. It intentionally accepts only the bounded prompt package produced by
build-ai-investigation-prompt.py, validates the model response contract, and
writes both JSON and Markdown notes into the local SOC Alerts corpus.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


HOME = Path.home()
DEFAULT_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_OUT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_SYSTEM_PROMPT_FILE = HOME / "n8n-local" / "config" / "soc_analyst_system_prompt.md"
DEFAULT_AI_SETTINGS_FILE = HOME / "n8n-local" / "config" / "ai_model_settings.json"
DEFAULT_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
DEFAULT_MODEL = os.environ.get("SOC_AI_MODEL", "")
FALLBACK_OLLAMA_MODEL = "devstral:latest"
DEFAULT_SYSTEM_PROMPT = (
    "You are a careful SOC analyst. Use only the supplied evidence. "
    "Return one valid JSON object and no prose outside JSON."
)

REQUIRED_KEYS = {
    "summary",
    "likely_meaning",
    "severity_reasoning",
    "alert_frequency_assessment",
    "false_positive_possibilities",
    "recommended_next_steps",
    "evidence_used",
    "evidence_gaps",
    "confidence",
    "escalation_needed",
    "hosted_second_opinion_recommended",
    "tuning_recommendation",
    "tuning_reason",
    "recommended_tuning_actions",
}
DEFAULT_RESPONSE_VALUES = {
    "alert_frequency_assessment": "The local model did not explicitly assess alert frequency.",
    "false_positive_possibilities": [],
    "recommended_next_steps": ["Review the raw alert, related alerts, and endpoint/network context."],
    "evidence_used": [],
    "evidence_gaps": ["The local model response did not provide this field explicitly."],
    "confidence": "low",
    "escalation_needed": False,
    "hosted_second_opinion_recommended": False,
    "tuning_recommendation": "needs_more_data",
    "tuning_reason": "The local model did not provide a tuning reason.",
    "recommended_tuning_actions": ["Review grouped alert count and disposition before changing tuning rules."],
}
LIST_KEYS = {
    "false_positive_possibilities",
    "recommended_next_steps",
    "evidence_used",
    "evidence_gaps",
    "recommended_tuning_actions",
}
CONFIDENCE_VALUES = {"low", "medium", "high"}
TUNING_VALUES = {"none", "suppress", "drop", "raise_score", "lower_score", "needs_more_data"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local AI analysis for a SOC alert prompt package")
    parser.add_argument("--prompt-package", type=Path, help="Prompt package JSON to analyze")
    parser.add_argument("--prompt-dir", type=Path, default=DEFAULT_PROMPT_DIR, help="Directory containing prompt packages")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Directory for AI analysis JSON/Markdown output")
    parser.add_argument("--ai-settings-file", type=Path, default=DEFAULT_AI_SETTINGS_FILE, help="AI model routing settings JSON")
    parser.add_argument("--analysis-mode", choices=("ollama", "cloud", "hybrid"), help="Override configured analysis mode")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Override local Ollama model name")
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL, help="Ollama base URL")
    parser.add_argument("--system-prompt-file", type=Path, default=DEFAULT_SYSTEM_PROMPT_FILE, help="Editable SOC Analyst system prompt file")
    parser.add_argument("--timeout", type=int, default=180, help="Ollama request timeout in seconds")
    parser.add_argument("--temperature", type=float, default=0.1, help="Low temperature keeps SOC analysis repeatable")
    parser.add_argument("--response-json", type=Path, help="Use an existing model response JSON instead of calling Ollama")
    parser.add_argument("--generate-prompt", action="store_true", help="Generate a fresh prompt package before analysis")
    parser.add_argument("--levels", default="critical,high,medium,low,informational", help="Levels passed to prompt generation")
    parser.add_argument("--hours", type=int, default=24, help="Lookback hours passed to prompt generation")
    parser.add_argument("--related-limit", type=int, default=8, help="Related alert limit passed to prompt generation")
    parser.add_argument("--stdout", action="store_true", help="Print paths and response JSON after writing files")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def filename_timestamp(value: str) -> str:
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:\d{2})$", value)
    if match:
        year, month, day, hour, minute, second, zone = match.groups()
        return f"{year}{month}{day}-{hour}{minute}{second}{zone.replace(':', '')}"
    return safe_filename(value)


def safe_filename(value: Any) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "alert")).strip("-")
    return (cleaned or "alert")[:120]


def latest_prompt(prompt_dir: Path) -> Path:
    files = sorted(prompt_dir.glob("*-ai-prompt.json"))
    if not files:
        raise SystemExit(f"no prompt packages found in {prompt_dir}")
    return files[-1]


def generate_prompt(args: argparse.Namespace) -> Path:
    """Call the existing prompt builder and return the newly written file path."""
    builder = Path(__file__).with_name("build-ai-investigation-prompt.py")
    if not builder.exists():
        raise SystemExit(f"prompt builder not found: {builder}")
    cmd = [
        sys.executable,
        str(builder),
        "--levels",
        args.levels,
        "--hours",
        str(args.hours),
        "--related-limit",
        str(args.related_limit),
        "--out-dir",
        str(args.prompt_dir),
    ]
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, end="")
        raise SystemExit(f"prompt builder failed with rc={proc.returncode}")
    path_text = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    prompt_path = Path(path_text)
    if not prompt_path.exists():
        raise SystemExit(f"prompt builder did not return a valid path: {path_text}")
    return prompt_path


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root must be an object: {path}")
    return value


def load_system_prompt(path: Path) -> str:
    """Read the editable SOC Analyst prompt, falling back to a safe default."""
    try:
        prompt = path.read_text(encoding="utf-8").strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_SYSTEM_PROMPT


def default_ai_settings() -> dict[str, Any]:
    """Return safe local-first AI routing defaults."""
    return {
        "mode": "ollama",
        "ollama_model": os.environ.get("SOC_AI_MODEL") or FALLBACK_OLLAMA_MODEL,
        "ollama_url": os.environ.get("OLLAMA_URL") or DEFAULT_OLLAMA_URL,
        "cloud_provider": "gpt-cli",
        "cloud_model": "",
        "cloud_command": "",
        "hybrid_policy": "cloud_for_critical_high_or_recommended",
    }


def load_ai_settings(path: Path) -> dict[str, Any]:
    """Load model routing settings written by the SOC Settings page."""
    settings = default_ai_settings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return settings
    except Exception:
        return settings
    if not isinstance(data, dict):
        return settings
    for key, value in data.items():
        if key in settings and value is not None:
            settings[key] = str(value).strip() if isinstance(value, str) else value
    if settings.get("mode") not in {"ollama", "cloud", "hybrid"}:
        settings["mode"] = "ollama"
    if settings.get("hybrid_policy") not in {"cloud_for_critical_high_or_recommended", "cloud_when_recommended_only"}:
        settings["hybrid_policy"] = "cloud_for_critical_high_or_recommended"
    settings["ollama_model"] = str(settings.get("ollama_model") or FALLBACK_OLLAMA_MODEL).strip()
    settings["ollama_url"] = str(settings.get("ollama_url") or DEFAULT_OLLAMA_URL).strip()
    return settings


def effective_ai_settings(args: argparse.Namespace) -> dict[str, Any]:
    """Merge settings file, environment defaults, and explicit CLI overrides."""
    settings = load_ai_settings(args.ai_settings_file)
    if args.analysis_mode:
        settings["mode"] = args.analysis_mode
    if args.model:
        settings["ollama_model"] = args.model
    if args.ollama_url:
        settings["ollama_url"] = args.ollama_url
    return settings


def extract_json_object(text: str) -> dict[str, Any]:
    """Parse strict JSON, fenced JSON, or the first balanced object in output."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(stripped[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError as exc:
            raise SystemExit(f"model output contained invalid JSON object: {exc}") from exc
    raise SystemExit("model output did not contain a JSON object")


def ollama_chat(prompt_package: dict[str, Any], args: argparse.Namespace, settings: dict[str, Any]) -> dict[str, Any]:
    """Send the bounded package to a local Ollama-compatible chat endpoint."""
    model = str(settings.get("ollama_model") or FALLBACK_OLLAMA_MODEL)
    url = str(settings.get("ollama_url") or DEFAULT_OLLAMA_URL).rstrip("/") + "/api/chat"
    system = load_system_prompt(args.system_prompt_file)
    user = {
        "task": (
            "Analyze this Security Onion alert and return JSON matching response_schema exactly. "
            "Use agent_memory.role_memory and agent_memory.shared_memory when relevant, but prefer current alert evidence if memory conflicts."
        ),
        "prompt_package": prompt_package,
    }
    body = json.dumps(
        {
            "model": model,
            "stream": False,
            "options": {"temperature": args.temperature},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(user, separators=(",", ":"))},
            ],
        }
    ).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise SystemExit(f"Ollama request failed at {url}: {exc}") from exc
    payload = json.loads(raw)
    content = payload.get("message", {}).get("content", "")
    if not content:
        raise SystemExit("Ollama returned no message content")
    response = extract_json_object(content)
    response["_analysis_model"] = model
    response["_analysis_model_path"] = "ollama"
    return response


def cloud_cli_chat(prompt_package: dict[str, Any], args: argparse.Namespace, settings: dict[str, Any], local_response: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a configured frontier/cloud CLI that reads JSON on stdin and returns JSON on stdout."""
    command_text = str(settings.get("cloud_command") or "").strip()
    if not command_text:
        raise SystemExit("Cloud analysis mode is selected, but no cloud_command is configured in AI model settings.")
    cloud_model = str(settings.get("cloud_model") or "").strip()
    cmd = [part.replace("{model}", cloud_model) for part in shlex.split(command_text)]
    if cloud_model and "{model}" not in command_text and "--model" not in cmd:
        cmd.extend(["--model", cloud_model])
    stdin_payload = {
        "task": "Analyze this Security Onion alert and return one valid JSON object matching response_schema exactly.",
        "system_prompt": load_system_prompt(args.system_prompt_file),
        "prompt_package": prompt_package,
        "local_response": local_response,
    }
    try:
        proc = subprocess.run(
            cmd,
            input=json.dumps(stdin_payload, separators=(",", ":")),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout,
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"Cloud analysis command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(f"Cloud analysis command timed out after {args.timeout} seconds: {' '.join(cmd)}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
        raise SystemExit(f"Cloud analysis command failed: {detail}")
    response = extract_json_object(proc.stdout)
    response["_analysis_model"] = cloud_model or str(settings.get("cloud_provider") or "cloud-cli")
    response["_analysis_model_path"] = "frontier-cloud"
    response["_analysis_provider"] = str(settings.get("cloud_provider") or "cloud-cli")
    return response


def should_run_cloud_second_opinion(prompt_package: dict[str, Any], local_response: dict[str, Any], settings: dict[str, Any]) -> bool:
    """Decide whether hybrid mode should spend a cloud/frontier analysis call."""
    if bool(local_response.get("hosted_second_opinion_recommended")):
        return True
    if str(settings.get("hybrid_policy") or "") == "cloud_when_recommended_only":
        return False
    alert = prompt_package.get("alert", {}) if isinstance(prompt_package.get("alert"), dict) else {}
    return str(alert.get("triage_level") or "").lower() in {"critical", "high"}


def analyze_with_config(prompt_package: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Analyze with configured Ollama, cloud CLI, or local-first hybrid mode."""
    settings = effective_ai_settings(args)
    mode = str(settings.get("mode") or "ollama")
    if mode == "cloud":
        return cloud_cli_chat(prompt_package, args, settings)
    if mode == "hybrid":
        local_response = validate_response(ollama_chat(prompt_package, args, settings))
        if should_run_cloud_second_opinion(prompt_package, local_response, settings):
            cloud_response = cloud_cli_chat(prompt_package, args, settings, local_response=local_response)
            cloud_response["_analysis_model_path"] = "hybrid"
            cloud_response["_local_analysis_model"] = local_response.get("_analysis_model")
            return cloud_response
        local_response["_analysis_model_path"] = "hybrid-local-only"
        return local_response
    return ollama_chat(prompt_package, args, settings)


def coerce_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value in (None, ""):
        return []
    return [str(value)]


def validate_response(response: dict[str, Any]) -> dict[str, Any]:
    """Normalize a model response without letting minor schema drift jam the queue.

    Local models occasionally omit a low-risk field such as tuning_reason. The
    dashboard still needs an artifact for every unique alert, so use explicit
    defaults for missing fields and preserve the model output that was present.
    """
    normalized = dict(response)
    missing = sorted(REQUIRED_KEYS.difference(normalized))
    for key in missing:
        normalized[key] = DEFAULT_RESPONSE_VALUES.get(key, "n/a")
    if missing:
        normalized["_schema_repair"] = {
            "missing_keys": missing,
            "repair_note": "Filled safe defaults so the alert still receives local AI analysis.",
        }
    for key in LIST_KEYS:
        normalized[key] = coerce_list(normalized.get(key))
    normalized["summary"] = str(normalized["summary"])
    normalized["likely_meaning"] = str(normalized["likely_meaning"])
    normalized["severity_reasoning"] = str(normalized["severity_reasoning"])
    normalized["alert_frequency_assessment"] = str(normalized["alert_frequency_assessment"])
    normalized["tuning_reason"] = str(normalized["tuning_reason"])
    normalized["confidence"] = str(normalized["confidence"]).lower()
    normalized["tuning_recommendation"] = str(normalized["tuning_recommendation"]).lower()
    normalized["escalation_needed"] = bool(normalized["escalation_needed"])
    normalized["hosted_second_opinion_recommended"] = bool(normalized["hosted_second_opinion_recommended"])

    if normalized["confidence"] not in CONFIDENCE_VALUES:
        normalized["_invalid_confidence"] = normalized["confidence"]
        normalized["confidence"] = "low"
    if normalized["tuning_recommendation"] not in TUNING_VALUES:
        normalized["_invalid_tuning_recommendation"] = normalized["tuning_recommendation"]
        normalized["tuning_recommendation"] = "needs_more_data"
    return normalized


def markdown_list(items: list[str]) -> str:
    if not items:
        return "- n/a"
    return "\n".join(f"- {item}" for item in items)


def render_markdown(prompt_package: dict[str, Any], response: dict[str, Any], generated_at: str, json_path: Path) -> str:
    alert = prompt_package.get("alert", {})
    policy = prompt_package.get("analysis_policy", {})
    alert_id = alert.get("alert_id", "")
    rule_name = alert.get("rule_name", "Security Onion Alert")
    level = str(alert.get("triage_level", "unknown")).lower()
    score = alert.get("triage_score", "")
    source_ip = alert.get("source_ip", "")
    destination_ip = alert.get("destination_ip", "")
    grouped_context = prompt_package.get("grouped_alert_context") if isinstance(prompt_package.get("grouped_alert_context"), dict) else {}
    total_observations = grouped_context.get("total_observations", alert.get("seen_count", ""))
    raw_alert_rows = grouped_context.get("raw_alert_rows", 1)
    first_seen = grouped_context.get("first_seen", alert.get("first_seen", ""))
    last_seen = grouped_context.get("last_seen", alert.get("last_seen", ""))

    lines = [
        "---",
        "type: soc-ai-analysis",
        f"analysis_model_path: {json.dumps(response.get('_analysis_model_path', 'ollama'))}",
        f"analysis_model: {json.dumps(response.get('_analysis_model', 'local'))}",
        f"generated_at: {json.dumps(generated_at)}",
        f"alert_id: {json.dumps(alert_id)}",
        f"triage_level: {json.dumps(level)}",
        f"triage_score: {json.dumps(score)}",
        f"source_ip: {json.dumps(source_ip)}",
        f"destination_ip: {json.dumps(destination_ip)}",
        "tags:",
        "  - security-onion",
        "  - soc-ai-analysis",
        f"  - {safe_filename(response.get('_analysis_model_path', 'ollama'))}",
        "---",
        "",
        f"# Local AI Analysis - {rule_name}",
        "",
        f"- **Generated:** {generated_at}",
        f"- **Alert ID:** {alert_id}",
        f"- **Triage:** {level} / {score}",
        f"- **Traffic:** {source_ip} -> {destination_ip}",
        f"- **Grouped observations:** {total_observations} observation(s) across {raw_alert_rows} alert row(s)",
        f"- **Grouped first/last seen:** {first_seen} -> {last_seen}",
        f"- **Hosted second opinion allowed:** {policy.get('hosted_second_opinion_allowed')}",
        f"- **Machine JSON:** `{json_path.name}`",
        "",
        "## Summary",
        "",
        response["summary"],
        "",
        "## Likely Meaning",
        "",
        response["likely_meaning"],
        "",
        "## Severity Reasoning",
        "",
        response["severity_reasoning"],
        "",
        "## Alert Frequency Assessment",
        "",
        response["alert_frequency_assessment"],
        "",
        "## False Positive Possibilities",
        "",
        markdown_list(response["false_positive_possibilities"]),
        "",
        "## Recommended Next Steps",
        "",
        markdown_list(response["recommended_next_steps"]),
        "",
        "## Evidence Used",
        "",
        markdown_list(response["evidence_used"]),
        "",
        "## Evidence Gaps",
        "",
        markdown_list(response["evidence_gaps"]),
        "",
        "## Tuning Recommendation",
        "",
        f"- **Recommendation:** {response['tuning_recommendation']}",
        f"- **Reason:** {response['tuning_reason']}",
        "",
        "### Recommended Tuning Actions",
        "",
        markdown_list(response["recommended_tuning_actions"]),
        "",
        "## Escalation",
        "",
        f"- **Confidence:** {response['confidence']}",
        f"- **Escalation needed:** {response['escalation_needed']}",
        f"- **Hosted second opinion recommended:** {response['hosted_second_opinion_recommended']}",
        "",
    ]
    return "\n".join(lines)


def write_outputs(prompt_path: Path, prompt_package: dict[str, Any], response: dict[str, Any], args: argparse.Namespace) -> tuple[Path, Path]:
    generated_at = project_now()
    alert = prompt_package.get("alert", {})
    alert_id = safe_filename(alert.get("alert_id"))
    stamp = filename_timestamp(generated_at)
    base = f"{stamp}-{alert_id}-local-ai-analysis"
    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / f"{base}.json"
    md_path = args.out_dir / f"{base}.md"

    enriched = {
        "analysis_type": str(response.get("_analysis_model_path") or "ollama"),
        "generated_at": generated_at,
        "prompt_package": str(prompt_path),
        "alert_id": alert.get("alert_id"),
        "rule_name": alert.get("rule_name"),
        "triage_level": alert.get("triage_level"),
        "system_prompt_file": str(args.system_prompt_file),
        "agent_memory_file": prompt_package.get("agent_memory_file"),
        "shared_memory_file": prompt_package.get("shared_memory_file"),
        "response": response,
    }
    json_path.write_text(json.dumps(enriched, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(prompt_package, response, generated_at, json_path), encoding="utf-8")
    return json_path, md_path


def main() -> int:
    args = parse_args()
    prompt_path = args.prompt_package
    if args.generate_prompt:
        prompt_path = generate_prompt(args)
    if prompt_path is None:
        prompt_path = latest_prompt(args.prompt_dir)

    prompt_package = load_json(prompt_path)
    if prompt_package.get("package_type") != "soc-ai-investigation-prompt":
        raise SystemExit(f"unexpected prompt package type in {prompt_path}")

    if args.response_json:
        response = load_json(args.response_json)
    else:
        response = analyze_with_config(prompt_package, args)
    response = validate_response(response)
    json_path, md_path = write_outputs(prompt_path, prompt_package, response, args)

    print(md_path)
    print(json_path)
    if args.stdout:
        print(json.dumps(response, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
