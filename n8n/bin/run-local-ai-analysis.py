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
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from agent_memory import normalize_memory_candidates, persist_memory_candidates


HOME = Path.home()
DEFAULT_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_OUT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_LLM_LOG_DIR = HOME / "n8n-local" / "soc-alerts" / "llm-analysis-logs"
DEFAULT_LLM_LOG_FILE = DEFAULT_LLM_LOG_DIR / "llm-analysis-log.jsonl"
DEFAULT_LLM_CURRENT_FILE = DEFAULT_LLM_LOG_DIR / "current-analysis.json"
DEFAULT_ANALYSIS_INDEX_QUEUE_DIR = DEFAULT_LLM_LOG_DIR / "analysis-index-pending"
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
    "detection_outcome",
    "bluf",
    "summary",
    "likely_meaning",
    "severity_reasoning",
    "alert_frequency_assessment",
    "public_enrichment_findings",
    "pcap_analysis_findings",
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
    "correlation_assessment",
    "memory_candidates",
}
DEFAULT_RESPONSE_VALUES = {
    "detection_outcome": "Inconclusive",
    "bluf": "Inconclusive - Needs More Data: The local model did not provide a BLUF classification.",
    "alert_frequency_assessment": "The local model did not explicitly assess alert frequency.",
    "public_enrichment_findings": [],
    "pcap_analysis_findings": [],
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
    "correlation_assessment": {
        "correlation_found": False,
        "confidence": "low",
        "related_groups": [],
        "shared_evidence": [],
        "contradicting_evidence": [],
        "attack_chain_hypothesis": "No supported cross-alert correlation was identified.",
        "recommended_pivots": [],
    },
    "memory_candidates": [],
}
LIST_KEYS = {
    "false_positive_possibilities",
    "public_enrichment_findings",
    "pcap_analysis_findings",
    "recommended_next_steps",
    "evidence_used",
    "evidence_gaps",
    "recommended_tuning_actions",
}
CONFIDENCE_VALUES = {"low", "medium", "high"}
TUNING_VALUES = {"none", "suppress", "drop", "raise_score", "lower_score", "needs_more_data"}
DETECTION_OUTCOME_VALUES = {
    "true_positive_malicious",
    "true_positive_suspicious",
    "true_positive_authorized_benign",
    "false_positive_logic_rule",
    "false_positive_data_parser",
    "false_positive_bad_intel_ioc",
    "duplicate",
    "informational_no_action",
    "inconclusive",
}


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
    parser.add_argument("--timeout", type=int, default=600, help="Ollama request timeout in seconds")
    parser.add_argument(
        "--max-predict-tokens",
        type=int,
        default=4096,
        help="Maximum output tokens for one bounded local analysis",
    )
    parser.add_argument("--temperature", type=float, default=0.1, help="Low temperature keeps SOC analysis repeatable")
    parser.add_argument("--response-json", type=Path, help="Use an existing model response JSON instead of calling Ollama")
    parser.add_argument("--generate-prompt", action="store_true", help="Generate a fresh prompt package before analysis")
    parser.add_argument("--levels", default="critical,high,medium,low,informational", help="Levels passed to prompt generation")
    parser.add_argument("--hours", type=int, default=24, help="Lookback hours passed to prompt generation")
    parser.add_argument("--related-limit", type=int, default=8, help="Related alert limit passed to prompt generation")
    parser.add_argument("--correlation-limit", type=int, default=8, help="Correlation candidate limit passed to prompt generation")
    parser.add_argument("--correlation-min-score", type=int, default=15, help="Minimum deterministic correlation score")
    parser.add_argument("--alert-store-url", default=os.environ.get("ALERT_STORE_URL", "http://127.0.0.1:8787"), help="Alert-store URL for durable analysis indexing")
    parser.add_argument("--stdout", action="store_true", help="Print paths and response JSON after writing files")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.max_predict_tokens <= 0:
        parser.error("--max-predict-tokens must be positive")
    if args.correlation_limit <= 0:
        parser.error("--correlation-limit must be positive")
    if args.correlation_min_score < 0 or args.correlation_min_score > 100:
        parser.error("--correlation-min-score must be between 0 and 100")
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


def prompt_alert_summary(prompt_package: dict[str, Any]) -> dict[str, Any]:
    """Return bounded alert metadata suitable for an operational LLM run log."""
    alert = prompt_package.get("alert") if isinstance(prompt_package.get("alert"), dict) else {}
    grouped = prompt_package.get("grouped_alert_context") if isinstance(prompt_package.get("grouped_alert_context"), dict) else {}
    timeline = grouped.get("timeline") if isinstance(grouped.get("timeline"), list) else []
    alert_ids: list[str] = []
    for item in timeline[:25]:
        if isinstance(item, dict) and item.get("alert_id"):
            alert_ids.append(str(item.get("alert_id")))
    primary_alert_id = str(alert.get("alert_id") or "").strip()
    if primary_alert_id and primary_alert_id not in alert_ids:
        alert_ids.insert(0, primary_alert_id)
    alert_count = grouped.get("raw_alert_rows") or grouped.get("total_observations") or alert.get("seen_count") or len(alert_ids) or 1
    try:
        alert_count = max(1, int(alert_count))
    except (TypeError, ValueError):
        alert_count = 1
    return {
        "primary_alert_id": primary_alert_id,
        "alert_ids": alert_ids,
        "alert_ids_truncated": max(0, len(timeline) - len(alert_ids)),
        "alert_count": alert_count,
        "rule_name": str(alert.get("rule_name") or "Security Onion Alert"),
        "triage_level": str(alert.get("triage_level") or "unknown"),
        "triage_score": alert.get("triage_score"),
        "source_ip": str(alert.get("source_ip") or ""),
        "destination_ip": str(alert.get("destination_ip") or ""),
        "destination_port": str(alert.get("destination_port") or ""),
        "first_seen": str(grouped.get("first_seen") or alert.get("first_seen") or ""),
        "last_seen": str(grouped.get("last_seen") or alert.get("last_seen") or ""),
        "total_observations": grouped.get("total_observations", alert.get("seen_count")),
    }


def prompt_pcap_size_bytes(prompt_package: dict[str, Any]) -> int:
    pcap_evidence = prompt_package.get("pcap_evidence") if isinstance(prompt_package.get("pcap_evidence"), dict) else {}
    parsed = pcap_evidence.get("parsed_evidence") if isinstance(pcap_evidence.get("parsed_evidence"), list) else []
    total = 0
    seen: set[tuple[str, str]] = set()
    for record in parsed:
        if not isinstance(record, dict):
            continue
        request_id = str(record.get("request_id") or "")
        files = record.get("pcap_files") if isinstance(record.get("pcap_files"), list) else []
        for item in files:
            if not isinstance(item, dict):
                continue
            key = (request_id, str(item.get("sha256") or item.get("name") or ""))
            if key in seen:
                continue
            seen.add(key)
            try:
                total += max(0, int(item.get("size_bytes") or 0))
            except (TypeError, ValueError):
                continue
    return total


def prompt_alert_context_size_bytes(prompt_package: dict[str, Any]) -> int:
    context = {
        "alert": prompt_package.get("alert"),
        "grouped_alert_context": prompt_package.get("grouped_alert_context"),
        "public_enrichment": prompt_package.get("public_enrichment"),
        "analyst_state": prompt_package.get("analyst_state"),
        "pcap_evidence": prompt_package.get("pcap_evidence"),
    }
    return len(json.dumps(context, sort_keys=True, default=str).encode("utf-8"))


def parse_gpu_temperature(output: str) -> float | None:
    """Extract a GPU temperature from common macOS sensor command output."""
    matches = re.findall(r"(?im)\bgpu\b[^\n:]*[:=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(?:°\s*)?c\b", output)
    if not matches:
        matches = re.findall(r"(?im)\bgpu\b.*?([0-9]+(?:\.[0-9]+)?)\s*(?:°\s*)?c\b", output)
    if not matches:
        return None
    values = [float(value) for value in matches]
    return max(values) if values else None


def mactop_command() -> list[str] | None:
    custom = os.environ.get("SOC_MACTOP_COMMAND", "").strip()
    if custom:
        return shlex.split(custom)
    for path in (
        "/opt/homebrew/bin/mactop",
        "/usr/local/bin/mactop",
        "mactop",
    ):
        if path.startswith("/") and not Path(path).exists():
            continue
        return [path]
    return None


def parse_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def parse_mactop_sample(
    output: str,
) -> tuple[
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
]:
    """Return max-relevant system metrics from mactop JSON for one sample."""
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return None, None, None, None, None, None, None
    sample = payload[0] if isinstance(payload, list) and payload else payload
    if not isinstance(sample, dict):
        return None, None, None, None, None, None, None
    soc_metrics = sample.get("soc_metrics") if isinstance(sample.get("soc_metrics"), dict) else {}
    gpu_metrics = sample.get("gpu_metrics") if isinstance(sample.get("gpu_metrics"), dict) else {}
    gpu_temp_value = parse_float(soc_metrics.get("gpu_temp"))
    gpu_percent = parse_float(gpu_metrics.get("active_percent"))
    if gpu_percent is None:
        gpu_percent = parse_float(sample.get("gpu_usage"))
    if gpu_percent is None:
        gpu_percent = parse_float(soc_metrics.get("gpu_active"))
    cpu_temp_value = parse_float(soc_metrics.get("cpu_temp"))
    soc_temp_value = parse_float(soc_metrics.get("soc_temp"))
    power_watts = parse_float(soc_metrics.get("total_power"))
    if power_watts is None:
        power_watts = parse_float(soc_metrics.get("system_power"))
    cpu_percent = parse_float(sample.get("cpu_usage"))

    memory = sample.get("memory") if isinstance(sample.get("memory"), dict) else {}
    used = memory.get("used")
    total = memory.get("total")
    try:
        memory_percent = (float(used) / float(total)) * 100 if used is not None and total else None
    except (TypeError, ValueError, ZeroDivisionError):
        memory_percent = None
    return gpu_temp_value, memory_percent, power_watts, cpu_percent, gpu_percent, cpu_temp_value, soc_temp_value


def read_mactop_system_sample() -> tuple[
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    str,
]:
    command = mactop_command()
    if not command:
        return None, None, None, None, None, None, None, "mactop not found"
    try:
        proc = subprocess.run(
            [*command, "--headless", "--format", "json", "--count", "1"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
        )
    except FileNotFoundError:
        return None, None, None, None, None, None, None, f"{command[0]} not found"
    except subprocess.TimeoutExpired:
        return None, None, None, None, None, None, None, f"{command[0]} timed out"
    except Exception as exc:
        return None, None, None, None, None, None, None, f"{command[0]} failed: {exc}"
    if proc.returncode != 0 and not proc.stdout.strip():
        detail = (proc.stderr or "").strip().splitlines()
        return None, None, None, None, None, None, None, f"{command[0]} unavailable" + (f": {detail[-1][:120]}" if detail else "")
    gpu_temp, memory_percent, power_watts, cpu_percent, gpu_percent, cpu_temp, soc_temp = parse_mactop_sample(proc.stdout)
    if any(value is not None for value in (gpu_temp, memory_percent, power_watts, cpu_percent, gpu_percent, cpu_temp, soc_temp)):
        return gpu_temp, memory_percent, power_watts, cpu_percent, gpu_percent, cpu_temp, soc_temp, "mactop sampled"
    return None, None, None, None, None, None, None, f"{command[0]} returned no parseable mactop metrics"


def read_gpu_temperature_celsius() -> tuple[float | None, str]:
    """Read GPU temperature if the Mac exposes it to an unprivileged command."""
    commands: list[list[str]] = []
    custom = os.environ.get("SOC_GPU_TEMP_COMMAND", "").strip()
    if custom:
        commands.append(shlex.split(custom))
    commands.extend([
        ["powermetrics", "--samplers", "smc", "-n", "1", "-i", "500"],
        ["/usr/bin/powermetrics", "--samplers", "smc", "-n", "1", "-i", "500"],
    ])
    notes: list[str] = []
    for command in commands:
        try:
            proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4)
        except FileNotFoundError:
            notes.append(f"{command[0]} not found")
            continue
        except subprocess.TimeoutExpired:
            notes.append(f"{command[0]} timed out")
            continue
        except Exception as exc:
            notes.append(f"{command[0]} failed: {exc}")
            continue
        output = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
        value = parse_gpu_temperature(output)
        if value is not None:
            return value, "GPU temperature sampled"
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        notes.append(f"{command[0]} unavailable" + (f": {detail[-1][:120]}" if detail else ""))
    return None, "; ".join(notes[:3]) or "GPU temperature unavailable"


class SystemResourceMonitor:
    """Best-effort mactop sampler for max system metrics per run."""

    def __init__(self, interval_seconds: float = 5.0) -> None:
        self.interval_seconds = interval_seconds
        self.max_gpu_celsius: float | None = None
        self.max_memory_percent: float | None = None
        self.max_power_watts: float | None = None
        self.max_cpu_percent: float | None = None
        self.max_gpu_percent: float | None = None
        self.max_cpu_celsius: float | None = None
        self.max_soc_celsius: float | None = None
        self.note = "system metrics not sampled"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._sample_once()
        self._thread = threading.Thread(target=self._run, name="system-resource-monitor", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._stop.wait(self.interval_seconds):
                break
            self._sample_once()

    def _sample_once(self) -> None:
        gpu_value, memory_value, power_value, cpu_value, gpu_percent, cpu_temp, soc_temp, note = read_mactop_system_sample()
        if gpu_value is None:
            gpu_value, fallback_note = read_gpu_temperature_celsius()
            if gpu_value is not None:
                note = f"{note}; {fallback_note}"
        self.note = note
        if gpu_value is not None:
            self.max_gpu_celsius = gpu_value if self.max_gpu_celsius is None else max(self.max_gpu_celsius, gpu_value)
        if memory_value is not None:
            self.max_memory_percent = memory_value if self.max_memory_percent is None else max(self.max_memory_percent, memory_value)
        if power_value is not None:
            self.max_power_watts = power_value if self.max_power_watts is None else max(self.max_power_watts, power_value)
        if cpu_value is not None:
            self.max_cpu_percent = cpu_value if self.max_cpu_percent is None else max(self.max_cpu_percent, cpu_value)
        if gpu_percent is not None:
            self.max_gpu_percent = gpu_percent if self.max_gpu_percent is None else max(self.max_gpu_percent, gpu_percent)
        if cpu_temp is not None:
            self.max_cpu_celsius = cpu_temp if self.max_cpu_celsius is None else max(self.max_cpu_celsius, cpu_temp)
        if soc_temp is not None:
            self.max_soc_celsius = soc_temp if self.max_soc_celsius is None else max(self.max_soc_celsius, soc_temp)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, sort_keys=True) + "\n")


def analysis_index_payload(
    analysis_id: str,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    generated_at: str,
    artifact_path: Path,
) -> dict[str, Any]:
    alert = prompt_package.get("alert") if isinstance(prompt_package.get("alert"), dict) else {}
    correlation = prompt_package.get("correlated_alert_context")
    candidates = correlation.get("candidates", []) if isinstance(correlation, dict) else []
    evidence_hash = hashlib.sha256(
        json.dumps(prompt_package, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "analysis_id": analysis_id,
        "alert_id": alert.get("alert_id"),
        "generated_at": generated_at,
        "model": response.get("_analysis_model"),
        "model_path": response.get("_analysis_model_path"),
        "artifact_path": str(artifact_path),
        "evidence_hash": evidence_hash,
        "response": response,
        "correlation_candidates": candidates,
    }


def post_analysis_index(payload: dict[str, Any], alert_store_url: str, timeout: int = 10) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        alert_store_url.rstrip("/") + "/analysis/result",
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Onion-Sentinel-AI/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        result = json.loads(response.read().decode("utf-8", errors="replace"))
    if not result.get("ok"):
        raise RuntimeError(result.get("reason") or "alert-store rejected analysis result")


def queue_analysis_index(payload: dict[str, Any], queue_dir: Path = DEFAULT_ANALYSIS_INDEX_QUEUE_DIR) -> Path:
    path = queue_dir / f"{safe_filename(payload.get('analysis_id'))}.json"
    atomic_write_json(path, payload)
    return path


def flush_analysis_index_queue(
    alert_store_url: str,
    queue_dir: Path = DEFAULT_ANALYSIS_INDEX_QUEUE_DIR,
    limit: int = 100,
) -> tuple[int, int]:
    if not queue_dir.exists():
        return 0, 0
    completed = 0
    failed = 0
    for path in sorted(queue_dir.glob("*.json"))[:limit]:
        try:
            post_analysis_index(load_json(path), alert_store_url)
            path.unlink(missing_ok=True)
            completed += 1
        except Exception:
            failed += 1
            break
    return completed, failed


def build_llm_log_record(
    *,
    run_id: str,
    status: str,
    started_at: str,
    finished_at: str | None,
    runtime_seconds: float | None,
    prompt_path: Path | None,
    prompt_package: dict[str, Any],
    settings: dict[str, Any],
    response: dict[str, Any] | None,
    json_path: Path | None,
    md_path: Path | None,
    resource_monitor: SystemResourceMonitor,
    error: str = "",
) -> dict[str, Any]:
    alert_summary = prompt_alert_summary(prompt_package) if prompt_package else {}
    model_path = str((response or {}).get("_analysis_model_path") or settings.get("mode") or "unknown")
    model = str((response or {}).get("_analysis_model") or settings.get("ollama_model") or settings.get("cloud_model") or "unknown")
    return {
        "log_id": run_id,
        "status": status,
        "success": status == "success",
        "started_at": started_at,
        "finished_at": finished_at,
        "runtime_seconds": round(runtime_seconds, 3) if runtime_seconds is not None else None,
        "mode": str(settings.get("mode") or "unknown"),
        "model": model,
        "model_path": model_path,
        "prompt_package": str(prompt_path) if prompt_path else "",
        "analysis_json": str(json_path) if json_path else "",
        "analysis_markdown": str(md_path) if md_path else "",
        "gpu_temperature_celsius_max": resource_monitor.max_gpu_celsius,
        "gpu_utilization_percent_max": resource_monitor.max_gpu_percent,
        "cpu_temperature_celsius_max": resource_monitor.max_cpu_celsius,
        "soc_temperature_celsius_max": resource_monitor.max_soc_celsius,
        "memory_used_percent_max": resource_monitor.max_memory_percent,
        "power_watts_max": resource_monitor.max_power_watts,
        "cpu_used_percent_max": resource_monitor.max_cpu_percent,
        "system_metrics_note": resource_monitor.note,
        "gpu_temperature_note": resource_monitor.note,
        "pcap_total_size_bytes": prompt_pcap_size_bytes(prompt_package) if prompt_package else 0,
        "alert_context_size_bytes": prompt_alert_context_size_bytes(prompt_package) if prompt_package else 0,
        "error": error,
        "alert": alert_summary,
    }


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
        "--correlation-limit",
        str(args.correlation_limit),
        "--correlation-min-score",
        str(args.correlation_min_score),
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
    """Parse strict JSON, fenced JSON, or the first complete object in output.

    Local models occasionally append a second object or a short explanation.
    ``raw_decode`` accepts the first complete JSON value without broad regex
    repair, preserving the fail-closed contract for malformed evidence.
    """
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

    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", stripped):
        try:
            parsed, _ = decoder.raw_decode(stripped, match.start())
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    raise SystemExit("model output did not contain a valid JSON object")


def ollama_chat(prompt_package: dict[str, Any], args: argparse.Namespace, settings: dict[str, Any]) -> dict[str, Any]:
    """Send the bounded package to a local Ollama-compatible chat endpoint."""
    model = str(settings.get("ollama_model") or FALLBACK_OLLAMA_MODEL)
    url = str(settings.get("ollama_url") or DEFAULT_OLLAMA_URL).rstrip("/") + "/api/chat"
    system = load_system_prompt(args.system_prompt_file)
    user = {
        "task": (
            "Analyze this Security Onion alert and return JSON matching response_schema exactly. "
            "Use public_enrichment records and parsed pcap_evidence when present. "
            "Use agent_memory.role_memory and agent_memory.shared_memory when relevant, "
            "evaluate correlated_alert_context candidates without treating prior model conclusions as facts, "
            "but prefer current alert evidence if memory conflicts."
        ),
        "prompt_package": prompt_package,
    }
    body = json.dumps(
        {
            "model": model,
            "stream": False,
            # Ollama's JSON grammar prevents formatting drift from turning a
            # completed inference into a failed durable job.
            "format": "json",
            "options": {
                "temperature": args.temperature,
                "num_predict": args.max_predict_tokens,
            },
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
        "task": (
            "Analyze this Security Onion alert and return one valid JSON object matching response_schema exactly. "
            "Evaluate bounded correlated_alert_context candidates and distinguish shared facts from prior hypotheses."
        ),
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


def normalize_correlation_assessment(value: Any) -> dict[str, Any]:
    assessment = value if isinstance(value, dict) else {}
    related_groups = []
    for item in assessment.get("related_groups", []) if isinstance(assessment.get("related_groups"), list) else []:
        if isinstance(item, str):
            group_id, reason = item, ""
        elif isinstance(item, dict):
            group_id, reason = item.get("group_id"), item.get("reason")
        else:
            continue
        group_id = str(group_id or "").strip().lower()[:64]
        if group_id:
            related_groups.append({"group_id": group_id, "reason": str(reason or "")[:1000]})
    confidence = str(assessment.get("confidence") or "low").lower()
    if confidence not in CONFIDENCE_VALUES:
        confidence = "low"
    return {
        "correlation_found": bool(assessment.get("correlation_found")) and bool(related_groups),
        "confidence": confidence,
        "related_groups": related_groups[:20],
        "shared_evidence": coerce_list(assessment.get("shared_evidence"))[:20],
        "contradicting_evidence": coerce_list(assessment.get("contradicting_evidence"))[:20],
        "attack_chain_hypothesis": str(assessment.get("attack_chain_hypothesis") or "")[:4000],
        "recommended_pivots": coerce_list(assessment.get("recommended_pivots"))[:20],
    }


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
    normalized["detection_outcome"] = str(normalized["detection_outcome"])
    normalized["bluf"] = str(normalized["bluf"])
    normalized["summary"] = str(normalized["summary"])
    normalized["likely_meaning"] = str(normalized["likely_meaning"])
    normalized["severity_reasoning"] = str(normalized["severity_reasoning"])
    normalized["alert_frequency_assessment"] = str(normalized["alert_frequency_assessment"])
    normalized["tuning_reason"] = str(normalized["tuning_reason"])
    normalized["confidence"] = str(normalized["confidence"]).lower()
    normalized["tuning_recommendation"] = str(normalized["tuning_recommendation"]).lower()
    normalized["escalation_needed"] = bool(normalized["escalation_needed"])
    normalized["hosted_second_opinion_recommended"] = bool(normalized["hosted_second_opinion_recommended"])
    normalized["correlation_assessment"] = normalize_correlation_assessment(normalized.get("correlation_assessment"))
    normalized["memory_candidates"] = normalize_memory_candidates(normalized.get("memory_candidates"))

    if normalized["confidence"] not in CONFIDENCE_VALUES:
        normalized["_invalid_confidence"] = normalized["confidence"]
        normalized["confidence"] = "low"
    if normalized["tuning_recommendation"] not in TUNING_VALUES:
        normalized["_invalid_tuning_recommendation"] = normalized["tuning_recommendation"]
        normalized["tuning_recommendation"] = "needs_more_data"
    outcome_key = re.sub(r"[^a-z0-9]+", "_", normalized["detection_outcome"].strip().lower()).strip("_")
    if outcome_key not in DETECTION_OUTCOME_VALUES:
        normalized["_invalid_detection_outcome"] = normalized["detection_outcome"]
        normalized["detection_outcome"] = "Inconclusive"
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
    correlation = normalize_correlation_assessment(response.get("correlation_assessment"))
    correlation_groups = [
        f"{item['group_id']}: {item['reason'] or 'relationship requires analyst validation'}"
        for item in correlation["related_groups"]
    ]

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
        "## BLUF",
        "",
        f"- **Detection outcome:** {response['detection_outcome']}",
        f"- **Bottom line:** {response['bluf']}",
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
        "## Correlation Assessment",
        "",
        f"- **Correlation found:** {correlation['correlation_found']}",
        f"- **Confidence:** {correlation['confidence']}",
        f"- **Attack-chain hypothesis:** {correlation['attack_chain_hypothesis'] or 'n/a'}",
        "",
        "### Related Alert Groups",
        "",
        markdown_list(correlation_groups),
        "",
        "### Shared Evidence",
        "",
        markdown_list(correlation["shared_evidence"]),
        "",
        "### Contradicting Evidence",
        "",
        markdown_list(correlation["contradicting_evidence"]),
        "",
        "### Recommended Correlation Pivots",
        "",
        markdown_list(correlation["recommended_pivots"]),
        "",
        "## Public Enrichment Findings",
        "",
        markdown_list(response["public_enrichment_findings"]),
        "",
        "## PCAP Analysis Findings",
        "",
        markdown_list(response["pcap_analysis_findings"]),
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


def write_outputs(
    prompt_path: Path,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    args: argparse.Namespace,
    analysis_id: str,
) -> tuple[Path, Path, str]:
    generated_at = project_now()
    alert = prompt_package.get("alert", {})
    alert_id = safe_filename(alert.get("alert_id"))
    stamp = filename_timestamp(generated_at)
    base = f"{stamp}-{alert_id}-local-ai-analysis"
    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / f"{base}.json"
    md_path = args.out_dir / f"{base}.md"

    enriched = {
        "analysis_id": analysis_id,
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
    return json_path, md_path, generated_at


def main() -> int:
    args = parse_args()
    prompt_path: Path | None = args.prompt_package
    prompt_package: dict[str, Any] = {}
    settings: dict[str, Any] = {}
    response: dict[str, Any] | None = None
    json_path: Path | None = None
    md_path: Path | None = None
    started_at = project_now()
    started_monotonic = time.monotonic()
    run_id = hashlib.sha1(f"{started_at}:{prompt_path or ''}:{os.getpid()}".encode("utf-8")).hexdigest()[:16]
    resource_monitor = SystemResourceMonitor()
    status = "failure"
    error = ""
    monitor_started = False

    try:
        # Retry compact analysis-index submissions before spending resources on
        # another inference. A failed local API call never requires rerunning
        # the LLM because the completed result remains in this durable spool.
        flush_analysis_index_queue(args.alert_store_url)
        if args.generate_prompt:
            prompt_path = generate_prompt(args)
        if prompt_path is None:
            prompt_path = latest_prompt(args.prompt_dir)

        prompt_package = load_json(prompt_path)
        if prompt_package.get("package_type") != "soc-ai-investigation-prompt":
            raise SystemExit(f"unexpected prompt package type in {prompt_path}")

        settings = effective_ai_settings(args)
        running_record = build_llm_log_record(
            run_id=run_id,
            status="running",
            started_at=started_at,
            finished_at=None,
            runtime_seconds=None,
            prompt_path=prompt_path,
            prompt_package=prompt_package,
            settings=settings,
            response=None,
            json_path=None,
            md_path=None,
            resource_monitor=resource_monitor,
        )
        atomic_write_json(DEFAULT_LLM_CURRENT_FILE, running_record)

        resource_monitor.start()
        monitor_started = True
        if args.response_json:
            response = load_json(args.response_json)
        else:
            response = analyze_with_config(prompt_package, args)
        response = validate_response(response)
        try:
            response["_memory_writeback"] = persist_memory_candidates(
                agent_role="soc-analyst",
                role_memory_file=Path(str(prompt_package.get("agent_memory_file") or "")),
                shared_memory_file=Path(str(prompt_package.get("shared_memory_file") or "")),
                candidates=response.get("memory_candidates", []),
                analysis_id=run_id,
                source_artifact=str(prompt_path),
            )
        except Exception as exc:
            # Memory is supplemental context. A writeback failure must remain
            # visible in the artifact without discarding a completed analysis.
            response["_memory_writeback"] = {"ok": False, "error": str(exc)[:500]}
        json_path, md_path, generated_at = write_outputs(prompt_path, prompt_package, response, args, run_id)
        index_payload = analysis_index_payload(run_id, prompt_package, response, generated_at, json_path)
        try:
            post_analysis_index(index_payload, args.alert_store_url)
        except Exception as exc:
            pending_path = queue_analysis_index(index_payload)
            print(f"analysis index deferred to {pending_path}: {exc}", file=sys.stderr)
        status = "success"

        print(md_path)
        print(json_path)
        if args.stdout:
            print(json.dumps(response, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        error = str(exc) if str(exc) else f"SystemExit({exc.code})"
        raise
    except Exception as exc:
        error = str(exc)
        raise
    finally:
        if monitor_started:
            resource_monitor.stop()
        finished_at = project_now()
        runtime_seconds = time.monotonic() - started_monotonic
        if prompt_path or prompt_package:
            record = build_llm_log_record(
                run_id=run_id,
                status=status,
                started_at=started_at,
                finished_at=finished_at,
                runtime_seconds=runtime_seconds,
                prompt_path=prompt_path,
                prompt_package=prompt_package,
                settings=settings or effective_ai_settings(args),
                response=response,
                json_path=json_path,
                md_path=md_path,
                resource_monitor=resource_monitor,
                error=error,
            )
            append_jsonl(DEFAULT_LLM_LOG_FILE, record)
            atomic_write_json(DEFAULT_LLM_CURRENT_FILE, record)


if __name__ == "__main__":
    raise SystemExit(main())
