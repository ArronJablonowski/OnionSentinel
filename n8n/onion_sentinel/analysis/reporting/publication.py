"""Path-confined planning and atomic publication of analysis artifacts."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Callable


@dataclass(frozen=True)
class OutputPublicationPlan:
    """Complete immutable content and paths for one artifact pair."""

    root: Path
    json_path: Path
    markdown_path: Path
    generated_at: str
    enriched: dict[str, Any]
    markdown: str

    @property
    def json_text(self) -> str:
        return json.dumps(self.enriched, indent=2, sort_keys=True) + "\n"


def _enriched_payload(
    prompt_path: Path, prompt_package: dict[str, Any], response: dict[str, Any],
    args: Any, analysis_id: str, generated_at: str, alert: dict[str, Any],
    saved_response_input_mode: str, default_second_opinion_prompt_file: Path,
) -> dict[str, Any]:
    return {
        "analysis_id": analysis_id,
        "analysis_type": (
            "saved-response"
            if response.get("_analysis_input_mode") == saved_response_input_mode
            else str(response.get("_analysis_model_path") or "unknown")
        ),
        "analysis_input_mode": str(
            response.get("_analysis_input_mode") or "model_execution"
        ),
        "generated_at": generated_at,
        "prompt_package": str(prompt_path),
        "alert_id": alert.get("alert_id"),
        "rule_name": alert.get("rule_name"),
        "triage_level": alert.get("triage_level"),
        "system_prompt_file": str(args.system_prompt_file),
        "second_opinion_system_prompt_file": str(
            prompt_package.get("second_opinion_system_prompt_file")
            or getattr(
                args, "second_opinion_prompt_file",
                default_second_opinion_prompt_file,
            )
        ),
        "agent_memory_file": prompt_package.get("agent_memory_file"),
        "shared_memory_file": prompt_package.get("shared_memory_file"),
        "response": response,
    }


def build_plan(
    prompt_path: Path,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    args: Any,
    analysis_id: str,
    *,
    generated_at: str,
    safe_filename: Callable[[Any], str],
    filename_timestamp: Callable[[str], str],
    render_markdown: Callable[
        [dict[str, Any], dict[str, Any], str, Path], str
    ],
    saved_response_input_mode: str,
    default_second_opinion_prompt_file: Path,
) -> OutputPublicationPlan:
    """Build one side-effect-free artifact publication plan."""
    alert = prompt_package.get("alert", {})
    alert = alert if isinstance(alert, dict) else {}
    alert_id = safe_filename(alert.get("alert_id"))
    base = f"{filename_timestamp(generated_at)}-{alert_id}-local-ai-analysis"
    root = Path(args.out_dir).expanduser()
    json_path = root / f"{base}.json"
    markdown_path = root / f"{base}.md"
    enriched = _enriched_payload(
        prompt_path, prompt_package, response, args, analysis_id, generated_at,
        alert, saved_response_input_mode, default_second_opinion_prompt_file,
    )
    return OutputPublicationPlan(
        root=root,
        json_path=json_path,
        markdown_path=markdown_path,
        generated_at=generated_at,
        enriched=enriched,
        markdown=render_markdown(
            prompt_package,
            response,
            generated_at,
            json_path,
        ),
    )


def _admit_root(root: Path) -> Path:
    if root.is_symlink():
        raise RuntimeError("analysis output directory must not be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("analysis output directory must be a regular directory")
    root.chmod(0o700)
    return root.resolve(strict=True)


def _admit_target(path: Path, root: Path) -> None:
    if path.parent.resolve(strict=True) != root:
        raise RuntimeError("analysis artifact path escaped the output directory")
    if path.name in {"", ".", ".."} or Path(path.name).name != path.name:
        raise RuntimeError("analysis artifact filename is invalid")
    if path.is_symlink():
        raise RuntimeError("analysis artifact destination must not be a symlink")
    if path.exists():
        raise FileExistsError(f"analysis artifact already exists: {path.name}")


def atomic_private_text(path: Path, content: str, *, root: Path) -> None:
    """Write one owner-only file through a same-directory atomic replacement."""
    admitted_root = _admit_root(root)
    _admit_target(path, admitted_root)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=admitted_root,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        directory_descriptor = os.open(admitted_root, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def publish(
    plan: OutputPublicationPlan,
    *,
    writer: Callable[..., None] = atomic_private_text,
) -> tuple[Path, Path, str]:
    """Publish a pair and clean this attempt's partial artifact on failure."""
    admitted_root = _admit_root(plan.root)
    for path in (plan.json_path, plan.markdown_path):
        _admit_target(path, admitted_root)
    created: list[Path] = []
    try:
        writer(plan.json_path, plan.json_text, root=admitted_root)
        created.append(plan.json_path)
        writer(plan.markdown_path, plan.markdown, root=admitted_root)
        created.append(plan.markdown_path)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    return plan.json_path, plan.markdown_path, plan.generated_at
