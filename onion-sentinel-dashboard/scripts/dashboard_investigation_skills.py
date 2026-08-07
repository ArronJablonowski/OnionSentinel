"""Load and render the dashboard's read-only investigation-skill catalog."""
from __future__ import annotations

import html
import importlib.util
from dataclasses import dataclass
from pathlib import Path


UNAVAILABLE_REGISTRY = {
    "schema": "onion-sentinel-investigation-skills-v1",
    "version": 0,
    "mode": "unavailable",
    "skills": [],
    "registry_sha256": "",
}


@dataclass(frozen=True)
class InvestigationSkillCatalogConfig:
    """Explicit runtime paths used to load and describe the skill registry."""

    registry_path: Path
    loader_candidates: tuple[Path, ...]
    home: Path


def unavailable_registry(error: object) -> dict:
    """Return the stable fail-closed projection used by Settings."""
    return {**UNAVAILABLE_REGISTRY, "error": str(error)}


def load_investigation_skill_registry(config: InvestigationSkillCatalogConfig) -> dict:
    """Load the registry through the same strict validator used by the harness."""
    try:
        module_path = next(path for path in config.loader_candidates if path.is_file())
        spec = importlib.util.spec_from_file_location(
            "_onion_sentinel_investigation_skills_dashboard",
            module_path,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("the investigation skill loader could not be initialized")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        registry = module.load_investigation_skills(config.registry_path)
        if not isinstance(registry, dict):
            raise ValueError("the investigation skill registry returned an invalid result")
        return registry
    except Exception as exc:
        return unavailable_registry(exc)


def _display_path(path: Path, home: Path) -> str:
    try:
        return f"~/{path.relative_to(home)}"
    except ValueError:
        return str(path)


def _text_items(values: object) -> str:
    items = values if isinstance(values, list) else []
    return "".join(f"<li>{html.escape(str(value))}</li>" for value in items)


def _chips(values: object) -> str:
    items = values if isinstance(values, list) else []
    return "".join(
        f'<span class="settings-skill-chip">{html.escape(str(value).replace("_", " "))}</span>'
        for value in items
    )


def _title(skill_id: object) -> str:
    words = str(skill_id or "").replace("-", " ").replace("_", " ").split()
    acronyms = {"dns", "http", "ssh", "tls", "pcap", "oql", "osquery"}
    return " ".join(word.upper() if word.lower() in acronyms else word.title() for word in words)


def _trigger_html(match: object) -> str:
    fields = match if isinstance(match, dict) else {}
    rows: list[str] = []
    for field, values in fields.items():
        display_values = values if isinstance(values, list) else [values]
        rows.append(
            '<span class="settings-skill-trigger">'
            f'<b>{html.escape(str(field).replace("_", " "))}</b> '
            f'{html.escape(", ".join(str(value) for value in display_values))}'
            "</span>"
        )
    return "".join(rows) or "<span>None recorded</span>"


def _pivot_html(raw_pivots: object) -> str:
    source = raw_pivots if isinstance(raw_pivots, list) else []
    rows: list[str] = []
    for index, pivot in enumerate(source, start=1):
        if not isinstance(pivot, dict):
            continue
        required = pivot.get("required") is True
        requirement = "required" if required else "advisory"
        label = "Required" if required else "Advisory"
        rows.append(
            '<li class="settings-skill-pivot">'
            f'<span class="settings-skill-step">{index}</span>'
            '<span class="settings-skill-pivot-copy">'
            f'<strong>{html.escape(str(pivot.get("step") or "Unnamed step"))}</strong>'
            '<span class="settings-skill-pivot-meta">'
            f'{html.escape(str(pivot.get("backend") or "unknown"))} · '
            f'{html.escape(str(pivot.get("pack") or "unknown"))} · '
            f'{html.escape(str(pivot.get("purpose") or "unknown").replace("_", " "))}'
            "</span>"
            f'<p>{html.escape(str(pivot.get("discriminator") or "No discriminator recorded."))}</p>'
            "</span>"
            f'<span class="settings-skill-requirement {requirement}">{label}</span>'
            "</li>"
        )
    return "".join(rows)


def _skill_grid(skill: dict) -> str:
    sections = (
        ("Alternative hypotheses", "alternative_hypotheses"),
        ("Stop conditions", "stop_conditions"),
        ("Confidence limiters", "confidence_limiters"),
        ("Known false-positive patterns", "known_false_positive_patterns"),
        ("Verification rules", "verification"),
    )
    return "".join(
        f'<section class="settings-skill-block"><h4>{heading}</h4>'
        f'<ul>{_text_items(skill.get(key))}</ul></section>'
        for heading, key in sections
    )


def _skill_html(skill: dict, mode: str, config: InvestigationSkillCatalogConfig) -> str:
    skill_id = str(skill.get("id") or "unnamed-skill")
    objective = html.escape(str(skill.get("objective") or "No objective recorded."))
    status = html.escape(str(skill.get("status") or mode))
    version = html.escape(str(skill.get("version") or "—"))
    digest = html.escape(str(skill.get("skill_sha256") or "Unavailable"))
    source_path = html.escape(_display_path(config.registry_path, config.home))
    source_title = html.escape(str(config.registry_path), quote=True)
    return f'''
            <details class="settings-skill-details" data-investigation-skill="{html.escape(skill_id, quote=True)}">
              <summary>
                <span class="settings-skill-summary-copy">
                  <strong>{html.escape(_title(skill_id))}</strong>
                  <small>{objective}</small>
                </span>
                <span class="settings-skill-summary-meta">
                  <span class="settings-skill-status">{status}</span>
                  <span>v{version}</span>
                  <span class="settings-skill-view-label" aria-hidden="true"></span>
                </span>
              </summary>
              <div class="settings-skill-body">
                <div class="settings-skill-facts">
                  <section><span class="settings-kicker">Skill ID</span><code>{html.escape(skill_id)}</code></section>
                  <section><span class="settings-kicker">Skill source file</span><code title="{source_title}">{source_path}</code></section>
                  <section><span class="settings-kicker">Definition SHA-256</span><code title="{digest}">{digest}</code></section>
                </div>
                <section class="settings-skill-block settings-skill-objective"><h4>Objective</h4><p>{objective}</p></section>
                <section class="settings-skill-block"><h4>Deterministic trigger</h4><div class="settings-skill-trigger-list">{_trigger_html(skill.get("match"))}</div></section>
                <section class="settings-skill-block"><h4>Applicable agents</h4><div class="settings-skill-chip-list">{_chips(skill.get("roles"))}</div></section>
                <section class="settings-skill-block"><h4>Required evidence</h4><div class="settings-skill-chip-list">{_chips(skill.get("required_evidence"))}</div></section>
                <section class="settings-skill-block settings-skill-pivot-block"><h4>Repeatable evidence pivots</h4><ol class="settings-skill-pivot-list">{_pivot_html(skill.get("pivot_plan"))}</ol></section>
                <div class="settings-skill-grid">{_skill_grid(skill)}</div>
              </div>
            </details>'''


def render_investigation_skill_catalog(
    registry: object,
    config: InvestigationSkillCatalogConfig,
) -> str:
    """Render an escaped, deterministic, read-only skill catalog."""
    data = registry if isinstance(registry, dict) else {}
    skills = data.get("skills") if isinstance(data.get("skills"), list) else []
    mode = str(data.get("mode") or "unavailable")
    rows = [_skill_html(skill, mode, config) for skill in skills if isinstance(skill, dict)]
    state = f"{len(rows)} {mode}" if rows else "Unavailable"
    digest = str(data.get("registry_sha256") or "")
    registry_meta = (
        f'<code title="{html.escape(digest, quote=True)}">{html.escape(digest)}</code>'
        if digest else "<span>Digest unavailable</span>"
    )
    error = str(data.get("error") or "").strip()
    error_notice = (
        '<div class="settings-skill-error" role="status">'
        f"Skills could not be loaded: {html.escape(error)}</div>"
        if error else ""
    )
    return f'''
      <section class="settings-harness-skills" aria-labelledby="onion-sentinel-skills-title">
        <div class="settings-harness-skills-heading">
          <span class="settings-harness-heading-copy">
            <span class="settings-kicker">Procedural investigation guidance</span>
            <strong id="onion-sentinel-skills-title">Harness Skills</strong>
            <small>Open a skill to inspect its deterministic trigger, evidence contract, repeatable pivots, competing hypotheses, confidence limits, and verification rules.</small>
          </span>
          <span class="settings-provider-state" id="onion-sentinel-skills-summary">{html.escape(state)}</span>
        </div>
        <div class="settings-skill-list">{"".join(rows)}</div>
        {error_notice}
        <div class="settings-skill-registry-meta"><span>Registry</span>{registry_meta}</div>
        <div class="settings-note">This catalog is read-only. Skills are versioned, digest-bound code assets. Candidate skills cannot activate themselves and still require replay evaluation, independent review, and human approval.</div>
      </section>'''
