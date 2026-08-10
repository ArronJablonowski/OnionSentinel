"""Runtime prompt, model-routing, and settings helpers for the dashboard."""
from __future__ import annotations

from dashboard_builder_contract import *  # noqa: F403
from dashboard_builder_contract import (  # noqa: F401
    _normalized_codex_cli_models,
    _normalized_reasoning_effort,
)


def load_soc_analyst_prompt() -> str:
    """Read the editable SOC Analyst system prompt for the Settings page."""
    try:
        prompt = SOC_ANALYST_PROMPT_FILE.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_SOC_ANALYST_PROMPT


def load_siem_engineer_prompt() -> str:
    """Read the editable SIEM Engineer system prompt for the Settings page."""
    try:
        prompt = SIEM_ENGINEER_PROMPT_FILE.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_SIEM_ENGINEER_PROMPT


def load_threat_hunter_prompt() -> str:
    """Read the editable Threat Hunter system prompt for the Settings page."""
    try:
        prompt = THREAT_HUNTER_PROMPT_FILE.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_THREAT_HUNTER_PROMPT


def load_cyber_threat_intel_prompt() -> str:
    """Read the editable Cyber Threat Intel Analyst system prompt for the Settings page."""
    try:
        prompt = CYBER_THREAT_INTEL_PROMPT_FILE.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_CYBER_THREAT_INTEL_PROMPT


def load_incident_responder_prompt() -> str:
    """Read the editable Incident Responder system prompt for the Settings page."""
    try:
        prompt = INCIDENT_RESPONDER_PROMPT_FILE.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_INCIDENT_RESPONDER_PROMPT


def load_second_opinion_prompt(path: Path) -> str:
    """Read a role-specific independent-review prompt with a safe local fallback."""
    try:
        prompt = path.read_text(encoding='utf-8').strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_SECOND_OPINION_PROMPT


def display_path(path: Path) -> str:
    """Return a compact operator-facing path with $HOME shown as ~."""
    return str(path).replace(str(HOME), '~')


def load_soc_ai_settings() -> dict:
    """Read persisted AI model-routing settings for display."""
    return load_ai_settings(SOC_AI_SETTINGS_FILE)


def load_dashboard_investigation_skills() -> dict:
    """Load the exact normalized skill registry used by the investigation runtime."""
    return load_investigation_skill_registry(_investigation_skill_catalog_config())


def _investigation_skill_catalog_config() -> InvestigationSkillCatalogConfig:
    return InvestigationSkillCatalogConfig(
        registry_path=INVESTIGATION_SKILLS_FILE,
        loader_candidates=(
            HOME / 'n8n-local' / 'bin' / 'investigation_skills.py',
            Path(__file__).resolve().parents[2] / 'n8n' / 'bin' / 'investigation_skills.py',
        ),
        home=HOME,
    )


def investigation_skill_catalog(registry: object) -> str:
    """Render the registry as a read-only, expandable skill catalog."""
    return render_investigation_skill_catalog(
        registry,
        _investigation_skill_catalog_config(),
    )


def severity_threshold_options(selected: str) -> str:
    """Render the closed severity policy vocabulary used by the Settings API."""
    return ''.join(
        (
            f'<option value="{value}" '
            f'{"selected" if value == selected else ""}>'
            f'{SOC_ANALYSIS_SEVERITY_LABELS[value]}</option>'
        )
        for value in SOC_ANALYSIS_SEVERITY_THRESHOLDS
    )




def agent_model_control(settings: dict, role: str, label: str) -> str:
    """Render primary and optional second-opinion assignments for one agent."""
    safe_role = html.escape(role, quote=True)
    return f'''
        <div class="settings-agent-model-control">
          <div class="settings-agent-model-fields">
            <label class="settings-field" for="{safe_role}-model">Assigned model
              <select id="{safe_role}-model" data-agent-model-select data-agent-role="{safe_role}">
                {agent_model_option_rows(settings, role)}
              </select>
            </label>
            <label class="settings-field" for="{safe_role}-second-opinion-model">Second-opinion model
              <select id="{safe_role}-second-opinion-model" data-agent-second-opinion-select data-agent-role="{safe_role}">
                {agent_model_option_rows(settings, role, second_opinion=True)}
              </select>
            </label>
            <label class="settings-field" for="{safe_role}-adjudicator-model">Disagreement adjudicator
              <select id="{safe_role}-adjudicator-model" data-agent-adjudicator-select data-agent-role="{safe_role}">
                {agent_model_option_rows(settings, role, adjudicator=True)}
              </select>
            </label>
          </div>
          <button class="settings-secondary-button" type="button" data-agent-model-save="{safe_role}">Save Models</button>
          <span class="settings-save-status" data-agent-model-status="{safe_role}" role="status" aria-live="polite"></span>
          <span class="settings-agent-model-help">The optional reviewer runs independently when required. The adjudicator runs only on material disagreement and remains shadow-only: it cannot authorize closure, containment, tuning, or memory writeback.</span>
        </div>'''


def agent_prompt_editors(
    *,
    role_label: str,
    primary_id: str,
    primary_prompt: str,
    primary_endpoint: str,
    reviewer_id: str,
    reviewer_prompt: str,
    reviewer_endpoint: str,
) -> str:
    """Render ordered, independently collapsible primary and reviewer prompts."""
    safe_label = html.escape(role_label)
    return f'''
        <div class="settings-agent-prompt-list">
          <details class="settings-provider-details settings-agent-prompt-details" data-prompt-section="{primary_id}">
            <summary>
              <span class="settings-provider-summary-copy">
                <span class="settings-kicker">Primary analysis</span>
                <strong>Main system prompt</strong>
                <small>Defines the agent's first-pass reasoning and structured response.</small>
              </span>
            </summary>
            <div class="settings-provider-body">
              <label class="prompt-editor-label" for="{primary_id}">Prompt body</label>
              <textarea id="{primary_id}" class="prompt-editor" spellcheck="false">{primary_prompt}</textarea>
              <div class="settings-actions">
                <button id="save-{primary_id}" class="settings-save-button" type="button" data-prompt-save data-prompt-editor="{primary_id}" data-prompt-endpoint="{primary_endpoint}" data-prompt-status="{primary_id}-status">Save {safe_label} Prompt</button>
                <span id="{primary_id}-status" class="settings-save-status" role="status" aria-live="polite"></span>
              </div>
            </div>
          </details>
          <details class="settings-provider-details settings-agent-prompt-details" data-prompt-section="{reviewer_id}">
            <summary>
              <span class="settings-provider-summary-copy">
                <span class="settings-kicker">Independent review</span>
                <strong>Second-opinion system prompt</strong>
                <small>Reviews the same evidence without seeing the primary conclusion.</small>
              </span>
            </summary>
            <div class="settings-provider-body">
              <label class="prompt-editor-label" for="{reviewer_id}">Prompt body</label>
              <textarea id="{reviewer_id}" class="prompt-editor" spellcheck="false">{reviewer_prompt}</textarea>
              <div class="settings-actions">
                <button id="save-{reviewer_id}" class="settings-save-button" type="button" data-prompt-save data-prompt-editor="{reviewer_id}" data-prompt-endpoint="{reviewer_endpoint}" data-prompt-status="{reviewer_id}-status">Save Second-Opinion Prompt</button>
                <span id="{reviewer_id}-status" class="settings-save-status" role="status" aria-live="polite"></span>
              </div>
            </div>
          </details>
        </div>'''


def list_ollama_models() -> list[str]:
    """Return locally available Ollama model names from `ollama ls`."""
    commands = [
        ['/opt/homebrew/bin/ollama', 'ls'],
        ['/usr/local/bin/ollama', 'ls'],
        ['ollama', 'ls'],
    ]
    output = ''
    for command in commands:
        try:
            proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        except Exception:
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            output = proc.stdout
            break
    models: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith('name'):
            continue
        name = stripped.split()[0].strip()
        if name and name not in models:
            models.append(name)
    return models


def ollama_model_toggle_rows(installed_models: list[str], enabled_models: list[str]) -> str:
    """Render one accessible on/off row per installed or retained configured model."""
    models = list(installed_models)
    for enabled_model in enabled_models:
        if enabled_model not in models:
            models.append(enabled_model)
    if not models:
        return '<p class="settings-model-empty">No local Ollama models were reported.</p>'
    rows = []
    for model in models:
        escaped = html.escape(model)
        installed = model in installed_models
        checked = ' checked' if model in enabled_models else ''
        availability = 'Installed locally' if installed else 'Configured, currently unavailable'
        warning = ''
        if not installed:
            reason = 'This model is configured but is not installed locally, so Onion Sentinel cannot run it.'
            warning = (
                f'<span class="settings-model-warning" tabindex="0" role="img" '
                f'aria-label="Workflow compatibility warning: {html.escape(reason)}" '
                f'title="{html.escape(reason)}">!</span>'
            )
        rows.append(f'''
          <label class="settings-model-option" data-model-row="{escaped}" data-installed="{'true' if installed else 'false'}">
            <span class="settings-model-option-copy"><span class="settings-model-name-line"><strong>{escaped}</strong>{warning}</span><small>{availability}</small></span>
            <span class="settings-switch"><input type="checkbox" data-ollama-model-toggle value="{escaped}"{checked}><span aria-hidden="true"></span></span>
          </label>''')
    return ''.join(rows)


def codex_cli_model_rows(models: list[dict]) -> str:
    """Render the fixed Codex catalog with one enable switch per model."""
    rows = []
    normalized_models = _normalized_codex_cli_models(
        models,
        legacy_model='gpt-5.5',
        legacy_effort='medium',
        legacy_enabled=False,
    )
    for entry in normalized_models:
        model_value = str(entry.get('model') or '')
        model = html.escape(model_value, quote=True)
        effort = str(entry.get('reasoning_effort') or 'medium')
        effort_options = ''.join(
            f'<option value="{value}"{" selected" if value == effort else ""}>'
            f'{"Extra high" if value == "xhigh" else value.title()}</option>'
            for value in CODEX_CLI_REASONING_EFFORTS
        )
        checked = ' checked' if entry.get('enabled') is True else ''
        rows.append(f'''
          <div class="settings-model-option settings-codex-model-option" data-codex-cli-model-row data-codex-cli-model="{model}">
            <span class="settings-model-option-copy">
              <span class="settings-model-name-line"><strong>Codex CLI · {model}</strong></span>
              <label class="settings-codex-effort"><span>Reasoning</span>
                <select data-codex-cli-model-effort aria-label="Reasoning effort for Codex CLI {model}">{effort_options}</select>
              </label>
            </span>
            <label class="settings-switch settings-codex-switch">
              <input type="checkbox" data-codex-cli-model-enabled value="{model}" aria-label="Enable Codex CLI {model}"{checked}>
              <span aria-hidden="true"></span>
            </label>
          </div>''')
    return ''.join(rows)


def reasoning_effort_options(selected: str) -> str:
    """Render the shared bounded reasoning-effort selector vocabulary."""
    normalized = _normalized_reasoning_effort(selected)
    return ''.join(
        f'<option value="{value}"{" selected" if value == normalized else ""}>'
        f'{"Extra high" if value == "xhigh" else value.title()}</option>'
        for value in CODEX_CLI_REASONING_EFFORTS
    )


def _latest_observed_model_projection() -> dict[str, str] | None:
    """Read the newest stamped analysis provenance without consulting settings."""
    for record in load_ai_analysis_records(
        _ai_artifact_repository_config(),
        newest_first=True,
    ):
        if projection := observed_model_projection(record):
            return projection
    return None


def current_soc_analysis_model(settings: dict | None = None) -> dict[str, str]:
    """Describe the configured SOC assignment or newest observed provenance."""
    configured = settings or load_soc_ai_settings()
    if projection := assigned_model_projection(configured, 'soc-analyst'):
        return projection
    if projection := _latest_observed_model_projection():
        return projection
    fallback = os.environ.get('SOC_AI_MODEL', '').strip() or 'unassigned'
    return unassigned_model_projection(fallback)


def current_local_ai_model() -> str:
    """Compatibility helper returning the effective SOC Analyst model label."""
    return current_soc_analysis_model()['label']


def count_ai_analysis_artifacts(suffix: str) -> int:
    """Count local AI output artifacts by extension for Flow page metrics."""
    if not AI_ANALYSIS_DIR.exists():
        return 0
    return sum(1 for path in AI_ANALYSIS_DIR.glob(f'*-local-ai-analysis{suffix}') if path.is_file())


def telegram_sent_counts() -> dict[str, int]:
    """Read actual Telegram notification send counts from alert-store SQLite."""
    counts = {'critical': 0, 'high': 0}
    if not DB_PATH.exists():
        return counts
    try:
        with closing(sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True, timeout=30)) as conn:
            rows = conn.execute(
                """
                SELECT lower(coalesce(triage_level, 'unknown')) AS level,
                       sum(coalesce(sent_count, 1)) AS sent
                FROM notification_log
                WHERE channel = 'telegram'
                GROUP BY 1
                """
            ).fetchall()
    except sqlite3.Error:
        return counts
    for level, sent in rows:
        if level in counts:
            counts[level] = safe_int(sent)
    return counts




def criticality_class(label: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-') or 'informational'




def compact_text(text: str, max_len: int = 150) -> str:
    text = normalize_iso_display_text(re.sub(r'\s+', ' ', str(text or '')).strip())
    if not text:
        return ''
    sentence = re.split(r'(?<=[.!?])\s+', text, maxsplit=1)[0].strip()
    clipped = sentence if sentence else text
    return (clipped[:max_len - 1].rstrip() + '…') if len(clipped) > max_len else clipped




def _report_repository_config() -> ReportRepositoryConfig:
    return ReportRepositoryConfig(
        sources=tuple(MARKDOWN_SOURCES),
        supported_suffixes=frozenset(SUPPORTED_SUFFIXES),
        derived_directories=frozenset(DERIVED_REPORT_DIRECTORIES),
    )


def load_markdown_reports_by_alert_id() -> dict[str, tuple[Path, str, os.stat_result]]:
    """Index primary Markdown reports through the read-only repository."""
    return index_markdown_reports(_report_repository_config())


def _ai_artifact_repository_config() -> AiArtifactRepositoryConfig:
    return AiArtifactRepositoryConfig(
        analysis_dir=AI_ANALYSIS_DIR,
        prompt_dir=AI_PROMPT_DIR,
    )


def load_ai_analysis_by_alert_id() -> dict[str, dict]:
    """Index newest AI results through the artifact repository."""
    return index_ai_analysis_by_alert_id(_ai_artifact_repository_config())


def load_ai_prompts_by_alert_id() -> dict[str, dict]:
    """Index newest prompt packages through the artifact repository."""
    return index_ai_prompts_by_alert_id(_ai_artifact_repository_config())


def running_ai_prompt_alert_ids(ai_prompts_by_alert_id: dict[str, dict]) -> set[str]:
    """Resolve running prompt packages through the process-inspection boundary."""
    return inspect_running_prompt_alert_ids(
        _ai_artifact_repository_config(),
        ai_prompts_by_alert_id,
    )


def active_alert_reports(reports: list[AlertReport]) -> list[AlertReport]:
    """Return currently open grouped detections for the nav badge."""
    statuses = load_analyst_group_statuses()
    active = []
    for report in reports:
        meta = statuses.get(report.digest)
        status = str((meta or {}).get('status') or 'open').lower()
        repeat_count = safe_int((meta or {}).get('repeat_count'))
        if report.filter_status == 'suppressed':
            continue
        if status == 'suppressed':
            continue
        if status == 'acknowledged' and report.repeat_count <= repeat_count:
            continue
        active.append(report)
    return active


def active_alert_count(reports: list[AlertReport]) -> int:
    """Count currently open grouped detections for the nav badge."""
    return len(active_alert_reports(reports))


def active_alert_highest_severity_class(reports: list[AlertReport]) -> str:
    """Return the highest open grouped detection severity for the nav badge."""
    active = active_alert_reports(reports)
    if not active:
        return 'none'
    return criticality_class(max(active, key=lambda report: report.criticality_rank).criticality)
