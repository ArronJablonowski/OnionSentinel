"""Pure renderer for a non-SOC Settings agent card."""
from __future__ import annotations

import html
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentSettingsCardViewModel:
    """Display data supplied by the dashboard composition root.

    Paths, labels, and notes are raw text escaped by this renderer. The two ``*_html``
    fields are trusted fragments produced by existing bounded control renderers.
    """

    role: str
    role_label: str
    kicker: str
    title: str
    trigger: str
    description: str
    icon_path: str
    prompt_path: str
    reviewer_prompt_path: str
    memory_path: str
    shared_memory_path: str
    model_label: str
    reviewer_model_label: str
    adjudicator_model_label: str
    model_control_html: str
    prompt_control_html: str
    note: str = ""


@dataclass(frozen=True)
class SocAgentSettingsCardViewModel:
    """SOC Analyst card data, including its automation-policy controls."""

    prompt_path: str
    reviewer_prompt_path: str
    memory_path: str
    shared_memory_path: str
    model_label: str
    reviewer_model_label: str
    adjudicator_model_label: str
    analysis_threshold_label: str
    pcap_threshold_label: str
    incident_threshold_label: str
    analysis_disabled: bool
    incident_disabled: bool
    analysis_threshold_options_html: str
    pcap_threshold_options_html: str
    incident_threshold_options_html: str
    model_control_html: str
    prompt_control_html: str
    capture_loss_threshold_percent: str = "5.0"


def render_agent_settings_card(view: AgentSettingsCardViewModel) -> str:
    """Render one agent card without reading runtime files or configuration."""
    escape = html.escape
    role = escape(view.role, quote=True)
    role_label = escape(view.role_label)
    title_id = f"{role}-prompt-title"
    note = f'        <div class="settings-note">{escape(view.note)}</div>\n' if view.note else ""
    return f'''      <details class="settings-panel settings-details" aria-labelledby="{title_id}">
        <summary>
          <span class="settings-summary-main">
            <span class="settings-summary-icon" aria-hidden="true"><img src="{escape(view.icon_path, quote=True)}" alt=""></span>
            <span class="settings-summary-copy">
              <span class="settings-kicker">{escape(view.kicker)}</span>
              <strong id="{title_id}">{escape(view.title)}</strong>
              <span class="settings-trigger-line">{escape(view.trigger)}</span>
              <span class="settings-model-line"><b>Model</b><span data-agent-model="{role}">{escape(view.model_label)}</span></span>
              <span class="settings-model-line settings-second-opinion-line"><b>Second opinion</b><span data-agent-second-opinion-model="{role}">{escape(view.reviewer_model_label)}</span></span>
              <span class="settings-model-line settings-adjudicator-line"><b>Adjudicator</b><span data-agent-adjudicator-model="{role}">{escape(view.adjudicator_model_label)}</span></span>
            </span>
          </span>
          <span class="settings-path-stack" aria-label="{role_label} files">
            <button class="settings-path-row settings-file-link settings-prompt-link" type="button" data-prompt-target="{role}-prompt" aria-label="Open {role_label} system prompt"><b>Prompt</b><code>{escape(view.prompt_path)}</code></button>
            <button class="settings-path-row settings-file-link settings-prompt-link" type="button" data-prompt-target="{role}-second-opinion-prompt" aria-label="Open {role_label} second-opinion prompt"><b>Review</b><code>{escape(view.reviewer_prompt_path)}</code></button>
            <button class="settings-path-row settings-memory-link" type="button" data-memory-key="{role}" aria-label="View {role_label} memory file"><b>Memory</b><code>{escape(view.memory_path)}</code></button>
            <button class="settings-path-row settings-memory-link" type="button" data-memory-key="shared" aria-label="View shared agent memory file"><b>Shared</b><code>{escape(view.shared_memory_path)}</code></button>
          </span>
        </summary>
        <div class="settings-panel-top">
          <div>
            <p>{escape(view.description)}</p>
          </div>
        </div>
        {view.model_control_html}
{note}        {view.prompt_control_html}
      </details>
'''


def render_soc_automation_policy(view: SocAgentSettingsCardViewModel) -> str:
    """Render the SOC thresholds from already normalized option fragments."""
    threshold = html.escape(view.capture_loss_threshold_percent, quote=True)
    return f'''        <section class="settings-agent-policy-control" aria-labelledby="soc-analyst-automation-title">
          <div class="settings-agent-policy-copy">
            <span class="settings-kicker">Automation thresholds</span>
            <h3 id="soc-analyst-automation-title">Evidence and escalation</h3>
            <p>The selected severity and every higher severity use the same automatic action.</p>
          </div>
          <div class="settings-grid">
            <label class="settings-field">Lowest severity for automatic AI analysis
              <select id="soc-analyst-analysis-min-severity">{view.analysis_threshold_options_html}</select>
            </label>
            <label class="settings-field">Lowest severity for automatic PCAP analysis
              <select id="soc-analyst-pcap-min-severity">{view.pcap_threshold_options_html}</select>
            </label>
            <label class="settings-field">Lowest severity for automatic incident response
              <select id="soc-analyst-incident-min-severity">{view.incident_threshold_options_html}</select>
            </label>
            <label class="settings-field">PCAP capture-loss safety threshold
              <span class="settings-number-with-unit">
                <input id="pcap-capture-loss-threshold-percent" type="number" min="0.1" max="100" step="0.1" inputmode="decimal" value="{threshold}">
                <span aria-hidden="true">%</span>
              </span>
              <small>Relay PCAP reads pause when current Zeek capture loss exceeds this value.</small>
            </label>
          </div>
          <div class="settings-actions">
            <button id="save-soc-analyst-policy" class="settings-secondary-button" type="button">Save Automation Thresholds</button>
            <span id="soc-analyst-policy-status" class="settings-save-status" role="status" aria-live="polite"></span>
          </div>
        </section>'''


def render_soc_agent_settings_card(view: SocAgentSettingsCardViewModel) -> str:
    """Render the SOC Analyst card without loading settings or runtime files."""
    escape = html.escape
    analysis_label = "Disabled" if view.analysis_disabled else f"{view.analysis_threshold_label} and higher"
    incident_label = "Disabled" if view.incident_disabled else view.incident_threshold_label
    return f'''      <details class="settings-panel settings-details" aria-labelledby="soc-analyst-prompt-title">
        <summary>
          <span class="settings-summary-main">
            <span class="settings-summary-icon" aria-hidden="true"><img src="assets/settings-soc-analyst-prompt.png" alt=""></span>
            <span class="settings-summary-copy">
              <span class="settings-kicker">SOC analyst prompt</span>
              <strong id="soc-analyst-prompt-title">SOC Analyst System Prompt</strong>
              <span class="settings-trigger-line">Trigger: new eligible alert; scheduled AI worker drains highest severity newest first.</span>
              <span class="settings-model-line"><b>Model</b><span data-agent-model="soc-analyst">{escape(view.model_label)}</span></span>
              <span class="settings-model-line settings-second-opinion-line"><b>Second opinion</b><span data-agent-second-opinion-model="soc-analyst">{escape(view.reviewer_model_label)}</span></span>
              <span class="settings-model-line settings-adjudicator-line"><b>Adjudicator</b><span data-agent-adjudicator-model="soc-analyst">{escape(view.adjudicator_model_label)}</span></span>
              <span class="settings-model-line"><b>Analysis</b><span data-soc-policy-label="analysis">{escape(analysis_label)}</span></span>
              <span class="settings-model-line"><b>PCAP</b><span data-soc-policy-label="pcap">{escape(view.pcap_threshold_label)} and higher</span></span>
              <span class="settings-model-line"><b>Incident</b><span data-soc-policy-label="incident">{escape(incident_label)}</span></span>
            </span>
          </span>
          <span class="settings-path-stack" aria-label="SOC Analyst files">
            <button class="settings-path-row settings-file-link settings-prompt-link" type="button" data-prompt-target="soc-analyst-prompt" aria-label="Open SOC Analyst system prompt"><b>Prompt</b><code>{escape(view.prompt_path)}</code></button>
            <button class="settings-path-row settings-file-link settings-prompt-link" type="button" data-prompt-target="soc-analyst-second-opinion-prompt" aria-label="Open SOC Analyst second-opinion prompt"><b>Review</b><code>{escape(view.reviewer_prompt_path)}</code></button>
            <button class="settings-path-row settings-memory-link" type="button" data-memory-key="soc-analyst" aria-label="View SOC Analyst memory file"><b>Memory</b><code>{escape(view.memory_path)}</code></button>
            <button class="settings-path-row settings-memory-link" type="button" data-memory-key="shared" aria-label="View shared agent memory file"><b>Shared</b><code>{escape(view.shared_memory_path)}</code></button>
          </span>
        </summary>
        <div class="settings-panel-top"><div><p>This prompt is sent as the system message when the assigned model analyzes Security Onion alerts.</p></div></div>
        {view.model_control_html}
{render_soc_automation_policy(view)}
        {view.prompt_control_html}
      </details>
'''
