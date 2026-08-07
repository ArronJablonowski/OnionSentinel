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
