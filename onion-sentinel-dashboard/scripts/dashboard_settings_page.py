"""Pure Settings page renderers driven by runtime-composed view models."""
from __future__ import annotations

import html
from dataclasses import dataclass


@dataclass(frozen=True)
class AiProviderSettingsViewModel:
    """Normalized provider data; ``*_html`` fields are trusted owned fragments."""

    ai_path: str
    onion_sentinel_harness_state: str
    ollama_state: str
    ollama_url: str
    ollama_model_rows_html: str
    codex_state: str
    codex_path: str
    codex_model_rows_html: str
    skill_catalog_html: str
    hermes_state: str
    hermes_enabled: bool
    hermes_path: str
    hermes_model_options_html: str
    hermes_effort_options_html: str
    openclaw_state: str
    openclaw_enabled: bool
    openclaw_path: str
    openclaw_model: str
    openclaw_effort_options_html: str


@dataclass(frozen=True)
class MaxMindSettingsViewModel:
    asn_path: str
    city_path: str
    country_path: str


@dataclass(frozen=True)
class SettingsPageViewModel:
    providers: AiProviderSettingsViewModel
    maxmind: MaxMindSettingsViewModel
    soc_agent_card_html: str
    agent_cards_html: str


def render_native_harness(view: AiProviderSettingsViewModel) -> str:
    """Render Onion Sentinel-owned Ollama and Codex routes."""
    escape = html.escape
    return f'''          <section class="settings-harness-section" id="onion-sentinel-harness-settings" aria-labelledby="onion-sentinel-harness-title">
            <div class="settings-harness-heading">
              <span class="settings-harness-heading-copy">
                <span class="settings-kicker">Native investigation runtime</span>
                <strong id="onion-sentinel-harness-title">Onion Sentinel Harness</strong>
                <small>Onion Sentinel-owned model routes governed by its evidence, query, review, and audit controls.</small>
              </span>
              <span class="settings-provider-state" id="onion-sentinel-harness-summary">{escape(view.onion_sentinel_harness_state)}</span>
            </div>
            <div class="settings-provider-list settings-provider-list-nested">
              <details class="settings-provider-details" id="ollama-provider-settings">
                <summary><span class="settings-provider-summary-copy"><span class="settings-kicker">Local inference</span><strong id="ollama-settings-title">Ollama</strong><small>Installed models available for agent assignment</small></span><span class="settings-provider-state" id="ollama-enabled-summary">{escape(view.ollama_state)}</span></summary>
                <div class="settings-provider-body">
                  <div class="settings-provider-toolbar"><label class="settings-field">Ollama URL<input id="ai-ollama-url" type="text" value="{escape(view.ollama_url, quote=True)}" placeholder="http://127.0.0.1:11434"></label><button id="refresh-ollama-models" class="settings-secondary-button" type="button">Refresh models</button></div>
                  <div class="settings-model-list" id="ai-ollama-models" aria-label="Available Ollama models">{view.ollama_model_rows_html}</div>
                  <div class="settings-note">The list is refreshed from <code>ollama ls</code> every 60 seconds. Enabled models become available in each agent's single-model selector.</div>
                </div>
              </details>
              <details class="settings-provider-details" id="gpt-cli-provider-settings">
                <summary><span class="settings-provider-summary-copy"><span class="settings-kicker">CLI inference</span><strong id="gpt-cli-settings-title">Codex CLI</strong><small>Fixed, ephemeral OpenAI CLI route for agent assignment</small></span><span class="settings-provider-state" id="gpt-cli-enabled-summary">{escape(view.codex_state)}</span></summary>
                <div class="settings-provider-body">
                  <div class="settings-provider-toolbar settings-codex-toolbar"><label class="settings-field">Executable<input id="ai-codex-cli-path" type="text" value="{escape(view.codex_path, quote=True)}" placeholder="codex"></label></div>
                  <div class="settings-codex-model-list" id="ai-codex-cli-models" aria-label="Available Codex CLI models">{view.codex_model_rows_html}</div>
                  <div class="settings-note">Enable each listed Codex CLI model separately and choose its reasoning effort. Only enabled models appear in agent selectors. The adapter invokes <code>codex exec --model</code> with the selected model and reasoning override, ephemeral read-only sandbox, bounded output, and no operator-defined shell command.</div>
                </div>
              </details>
            </div>
            {view.skill_catalog_html}
          </section>'''


def render_hermes_harness(view: AiProviderSettingsViewModel) -> str:
    checked = " checked" if view.hermes_enabled else ""
    return f'''          <section class="settings-harness-section" id="hermes-harness-settings" aria-labelledby="hermes-harness-title">
            <div class="settings-harness-heading"><span class="settings-harness-heading-copy"><span class="settings-kicker">Isolated external harness</span><strong id="hermes-harness-title">Hermes Harness</strong><small>One exact, ephemeral Hermes Agent route for primary analysis or independent review.</small></span><span class="settings-provider-state" id="hermes-harness-summary">{html.escape(view.hermes_state)}</span></div>
            <div class="settings-agent-runtime-card" data-hermes-agent-settings>
              <label class="settings-provider-toggle-row" for="ai-hermes-agent-enabled"><span><strong>Hermes Agent</strong><small>Enable this harness before it can be assigned to an Onion Sentinel agent duty.</small></span><span class="settings-switch"><input id="ai-hermes-agent-enabled" type="checkbox" data-hermes-agent-enabled aria-label="Enable Hermes Agent"{checked}><span aria-hidden="true"></span></span></label>
              <div class="settings-grid settings-runtime-grid">
                <label class="settings-field">Executable<input id="ai-hermes-agent-path" type="text" value="{html.escape(view.hermes_path, quote=True)}" placeholder="hermes"></label>
                <label class="settings-field">Model<select id="ai-hermes-agent-model">{view.hermes_model_options_html}</select></label>
                <label class="settings-field">Reasoning<select id="ai-hermes-agent-reasoning-effort" disabled>{view.hermes_effort_options_html}</select></label>
              </div>
            </div>
            <div class="settings-note">Hermes remains isolated from direct Security Onion credentials, unrestricted tools, persistent skills, and operator profile state. Onion Sentinel supplies the bounded investigation package.</div>
          </section>'''


def render_openclaw_harness(view: AiProviderSettingsViewModel) -> str:
    checked = " checked" if view.openclaw_enabled else ""
    return f'''          <section class="settings-harness-section" id="openclaw-harness-settings" aria-labelledby="openclaw-harness-title">
            <div class="settings-harness-heading"><span class="settings-harness-heading-copy"><span class="settings-kicker">Isolated external harness</span><strong id="openclaw-harness-title">OpenClaw Harness</strong><small>One isolated, explicit Ollama route for primary analysis or independent review.</small></span><span class="settings-provider-state" id="openclaw-harness-summary">{html.escape(view.openclaw_state)}</span></div>
            <div class="settings-agent-runtime-card" data-openclaw-settings>
              <label class="settings-provider-toggle-row" for="ai-openclaw-enabled"><span><strong>OpenClaw</strong><small>Uses this Mac's GPU and memory through its admitted loopback Ollama route.</small></span><span class="settings-switch"><input id="ai-openclaw-enabled" type="checkbox" data-openclaw-enabled aria-label="Enable OpenClaw"{checked}><span aria-hidden="true"></span></span></label>
              <div class="settings-grid settings-runtime-grid">
                <label class="settings-field">Executable<input id="ai-openclaw-path" type="text" value="{html.escape(view.openclaw_path, quote=True)}" placeholder="openclaw"></label>
                <label class="settings-field">Model (ollama/model)<input id="ai-openclaw-model" type="text" value="{html.escape(view.openclaw_model, quote=True)}" placeholder="ollama/gemma4:26b-mlx"></label>
                <label class="settings-field">Reasoning<select id="ai-openclaw-reasoning-effort">{view.openclaw_effort_options_html}</select></label>
              </div>
            </div>
            <div class="settings-note">OpenClaw remains an isolated harness boundary and accepts only the configured <code>ollama/&lt;model&gt;</code> route on the loopback Ollama endpoint.</div>
          </section>'''


def render_ai_provider_panel(view: AiProviderSettingsViewModel) -> str:
    """Render the complete model-routing panel from normalized provider data."""
    return f'''      <details class="settings-panel settings-details settings-model-details" aria-labelledby="soc-ai-model-title">
        <summary><span class="settings-summary-main"><span class="settings-summary-icon" aria-hidden="true"><img src="assets/settings-ai-model-routing.png" alt=""></span><span class="settings-summary-copy"><span class="settings-kicker">AI model routing</span><strong id="soc-ai-model-title">AI Analysis Model Selection</strong></span></span><code>{html.escape(view.ai_path)}</code></summary>
        <div class="settings-panel-top"><div><p>Enable the models available to Onion Sentinel, then assign exactly one enabled model to each Cyber Security Agent below.</p></div></div>
        <div class="settings-harness-list">
{render_native_harness(view)}
{render_hermes_harness(view)}
{render_openclaw_harness(view)}
        </div>
        <div class="settings-actions"><button id="save-ai-model-settings" class="settings-save-button" type="button">Save Model Settings</button><span id="ai-model-settings-status" class="settings-save-status" role="status" aria-live="polite"></span></div>
      </details>'''


def render_maxmind_database(kind: str, title: str, purpose: str, path: str) -> str:
    database_id = html.escape(kind, quote=True)
    return f'''            <section class="settings-maxmind-database" aria-labelledby="maxmind-{database_id}-title">
              <span class="settings-kicker">GeoLite {html.escape(title)}</span><h3 id="maxmind-{database_id}-title">{html.escape(purpose)}</h3>
              <label class="settings-field">Database path<input id="maxmind-geoip-{database_id}-db-path" type="text" value="{html.escape(path, quote=True)}" placeholder="~/n8n-local/config/maxmind/GeoLite2-{html.escape(title, quote=True)}.mmdb" spellcheck="false"></label>
              <p class="settings-maxmind-status">Status: <strong id="maxmind-geoip-{database_id}-db-state">Checking configured database...</strong></p>
            </section>'''


def render_maxmind_panel(view: MaxMindSettingsViewModel) -> str:
    databases = "\n".join((
        render_maxmind_database("asn", "ASN", "Network ownership", view.asn_path),
        render_maxmind_database("city", "City", "Approximate locality", view.city_path),
        render_maxmind_database("country", "Country", "Country context", view.country_path),
    ))
    return f'''      <section class="settings-maxmind-section" aria-labelledby="maxmind-geoip-title">
        <div class="settings-agent-heading"><span class="settings-kicker">Offline IP context</span><h2 id="maxmind-geoip-title">MaxMind GeoIP Databases</h2></div>
        <section class="settings-panel settings-maxmind-panel" aria-label="MaxMind GeoIP database paths">
          <div class="settings-panel-top"><div><span class="settings-kicker">Runtime-only databases</span><h2>Configure MaxMind GeoIP</h2><p>Configure independent local GeoLite ASN, City, and Country databases. Onion Sentinel only looks up globally routable IPs and never sends these lookups to a network service.</p></div></div>
          <div class="settings-maxmind-database-grid">{databases}</div>
          <div class="settings-note">The MMDB files remain on the Mac Studio, are excluded from Git, and are treated as replaceable runtime data. GeoIP is contextual evidence rather than proof of endpoint ownership or user location.</div>
          <div class="settings-actions"><button id="save-maxmind-geoip-settings" class="settings-save-button" type="button">Save MaxMind Paths</button><span id="maxmind-geoip-settings-status" class="settings-save-status" role="status" aria-live="polite"></span></div>
        </section>
      </section>'''


def render_memory_modal() -> str:
    return '''      <div id="settings-memory-modal" class="settings-memory-modal" hidden>
        <button class="settings-memory-backdrop" type="button" data-memory-close aria-label="Close memory viewer"></button>
        <section class="settings-memory-dialog" role="dialog" aria-modal="true" aria-labelledby="settings-memory-title" tabindex="-1">
          <header class="settings-memory-header"><div><span class="settings-kicker">Read-only memory</span><h2 id="settings-memory-title">Agent Memory</h2></div><button class="settings-memory-close" type="button" data-memory-close aria-label="Close memory viewer" title="Close">×</button></header>
          <div class="settings-memory-meta"><code id="settings-memory-path"></code><span id="settings-memory-stats"></span></div>
          <p id="settings-memory-status" class="settings-memory-status" role="status" aria-live="polite">Select a memory file to view it.</p>
          <pre id="settings-memory-content" class="settings-memory-content" tabindex="0" aria-label="Read-only agent memory content"></pre>
        </section>
      </div>'''


def render_settings_page(view: SettingsPageViewModel) -> str:
    """Render the complete Settings view without filesystem or config access."""
    return f'''    <section class="view-section active settings-view" aria-label="SOC workflow settings">
{render_ai_provider_panel(view.providers)}
      <section class="settings-agent-section" aria-labelledby="cyber-security-agents-title">
        <div class="settings-agent-heading"><span class="settings-kicker">Agent prompts</span><h2 id="cyber-security-agents-title">Cyber Security Agents</h2></div>
{view.soc_agent_card_html.rstrip()}
{view.agent_cards_html.rstrip()}
      </section>
{render_maxmind_panel(view.maxmind)}
{render_memory_modal()}
    </section>'''
