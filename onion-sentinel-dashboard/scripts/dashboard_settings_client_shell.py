"""DOM, prompt, memory, and provider-summary Settings client fragment."""
from __future__ import annotations


SETTINGS_CLIENT_SHELL = '''
<script>
(() => {
  const promptConfigurations = [...document.querySelectorAll('[data-prompt-save]')].map(button => ({
    button,
    editor: document.getElementById(button.dataset.promptEditor || ''),
    endpoint: button.dataset.promptEndpoint || '',
    status: document.getElementById(button.dataset.promptStatus || '')
  })).filter(config => config.editor && config.endpoint && config.status);
  const ollamaModels = document.querySelector('#ai-ollama-models');
  const ollamaUrl = document.querySelector('#ai-ollama-url');
  const refreshOllamaButton = document.querySelector('#refresh-ollama-models');
  const onionSentinelHarnessSummary = document.querySelector('#onion-sentinel-harness-summary');
  const ollamaEnabledSummary = document.querySelector('#ollama-enabled-summary');
  const gptCliEnabledSummary = document.querySelector('#gpt-cli-enabled-summary');
  const hermesHarnessSummary = document.querySelector('#hermes-harness-summary');
  const openclawHarnessSummary = document.querySelector('#openclaw-harness-summary');
  const codexCliPath = document.querySelector('#ai-codex-cli-path');
  const codexCliModels = document.querySelector('#ai-codex-cli-models');
  const codexCliCatalog = ['gpt-5.5', 'gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna'];
  const hermesAgentEnabled = document.querySelector('#ai-hermes-agent-enabled');
  const hermesAgentPath = document.querySelector('#ai-hermes-agent-path');
  const hermesAgentModel = document.querySelector('#ai-hermes-agent-model');
  const hermesAgentReasoningEffort = document.querySelector('#ai-hermes-agent-reasoning-effort');
  const openclawEnabled = document.querySelector('#ai-openclaw-enabled');
  const openclawPath = document.querySelector('#ai-openclaw-path');
  const openclawModel = document.querySelector('#ai-openclaw-model');
  const openclawReasoningEffort = document.querySelector('#ai-openclaw-reasoning-effort');
  const socAnalysisMinSeverity = document.querySelector('#soc-analyst-analysis-min-severity');
  const socPcapMinSeverity = document.querySelector('#soc-analyst-pcap-min-severity');
  const socIncidentMinSeverity = document.querySelector('#soc-analyst-incident-min-severity');
  const pcapCaptureLossThreshold = document.querySelector('#pcap-capture-loss-threshold-percent');
  const saveSocPolicyButton = document.querySelector('#save-soc-analyst-policy');
  const socPolicyStatus = document.querySelector('#soc-analyst-policy-status');
  const socPolicyLabels = [...document.querySelectorAll('[data-soc-policy-label]')];
  const maxmindGeoIpPaths = {
    asn: document.querySelector('#maxmind-geoip-asn-db-path'),
    city: document.querySelector('#maxmind-geoip-city-db-path'),
    country: document.querySelector('#maxmind-geoip-country-db-path')
  };
  const maxmindGeoIpStates = {
    asn: document.querySelector('#maxmind-geoip-asn-db-state'),
    city: document.querySelector('#maxmind-geoip-city-db-state'),
    country: document.querySelector('#maxmind-geoip-country-db-state')
  };
  const maxmindGeoIpDefaults = {
    asn: '~/n8n-local/config/maxmind/GeoLite2-ASN.mmdb',
    city: '~/n8n-local/config/maxmind/GeoLite2-City.mmdb',
    country: '~/n8n-local/config/maxmind/GeoLite2-Country.mmdb'
  };
  const agentModelLabels = [...document.querySelectorAll('[data-agent-model]')];
  const agentSecondOpinionModelLabels = [...document.querySelectorAll('[data-agent-second-opinion-model]')];
  const agentAdjudicatorModelLabels = [...document.querySelectorAll('[data-agent-adjudicator-model]')];
  const agentModelSelects = [...document.querySelectorAll('[data-agent-model-select]')];
  const agentSecondOpinionSelects = [...document.querySelectorAll('[data-agent-second-opinion-select]')];
  const agentAdjudicatorSelects = [...document.querySelectorAll('[data-agent-adjudicator-select]')];
  const agentModelSaveButtons = [...document.querySelectorAll('[data-agent-model-save]')];
  const saveAiButton = document.querySelector('#save-ai-model-settings');
  const aiStatus = document.querySelector('#ai-model-settings-status');
  const saveMaxmindButton = document.querySelector('#save-maxmind-geoip-settings');
  const maxmindStatus = document.querySelector('#maxmind-geoip-settings-status');
  const memoryModal = document.querySelector('#settings-memory-modal');
  const memoryDialog = memoryModal?.querySelector('.settings-memory-dialog');
  const memoryTitle = document.querySelector('#settings-memory-title');
  const memoryPath = document.querySelector('#settings-memory-path');
  const memoryStats = document.querySelector('#settings-memory-stats');
  const memoryStatus = document.querySelector('#settings-memory-status');
  const memoryContent = document.querySelector('#settings-memory-content');
  const memoryLabels = {
    'soc-analyst': 'SOC Analyst Memory',
    'incident-responder': 'Incident Responder Memory',
    'siem-engineer': 'SIEM Engineer Memory',
    'cyber-threat-intel': 'Cyber Threat Intel Memory',
    'threat-hunter': 'Threat Hunter Memory',
    'shared': 'Shared Agent Memory'
  };
  if (memoryModal) document.body.appendChild(memoryModal);
  let memoryReturnFocus = null;
  let modelSelectionDirty = false;
  let configuredEnabledModels = [];
  let configuredAgentModels = {};
  let configuredAgentSecondOpinionModels = {};
  let configuredAgentAdjudicatorModels = {};
  const agentRoles = ['soc-analyst', 'incident-responder', 'siem-engineer', 'cyber-threat-intel', 'threat-hunter'];
  function setPromptStatus(config, message, kind = '') {
    if (!config?.status) return;
    config.status.textContent = message;
    config.status.className = `settings-save-status ${kind}`.trim();
  }
  function setAiStatus(message, kind = '') {
    if (!aiStatus) return;
    aiStatus.textContent = message;
    aiStatus.className = `settings-save-status ${kind}`.trim();
  }
  function setMaxmindStatus(message, kind = '') {
    if (!maxmindStatus) return;
    maxmindStatus.textContent = message;
    maxmindStatus.className = `settings-save-status ${kind}`.trim();
  }
  function setSocPolicyStatus(message, kind = '') {
    if (!socPolicyStatus) return;
    socPolicyStatus.textContent = message;
    socPolicyStatus.className = `settings-save-status ${kind}`.trim();
  }
  function severityThresholdLabel(value) {
    const normalized = String(value || '').trim().toLowerCase();
    if (normalized === 'disabled') return 'Disabled';
    const labels = {
      critical: 'Critical',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      informational: 'Informational'
    };
    return labels[normalized] ? `${labels[normalized]} and higher` : 'Invalid policy';
  }
  function syncSocPolicyLabels(analysisThreshold, pcapThreshold, incidentThreshold) {
    socPolicyLabels.forEach(element => {
      const policy = element.dataset.socPolicyLabel || '';
      element.textContent = severityThresholdLabel(
        policy === 'analysis'
          ? analysisThreshold
          : policy === 'pcap' ? pcapThreshold : incidentThreshold
      );
    });
  }
  function closeMemoryViewer() {
    if (!memoryModal || memoryModal.hidden) return;
    memoryModal.hidden = true;
    document.body.classList.remove('settings-memory-open');
    memoryReturnFocus?.focus();
    memoryReturnFocus = null;
  }
  async function openMemoryViewer(memoryKey, trigger) {
    if (!memoryModal || !memoryDialog || !memoryTitle || !memoryPath || !memoryStats || !memoryStatus || !memoryContent) return;
    memoryReturnFocus = trigger;
    memoryModal.hidden = false;
    document.body.classList.add('settings-memory-open');
    memoryTitle.textContent = memoryLabels[memoryKey] || 'Agent Memory';
    memoryPath.textContent = trigger.querySelector('code')?.textContent || '';
    memoryStats.textContent = '';
    memoryStatus.textContent = 'Loading memory file...';
    memoryStatus.className = 'settings-memory-status';
    memoryContent.textContent = '';
    memoryDialog.focus();
    try {
      const response = await fetch(`/api/soc-settings/agent-memory?key=${encodeURIComponent(memoryKey)}`, {cache: 'no-store'});
      const data = await response.json().catch(() => ({}));
      memoryTitle.textContent = data.label || memoryTitle.textContent;
      memoryPath.textContent = data.path || memoryPath.textContent;
      if (Number.isFinite(Number(data.bytes))) {
        memoryStats.textContent = `${Number(data.bytes).toLocaleString()} bytes${data.modified_at ? ` · Updated ${data.modified_at}` : ''}`;
      }
      if (!response.ok || !data.ok) throw new Error(data.error || `Memory read failed with HTTP ${response.status}`);
      memoryStats.textContent = `${Number(data.bytes || 0).toLocaleString()} bytes · Updated ${data.modified_at || 'unknown'}`;
      memoryStatus.textContent = data.content ? 'Read-only view' : 'This memory file is empty.';
      memoryContent.textContent = data.content || '';
    } catch (error) {
      memoryStatus.textContent = String(error.message || error);
      memoryStatus.className = 'settings-memory-status error';
      memoryContent.textContent = '';
    }
  }
  function openPromptEditor(promptId, trigger) {
    const promptEditor = document.getElementById(promptId);
    const panel = trigger.closest('details.settings-details');
    if (!promptEditor || !panel) return;
    panel.open = true;
    const promptSection = promptEditor.closest('details[data-prompt-section]');
    if (promptSection) promptSection.open = true;
    window.requestAnimationFrame(() => {
      promptEditor.focus({preventScroll: true});
      promptEditor.scrollIntoView({
        behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
        block: 'center'
      });
    });
  }
  function normalizeModelList(value) {
    if (!Array.isArray(value)) return [];
    return value.map(model => String(model || '').trim()).filter((model, index, models) => model && models.indexOf(model) === index);
  }
  function enabledOllamaModels() {
    if (!ollamaModels) return [];
    return [...ollamaModels.querySelectorAll('[data-ollama-model-toggle]:checked')].map(input => input.value.trim()).filter(Boolean);
  }
  function normalizeCodexCliModels(value) {
    const source = Array.isArray(value) ? value : [];
    return codexCliCatalog.map(model => {
      const entry = source.find(candidate => String(candidate?.model || '').trim() === model);
      const effort = String(entry?.reasoning_effort || 'medium').trim().toLowerCase();
      return {
        model,
        reasoning_effort: ['low', 'medium', 'high', 'xhigh'].includes(effort) ? effort : 'medium',
        enabled: entry?.enabled === true
      };
    });
  }
  function currentCodexCliModels() {
    if (!codexCliModels) return normalizeCodexCliModels([]);
    return [...codexCliModels.querySelectorAll('[data-codex-cli-model-row]')].map(row => ({
      model: String(row.dataset.codexCliModel || '').trim(),
      reasoning_effort: String(row.querySelector('[data-codex-cli-model-effort]')?.value || 'medium').trim(),
      enabled: Boolean(row.querySelector('[data-codex-cli-model-enabled]')?.checked)
    }));
  }
  function renderCodexCliModels(entries) {
    if (!codexCliModels) return;
    const normalized = new Map(
      normalizeCodexCliModels(entries).map(entry => [entry.model, entry])
    );
    codexCliModels.querySelectorAll('[data-codex-cli-model-row]').forEach(row => {
      const entry = normalized.get(String(row.dataset.codexCliModel || ''));
      if (!entry) return;
      const effort = row.querySelector('[data-codex-cli-model-effort]');
      const toggle = row.querySelector('[data-codex-cli-model-enabled]');
      if (effort) effort.value = entry.reasoning_effort;
      if (toggle) toggle.checked = entry.enabled;
    });
  }
  function derivedAnalysisMode(localModels, gptEnabled) {
    if (localModels.length && gptEnabled) return 'hybrid';
    if (gptEnabled) return 'cloud';
    return 'ollama';
  }
  function updateProviderSummaries() {
    const enabledModels = enabledOllamaModels();
    const enabledCodexCount = currentCodexCliModels().filter(entry => entry.enabled).length;
    const onionSentinelCount = enabledModels.length + enabledCodexCount;
    if (onionSentinelHarnessSummary) {
      onionSentinelHarnessSummary.textContent = onionSentinelCount ? `${onionSentinelCount} enabled` : 'Disabled';
      onionSentinelHarnessSummary.classList.toggle('is-disabled', onionSentinelCount === 0);
    }
    if (ollamaEnabledSummary) {
      ollamaEnabledSummary.textContent = enabledModels.length ? `${enabledModels.length} enabled` : 'Disabled';
      ollamaEnabledSummary.classList.toggle('is-disabled', !enabledModels.length);
    }
    if (gptCliEnabledSummary) {
      gptCliEnabledSummary.textContent = enabledCodexCount ? `${enabledCodexCount} enabled` : 'Disabled';
      gptCliEnabledSummary.classList.toggle('is-disabled', enabledCodexCount === 0);
    }
    if (hermesHarnessSummary) {
      const enabled = Boolean(hermesAgentEnabled?.checked);
      hermesHarnessSummary.textContent = enabled ? 'Enabled' : 'Disabled';
      hermesHarnessSummary.classList.toggle('is-disabled', !enabled);
    }
    if (openclawHarnessSummary) {
      const enabled = Boolean(openclawEnabled?.checked);
      openclawHarnessSummary.textContent = enabled ? 'Enabled' : 'Disabled';
      openclawHarnessSummary.classList.toggle('is-disabled', !enabled);
    }
  }
'''


def settings_client_shell_fragment() -> str:
    """Return the opening Settings client and provider-summary behavior."""
    return SETTINGS_CLIENT_SHELL
