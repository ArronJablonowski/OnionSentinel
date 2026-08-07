"""Persistence and interaction half of the Settings page client script."""
from __future__ import annotations


SETTINGS_CLIENT_ACTIONS = '''
  async function refreshAiSettings() {
    if (!saveAiButton && !saveMaxmindButton) return;
    try {
      const response = await fetch('/api/soc-settings/ai-model', {cache: 'no-store'});
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok || !data.settings) {
        throw new Error(data.error || `Model settings refresh failed with HTTP ${response.status}`);
      }
      applyAiSettings(data.settings);
      applyGeoIpDatabaseStatuses(data.geoip_databases, data.geoip_database);
    } catch (error) {
      setAiStatus(String(error.message || error), 'error');
    }
  }
  async function refreshOllamaModels(announce = false) {
    if (!ollamaModels) return;
    const unsavedModels = enabledOllamaModels();
    if (refreshOllamaButton) refreshOllamaButton.disabled = true;
    try {
      const response = await fetch(`/api/soc-settings/ollama-models${announce ? '?refresh=1' : ''}`, {cache: 'no-store'});
      const data = await response.json();
      if (!response.ok || !data.ok || !Array.isArray(data.models)) {
        throw new Error(data.error || `Model refresh failed with HTTP ${response.status}`);
      }
      const installed = new Set(normalizeModelList(data.installed_models));
      const compatibility = data.compatibility && typeof data.compatibility === 'object' ? data.compatibility : {};
      const enabled = modelSelectionDirty ? unsavedModels : normalizeModelList(data.enabled_models || configuredEnabledModels);
      const models = normalizeModelList([...data.models, ...enabled]);
      ollamaModels.replaceChildren();
      if (!models.length) {
        const empty = document.createElement('p');
        empty.className = 'settings-model-empty';
        empty.textContent = 'No local Ollama models were reported.';
        ollamaModels.appendChild(empty);
      }
      models.forEach(model => {
        const row = document.createElement('label');
        row.className = 'settings-model-option';
        row.dataset.modelRow = model;
        row.dataset.installed = installed.has(model) ? 'true' : 'false';
        const assessment = compatibility[model];
        const warningReason = workflowCompatibilityReason(assessment);
        row.dataset.compatible = assessment?.compatible === false ? 'false' : 'true';
        const copy = document.createElement('span');
        copy.className = 'settings-model-option-copy';
        const nameLine = document.createElement('span');
        nameLine.className = 'settings-model-name-line';
        const name = document.createElement('strong');
        name.textContent = model;
        name.title = model;
        nameLine.appendChild(name);
        if (warningReason) {
          const warning = document.createElement('span');
          warning.className = 'settings-model-warning';
          warning.textContent = '!';
          warning.tabIndex = 0;
          warning.title = warningReason;
          warning.setAttribute('role', 'img');
          warning.setAttribute('aria-label', `Workflow compatibility warning: ${warningReason}`);
          warning.addEventListener('click', event => {
            event.preventDefault();
            event.stopPropagation();
          });
          nameLine.appendChild(warning);
        }
        const availability = document.createElement('small');
        availability.textContent = modelAvailabilityLabel(installed.has(model), assessment);
        copy.append(nameLine, availability);
        const toggle = document.createElement('span');
        toggle.className = 'settings-switch';
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.value = model;
        input.checked = enabled.includes(model);
        input.setAttribute('data-ollama-model-toggle', '');
        input.setAttribute('aria-label', `Enable ${model}`);
        const track = document.createElement('span');
        track.setAttribute('aria-hidden', 'true');
        toggle.append(input, track);
        row.append(copy, toggle);
        ollamaModels.appendChild(row);
      });
      configuredEnabledModels = modelSelectionDirty ? configuredEnabledModels : enabled;
      updateProviderSummaries();
      const routingSettings = currentAiSettings();
      syncAgentModelControls(
        routingSettings.agent_models,
        routingSettings.agent_second_opinion_models,
        routingSettings.agent_adjudicator_models,
        routingSettings
      );
      if (announce) setAiStatus(`Refreshed ${installed.size} installed Ollama model${installed.size === 1 ? '' : 's'}.`, 'ok');
    } catch (error) {
      setAiStatus(`Could not refresh Ollama model list: ${String(error.message || error)}`, 'error');
    } finally {
      if (refreshOllamaButton) refreshOllamaButton.disabled = false;
    }
  }
  function validateAiSettings(payload) {
    if (
      !payload.enabled_ollama_models.length
      && !payload.gpt_cli_enabled
      && !payload.hermes_agent_enabled
      && !payload.openclaw_enabled
    ) {
      return 'Enable at least one Ollama model, Codex CLI model, Hermes Agent, or OpenClaw.';
    }
    const absoluteExecutablePattern = /^\\/[A-Za-z0-9._\\/+-]+$/;
    const validExecutable = (value, basename) => (
      value === basename
      || (
        value.startsWith('/')
        && value.endsWith(`/${basename}`)
        && absoluteExecutablePattern.test(value)
        && !/[\\x00-\\x1f\\x7f]/.test(value)
      )
    );
    if (
      !validExecutable(payload.codex_cli_path, 'codex')
    ) {
      return 'Codex CLI executable must be "codex" or an absolute path ending in /codex.';
    }
    if (payload.codex_cli_models.length !== codexCliCatalog.length) {
      return 'The fixed Codex CLI model catalog is incomplete.';
    }
    const seenCodexModels = new Set();
    for (const entry of payload.codex_cli_models) {
      if (!codexCliCatalog.includes(entry.model)) {
        return 'The Codex CLI model is not in the supported catalog.';
      }
      if (!['low', 'medium', 'high', 'xhigh'].includes(entry.reasoning_effort)) {
        return 'Codex CLI reasoning effort is invalid.';
      }
      if (seenCodexModels.has(entry.model)) {
        return 'Each Codex CLI model must appear exactly once.';
      }
      seenCodexModels.add(entry.model);
    }
    const providerSettings = [
      {
        label: 'Hermes Agent',
        executable: payload.hermes_agent_path,
        basename: 'hermes',
        model: payload.hermes_agent_model,
        effort: payload.hermes_agent_reasoning_effort
      },
      {
        label: 'OpenClaw',
        executable: payload.openclaw_path,
        basename: 'openclaw',
        model: payload.openclaw_model,
        effort: payload.openclaw_reasoning_effort
      }
    ];
    for (const provider of providerSettings) {
      if (!validExecutable(provider.executable, provider.basename)) {
        return `${provider.label} executable must be "${provider.basename}" or an absolute path ending in /${provider.basename}.`;
      }
      const modelIsValid = provider.label === 'Hermes Agent'
        ? codexCliCatalog.includes(provider.model)
        : /^ollama\\/[A-Za-z0-9][A-Za-z0-9._:\\/+-]{0,232}$/.test(provider.model);
      if (!modelIsValid) {
        return provider.label === 'OpenClaw'
          ? 'OpenClaw currently supports explicit ollama/<model> routes only.'
          : `${provider.label} model is invalid.`;
      }
      if (!['low', 'medium', 'high', 'xhigh'].includes(provider.effort)) {
        return `${provider.label} reasoning effort is invalid.`;
      }
    }
    if (payload.hermes_agent_reasoning_effort !== 'medium') {
      return 'Hermes Agent reasoning effort must be medium for this installed CLI.';
    }
    const normalizedOllamaUrl = String(payload.ollama_url || '').replace(/\\/+$/, '');
    if (
      payload.openclaw_enabled
      && !['http://127.0.0.1:11434', 'http://localhost:11434']
        .includes(normalizedOllamaUrl)
    ) {
      return 'OpenClaw requires a loopback Ollama endpoint on port 11434.';
    }
    const thresholds = ['disabled', 'critical', 'high', 'medium', 'low', 'informational'];
    if (
      !thresholds.includes(payload.soc_analyst_analysis_min_severity)
      || !thresholds.includes(payload.soc_analyst_pcap_min_severity)
      || !thresholds.includes(payload.soc_analyst_incident_min_severity)
    ) {
      return 'SOC Analyst automation severity threshold is invalid.';
    }
    if (
      !Number.isFinite(payload.pcap_capture_loss_threshold_percent)
      || payload.pcap_capture_loss_threshold_percent < 0.1
      || payload.pcap_capture_loss_threshold_percent > 100
    ) {
      return 'PCAP capture-loss threshold must be between 0.1 and 100 percent.';
    }
    return '';
  }
  async function saveAiSettings() {
    if (!saveAiButton) return;
    const payload = currentAiSettings();
    const validationError = validateAiSettings(payload);
    if (validationError) {
      setAiStatus(validationError, 'error');
      return;
    }
    saveAiButton.disabled = true;
    setAiStatus('Saving...');
    try {
      const response = await fetch('/api/soc-settings/ai-model', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      applyAiSettings(data.settings);
      applyGeoIpDatabaseStatuses(data.geoip_databases, data.geoip_database);
      setAiStatus('Saved. Enabled providers and agent assignments are active.', 'ok');
    } catch (error) {
      setAiStatus(String(error.message || error), 'error');
    } finally {
      saveAiButton.disabled = false;
    }
  }
  function setAgentModelStatus(role, message, kind = '') {
    const element = document.querySelector(`[data-agent-model-status="${role}"]`);
    if (!element) return;
    element.textContent = message;
    element.classList.toggle('error', kind === 'error');
    element.classList.toggle('ok', kind === 'ok');
  }
  async function saveAgentModel(role, button) {
    const select = agentModelSelects.find(element => element.dataset.agentRole === role);
    const secondOpinionSelect = agentSecondOpinionSelects.find(element => element.dataset.agentRole === role);
    const adjudicatorSelect = agentAdjudicatorSelects.find(element => element.dataset.agentRole === role);
    const model = String(select?.value || '').trim();
    const secondOpinionModel = String(secondOpinionSelect?.value || '').trim();
    const adjudicatorModel = String(adjudicatorSelect?.value || '').trim();
    if (!role || !model || !button) {
      setAgentModelStatus(role, 'Choose an enabled model.', 'error');
      return;
    }
    if (
      adjudicatorModel
      && [modelRouteIdentity(model), modelRouteIdentity(secondOpinionModel)]
        .includes(modelRouteIdentity(adjudicatorModel))
    ) {
      setAgentModelStatus(
        role,
        'The adjudicator must resolve to a different provider/model identity than both positions.',
        'error'
      );
      return;
    }
    if (
      secondOpinionModel
      && modelRouteIdentity(secondOpinionModel) === modelRouteIdentity(model)
    ) {
      setAgentModelStatus(
        role,
        'Primary and second-opinion models must resolve to different provider/model identities.',
        'error'
      );
      return;
    }
    button.disabled = true;
    setAgentModelStatus(role, 'Saving...');
    try {
      const response = await fetch('/api/soc-settings/agent-model', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          role,
          model,
          second_opinion_model: secondOpinionModel,
          adjudicator_model: adjudicatorModel
        })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      applyAiSettings(data.settings);
      setAgentModelStatus(role, 'Saved.', 'ok');
    } catch (error) {
      setAgentModelStatus(role, String(error.message || error), 'error');
    } finally {
      button.disabled = false;
    }
  }
  async function saveMaxmindSettings() {
    if (!saveMaxmindButton) return;
    const payload = currentAiSettings();
    const validationError = validateAiSettings(payload);
    if (validationError) {
      setMaxmindStatus(validationError, 'error');
      return;
    }
    saveMaxmindButton.disabled = true;
    setMaxmindStatus('Saving...');
    try {
      const response = await fetch('/api/soc-settings/ai-model', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      applyAiSettings(data.settings);
      applyGeoIpDatabaseStatuses(data.geoip_databases, data.geoip_database);
      setMaxmindStatus('Saved. New PCAP analyses will use these offline databases.', 'ok');
    } catch (error) {
      setMaxmindStatus(String(error.message || error), 'error');
    } finally {
      saveMaxmindButton.disabled = false;
    }
  }
  async function saveSocPolicySettings() {
    if (!saveSocPolicyButton) return;
    const payload = currentAiSettings();
    const validationError = validateAiSettings(payload);
    if (validationError) {
      setSocPolicyStatus(validationError, 'error');
      return;
    }
    saveSocPolicyButton.disabled = true;
    setSocPolicyStatus('Saving...');
    try {
      const response = await fetch('/api/soc-settings/ai-model', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      applyAiSettings(data.settings);
      setSocPolicyStatus('Saved. New alerts and Relay PCAP reads will use these thresholds.', 'ok');
    } catch (error) {
      setSocPolicyStatus(String(error.message || error), 'error');
    } finally {
      saveSocPolicyButton.disabled = false;
    }
  }
  async function refreshPromptEditor(config) {
    try {
      const response = await fetch(config.endpoint, {cache: 'no-store'});
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok || typeof data.prompt !== 'string') {
        throw new Error(data.error || `Prompt read failed with HTTP ${response.status}`);
      }
      config.editor.value = data.prompt.trimEnd();
    } catch (_) {
      setPromptStatus(config, 'Could not refresh this prompt from the Onion Sentinel API.', 'error');
    }
  }
  async function savePromptEditor(config) {
    const prompt = config.editor.value.trim();
    if (!prompt) {
      setPromptStatus(config, 'Prompt cannot be empty.', 'error');
      return;
    }
    config.button.disabled = true;
    setPromptStatus(config, 'Saving...');
    try {
      const response = await fetch(config.endpoint, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({prompt})
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `Save failed with HTTP ${response.status}`);
      }
      setPromptStatus(config, 'Saved. New agent runs will use this prompt.', 'ok');
    } catch (error) {
      setPromptStatus(config, String(error.message || error), 'error');
    } finally {
      config.button.disabled = false;
    }
  }
  saveAiButton?.addEventListener('click', saveAiSettings);
  saveMaxmindButton?.addEventListener('click', saveMaxmindSettings);
  saveSocPolicyButton?.addEventListener('click', saveSocPolicySettings);
  [socAnalysisMinSeverity, socPcapMinSeverity, socIncidentMinSeverity].forEach(select => {
    select?.addEventListener('change', () => {
      syncSocPolicyLabels(
        socAnalysisMinSeverity?.value || 'informational',
        socPcapMinSeverity?.value || 'informational',
        socIncidentMinSeverity?.value || 'disabled'
      );
      setSocPolicyStatus('Unsaved');
    });
  });
  agentModelSaveButtons.forEach(button => {
    button.addEventListener('click', () => saveAgentModel(button.dataset.agentModelSave || '', button));
  });
  agentModelSelects.forEach(select => {
    select.addEventListener('change', () => {
      const settings = currentAiSettings();
      const role = select.dataset.agentRole || '';
      syncAgentModelControls(
        settings.agent_models,
        settings.agent_second_opinion_models,
        settings.agent_adjudicator_models,
        settings
      );
      setAgentModelStatus(role, 'Unsaved');
    });
  });
  agentSecondOpinionSelects.forEach(select => {
    select.addEventListener('change', () => {
      const settings = currentAiSettings();
      syncAgentModelControls(
        settings.agent_models,
        settings.agent_second_opinion_models,
        settings.agent_adjudicator_models,
        settings
      );
      setAgentModelStatus(select.dataset.agentRole || '', 'Unsaved');
    });
  });
  agentAdjudicatorSelects.forEach(select => {
    select.addEventListener('change', () => {
      setAgentModelStatus(select.dataset.agentRole || '', 'Unsaved');
    });
  });
  refreshOllamaButton?.addEventListener('click', () => refreshOllamaModels(true));
  ollamaModels?.addEventListener('change', event => {
    if (!event.target.matches('[data-ollama-model-toggle]')) return;
    modelSelectionDirty = true;
    updateProviderSummaries();
    const settings = currentAiSettings();
    syncAgentModelControls(settings.agent_models, settings.agent_second_opinion_models, settings.agent_adjudicator_models, settings);
  });
  codexCliModels?.addEventListener('change', event => {
    if (!event.target.matches('[data-codex-cli-model-enabled], [data-codex-cli-model-effort]')) return;
    updateProviderSummaries();
    const settings = currentAiSettings();
    syncAgentModelControls(settings.agent_models, settings.agent_second_opinion_models, settings.agent_adjudicator_models, settings);
  });
  [
    hermesAgentEnabled,
    hermesAgentPath,
    hermesAgentModel,
    hermesAgentReasoningEffort,
    openclawEnabled,
    openclawPath,
    openclawModel,
    openclawReasoningEffort
  ].forEach(control => {
    control?.addEventListener('change', () => {
      updateProviderSummaries();
      const settings = currentAiSettings();
      syncAgentModelControls(
        settings.agent_models,
        settings.agent_second_opinion_models,
        settings.agent_adjudicator_models,
        settings
      );
      setAiStatus('Unsaved');
    });
  });
  promptConfigurations.forEach(config => {
    config.button.addEventListener('click', () => savePromptEditor(config));
  });
  document.querySelectorAll('.settings-prompt-link').forEach(button => {
    button.addEventListener('click', event => {
      event.preventDefault();
      event.stopPropagation();
      openPromptEditor(button.dataset.promptTarget || '', button);
    });
  });
  document.querySelectorAll('.settings-memory-link').forEach(button => {
    button.addEventListener('click', event => {
      event.preventDefault();
      event.stopPropagation();
      openMemoryViewer(button.dataset.memoryKey || '', button);
    });
  });
  memoryModal?.querySelectorAll('[data-memory-close]').forEach(button => button.addEventListener('click', closeMemoryViewer));
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && memoryModal && !memoryModal.hidden) closeMemoryViewer();
  });
  refreshAiSettings().then(() => refreshOllamaModels(false));
  if (ollamaModels) {
    setInterval(() => refreshOllamaModels(false), 60000);
  }
  promptConfigurations.forEach(refreshPromptEditor);
})();
</script>
'''


def settings_client_actions_fragment() -> str:
    """Return the closing persistence and interaction Settings client."""
    return SETTINGS_CLIENT_ACTIONS
