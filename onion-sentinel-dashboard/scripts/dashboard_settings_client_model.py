"""Model-routing and settings-normalization client fragment."""
from __future__ import annotations


SETTINGS_CLIENT_MODEL = '''
  function workflowCompatibilityReason(assessment) {
    if (!assessment || assessment.compatible === true) return '';
    const reasons = Array.isArray(assessment.reasons)
      ? assessment.reasons.map(reason => String(reason || '').trim()).filter(Boolean)
      : [];
    return reasons.join(' ') || 'This model cannot be verified for the current Onion Sentinel analysis workflow.';
  }
  function modelAvailabilityLabel(installed, assessment) {
    if (!installed) return 'Configured, currently unavailable';
    if (!assessment) return 'Installed locally';
    if (assessment.compatible === false) {
      return assessment.status === 'unverified'
        ? 'Installed locally · Compatibility unverified'
        : 'Installed locally · Workflow incompatible';
    }
    const contextLength = Number(assessment.context_length || 0);
    return contextLength > 0
      ? `Installed locally · Compatible · ${contextLength.toLocaleString()} token context`
      : 'Installed locally · Compatible';
  }
  function enabledAgentRoutes(settings) {
    const routes = normalizeModelList(settings?.enabled_ollama_models).map(model => `ollama:${model}`);
    normalizeCodexCliModels(settings?.codex_cli_models)
      .filter(entry => entry.enabled)
      .forEach(entry => routes.push(`codex-cli:${entry.model}:${entry.reasoning_effort}`));
    if (settings?.hermes_agent_enabled === true) {
      const model = String(settings.hermes_agent_model || 'gpt-5.5').trim();
      const effort = String(settings.hermes_agent_reasoning_effort || 'medium').trim();
      routes.push(`hermes-agent:${model}:${effort}`);
    }
    if (settings?.openclaw_enabled === true) {
      const model = String(settings.openclaw_model || 'ollama/gemma4:26b-mlx').trim();
      const effort = String(settings.openclaw_reasoning_effort || 'medium').trim();
      routes.push(`openclaw:${model}:${effort}`);
    }
    return routes;
  }
  function canonicalAgentRoute(route, routes = []) {
    const normalized = String(route || '').trim();
    if (['gpt-cli', 'codex-cli'].includes(normalized)) {
      return routes.find(candidate => candidate.startsWith('codex-cli:')) || normalized;
    }
    if (normalized.startsWith('codex-cli:') && !routes.includes(normalized)) {
      const parts = normalized.slice('codex-cli:'.length).split(':');
      parts.pop();
      const model = parts.join(':');
      return routes.find(candidate => candidate.startsWith(`codex-cli:${model}:`)) || normalized;
    }
    for (const provider of ['hermes-agent', 'openclaw']) {
      const prefix = `${provider}:`;
      if (normalized.startsWith(prefix) && !routes.includes(normalized)) {
        return routes.find(candidate => candidate.startsWith(prefix)) || normalized;
      }
    }
    return normalized;
  }
  function modelRouteIdentity(route, settings = {}) {
    const normalized = String(route || '').trim().toLowerCase();
    if (normalized.startsWith('codex-cli:')) {
      const parts = normalized.slice('codex-cli:'.length).split(':');
      const effort = parts.pop() || '';
      const model = parts.join(':');
      if (model && ['low', 'medium', 'high', 'xhigh'].includes(effort)) {
        return `openai-codex:${model}`;
      }
    }
    if (['gpt-cli', 'codex-cli'].includes(normalized)) {
      const model = String(settings.codex_cli_model || 'configured-default').trim().toLowerCase();
      return `openai-codex:${model}`;
    }
    if (normalized.startsWith('hermes-agent:')) {
      const parts = normalized.slice('hermes-agent:'.length).split(':');
      const effort = parts.pop() || '';
      const model = parts.join(':');
      if (model && ['low', 'medium', 'high', 'xhigh'].includes(effort)) {
        return `openai-codex:${model}`;
      }
    }
    if (normalized.startsWith('openclaw:')) {
      const parts = normalized.slice('openclaw:'.length).split(':');
      const effort = parts.pop() || '';
      const model = parts.join(':');
      if (model && ['low', 'medium', 'high', 'xhigh'].includes(effort)) {
        if (model.includes('/')) {
          const separator = model.indexOf('/');
          return `${model.slice(0, separator)}:${model.slice(separator + 1)}`;
        }
        return `openclaw:${model}`;
      }
    }
    return normalized;
  }
  function normalizeAgentModels(value, routes) {
    const source = value && typeof value === 'object' ? value : {};
    const fallback = routes[0] || '';
    return Object.fromEntries(agentRoles.map(role => {
      const route = canonicalAgentRoute(source[role], routes);
      return [role, routes.includes(route) ? route : fallback];
    }));
  }
  function normalizeAgentSecondOpinionModels(value, routes, primaryAssignments) {
    const source = value && typeof value === 'object' ? value : {};
    return Object.fromEntries(agentRoles.map(role => {
      const route = canonicalAgentRoute(source[role], routes);
      const primary = canonicalAgentRoute(primaryAssignments?.[role], routes);
      return [
        role,
        routes.includes(route)
          && modelRouteIdentity(route) !== modelRouteIdentity(primary)
          ? route
          : ''
      ];
    }));
  }
  function normalizeAgentAdjudicatorModels(value, routes, primaryAssignments, reviewerAssignments) {
    const source = value && typeof value === 'object' ? value : {};
    return Object.fromEntries(agentRoles.map(role => {
      const route = canonicalAgentRoute(source[role], routes);
      const identity = modelRouteIdentity(route);
      const excluded = new Set([
        modelRouteIdentity(canonicalAgentRoute(primaryAssignments?.[role], routes)),
        modelRouteIdentity(canonicalAgentRoute(reviewerAssignments?.[role], routes))
      ]);
      return [role, routes.includes(route) && identity && !excluded.has(identity) ? route : ''];
    }));
  }
  function agentModelRouteLabel(route, settings) {
    if (route.startsWith('ollama:')) return `Ollama: ${route.slice('ollama:'.length)}`;
    if (route.startsWith('codex-cli:')) {
      const parts = route.slice('codex-cli:'.length).split(':');
      const effort = parts.pop() || 'medium';
      const model = parts.join(':');
      return `Codex CLI: ${model} (${effort})`;
    }
    if (route.startsWith('hermes-agent:')) {
      const parts = route.slice('hermes-agent:'.length).split(':');
      const effort = parts.pop() || 'medium';
      const model = parts.join(':');
      return `Hermes Agent: ${model} (${effort})`;
    }
    if (route.startsWith('openclaw:')) {
      const parts = route.slice('openclaw:'.length).split(':');
      const effort = parts.pop() || 'medium';
      const model = parts.join(':');
      return `OpenClaw: ${model} (${effort})`;
    }
    if (['gpt-cli', 'codex-cli'].includes(route)) {
      const model = String(settings?.codex_cli_model || settings?.cloud_model || 'gpt-5.5').trim();
      const effort = String(settings?.codex_cli_reasoning_effort || 'medium').trim();
      return `Codex CLI: ${model} (${effort})`;
    }
    return 'No analysis model assigned';
  }
  function currentAgentModels(routes) {
    const selected = {...configuredAgentModels};
    agentModelSelects.forEach(select => {
      selected[select.dataset.agentRole || ''] = select.value;
    });
    return normalizeAgentModels(selected, routes);
  }
  function currentAgentSecondOpinionModels(routes, primaryAssignments) {
    const selected = {...configuredAgentSecondOpinionModels};
    agentSecondOpinionSelects.forEach(select => {
      selected[select.dataset.agentRole || ''] = select.value;
    });
    return normalizeAgentSecondOpinionModels(selected, routes, primaryAssignments);
  }
  function currentAgentAdjudicatorModels(routes, primaryAssignments, reviewerAssignments) {
    const selected = {...configuredAgentAdjudicatorModels};
    agentAdjudicatorSelects.forEach(select => {
      selected[select.dataset.agentRole || ''] = select.value;
    });
    return normalizeAgentAdjudicatorModels(
      selected,
      routes,
      primaryAssignments,
      reviewerAssignments
    );
  }
  function syncAgentModelControls(assignments, secondOpinionAssignments, adjudicatorAssignments, settings) {
    const routes = enabledAgentRoutes(settings);
    const normalized = normalizeAgentModels(assignments, routes);
    const normalizedSecondOpinions = normalizeAgentSecondOpinionModels(
      secondOpinionAssignments,
      routes,
      normalized
    );
    const normalizedAdjudicators = normalizeAgentAdjudicatorModels(
      adjudicatorAssignments,
      routes,
      normalized,
      normalizedSecondOpinions
    );
    agentModelSelects.forEach(select => {
      const role = select.dataset.agentRole || '';
      select.replaceChildren();
      routes.forEach(route => {
        const option = document.createElement('option');
        option.value = route;
        option.textContent = agentModelRouteLabel(route, settings);
        option.selected = route === normalized[role];
        select.appendChild(option);
      });
      select.disabled = routes.length === 0;
    });
    agentSecondOpinionSelects.forEach(select => {
      const role = select.dataset.agentRole || '';
      const primary = normalized[role] || '';
      const primaryIdentity = modelRouteIdentity(primary, settings);
      const availableRoutes = routes.filter(
        route => modelRouteIdentity(route, settings) !== primaryIdentity
      );
      select.replaceChildren();
      const emptyOption = document.createElement('option');
      emptyOption.value = '';
      emptyOption.textContent = 'Not assigned';
      emptyOption.selected = !normalizedSecondOpinions[role];
      select.appendChild(emptyOption);
      availableRoutes.forEach(route => {
        const option = document.createElement('option');
        option.value = route;
        option.textContent = agentModelRouteLabel(route, settings);
        option.selected = route === normalizedSecondOpinions[role];
        select.appendChild(option);
      });
      select.disabled = availableRoutes.length === 0;
    });
    agentAdjudicatorSelects.forEach(select => {
      const role = select.dataset.agentRole || '';
      const excluded = new Set([
        modelRouteIdentity(normalized[role] || '', settings),
        modelRouteIdentity(normalizedSecondOpinions[role] || '', settings)
      ]);
      const availableRoutes = routes.filter(
        route => !excluded.has(modelRouteIdentity(route, settings))
      );
      select.replaceChildren();
      const emptyOption = document.createElement('option');
      emptyOption.value = '';
      emptyOption.textContent = 'Not assigned';
      emptyOption.selected = !normalizedAdjudicators[role];
      select.appendChild(emptyOption);
      availableRoutes.forEach(route => {
        const option = document.createElement('option');
        option.value = route;
        option.textContent = agentModelRouteLabel(route, settings);
        option.selected = route === normalizedAdjudicators[role];
        select.appendChild(option);
      });
      select.disabled = availableRoutes.length === 0;
    });
    agentModelLabels.forEach(element => {
      const role = element.dataset.agentModel || '';
      element.textContent = agentModelRouteLabel(normalized[role] || '', settings);
    });
    agentSecondOpinionModelLabels.forEach(element => {
      const role = element.dataset.agentSecondOpinionModel || '';
      const route = normalizedSecondOpinions[role] || '';
      element.textContent = route ? agentModelRouteLabel(route, settings) : 'None selected';
    });
    agentAdjudicatorModelLabels.forEach(element => {
      const role = element.dataset.agentAdjudicatorModel || '';
      const route = normalizedAdjudicators[role] || '';
      element.textContent = route ? agentModelRouteLabel(route, settings) : 'None selected';
    });
    configuredAgentModels = normalized;
    configuredAgentSecondOpinionModels = normalizedSecondOpinions;
    configuredAgentAdjudicatorModels = normalizedAdjudicators;
  }
  function currentAiSettings() {
    const enabledModels = enabledOllamaModels();
    const codexModels = currentCodexCliModels();
    const enabledCodexModels = codexModels.filter(entry => entry.enabled);
    const primaryCodex = enabledCodexModels[0] || codexModels[0] || {
      model: 'gpt-5.5',
      reasoning_effort: 'medium'
    };
    const gptEnabled = enabledCodexModels.length > 0;
    const hermesEnabled = Boolean(hermesAgentEnabled?.checked);
    const openclawIsEnabled = Boolean(openclawEnabled?.checked);
    const selectedOpenClawModel = openclawModel?.value.trim() || 'ollama/gemma4:26b-mlx';
    const hostedEnabled = gptEnabled || hermesEnabled;
    const localModelsForMode = enabledModels.length || openclawIsEnabled
      ? ['local-enabled']
      : [];
    const settings = {
      mode: derivedAnalysisMode(localModelsForMode, hostedEnabled),
      ollama_model: enabledModels[0] || configuredEnabledModels[0] || 'devstral:latest',
      enabled_ollama_models: enabledModels,
      ollama_url: ollamaUrl?.value.trim() || 'http://127.0.0.1:11434',
      cloud_provider: 'codex-cli',
      cloud_model: primaryCodex.model,
      cloud_command: '',
      codex_cli_path: codexCliPath?.value.trim() || 'codex',
      codex_cli_model: primaryCodex.model,
      codex_cli_reasoning_effort: primaryCodex.reasoning_effort,
      codex_cli_models: codexModels,
      gpt_cli_enabled: gptEnabled,
      hermes_agent_enabled: hermesEnabled,
      hermes_agent_path: hermesAgentPath?.value.trim() || 'hermes',
      hermes_agent_model: hermesAgentModel?.value.trim() || 'gpt-5.5',
      hermes_agent_reasoning_effort: hermesAgentReasoningEffort?.value || 'medium',
      openclaw_enabled: openclawIsEnabled,
      openclaw_path: openclawPath?.value.trim() || 'openclaw',
      openclaw_model: selectedOpenClawModel,
      openclaw_reasoning_effort: openclawReasoningEffort?.value || 'medium',
      soc_analyst_analysis_min_severity: socAnalysisMinSeverity?.value || 'informational',
      soc_analyst_pcap_min_severity: socPcapMinSeverity?.value || 'informational',
      soc_analyst_incident_min_severity: socIncidentMinSeverity?.value || 'disabled',
      pcap_capture_loss_threshold_percent: Number(pcapCaptureLossThreshold?.value || 5),
      maxmind_geoip_asn_db_path: maxmindGeoIpPaths.asn?.value.trim() || maxmindGeoIpDefaults.asn,
      maxmind_geoip_city_db_path: maxmindGeoIpPaths.city?.value.trim() || maxmindGeoIpDefaults.city,
      maxmind_geoip_country_db_path: maxmindGeoIpPaths.country?.value.trim() || maxmindGeoIpDefaults.country
    };
    const routes = enabledAgentRoutes(settings);
    settings.agent_models = currentAgentModels(routes);
    settings.agent_second_opinion_models = currentAgentSecondOpinionModels(routes, settings.agent_models);
    settings.agent_adjudicator_models = currentAgentAdjudicatorModels(
      routes,
      settings.agent_models,
      settings.agent_second_opinion_models
    );
    return settings;
  }
  function applyAiSettings(settings) {
    if (!settings) return;
    const mode = String(settings.mode || 'ollama').trim().toLowerCase();
    configuredEnabledModels = normalizeModelList(settings.enabled_ollama_models);
    const openclawProvidesLocal = settings.openclaw_enabled === true;
    if (!configuredEnabledModels.length && mode !== 'cloud' && !openclawProvidesLocal) {
      configuredEnabledModels = [String(settings.ollama_model || 'devstral:latest').trim()];
    }
    if (ollamaModels) {
      ollamaModels.querySelectorAll('[data-ollama-model-toggle]').forEach(input => {
        input.checked = configuredEnabledModels.includes(input.value);
      });
    }
    if (ollamaUrl) ollamaUrl.value = settings.ollama_url || 'http://127.0.0.1:11434';
    if (codexCliPath) codexCliPath.value = settings.codex_cli_path || 'codex';
    const codexEntries = Array.isArray(settings.codex_cli_models)
      ? settings.codex_cli_models
      : [{
          model: settings.codex_cli_model || settings.cloud_model || 'gpt-5.5',
          reasoning_effort: settings.codex_cli_reasoning_effort || 'medium',
          enabled: settings.gpt_cli_enabled === true || (settings.gpt_cli_enabled == null && ['cloud', 'hybrid'].includes(mode))
        }];
    renderCodexCliModels(codexEntries);
    if (hermesAgentEnabled) hermesAgentEnabled.checked = settings.hermes_agent_enabled === true;
    if (hermesAgentPath) hermesAgentPath.value = settings.hermes_agent_path || 'hermes';
    if (hermesAgentModel) hermesAgentModel.value = settings.hermes_agent_model || 'gpt-5.5';
    if (hermesAgentReasoningEffort) {
      hermesAgentReasoningEffort.value = settings.hermes_agent_reasoning_effort || 'medium';
    }
    if (openclawEnabled) openclawEnabled.checked = settings.openclaw_enabled === true;
    if (openclawPath) openclawPath.value = settings.openclaw_path || 'openclaw';
    if (openclawModel) {
      openclawModel.value = settings.openclaw_model || 'ollama/gemma4:26b-mlx';
    }
    if (openclawReasoningEffort) {
      openclawReasoningEffort.value = settings.openclaw_reasoning_effort || 'medium';
    }
    if (socAnalysisMinSeverity) {
      socAnalysisMinSeverity.value = settings.soc_analyst_analysis_min_severity || 'informational';
    }
    if (socPcapMinSeverity) {
      socPcapMinSeverity.value = settings.soc_analyst_pcap_min_severity || 'informational';
    }
    if (socIncidentMinSeverity) {
      socIncidentMinSeverity.value = settings.soc_analyst_incident_min_severity || 'disabled';
    }
    if (pcapCaptureLossThreshold) {
      pcapCaptureLossThreshold.value = Number(
        settings.pcap_capture_loss_threshold_percent ?? 5
      ).toFixed(1);
    }
    syncSocPolicyLabels(
      settings.soc_analyst_analysis_min_severity || 'informational',
      settings.soc_analyst_pcap_min_severity || 'informational',
      settings.soc_analyst_incident_min_severity || 'disabled'
    );
    Object.entries(maxmindGeoIpPaths).forEach(([databaseType, input]) => {
      if (!input) return;
      const settingKey = `maxmind_geoip_${databaseType}_db_path`;
      input.value = settings[settingKey] || maxmindGeoIpDefaults[databaseType];
    });
    syncAgentModelControls(settings.agent_models, settings.agent_second_opinion_models, settings.agent_adjudicator_models, {
      ...settings,
      enabled_ollama_models: configuredEnabledModels,
      codex_cli_models: currentCodexCliModels(),
      gpt_cli_enabled: currentCodexCliModels().some(entry => entry.enabled),
      hermes_agent_enabled: Boolean(hermesAgentEnabled?.checked),
      hermes_agent_model: hermesAgentModel?.value.trim() || 'gpt-5.5',
      hermes_agent_reasoning_effort: hermesAgentReasoningEffort?.value || 'medium',
      openclaw_enabled: Boolean(openclawEnabled?.checked),
      openclaw_model: openclawModel?.value.trim() || 'ollama/gemma4:26b-mlx',
      openclaw_reasoning_effort: openclawReasoningEffort?.value || 'medium'
    });
    modelSelectionDirty = false;
    updateProviderSummaries();
  }
  function applyGeoIpDatabaseStatus(databaseType, database) {
    const stateElement = maxmindGeoIpStates[databaseType];
    if (!stateElement) return;
    const state = database?.state || 'unknown';
    if (state === 'ready') {
      const size = Number(database.size_bytes || 0).toLocaleString();
      stateElement.textContent = `Ready · ${size} bytes`;
      stateElement.style.color = '#86efac';
      return;
    }
    stateElement.textContent = state === 'missing'
      ? 'Waiting for database upload'
      : state === 'unreadable' ? 'Database is not readable' : 'Status unavailable';
    stateElement.style.color = state === 'unreadable' ? '#fb7185' : '#f6c76d';
  }
  function applyGeoIpDatabaseStatuses(databases, legacyCity) {
    Object.keys(maxmindGeoIpStates).forEach(databaseType => {
      const database = databases?.[databaseType] || (databaseType === 'city' ? legacyCity : null);
      applyGeoIpDatabaseStatus(databaseType, database);
    });
  }
'''


def settings_client_model_fragment() -> str:
    """Return the model-routing portion of the Settings client."""
    return SETTINGS_CLIENT_MODEL
