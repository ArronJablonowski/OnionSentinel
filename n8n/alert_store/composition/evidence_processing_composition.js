'use strict';

const {createAiCorrelationRepository} = require('../repositories/ai_correlation_repository');
const {createAiReviewRepository} = require('../repositories/ai_review_repository');
const {createPcapRequestRepository} = require('../repositories/pcap_request_repository');
const {createAiAnalysisAcceptance} = require('../services/ai_analysis_acceptance');
const {createDurableBackgroundDrains} = require('../services/durable_background_drains');
const {createPcapAnalysisCompletion} = require('../services/pcap_analysis_completion');

function requireSection(options, name) {
  const section = options && options[name];
  if (!section || typeof section !== 'object') {
    throw new Error(`${name} evidence processing composition section is required`);
  }
  return section;
}

function createEvidenceProcessingComposition(options = {}) {
  const database = requireSection(options, 'database');
  const runtime = requireSection(options, 'runtime');
  const policy = requireSection(options, 'policy');
  const services = requireSection(options, 'services');
  const serialization = requireSection(options, 'serialization');

  const recordMetric = (...args) => services.pipelineMetrics().record(...args);
  const pcapRequestRepository = createPcapRequestRepository({
    get: database.get,
    all: database.all,
    run: database.run,
    safeString: serialization.safeString,
    parseJsonObject: serialization.parseJsonObject,
    jsonText: serialization.jsonText,
    nowUtc: serialization.nowUtc,
    pcapCandidateFromRow: policy.pcapCandidateFromRow,
    normalizePcapRequest: policy.normalizePcapRequest,
    pcapRetentionError: policy.pcapRetentionError,
    pcapRequestFromRow: policy.pcapRequestFromRow,
    classifyPcapOutcome: policy.classifyPcapOutcome,
    recordMetric,
    readCaptureLossThreshold: policy.readCaptureLossThreshold,
    requeueStaleClaims: (...args) => (
      services.pcapTransferRepository().requeueStaleClaims(...args)
    ),
    priorityMaxWaitSeconds: runtime.pcapPriorityMaxWaitSeconds,
    captureRetentionSeconds: runtime.pcapCaptureRetentionSeconds,
  });
  const pcapAnalysisCompletion = createPcapAnalysisCompletion({
    run: database.run,
    get: database.get,
    safeString: serialization.safeString,
    nowUtc: serialization.nowUtc,
    recordMetric,
    matchesAnalysis: policy.matchesAnalysis,
    authorizedCampaignForAlertId: services.authorizedCampaignForAlertId,
    enqueueAiJob: (...args) => services.durableJobs().enqueue('ai_analysis', ...args),
    severityRank: policy.severityRank,
  });
  const aiReviewRepository = createAiReviewRepository({
    run: database.run,
    safeString: serialization.safeString,
    jsonText: serialization.jsonText,
    nowUtc: serialization.nowUtc,
  });
  const aiCorrelationRepository = createAiCorrelationRepository({
    get: database.get,
    run: database.run,
    safeString: serialization.safeString,
    jsonText: serialization.jsonText,
    nowUtc: serialization.nowUtc,
    compactCorrelationCandidates: policy.compactCorrelationCandidates,
  });
  const durableBackgroundDrains = createDurableBackgroundDrains({
    durableJobs: services.durableJobs,
    withWriteTransaction: database.withWriteTransaction,
    get: database.get,
    run: database.run,
    enrichAlert: services.enrichAlert,
    enrichmentRecord: policy.enrichmentRecord,
    jsonText: serialization.jsonText,
    indexAlertObservables: services.indexAlertObservables,
    groupKeyFromRow: policy.groupKeyFromRow,
    groupIdFromKey: policy.groupIdFromKey,
    authorizedCampaignForAlertId: services.authorizedCampaignForAlertId,
    matchesAnalysis: policy.matchesAnalysis,
    severityRank: policy.severityRank,
    recordMetric,
    signalAiWorkers: services.signalAiWorkers,
    requestJson: services.requestJson,
    safeString: serialization.safeString,
    enrichmentTimeoutMs: runtime.enrichmentTimeoutMs,
    n8nPostCommitUrl: runtime.n8nPostCommitUrl,
    n8nPostCommitToken: runtime.n8nPostCommitToken,
    n8nPostCommitTimeoutMs: runtime.n8nPostCommitTimeoutMs,
    n8nPostCommitBaseRetrySeconds: runtime.n8nPostCommitBaseRetrySeconds,
  });

  function createAiAcceptance(incident) {
    if (!incident || typeof incident !== 'object') {
      throw new Error('incident evidence processing composition section is required');
    }
    return createAiAnalysisAcceptance({
      get: database.get,
      run: database.run,
      safeString: serialization.safeString,
      jsonText: serialization.jsonText,
      nowUtc: serialization.nowUtc,
      parseJsonObject: serialization.parseJsonObject,
      canonicalJsonText: serialization.canonicalJsonText,
      normalizeTimestampValue: serialization.normalizeTimestampValue,
      supportedAgentRoles: policy.supportedAgentRoles,
      incidentReanalysisBindingAuthority: incident.bindingAuthority,
      aiReviewRepository,
      incidentAnalysisCompletion: incident.analysisCompletion,
      aiCorrelationRepository,
    });
  }

  return {
    aiCorrelationRepository,
    aiReviewRepository,
    pcapRequestRepository,
    pcapAnalysisCompletion,
    durableBackgroundDrains,
    createAiAcceptance,
  };
}

module.exports = {createEvidenceProcessingComposition};
