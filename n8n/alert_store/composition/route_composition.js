'use strict';

const {createRouteRegistry} = require('../lib/route_registry');
const {createHealthRepository} = require('../repositories/health_repository');
const {createInventoryService} = require('../services/inventory_service');
const {createHealthService} = require('../services/health_service');
const {createAnalystStateService} = require('../services/analyst_state_service');
const {createDurableJobService} = require('../services/durable_job_service');
const {createAnalysisRequestService} = require('../services/analysis_request_service');
const {createAnalysisResultService} = require('../services/analysis_result_service');
const {createPcapService} = require('../services/pcap_service');
const {createEnrichmentService} = require('../services/enrichment_service');
const {createAlertIngestService} = require('../services/alert_ingest_service');
const {createInventoryRoutes} = require('../routes/inventory_routes');
const {createHealthRoutes} = require('../routes/health_routes');
const {createAnalystStateRoutes} = require('../routes/analyst_state_routes');
const {createDurableJobRoutes} = require('../routes/durable_job_routes');
const {createAnalysisRequestRoutes} = require('../routes/analysis_request_routes');
const {createAnalysisResultRoutes} = require('../routes/analysis_result_routes');
const {createPcapRoutes} = require('../routes/pcap_routes');
const {createEnrichmentRoutes} = require('../routes/enrichment_routes');
const {createMaintenanceRoutes} = require('../routes/maintenance_routes');
const {createAlertIngestRoutes} = require('../routes/alert_ingest_routes');

function requireSection(value, name) {
  if (!value || typeof value !== 'object') {
    throw new TypeError(`${name} route composition section is required`);
  }
  return value;
}

function createRouteComposition(options = {}) {
  const http = requireSection(options.http, 'http');
  const transaction = requireSection(options.transaction, 'transaction');
  const inventory = requireSection(options.inventory, 'inventory');
  const health = requireSection(options.health, 'health');
  const analystState = requireSection(options.analystState, 'analystState');
  const durableJob = requireSection(options.durableJob, 'durableJob');
  const analysisRequest = requireSection(options.analysisRequest, 'analysisRequest');
  const analysisResult = requireSection(options.analysisResult, 'analysisResult');
  const pcap = requireSection(options.pcap, 'pcap');
  const enrichment = requireSection(options.enrichment, 'enrichment');
  const maintenance = requireSection(options.maintenance, 'maintenance');
  const alertIngest = requireSection(options.alertIngest, 'alertIngest');
  const {readJsonBody, sendJson} = http;
  const {withWriteGate, withTransaction} = transaction;

  const inventoryService = createInventoryService({
    requireAcHunterStore: inventory.requireAcHunterStore,
    requireSoftwareStore: inventory.requireSoftwareStore,
    requireAssetStore: inventory.requireAssetStore,
  });
  const routes = createRouteRegistry(createInventoryRoutes({
    service: inventoryService,
    authorizeWrite: inventory.authorizeWrite,
    readJsonBody,
    sendJson,
  }));

  const healthRepository = createHealthRepository({get: health.get, all: health.all});
  const healthService = createHealthService({repository: healthRepository, runtime: health.runtime});
  routes.registerAll(createHealthRoutes({service: healthService, sendJson}));

  const analystStateService = createAnalystStateService({
    analystStatusSnapshot: analystState.analystStatusSnapshot,
    updateAnalystStatus: analystState.updateAnalystStatus,
    analystAdjudicationSnapshot: analystState.analystAdjudicationSnapshot,
    recordAnalystAdjudication: analystState.recordAnalystAdjudication,
    updateIncidentCaseStatus: analystState.updateIncidentCaseStatus,
    withWriteGate,
    withTransaction,
  });
  routes.registerAll(createAnalystStateRoutes({
    service: analystStateService,
    readJsonBody,
    sendJson,
  }));

  const durableJobService = createDurableJobService({
    safeString: durableJob.safeString,
    withWriteGate,
    withTransaction,
    controlledTransitionAdmission: durableJob.controlledTransitionAdmission,
    transitionJobStatus: durableJob.transitionJobStatus,
    applyControlledTransition: durableJob.applyControlledTransition,
    completePendingByDedupeKeys: durableJob.completePendingByDedupeKeys,
  });
  routes.registerAll(createDurableJobRoutes({
    service: durableJobService,
    readJsonBody,
    sendJson,
  }));

  const analysisRequestService = createAnalysisRequestService({
    ...analysisRequest,
    withWriteGate,
    withTransaction,
  });
  routes.registerAll(createAnalysisRequestRoutes({
    service: analysisRequestService,
    readJsonBody,
    sendJson,
  }));

  const analysisResultService = createAnalysisResultService({
    ...analysisResult,
    withWriteGate,
    withTransaction,
  });
  routes.registerAll(createAnalysisResultRoutes({
    service: analysisResultService,
    readJsonBody,
    sendJson,
  }));

  const pcapService = createPcapService({
    ...pcap,
    withWriteGate,
    withTransaction,
  });
  routes.registerAll(createPcapRoutes({service: pcapService, readJsonBody, sendJson}));

  const enrichmentService = createEnrichmentService({
    assertDiskWriteAdmission: enrichment.assertDiskWriteAdmission,
    enrichAlert: enrichment.enrichAlert,
    cachedInvestigationEnrichment: enrichment.cachedInvestigationEnrichment,
    queryInvestigationEnrichment: enrichment.queryInvestigationEnrichment,
  });
  routes.registerAll(createEnrichmentRoutes({
    service: enrichmentService,
    authorizeInvestigation: enrichment.authorizeInvestigation,
    readJsonBody,
    sendJson,
  }));

  routes.registerAll(createMaintenanceRoutes({service: maintenance, sendJson}));
  const alertIngestService = createAlertIngestService(alertIngest);
  routes.registerAll(createAlertIngestRoutes({service: alertIngestService, sendJson}));
  return routes;
}

module.exports = {createRouteComposition};
