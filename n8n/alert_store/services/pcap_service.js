'use strict';

function createPcapService({
  withWriteGate,
  withTransaction,
  createRequest,
  listRequests,
  claimRequest,
  completeRequest,
  updateTransferProgress,
  retryRequest,
  completeAnalysis,
  requeueRequests,
  signalPcapWorker,
  signalAiWorkers,
}) {
  for (const [name, value] of Object.entries({
    withWriteGate,
    withTransaction,
    createRequest,
    listRequests,
    claimRequest,
    completeRequest,
    updateTransferProgress,
    retryRequest,
    completeAnalysis,
    requeueRequests,
    signalPcapWorker,
    signalAiWorkers,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  const gated = (operation) => withWriteGate(operation);

  async function request(payload) {
    return gated(() => createRequest(payload));
  }

  async function list(searchParams) {
    // Selection also performs bounded expiry, stale-lease recovery, and policy
    // retirement, so keep those compare-and-set writes behind the same gate as
    // claim and retry.
    return gated(() => listRequests(searchParams));
  }

  async function claim(payload) {
    return gated(() => claimRequest(payload));
  }

  async function complete(payload) {
    const result = await gated(() => completeRequest(payload));
    if (result.wake_pcap_analysis) {
      void signalPcapWorker('pcap-transfer-completed');
    }
    delete result.wake_pcap_analysis;
    return result;
  }

  async function progress(payload) {
    return gated(() => updateTransferProgress(payload));
  }

  async function retry(payload) {
    return gated(() => retryRequest(payload));
  }

  async function analysisStatus(payload) {
    const result = await gated(
      () => withTransaction(() => completeAnalysis(payload)),
    );
    if (result.wake_ai_analysis) {
      void signalAiWorkers('pcap-analysis-completed');
    }
    delete result.wake_ai_analysis;
    return result;
  }

  async function requeue(payload) {
    return gated(() => requeueRequests(payload));
  }

  return {request, list, claim, complete, progress, retry, analysisStatus, requeue};
}

module.exports = {createPcapService};
