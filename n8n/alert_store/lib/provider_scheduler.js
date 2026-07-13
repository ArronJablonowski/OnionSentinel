'use strict';

/**
 * Build independent serial queues with a failure circuit for external providers.
 *
 * Serializing by provider protects free-tier quotas and cache coherence. Using
 * separate gates lets unrelated providers progress even when one is slow.
 */
function createProviderScheduler({failureThreshold = 3, resetMs = 60000, formatTimestamp = String} = {}) {
  const gates = new Map();
  const states = new Map();

  function run(source, task) {
    const state = states.get(source) || {queued: 0, failures: 0, openUntil: 0};
    state.queued += 1;
    states.set(source, state);
    const gate = gates.get(source) || Promise.resolve();
    const next = gate.catch(() => undefined).then(async () => {
      try {
        if (state.openUntil > Date.now()) {
          const error = new Error(`provider circuit open until ${formatTimestamp(new Date(state.openUntil))}`);
          error.providerCircuitOpen = true;
          throw error;
        }
        const result = await task();
        state.failures = 0;
        state.openUntil = 0;
        return result;
      } catch (error) {
        if (!error.providerCircuitOpen) {
          state.failures += 1;
          if (state.failures >= failureThreshold) state.openUntil = Date.now() + resetMs;
        }
        throw error;
      } finally {
        state.queued = Math.max(0, state.queued - 1);
      }
    });
    gates.set(source, next.catch(() => undefined));
    return next;
  }

  function snapshot() {
    return Object.fromEntries([...states.entries()].map(([source, state]) => [source, {
      queued: state.queued,
      failures: state.failures,
      circuit_open: state.openUntil > Date.now(),
    }]));
  }

  return {run, snapshot};
}

module.exports = {createProviderScheduler};
