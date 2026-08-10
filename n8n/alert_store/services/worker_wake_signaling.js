'use strict';

function createWorkerWakeSignaling({
  fs, path, nowUtc, isControlledEvaluation, aiAnalysisWakePaths, logError,
}) {
  if (!fs?.promises || typeof fs.promises.mkdir !== 'function'
    || typeof fs.promises.writeFile !== 'function') {
    throw new TypeError('fs.promises must provide mkdir and writeFile');
  }
  if (!path || typeof path.dirname !== 'function') {
    throw new TypeError('path must provide dirname');
  }
  if (typeof nowUtc !== 'function') throw new TypeError('nowUtc must be a function');
  if (typeof isControlledEvaluation !== 'function') {
    throw new TypeError('isControlledEvaluation must be a function');
  }
  if (!Array.isArray(aiAnalysisWakePaths)) {
    throw new TypeError('aiAnalysisWakePaths must be an array');
  }
  if (typeof logError !== 'function') throw new TypeError('logError must be a function');

  async function signalWorker(wakePath, eventName) {
    if (!wakePath) return false;
    try {
      await fs.promises.mkdir(path.dirname(wakePath), {recursive: true, mode: 0o700});
      const safeEvent = String(eventName || 'work-available')
        .replace(/[^a-z0-9_-]/gi, '-')
        .slice(0, 64);
      await fs.promises.writeFile(
        wakePath,
        `${nowUtc()} ${safeEvent}\n`,
        {encoding: 'utf8', mode: 0o600},
      );
      return true;
    } catch (error) {
      // Wake files are an optimization. Durable SQLite state and launchd's
      // interval fallback remain authoritative if the filesystem signal fails.
      logError(`${nowUtc()} worker wake signal failed for ${eventName}: ${error.message}`);
      return false;
    }
  }

  async function signalAiWorkers(eventName) {
    if (isControlledEvaluation()) return false;
    const results = await Promise.all(
      aiAnalysisWakePaths.map((wakePath) => signalWorker(wakePath, eventName)),
    );
    return results.some(Boolean);
  }

  return {signalWorker, signalAiWorkers};
}

module.exports = {createWorkerWakeSignaling};
