'use strict';

function createDiskWriteAdmission({
  fs, path, dbPath, diskStartMaxUsedPercent, diskHardMaxUsedPercent,
  diskMinFreeBytes, maxRequestBytes,
}) {
  if (!fs || typeof fs.existsSync !== 'function' || typeof fs.statfsSync !== 'function') {
    throw new TypeError('fs must provide existsSync and statfsSync');
  }
  if (!path || typeof path.resolve !== 'function' || typeof path.dirname !== 'function') {
    throw new TypeError('path must provide resolve and dirname');
  }

  function existingFilesystemAnchor(targetPath) {
    let candidate = path.resolve(targetPath);
    while (!fs.existsSync(candidate) && candidate !== path.dirname(candidate)) {
      candidate = path.dirname(candidate);
    }
    return candidate;
  }

  function diskCapacitySnapshot(additionalBytes = 0) {
    const anchor = existingFilesystemAnchor(path.dirname(dbPath));
    const stats = fs.statfsSync(anchor);
    const totalBytes = Number(stats.blocks) * Number(stats.bsize);
    const freeBytes = Number(stats.bavail) * Number(stats.bsize);
    const usedBytes = Math.max(0, totalBytes - freeBytes);
    const additional = Math.max(0, Number(additionalBytes) || 0);
    const usedPercent = totalBytes ? usedBytes / totalBytes * 100 : 100;
    const projectedUsedPercent = totalBytes
      ? (usedBytes + additional) / totalBytes * 100
      : 100;
    return {
      filesystem_anchor: anchor,
      total_bytes: totalBytes,
      used_bytes: usedBytes,
      free_bytes: freeBytes,
      additional_bytes: additional,
      free_after_bytes: freeBytes - additional,
      used_percent: Number(usedPercent.toFixed(2)),
      projected_used_percent: Number(projectedUsedPercent.toFixed(2)),
      start_max_used_percent: diskStartMaxUsedPercent,
      hard_max_used_percent: diskHardMaxUsedPercent,
      min_free_bytes: diskMinFreeBytes,
    };
  }

  function assertDiskWriteAdmission(label, additionalBytes = maxRequestBytes) {
    const snapshot = diskCapacitySnapshot(additionalBytes);
    let reason = '';
    if (snapshot.used_percent >= diskHardMaxUsedPercent) {
      reason = `disk is ${snapshot.used_percent}% used; hard limit is ${diskHardMaxUsedPercent}%`;
    } else if (snapshot.used_percent >= diskStartMaxUsedPercent) {
      reason = `disk is ${snapshot.used_percent}% used; new-write limit is ${diskStartMaxUsedPercent}%`;
    } else if (snapshot.projected_used_percent >= diskStartMaxUsedPercent) {
      reason = `projected disk use is ${snapshot.projected_used_percent}%; new-write limit is ${diskStartMaxUsedPercent}%`;
    } else if (snapshot.free_after_bytes < diskMinFreeBytes) {
      reason = `projected free space is ${snapshot.free_after_bytes} bytes; reserve is ${diskMinFreeBytes} bytes`;
    }
    if (reason) {
      const error = new Error(`${label} refused: ${reason}`);
      error.statusCode = 507;
      throw error;
    }
    return snapshot;
  }

  return {existingFilesystemAnchor, diskCapacitySnapshot, assertDiskWriteAdmission};
}

module.exports = {createDiskWriteAdmission};
