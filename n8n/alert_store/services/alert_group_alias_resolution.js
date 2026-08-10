'use strict';

const stableGroupIdPattern = /^[a-f0-9]{12,64}$/;

function createAlertGroupAliasResolution({all, conflict}) {
  if (typeof all !== 'function') throw new TypeError('all must be a function');
  if (typeof conflict !== 'function') throw new TypeError('conflict must be a function');

  function resolve(groupId, aliases) {
    let current = typeof groupId === 'string' ? groupId.trim().toLowerCase() : '';
    if (!current || !stableGroupIdPattern.test(current)) {
      throw conflict('incident case contains an invalid stable group identity');
    }
    const visited = new Set();
    let canonicalGroupKey = '';
    for (let depth = 0; depth < 64; depth += 1) {
      if (visited.has(current)) {
        throw conflict('incident case stable group alias cycle detected');
      }
      visited.add(current);
      const alias = aliases.get(current);
      if (!alias) return {stableGroupId: current, stableGroupKey: canonicalGroupKey};
      const next = typeof alias.stable_group_id === 'string'
        ? alias.stable_group_id.trim().toLowerCase()
        : '';
      if (!next || !stableGroupIdPattern.test(next)) {
        throw conflict('incident case contains an invalid stable group alias');
      }
      const aliasGroupKey = typeof alias.stable_group_key === 'string'
        ? alias.stable_group_key
        : '';
      if (canonicalGroupKey && aliasGroupKey && canonicalGroupKey !== aliasGroupKey) {
        throw conflict('incident case stable group alias key is ambiguous');
      }
      if (aliasGroupKey) canonicalGroupKey = aliasGroupKey;
      current = next;
    }
    throw conflict('incident case stable group alias chain is too deep');
  }

  async function loadSnapshot() {
    const aliases = new Map();
    const rows = await all(
      `SELECT legacy_group_id, stable_group_id, stable_group_key
       FROM alert_group_alias`,
    );
    for (const row of rows) {
      const legacyGroupId = typeof row.legacy_group_id === 'string'
        ? row.legacy_group_id.trim().toLowerCase()
        : '';
      if (!legacyGroupId || aliases.has(legacyGroupId)) {
        throw conflict('incident case stable group alias map is ambiguous');
      }
      aliases.set(legacyGroupId, row);
    }
    return aliases;
  }

  return {loadSnapshot, resolve};
}

module.exports = {createAlertGroupAliasResolution};
