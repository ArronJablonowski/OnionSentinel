'use strict';

function createProjectSerialization({nowDate = () => new Date()} = {}) {
  if (typeof nowDate !== 'function') throw new TypeError('nowDate must be a function');
  const isoTimestampPattern = /\b\d{4}-\d{2}-\d{2}(?:T|\s+)\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g;

  function projectOffset(date) {
    const offsetMinutes = -date.getTimezoneOffset();
    const sign = offsetMinutes >= 0 ? '+' : '-';
    const absolute = Math.abs(offsetMinutes);
    const hours = String(Math.floor(absolute / 60)).padStart(2, '0');
    const minutes = String(absolute % 60).padStart(2, '0');
    return `${sign}${hours}:${minutes}`;
  }

  function formatProjectTimestamp(date) {
    const pad = (value, length = 2) => String(value).padStart(length, '0');
    const milliseconds = date.getMilliseconds();
    const fractional = milliseconds ? `.${pad(milliseconds, 3)}` : '';
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}  ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}${fractional}${projectOffset(date)}`;
  }

  function parseProjectTimestamp(value) {
    const text = String(value || '').trim();
    if (!text) return null;
    const parseable = text.replace(
      /(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})/,
      '$1T',
    );
    const hasOffset = /(?:Z|[+-]\d{2}:?\d{2})$/.test(parseable);
    const parsed = new Date(hasOffset ? parseable : `${parseable}Z`);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  function nowUtc() {
    return formatProjectTimestamp(nowDate());
  }

  function normalizeTimestampValue(value) {
    // Keep project-visible timestamps consistent. Accept historical
    // UTC/local ISO strings and store local ISO 8601 with a two-space separator.
    if (value === null || value === undefined || value === '') return null;
    return String(value).trim().replace(isoTimestampPattern, (match) => {
      const parsed = parseProjectTimestamp(match);
      return parsed
        ? formatProjectTimestamp(parsed)
        : match.replace(
          /(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})/g,
          '$1  ',
        );
    });
  }

  function normalizeJsonTimestamps(value) {
    if (typeof value === 'string') return normalizeTimestampValue(value);
    if (Array.isArray(value)) return value.map((item) => normalizeJsonTimestamps(item));
    if (value && typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value).map(([key, item]) => [key, normalizeJsonTimestamps(item)]),
      );
    }
    return value;
  }

  function jsonText(value) {
    return JSON.stringify(normalizeJsonTimestamps(value ?? null));
  }

  function canonicalJsonText(value) {
    const canonicalize = (item) => {
      if (Array.isArray(item)) return item.map((entry) => canonicalize(entry));
      if (item && typeof item === 'object') {
        return Object.fromEntries(
          Object.keys(item).sort().map((key) => [key, canonicalize(item[key])]),
        );
      }
      return item;
    };
    return JSON.stringify(canonicalize(normalizeJsonTimestamps(value ?? null)));
  }

  return {
    projectOffset,
    formatProjectTimestamp,
    parseProjectTimestamp,
    nowUtc,
    normalizeTimestampValue,
    normalizeJsonTimestamps,
    jsonText,
    canonicalJsonText,
  };
}

module.exports = {createProjectSerialization};
