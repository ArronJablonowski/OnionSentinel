'use strict';

function routeKey(method, pathname) {
  const normalizedMethod = String(method || '').trim().toUpperCase();
  const normalizedPath = String(pathname || '').trim();
  if (!/^[A-Z]+$/.test(normalizedMethod)) {
    throw new TypeError('route method must contain only letters');
  }
  if (
    !normalizedPath.startsWith('/')
    || normalizedPath.includes('?')
    || normalizedPath.includes('#')
  ) {
    throw new TypeError('route path must be an exact pathname');
  }
  return `${normalizedMethod} ${normalizedPath}`;
}

function validateDefinition(definition) {
  if (!definition || typeof definition !== 'object') {
    throw new TypeError('route definition must be an object');
  }
  if (typeof definition.handler !== 'function') {
    throw new TypeError('route handler must be a function');
  }
  return {
    ...definition,
    key: routeKey(definition.method, definition.path),
  };
}

function createRouteRegistry(initialDefinitions = []) {
  const routes = new Map();

  function registerAll(definitions) {
    if (!Array.isArray(definitions)) {
      throw new TypeError('route definitions must be an array');
    }
    const validated = definitions.map(validateDefinition);
    const staged = new Set();
    for (const definition of validated) {
      if (routes.has(definition.key) || staged.has(definition.key)) {
        throw new Error(`duplicate route registration: ${definition.key}`);
      }
      staged.add(definition.key);
    }
    for (const definition of validated) routes.set(definition.key, definition);
    return validated.length;
  }

  async function dispatch(context) {
    const request = context?.request;
    const parsedUrl = context?.parsedUrl;
    if (!request || !parsedUrl) {
      throw new TypeError('route dispatch requires request and parsedUrl');
    }
    const definition = routes.get(routeKey(request.method, parsedUrl.pathname));
    if (!definition) return false;
    await definition.handler(context);
    return true;
  }

  registerAll(initialDefinitions);
  return {
    dispatch,
    registerAll,
    routeKeys: () => [...routes.keys()].sort(),
  };
}

module.exports = {
  createRouteRegistry,
  routeKey,
};
