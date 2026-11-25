// Mounts declared endpoints behind their permission checks, with safe fallback responses.
import { sendApiError } from '../contracts/error-codes.mjs';

// Placeholder for declared routes whose handlers belong to later work packages.
function notImplemented(_request, response) {
  sendApiError(response, 'NOT_IMPLEMENTED');
}

// Register every endpoint; authorization always runs before the handler and any body parsing.
export function mountEndpoints(app, endpoints, { requireAction, handlers = {} }) {
  for (const endpoint of endpoints) {
    const handler = Object.hasOwn(handlers, endpoint.name) ? handlers[endpoint.name] : notImplemented;
    const guards = endpoint.public ? [] :
      [requireAction(endpoint.action, { method: endpoint.method, route: endpoint.path })];
    app[endpoint.method.toLowerCase()](endpoint.path, ...guards, handler);
  }
}

// Final handlers: unknown routes get NOT_FOUND and errors never expose details.
export function mountFallbacks(app) {
  app.use((_request, response) => {
    sendApiError(response, 'NOT_FOUND');
  });
  app.use((error, _request, response, next) => {
    if (response.headersSent) {
      next(error);
      return;
    }
    const code = error?.status === 413 ? 'PAYLOAD_TOO_LARGE' :
      error?.status === 400 ? 'MALFORMED_INPUT' : 'INTERNAL_ERROR';
    sendApiError(response, code);
  });
}
