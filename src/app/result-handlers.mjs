// Result read handlers that return the caller's role-based sanitized projection.
import { sendApiError } from '../contracts/error-codes.mjs';
import { projectResult } from '../contracts/verification-result.mjs';

// Build list and detail handlers over an injected store of stored verification results.
export function createResultHandlers(resultStore) {
  return {
    async listResults(request, response) {
      const results = await resultStore.list();
      response.json({ results: results.map((result) => projectResult(result, request.auth.role)) });
    },
    async getResult(request, response) {
      const result = await resultStore.get(request.params.resultId);
      if (!result) {
        sendApiError(response, 'NOT_FOUND');
        return;
      }
      response.json(projectResult(result, request.auth.role));
    },
  };
}
