import { ERROR_CODES } from '../config/constants.js';
import { sendError, AppError } from '../utils/response.js';
import { logger } from '../utils/logger.js';

/**
 * Global Express Error Handling Middleware.
 * Complies with CYBERLENS contract:
 * { "success": false, "error": { "code": "...", "message": "...", "details": {} } }
 * Never leaks stack traces, secrets, or internal engine details.
 */
export function errorHandler(err, req, res, next) {
  // If response has already started streaming, delegate to default Express handler
  if (res.headersSent) {
    return next(err);
  }

  // Expected client errors (4xx AppErrors) are routine: log quietly, without query strings.
  const expected = err instanceof AppError && err.status < 500;
  (expected ? logger.debug : logger.error)(`Error processing ${req.method} ${req.path}: ${err.message}`, {
    stack: !expected && process.env.NODE_ENV === 'development' ? err.stack : undefined,
  });

  // Handle known application errors
  if (err instanceof AppError) {
    return sendError(res, {
      code: err.code,
      message: err.message,
      details: err.details,
    }, err.status);
  }

  // Handle SyntaxError (e.g. malformed JSON in request body)
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return sendError(res, {
      code: ERROR_CODES.VALIDATION_ERROR,
      message: 'Invalid JSON payload received in request body.',
      details: {},
    }, 400);
  }

  // Body too large (express.json limit)
  if (err?.type === 'entity.too.large') {
    return sendError(res, {
      code: ERROR_CODES.PAYLOAD_TOO_LARGE,
      message: 'Request body is too large.',
      details: {},
    }, 413);
  }

  // Catch-all internal server error
  return sendError(res, {
    code: ERROR_CODES.INTERNAL,
    message: 'An internal server error occurred while processing your request.',
    details: {},
  }, 500);
}

