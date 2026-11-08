import { ERROR_CODES } from '../config/constants.js';

export class AppError extends Error {
  constructor(message, { code = ERROR_CODES.INTERNAL, status = 500, details = {} } = {}) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

/**
 * Standard success response helper conforming to CYBERLENS contract:
 * { "success": true, ...data }
 */
export function sendSuccess(res, data = {}, statusCode = 200) {
  return res.status(statusCode).json({
    success: true,
    ...data,
  });
}

/**
 * Standard error response helper conforming to CYBERLENS contract:
 * { "success": false, "error": { "code": "...", "message": "...", "details": {} } }
 */
export function sendError(res, { code = ERROR_CODES.INTERNAL, message = 'An unexpected error occurred.', details = {} }, statusCode = 500) {
  return res.status(statusCode).json({
    success: false,
    error: {
      code,
      message,
      details: details || {},
    },
  });
}

