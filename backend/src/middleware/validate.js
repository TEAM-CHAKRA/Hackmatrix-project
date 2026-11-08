import { ERROR_CODES } from '../config/constants.js';
import { AppError } from '../utils/response.js';

/**
 * Validate request payload using a Zod schema
 * @param {import('zod').ZodSchema} schema 
 * @param {'body' | 'query' | 'params'} source 
 */
export function validate(schema, source = 'body') {
  return (req, res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      const issue = result.error.issues[0];
      const path = issue?.path?.join('.');
      const message = issue ? (path ? `${path}: ${issue.message}` : issue.message) : 'Validation error.';
      const formattedDetails = result.error.flatten().fieldErrors;

      return next(
        new AppError(message, {
          code: ERROR_CODES.VALIDATION_ERROR,
          status: 400,
          details: formattedDetails,
        })
      );
    }
    req[source] = result.data;
    next();
  };
}

